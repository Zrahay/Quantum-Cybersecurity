"""Result-returning runners over the circuit builders. Track M1 (Ashab).

M2's QuantumCore wants measurement RESULTS. core/ elsewhere exposes circuit
BUILDERS. This module is the seam: run Aer one-shot, preserve copy order,
convert Qiskit little-endian memory into the frozen (clbit0, clbit1) order.

EntanglementBatch is opaque to M2 -- prepare, then pass straight back in.
Each teleport/measure call re-prepares independently (lazy handle, like the
mock), which matches M4's Hoeffding independence assumption on L copies.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from qiskit import QuantumCircuit
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_aer import AerSimulator

from contracts import Basis
from core.measurements import measure_in_basis
from core.teleportation import teleportation_circuit

# Bob's qubit / classical bit in teleportation_circuit (3q, 3c).
_BOB_QUBIT = 2
_MESSAGE_QUBIT = 0


@dataclass(frozen=True)
class EntanglementBatch:
    """Opaque handle for n independent teleportation copies.

    M2 must not inspect fields. Shape mirrors MockResource on purpose so the
    adapter swap is mechanical.
    """

    n_pairs: int
    noise_level: float


def bell_bits_from_memory(bitstring: str) -> tuple[int, int]:
    """Map one Qiskit memory string to frozen (clbit0, clbit1) circuit order.

    Qiskit memory is little-endian: the RIGHTMOST character is clbit0.
    Reading bitstring[0] would grab Bob's clbit2 on a 3-clbit teleport
    circuit -- the silent endian bug M3's forgery path already documents.
    """
    if len(bitstring) < 2:
        raise ValueError(f"need at least 2 classical bits in memory string; got {bitstring!r}")
    return (int(bitstring[-1]), int(bitstring[-2]))


def bob_bit_from_memory(bitstring: str) -> int:
    """Bob's classical bit (clbit2) from a 3-clbit teleport memory string."""
    if len(bitstring) < 3:
        raise ValueError(f"need 3 classical bits for Bob's outcome; got {bitstring!r}")
    return int(bitstring[0])


def prepare_batch(n: int, noise_level: float = 0.0) -> EntanglementBatch:
    """Validate and return a lazy batch handle. No qubits are allocated yet."""
    if n < 1:
        raise ValueError(f"need at least one Bell pair, got {n}")
    if not 0.0 <= noise_level <= 1.0:
        raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {noise_level}")
    return EntanglementBatch(n_pairs=n, noise_level=noise_level)


def _resolve_noise(batch: EntanglementBatch, noise_level: float | None) -> float:
    level = batch.noise_level if noise_level is None else noise_level
    if not 0.0 <= level <= 1.0:
        raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {level}")
    return level


def _require_batch(resource: object) -> EntanglementBatch:
    if not isinstance(resource, EntanglementBatch):
        raise TypeError(
            f"resource must be an EntanglementBatch from prepare_batch/bell_pairs; "
            f"got {type(resource).__name__}"
        )
    return resource


def _run_one(qc: QuantumCircuit, *, seed: int | None) -> str:
    sim = AerSimulator(seed_simulator=seed)
    pm = generate_preset_pass_manager(backend=sim, optimization_level=0)
    result = sim.run(pm.run(qc), shots=1, memory=True).result()
    return result.get_memory()[0]


def run_teleport_bell_outcomes(
    batch: EntanglementBatch,
    *,
    noise_level: float | None = None,
    seed: int | None = None,
) -> list[tuple[int, int]]:
    """One (clbit0, clbit1) pair per copy, circuit order, independent shots.

    Message defaults to |0⟩ -- QuantumCore.teleport has no message argument.
    """
    batch = _require_batch(batch)
    level = _resolve_noise(batch, noise_level)
    outcomes: list[tuple[int, int]] = []
    for i in range(batch.n_pairs):
        qc = teleportation_circuit(noise_level=level)
        # Reserve Bob's clbit so the memory string is always length 3 and
        # endian indexing matches forgery / measure.
        qc.measure(_BOB_QUBIT, _BOB_QUBIT)
        shot_seed = None if seed is None else seed + i
        outcomes.append(bell_bits_from_memory(_run_one(qc, seed=shot_seed)))
    return outcomes


def run_measure_bits(
    batch: EntanglementBatch,
    basis: Basis,
    *,
    noise_level: float | None = None,
    seed: int | None = None,
) -> list[int]:
    """Teleport |0⟩ then measure Bob in `basis`; one classical bit per copy."""
    batch = _require_batch(batch)
    if not isinstance(basis, Basis):
        raise TypeError(f"basis must be a contracts.Basis, got {type(basis).__name__}")
    level = _resolve_noise(batch, noise_level)
    bits: list[int] = []
    for i in range(batch.n_pairs):
        qc = teleportation_circuit(noise_level=level)
        measure_in_basis(qc, _BOB_QUBIT, basis)
        shot_seed = None if seed is None else seed + i
        bits.append(bob_bit_from_memory(_run_one(qc, seed=shot_seed)))
    return bits


def prepare_pauli_eigenstate(
    circuit: QuantumCircuit, qubit: int, basis: Basis, bit: int
) -> None:
    """Prepare an eigenstate of the named Pauli on `qubit`, in place.

    `bit` selects the eigenvalue, and the convention is the one frozen in
    contracts.MeasurementRecord: bit 0 is the +1 eigenstate, bit 1 the -1
    eigenstate. Never +1/-1 themselves.

        Z: |0>, |1>        X: |+>, |->        Y: |+i>, |-i>

    This is the exact inverse of `measure_in_basis`: prepare in a basis,
    measure in the SAME basis, and on an ideal channel you get `bit` back
    with certainty. Measure in a different basis and the outcome is
    uniformly random -- which is the whole mechanism the signature
    verification rests on, so the two functions must stay inverse. There is
    a round-trip test per (basis, bit) pair in tests/test_runtime.py.
    """
    if qubit < 0 or qubit >= circuit.num_qubits:
        raise ValueError(
            f"qubit index {qubit} out of range for circuit with "
            f"{circuit.num_qubits} qubits"
        )
    if not isinstance(basis, Basis):
        raise TypeError(f"basis must be a contracts.Basis, got {type(basis).__name__}")
    if bit not in (0, 1):
        raise ValueError(f"bit must be a classical bit 0 or 1; got {bit!r}")

    if bit:
        circuit.x(qubit)
    if basis is Basis.Z:
        return
    if basis is Basis.X:
        circuit.h(qubit)
        return
    if basis is Basis.Y:
        # measure_in_basis(Y) undoes this with sdg then h.
        circuit.h(qubit)
        circuit.s(qubit)
        return
    raise ValueError(f"unknown Basis: {basis!r}")


def run_teleport_and_measure(
    batch: EntanglementBatch,
    preparations: Sequence[tuple[Basis, int]],
    bases: Sequence[Basis],
    *,
    noise_level: float | None = None,
    seed: int | None = None,
) -> list[tuple[tuple[int, int], int]]:
    """Prepare, teleport and measure each copy in ONE shot.

    Returns ((clbit0, clbit1), bob_bit) per copy, in copy order.

    WHY THIS EXISTS SEPARATELY from run_teleport_bell_outcomes and
    run_measure_bits: those two run independent shots, so a Bell outcome
    from one and a measured bit from the other belong to different copies
    and are uncorrelated. A signature protocol needs the Bell outcome and
    the recipient's measured bit FROM THE SAME teleportation, because the
    correction implied by that outcome is what makes the measured bit
    meaningful. Splitting them across two runs silently produces a 50%
    mismatch rate on legitimate signatures.

    `preparations[i]` is the (basis, bit) Pauli eigenstate the sender puts
    on the message qubit; `bases[i]` is the basis the recipient measures
    Bob's qubit in. Both must be as long as the batch.
    """
    batch = _require_batch(batch)
    if len(preparations) != batch.n_pairs:
        raise ValueError(
            f"preparations length {len(preparations)} does not match batch "
            f"size {batch.n_pairs}"
        )
    if len(bases) != batch.n_pairs:
        raise ValueError(
            f"bases length {len(bases)} does not match batch size {batch.n_pairs}"
        )
    level = _resolve_noise(batch, noise_level)

    results: list[tuple[tuple[int, int], int]] = []
    for i, ((prep_basis, prep_bit), meas_basis) in enumerate(zip(preparations, bases)):
        if not isinstance(meas_basis, Basis):
            raise TypeError(
                f"bases[{i}] must be a contracts.Basis, got {type(meas_basis).__name__}"
            )
        qc = QuantumCircuit(3, 3)
        prepare_pauli_eigenstate(qc, _MESSAGE_QUBIT, prep_basis, prep_bit)
        qc.compose(teleportation_circuit(noise_level=level), inplace=True)
        measure_in_basis(qc, _BOB_QUBIT, meas_basis)
        shot_seed = None if seed is None else seed + i
        memory = _run_one(qc, seed=shot_seed)
        results.append((bell_bits_from_memory(memory), bob_bit_from_memory(memory)))
    return results
