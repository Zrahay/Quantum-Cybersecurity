"""Result-returning runners over the circuit builders. Track M1 (Ashab).

M2's QuantumCore wants measurement RESULTS. core/ elsewhere exposes circuit
BUILDERS. This module is the seam: run Aer one-shot, preserve copy order,
convert Qiskit little-endian memory into the frozen (clbit0, clbit1) order.

EntanglementBatch is opaque to M2 -- prepare, then pass straight back in.
Each teleport/measure call re-prepares independently (lazy handle, like the
mock), which matches M4's Hoeffding independence assumption on L copies.
"""

from __future__ import annotations

from dataclasses import dataclass

from qiskit import QuantumCircuit
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_aer import AerSimulator

from contracts import Basis
from core.measurements import measure_in_basis
from core.teleportation import teleportation_circuit

# Bob's qubit / classical bit in teleportation_circuit (3q, 3c).
_BOB_QUBIT = 2


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
