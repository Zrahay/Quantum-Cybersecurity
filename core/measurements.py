"""Projective measurement in the Pauli bases. Track M1 (Ashab).

Bob's "flip the coin" step: rotate into the named basis, measure, and
hand per-copy bits to M4 as MeasurementRecords.
"""

from __future__ import annotations

from collections.abc import Sequence

from qiskit import QuantumCircuit

from contracts import Basis, MeasurementRecord


def measure_in_basis(circuit: QuantumCircuit, qubit: int, basis: Basis) -> None:
    """Rotate `qubit` into `basis` and measure it, in place.

    Z: measure directly. X: H first. Y: S-dagger then H.

    The outcome is written to classical bit `qubit` (same index). That matches
    teleportation's reserved Bob slot: qubit 2 → clbit 2. Callers that need a
    different clbit should map registers before calling, not invent a second API.
    """
    if qubit < 0 or qubit >= circuit.num_qubits:
        raise ValueError(
            f"qubit index {qubit} out of range for circuit with "
            f"{circuit.num_qubits} qubits"
        )
    if qubit >= circuit.num_clbits:
        raise ValueError(
            f"no classical bit at index {qubit} for circuit with "
            f"{circuit.num_clbits} clbits"
        )

    if basis is Basis.Z:
        pass
    elif basis is Basis.X:
        circuit.h(qubit)
    elif basis is Basis.Y:
        circuit.sdg(qubit)
        circuit.h(qubit)
    else:
        raise ValueError(f"unknown Basis: {basis!r}")

    circuit.measure(qubit, qubit)


def _require_bit(name: str, value: int, index: int) -> int:
    if value not in (0, 1):
        raise ValueError(
            f"{name}[{index}] must be a classical bit 0 or 1; got {value!r}"
        )
    return value


def records_from_shots(
    observed: Sequence[int],
    expected: Sequence[int],
    sig_id: str,
    basis: Basis,
) -> list[MeasurementRecord]:
    """Build one MeasurementRecord per copy. The seam into M4.

    Takes PER-COPY sequences, not a Qiskit counts dict. A counts dict is
    aggregated by outcome string and carries no shot ordering, so there is
    no honest way to recover `copy_index` from it -- and `expected` varies
    per copy anyway, since pauli_map is per message bit. Whoever runs the
    circuit must keep the per-shot order and pass it here.

    `copy_index` is the position in these sequences, 0 .. L-1. The
    exponential forgery bound in L only means anything if that index is
    real rather than invented by enumerate() over a dict.
    """
    if len(observed) != len(expected):
        raise ValueError(f"observed/expected length mismatch: {len(observed)} vs {len(expected)}")

    records: list[MeasurementRecord] = []
    for i, (obs, exp) in enumerate(zip(observed, expected)):
        records.append(
            MeasurementRecord(
                sig_id=sig_id,
                copy_index=i,
                basis=basis,
                expected=_require_bit("expected", exp, i),
                observed=_require_bit("observed", obs, i),
            )
        )
    return records
