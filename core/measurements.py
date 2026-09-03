"""Projective measurement in the Pauli bases. Track M1 (Ashab).

STUB -- importable and correctly typed. Real implementation is M1's.
"""

from __future__ import annotations

from collections.abc import Sequence

from qiskit import QuantumCircuit

from contracts import Basis, MeasurementRecord


def measure_in_basis(circuit: QuantumCircuit, qubit: int, basis: Basis) -> None:
    """Rotate `qubit` into `basis` and measure it, in place.

    Z: measure directly. X: H first. Y: S-dagger then H.
    """
    # TODO(M1): real basis rotation + measurement.
    return None


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
    # TODO(M1): real expansion.
    return []
