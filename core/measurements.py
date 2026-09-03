"""Projective measurement in the Pauli bases. Track M1 (Ashab).

STUB -- importable and correctly typed. Real implementation is M1's.
"""

from __future__ import annotations

from contracts import Basis, MeasurementRecord


def measure_in_basis(circuit, qubit: int, basis: Basis) -> None:
    """Rotate `qubit` into `basis` and measure it, in place.

    Z: measure directly. X: H first. Y: S-dagger then H.
    """
    # TODO(M1): real basis rotation + measurement.
    return None


def records_from_counts(
    counts: dict[str, int],
    sig_id: str,
    basis: Basis,
    expected: int,
) -> list[MeasurementRecord]:
    """Expand simulator counts into one MeasurementRecord per shot.

    This is the seam into M4 -- MeasurementRecord is the only type that
    crosses from the quantum half to the statistics half.
    """
    # TODO(M1): real expansion.
    return []
