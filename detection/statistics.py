"""Statistical primitives for detection. Track M4 (Hemang).

No machine learning. Every function here is a closed-form bound or a
hypothesis test you could write on a whiteboard.

STUB -- importable and correctly typed. Real implementation is M4's.
"""

from __future__ import annotations

from contracts import MeasurementRecord


def mismatch_rate(records: list[MeasurementRecord]) -> float:
    """Fraction of measurements disagreeing with prediction. 0.0 - 1.0."""
    if not records:
        return 0.0
    return sum(r.mismatch for r in records) / len(records)


def hoeffding_bound(n: int, margin: float) -> float:
    """One-sided Hoeffding bound: exp(-2 n margin^2).

    Assumes the n outcomes are INDEPENDENT. M2 must justify that from how
    the copies are prepared -- if they are correlated this does not hold.
    """
    # TODO(M4): real bound.
    return 1.0


def chi2_uniformity(counts: dict[str, int], expected: dict[str, float]) -> tuple[float, float]:
    """Goodness-of-fit of observed outcomes against the predicted distribution.

    Returns (statistic, p_value). Requires an expected count of at least 5
    per cell -- below that the test is invalid and the caller should report
    insufficient data rather than a meaningless p-value.
    """
    # TODO(M4): real chi-square.
    return (0.0, 1.0)
