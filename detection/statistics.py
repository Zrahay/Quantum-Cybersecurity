"""Statistical primitives for detection. Track M4 (Hemang).

No machine learning. Every function here is a closed-form bound or a
hypothesis test you could write on a whiteboard.
"""

from __future__ import annotations

import math

from scipy import stats

from contracts import MeasurementRecord


def mismatch_rate(records: list[MeasurementRecord]) -> float:
    """Fraction of measurements disagreeing with prediction. 0.0 - 1.0.

    Raises ValueError on an empty list. This is deliberate: a rate of 0.0
    is the single strongest evidence of a legitimate signature, so
    returning it for "we have no data" fails open — every forgery would
    sail through `r < s_a`. No measurements is insufficient data, and the
    caller must say so, exactly as chi2_uniformity below refuses to return
    a p-value it cannot justify.
    """
    if not records:
        raise ValueError("no measurement records: insufficient data, not a zero mismatch rate")
    return sum(r.mismatch for r in records) / len(records)


def hoeffding_bound(n: int, margin: float) -> float:
    """One-sided Hoeffding bound: exp(-2 n margin^2).

    Assumes the n outcomes are INDEPENDENT. M2 must justify that from how
    the copies are prepared -- if they are correlated this does not hold.

    n <= 0 or margin <= 0 gives no guarantee at all -- 1.0, the honest
    "cannot bound this" value, not 0.0 (which would read as "certainly
    safe" for zero evidence, the exact fail-open shape `mismatch_rate`'s
    docstring warns against).
    """
    if n <= 0 or margin <= 0:
        return 1.0
    return math.exp(-2.0 * n * margin * margin)


def chi2_uniformity(counts: dict[str, int], expected: dict[str, float]) -> tuple[float, float]:
    """Goodness-of-fit of observed outcomes against the predicted distribution.

    Returns (statistic, p_value). Requires an expected count of at least 5
    per cell -- below that the test is invalid and the caller should report
    insufficient data rather than a meaningless p-value, so this returns
    the same honest placeholder as an unresolved test: (0.0, 1.0), a
    p-value of 1.0 meaning "no evidence against the null", never a
    fabricated small p-value implying detection.

    `counts` and `expected` must share the same cell keys (a key missing
    from one is treated as a zero-count / zero-expected cell in the other).
    """
    keys = sorted(set(counts) | set(expected))
    if not keys:
        return (0.0, 1.0)
    observed = [float(counts.get(k, 0)) for k in keys]
    expected_counts = [float(expected.get(k, 0.0)) for k in keys]
    if any(e < 5.0 for e in expected_counts):
        return (0.0, 1.0)
    stat, p_value = stats.chisquare(observed, expected_counts)
    return (float(stat), float(p_value))
