"""Threat detection engine. Track M4 (Hemang). Deliverable D2.

No machine learning anywhere in this path.

STUB -- importable and correctly typed. Real implementation is M4's.
"""

from __future__ import annotations

from contracts import (
    DetectionResult,
    MeasurementRecord,
    Signature,
    ThreatType,
    Verdict,
)


def evaluate(
    records: list[MeasurementRecord],
    sig: Signature,
    seen_nonces: set[str],
) -> DetectionResult:
    """Classify a signature from its measurement statistics.

    Pure function: replay state is passed in as `seen_nonces` rather than
    held at module level, so the same inputs always give the same output.
    The caller owns the set and updates it afterwards.

    Check replay FIRST -- a replayed signature has perfect statistics, so
    any other ordering lets it through.
    """
    # TODO(M4): real detection.
    return DetectionResult(
        sig_id=sig.sig_id,
        verdict=Verdict.ACCEPT,
        threat=ThreatType.NONE,
        mismatch_rate=0.0,
        n_measurements=len(records),
        forgery_prob_bound=1.0,
        chi2_stat=0.0,
        chi2_p_value=1.0,
        reason="stub detector: always accepts",
        timestamp=0.0,
    )
