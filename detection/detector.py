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

    CALLER PROTOCOL -- the order is load-bearing, get it wrong and replay
    detection either fires on everything or on nothing:

        1. result = evaluate(records, sig, seen_nonces)   # do NOT add first
        2. seen_nonces.add(sig.nonce)                     # only after

    Adding before evaluating makes every signature a replay of itself and
    rejects 100% of legitimate traffic. Never adding at all disables replay
    detection silently. `evaluate` never mutates the set.

    Check replay FIRST inside this function -- a replayed signature has
    perfect statistics, so any other ordering lets it through.
    """
    # TODO(M4): real detection. Until then this FAILS CLOSED: an
    # unimplemented detector must not report ACCEPT/NONE, or wiring M3's
    # attack buttons to this stub renders four undetected attacks on the
    # dashboard and a green demo proves nothing.
    return DetectionResult(
        sig_id=sig.sig_id,
        verdict=Verdict.REJECT,
        threat=ThreatType.NONE,
        mismatch_rate=0.0,
        n_measurements=len(records),
        forgery_prob_bound=1.0,  # 1.0 = no guarantee, the honest stub value
        chi2_stat=0.0,
        chi2_p_value=1.0,
        reason="STUB DETECTOR — not implemented, rejecting by default",
        timestamp=0.0,
    )
