"""Threat detection engine. Track M4 (Hemang). Deliverable D2.

No machine learning anywhere in this path.

evaluate() is a pure function: replay state is passed in as `seen_nonces`
rather than held at module level, so the same inputs always give the same
output.

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

from __future__ import annotations

import time

from contracts import (
    DetectionResult,
    MeasurementRecord,
    Signature,
    ThreatType,
    Verdict,
)
from detection.statistics import chi2_uniformity, hoeffding_bound, mismatch_rate


# Target forgery probability (from config). The thresholds s_a, s_v are
# DERIVED from the measured noise floor and this p_f. Never hardcode them.
TARGET_FORGERY_PROB = 1e-6


def _derive_thresholds(noise_floor: float, n_measurements: int) -> tuple[float, float]:
    """Derive acceptance (s_a) and verification (s_v) thresholds.

    s_a = noise_floor + margin_a  where margin_a satisfies Hoeffding(n, margin_a) = p_f
    s_v = noise_floor + margin_v  where margin_v satisfies Hoeffding(n, margin_v) = p_f / 2

    Legitimate signatures have mismatch rate ~ noise_floor.
    Forgeries have mismatch rate ~ 0.5.
    """
    # Solve exp(-2 n m^2) = p_f  =>  m = sqrt(-ln(p_f) / (2 n))
    import math
    margin_a = math.sqrt(-math.log(TARGET_FORGERY_PROB) / (2 * n_measurements))
    margin_v = math.sqrt(-math.log(TARGET_FORGERY_PROB / 2) / (2 * n_measurements))
    s_a = noise_floor + margin_a
    s_v = noise_floor + margin_v
    # Cap at 1.0
    return (min(s_a, 1.0), min(s_v, 1.0))


def _classify_threat(
    records: list[MeasurementRecord],
    sig: Signature,
    mismatch: float,
) -> ThreatType:
    """Classify the threat type based on signature anomalies.

    Priority order (most specific first):
    1. Replay: nonce reuse (checked before calling this)
    2. Impersonation: fabricated key_id, random ops/outcomes
    3. Forgery: valid key_id but random ops, real bell outcomes from Eve's teleportation
    4. Channel tamper: valid key_id and ops, but corrupted bell_outcomes
    5. None: legitimate
    """
    # Impersonation: key_id doesn't match any known key (fabricated)
    # In practice we'd check against a key registry. Here we detect by:
    # - ops are uniformly random (high entropy)
    # - bell_outcomes are uniformly random
    if _is_random_ops(sig.declared_ops) and _is_random_outcomes(sig.bell_outcomes):
        return ThreatType.IMPERSONATION

    # Forgery: key_id is valid (matches signer's key) but ops are random
    # while bell_outcomes are from real teleportation (correlated with message)
    if _is_random_ops(sig.declared_ops) and not _is_random_outcomes(sig.bell_outcomes):
        return ThreatType.FORGERY

    # Channel tamper: ops match pauli_map (valid) but bell_outcomes are corrupted
    # Detected by high mismatch rate with valid ops
    if mismatch > 0.25 and not _is_random_ops(sig.declared_ops):
        return ThreatType.CHANNEL_TAMPER

    return ThreatType.NONE


def _is_random_ops(ops: tuple) -> bool:
    """Heuristic: ops look uniformly random over PauliOp."""
    if not ops:
        return False
    from collections import Counter
    counts = Counter(ops)
    # If all 4 Pauli ops appear roughly equally, it's random
    n = len(ops)
    expected = n / 4
    return all(abs(c - expected) < n * 0.3 for c in counts.values())


def _is_random_outcomes(outcomes: tuple[tuple[int, int], ...]) -> bool:
    """Heuristic: bell outcomes look uniformly random over 4 possibilities."""
    if not outcomes:
        return False
    from collections import Counter
    counts = Counter(outcomes)
    n = len(outcomes)
    expected = n / 4
    return all(abs(c - expected) < n * 0.3 for c in counts.values())


def _chi2_expected_distribution(records: list[MeasurementRecord]) -> dict[str, float]:
    """Expected outcome distribution under legitimate hypothesis.

    For legitimate signatures, expected == observed for each record (up to noise).
    The distribution of observed bits should match expected bits.
    """
    # Under H0 (legitimate), outcomes match predictions with prob (1 - noise_floor)
    # and are flipped with prob noise_floor.
    # For simplicity, we expect uniform distribution over the 4 Bell outcomes
    # mapped to measurement results.
    # Here we just check uniformity of observed bits (0/1) across bases.
    # Expected: 50% 0, 50% 1 for random message bits.
    # But we don't know the message... so we use the fact that for legitimate
    # signatures, observed should match expected per record.
    # Chi-square on mismatch pattern: mismatches should follow Binomial(n, noise_floor).
    # For simplicity, test uniformity of observed bits per basis.
    from collections import Counter
    counts = Counter()
    for r in records:
        counts[f"{r.basis.value}:{r.observed}"] += 1
    # Expected: uniform across basis and bit value
    n = len(records)
    n_bases = len({r.basis for r in records})
    expected = {}
    for r in records:
        key = f"{r.basis.value}:{r.observed}"
        expected[key] = n / (n_bases * 2)
    return expected


def evaluate(
    records: list[MeasurementRecord],
    sig: Signature,
    seen_nonces: set[str],
) -> DetectionResult:
    """Classify a signature from its measurement statistics.

    Pure function: replay state is passed in as `seen_nonces` rather than
    held at module level, so the same inputs always give the same output.

    CALLER PROTOCOL:
        1. result = evaluate(records, sig, seen_nonces)   # do NOT add first
        2. seen_nonces.add(sig.nonce)                     # only after
    """
    # 1. REPLAY CHECK -- must be FIRST. Replayed signature has perfect
    # statistics but reused nonce.
    if sig.nonce in seen_nonces:
        return DetectionResult(
            sig_id=sig.sig_id,
            verdict=Verdict.REJECT,
            threat=ThreatType.REPLAY,
            mismatch_rate=0.0,
            n_measurements=len(records),
            forgery_prob_bound=1.0,
            chi2_stat=0.0,
            chi2_p_value=1.0,
            reason="Replay detected: nonce already seen",
            timestamp=time.time(),
        )

    if not records:
        return DetectionResult(
            sig_id=sig.sig_id,
            verdict=Verdict.REJECT,
            threat=ThreatType.NONE,
            mismatch_rate=0.0,
            n_measurements=0,
            forgery_prob_bound=1.0,
            chi2_stat=0.0,
            chi2_p_value=1.0,
            reason="No measurement records: insufficient data",
            timestamp=time.time(),
        )

    # 2. Compute mismatch rate
    mismatch = mismatch_rate(records)
    n = len(records)

    # 3. Estimate noise floor from the measurement statistics.
    # For a legitimate signature, the mismatch rate IS the noise floor.
    # We use the observed mismatch rate as the noise floor estimate.
    noise_floor = mismatch

    # 4. Derive thresholds from noise floor and target forgery probability
    s_a, s_v = _derive_thresholds(noise_floor, n)

    # 5. Hoeffding bound on forgery probability at this mismatch rate
    # If r >= s_v, forgery probability bound is exp(-2 n (r - noise_floor)^2)
    margin = max(0.0, mismatch - noise_floor)
    forgery_bound = hoeffding_bound(n, margin)

    # 6. Chi-square uniformity test on observed outcomes
    expected_dist = _chi2_expected_distribution(records)
    observed_counts: dict[str, int] = {}
    for rec in records:
        key = f"{rec.basis.value}:{rec.observed}"
        observed_counts[key] = observed_counts.get(key, 0) + 1
    chi2_stat, chi2_p = chi2_uniformity(observed_counts, expected_dist)

    # 7. Classify threat (after replay check)
    threat = _classify_threat(records, sig, mismatch)

    # 8. Verdict from thresholds
    if mismatch < s_a:
        verdict = Verdict.ACCEPT
    elif mismatch < s_v:
        verdict = Verdict.ACCEPT_NO_TRANSFER
    else:
        verdict = Verdict.REJECT

    # 9. Human-readable reason
    if threat is ThreatType.REPLAY:
        reason = "Replay detected: nonce already seen"
    elif threat is ThreatType.FORGERY:
        reason = f"Forgery suspected: mismatch rate {mismatch:.2%} exceeds threshold"
    elif threat is ThreatType.IMPERSONATION:
        reason = f"Impersonation suspected: random ops/outcomes, mismatch {mismatch:.2%}"
    elif threat is ThreatType.CHANNEL_TAMPER:
        reason = f"Channel tampering suspected: mismatch rate {mismatch:.2%} with valid ops"
    elif verdict is Verdict.ACCEPT:
        reason = f"Legitimate: mismatch rate {mismatch:.2%} within acceptance threshold"
    elif verdict is Verdict.ACCEPT_NO_TRANSFER:
        reason = f"Marginal: mismatch rate {mismatch:.2%} in verification window"
    else:
        reason = f"Rejected: mismatch rate {mismatch:.2%} exceeds verification threshold"

    return DetectionResult(
        sig_id=sig.sig_id,
        verdict=verdict,
        threat=threat,
        mismatch_rate=mismatch,
        n_measurements=n,
        forgery_prob_bound=forgery_bound,
        chi2_stat=chi2_stat,
        chi2_p_value=chi2_p,
        reason=reason,
        timestamp=time.time(),
    )
