"""Attack batch runner. Track M3 (Nikita). Deliverable D4.

Runs an adversary against a list of signatures and collects a clean
DataFrame for M4 (detection) and M6 (benchmarks).

No AI/ML is used.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    from attacks.base import BaseAdversary
    from contracts import Signature


def run_batch(
    adversary: BaseAdversary,
    signatures: list[Signature],
) -> pd.DataFrame:
    """Run *adversary* against each signature and collect results.

    Every row is one trial.  Columns are fields actually available on
    ``Signature`` and ``BaseAdversary`` — nothing invented.

    M4 can use this directly for Hoeffding / chi-square by grouping on
    ``attack_type`` and comparing ``ops_match`` / ``outcomes_match``
    rates.  M6 can use it for benchmarking by timing the loop externally.

    Args:
        adversary:   An ``Adversary`` implementation (Forgery, Replay, etc.).
        signatures:  List of original (untampered) ``Signature`` objects.

    Returns:
        A :class:`pandas.DataFrame` with one row per trial.
    """
    records: list[dict] = []
    for trial_id, sig in enumerate(signatures):
        tampered = adversary.attack(sig)

        # Bit-level comparison of declared_ops
        ops_diff = sum(
            1 for o, t in zip(sig.declared_ops, tampered.declared_ops)
            if o != t
        )
        n_ops = len(sig.declared_ops)

        # Bit-level comparison of bell_outcomes
        outcomes_diff = sum(
            1 for o, t in zip(sig.bell_outcomes, tampered.bell_outcomes)
            if o != t
        )
        n_outcomes = len(sig.bell_outcomes)

        records.append({
            "trial_id": trial_id,
            "attack_type": adversary.threat.value,
            "strength": adversary.strength,
            "original_sig_id": sig.sig_id,
            "tampered_sig_id": tampered.sig_id,
            "n_bits": len(sig.message),
            "nonce_changed": sig.nonce != tampered.nonce,
            "key_id_changed": sig.key_id != tampered.key_id,
            "signer_id_changed": sig.signer_id != tampered.signer_id,
            "ops_changed": sig.declared_ops != tampered.declared_ops,
            "ops_diff_count": ops_diff,
            "ops_match_rate": 1.0 - (ops_diff / n_ops) if n_ops > 0 else 0.0,
            "outcomes_changed": sig.bell_outcomes != tampered.bell_outcomes,
            "outcomes_diff_count": outcomes_diff,
            "outcomes_match_rate": (
                1.0 - (outcomes_diff / n_outcomes) if n_outcomes > 0 else 0.0
            ),
        })

    return pd.DataFrame(records)
