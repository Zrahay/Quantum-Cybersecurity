"""Attack strength sweep utility. Track M3 (Nikita). Phase 4.

Runs an adversary at multiple ``strength`` (or ``key_knowledge``) values
and collects match-rate statistics.  The output DataFrame is ready for
M4 (detection curves) and M6 (benchmark plots).

No AI/ML is used.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pandas as pd

from attacks.utils import run_batch

if TYPE_CHECKING:
    from attacks.base import BaseAdversary
    from contracts import Signature


def sweep_strength(
    adversary_cls: type[BaseAdversary],
    signatures: list[Signature],
    strengths: list[float] | None = None,
    **kwargs,
) -> pd.DataFrame:
    """Run *adversary_cls* at each strength level and collect results.

    Args:
        adversary_cls: The adversary class to instantiate (e.g.
            ``ForgeryAdversary``, ``PartialKeyForgeryAdversary``).
        signatures: List of original (untampered) ``Signature`` objects.
        strengths: Strength values to sweep.  Defaults to
            ``[0.0, 0.1, 0.2, ..., 1.0]``.
        **kwargs: Extra keyword arguments forwarded to the adversary
            constructor (e.g. ``key_knowledge=0.5``).

    Returns:
        A :class:`pandas.DataFrame` with one row per (strength, trial).
        Includes ``mean_ops_match_rate`` and ``mean_outcomes_match_rate``
        per strength level for easy plotting.
    """
    if strengths is None:
        strengths = [round(i * 0.1, 1) for i in range(11)]

    frames: list[pd.DataFrame] = []
    for s in strengths:
        adv = adversary_cls(strength=s, **kwargs)
        df = run_batch(adv, signatures)
        frames.append(df)

    return pd.concat(frames, ignore_index=True)


def sweep_key_knowledge(
    signatures: list[Signature],
    knowledge_levels: list[float] | None = None,
    strengths: list[float] | None = None,
) -> pd.DataFrame:
    """Sweep ``PartialKeyForgeryAdversary`` across key knowledge levels.

    This is the Phase 4 demo curve: detection degrades gracefully as
    Eve's key knowledge increases.

    Args:
        signatures: List of original (untampered) ``Signature`` objects.
        knowledge_levels: ``key_knowledge`` values to sweep.  Defaults
            to ``[0.0, 0.1, 0.2, ..., 1.0]``.
        strengths: Strength values within each knowledge level.
            Defaults to ``[1.0]`` (full forgery at each knowledge level).

    Returns:
        A :class:`pandas.DataFrame` with columns including
        ``key_knowledge``, ``ops_match_rate``, and
        ``outcomes_match_rate``.
    """
    from attacks.partial_forgery import PartialKeyForgeryAdversary

    if knowledge_levels is None:
        knowledge_levels = [round(i * 0.1, 1) for i in range(11)]
    if strengths is None:
        strengths = [1.0]

    frames: list[pd.DataFrame] = []
    for kk in knowledge_levels:
        for s in strengths:
            adv = PartialKeyForgeryAdversary(key_knowledge=kk, strength=s)
            df = run_batch(adv, signatures)
            df["key_knowledge"] = kk
            frames.append(df)

    return pd.concat(frames, ignore_index=True)


def summary_by_strength(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate a sweep DataFrame into per-strength summary stats.

    Returns a DataFrame with columns:
        strength, mean_ops_match_rate, std_ops_match_rate,
        mean_outcomes_match_rate, std_outcomes_match_rate, n_trials
    """
    return (
        df.groupby("strength")
        .agg(
            mean_ops_match_rate=("ops_match_rate", "mean"),
            std_ops_match_rate=("ops_match_rate", "std"),
            mean_outcomes_match_rate=("outcomes_match_rate", "mean"),
            std_outcomes_match_rate=("outcomes_match_rate", "std"),
            n_trials=("trial_id", "count"),
        )
        .reset_index()
    )


def summary_by_key_knowledge(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate a key-knowledge sweep into per-knowledge summary stats.

    Returns a DataFrame with columns:
        key_knowledge, mean_ops_match_rate, std_ops_match_rate,
        mean_outcomes_match_rate, std_outcomes_match_rate, n_trials
    """
    return (
        df.groupby("key_knowledge")
        .agg(
            mean_ops_match_rate=("ops_match_rate", "mean"),
            std_ops_match_rate=("ops_match_rate", "std"),
            mean_outcomes_match_rate=("outcomes_match_rate", "mean"),
            std_outcomes_match_rate=("outcomes_match_rate", "std"),
            n_trials=("trial_id", "count"),
        )
        .reset_index()
    )
