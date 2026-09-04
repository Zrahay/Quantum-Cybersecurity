"""Tests for the Attack Simulator (M3). Track M3 (Nikita). Deliverable D4.

Covers all four adversary classes against Ashab's contracts.
Each test verifies the ``Adversary`` protocol contract and
attack-specific behaviour.

No AI/ML is used.
"""

import unittest

from contracts import (
    Basis,
    PauliOp,
    Signature,
    ThreatType,
)

from attacks.replay import ReplayAdversary
from attacks.forgery import ForgeryAdversary
from attacks.channel_tamper import ChannelTamperAdversary
from attacks.impersonation import ImpersonationAdversary
from attacks.base import BaseAdversary


# ── Helpers ──────────────────────────────────────────────────────────────

def _make_sig(
    n_bits: int = 4,
    signer_id: str = "alice",
    key_id: str = "key-real",
    nonce: str = "nonce-1",
) -> Signature:
    """Build a minimal valid Signature for testing."""
    return Signature(
        sig_id="sig-test",
        key_id=key_id,
        signer_id=signer_id,
        message=(0,) * n_bits,
        declared_ops=(PauliOp.I,) * n_bits,
        bell_outcomes=((0, 0),) * n_bits,
        nonce=nonce,
        timestamp=1.0,
    )


# ── Protocol contract ────────────────────────────────────────────────────

class TestAdversaryProtocol(unittest.TestCase):
    """All four adversaries must satisfy the Adversary protocol."""

    def setUp(self):
        self.sig = _make_sig()
        self.adversaries = [
            ReplayAdversary(),
            ForgeryAdversary(),
            ChannelTamperAdversary(),
            ImpersonationAdversary(),
        ]

    def test_all_have_threat(self):
        for adv in self.adversaries:
            self.assertIsInstance(adv.threat, ThreatType)

    def test_all_have_name(self):
        for adv in self.adversaries:
            self.assertIsInstance(adv.name, str)
            self.assertEqual(adv.name, adv.threat.value)

    def test_all_return_signature(self):
        for adv in self.adversaries:
            result = adv.attack(self.sig)
            self.assertIsInstance(result, Signature)

    def test_threat_types_are_distinct(self):
        threats = {adv.threat for adv in self.adversaries}
        self.assertEqual(len(threats), 4)


# ── Replay ───────────────────────────────────────────────────────────────

class TestReplay(unittest.TestCase):

    def test_returns_same_nonce(self):
        sig = _make_sig(nonce="abc")
        adv = ReplayAdversary()
        result = adv.attack(sig)
        self.assertEqual(result.nonce, "abc")

    def test_returns_same_sig_id(self):
        sig = _make_sig()
        adv = ReplayAdversary()
        result = adv.attack(sig)
        self.assertEqual(result.sig_id, sig.sig_id)

    def test_nonce_recorded(self):
        sig = _make_sig(nonce="xyz")
        adv = ReplayAdversary()
        adv.attack(sig)
        self.assertIn("xyz", adv.seen_nonces)

    def test_multiple_replays(self):
        sig = _make_sig(nonce="r1")
        adv = ReplayAdversary()
        for _ in range(5):
            result = adv.attack(sig)
        self.assertEqual(result.nonce, "r1")
        self.assertIn("r1", adv.seen_nonces)


# ── Forgery ──────────────────────────────────────────────────────────────

class TestForgery(unittest.TestCase):

    def test_different_ops_each_time(self):
        sig = _make_sig()
        adv = ForgeryAdversary()
        r1 = adv.attack(sig)
        r2 = adv.attack(sig)
        self.assertNotEqual(r1.declared_ops, r2.declared_ops)

    def test_different_outcomes_each_time(self):
        sig = _make_sig()
        adv = ForgeryAdversary()
        r1 = adv.attack(sig)
        r2 = adv.attack(sig)
        self.assertNotEqual(r1.bell_outcomes, r2.bell_outcomes)

    def test_message_preserved(self):
        sig = _make_sig(n_bits=8)
        adv = ForgeryAdversary()
        result = adv.attack(sig)
        self.assertEqual(result.message, sig.message)

    def test_ops_length_matches_message(self):
        sig = _make_sig(n_bits=6)
        adv = ForgeryAdversary()
        result = adv.attack(sig)
        self.assertEqual(len(result.declared_ops), 6)

    def test_outcomes_length_matches_message(self):
        sig = _make_sig(n_bits=6)
        adv = ForgeryAdversary()
        result = adv.attack(sig)
        self.assertEqual(len(result.bell_outcomes), 6)

    def test_ops_are_valid_pauli(self):
        sig = _make_sig()
        adv = ForgeryAdversary()
        result = adv.attack(sig)
        for op in result.declared_ops:
            self.assertIsInstance(op, PauliOp)

    def test_outcomes_are_valid_bits(self):
        sig = _make_sig()
        adv = ForgeryAdversary()
        result = adv.attack(sig)
        for c0, c1 in result.bell_outcomes:
            self.assertIn(c0, (0, 1))
            self.assertIn(c1, (0, 1))

    def test_full_forgery_ops_differ_from_original(self):
        """At strength=1.0, ops should be randomised — far fewer matches than bits."""
        sig = _make_sig(n_bits=32)
        adv = ForgeryAdversary(strength=1.0)
        result = adv.attack(sig)
        ops_match = sum(
            1 for o, f in zip(sig.declared_ops, result.declared_ops) if o == f
        )
        # Random Pauli against random Pauli: ~25% match by chance.
        # 32 bits → expect ~8 matches.  Assert well below half.
        self.assertLess(ops_match, 16)

    def test_forgery_detectable_via_batch(self):
        """Forgery match rate should be well below 1.0 — M4 can catch it."""
        from attacks.utils import run_batch
        sigs = [_make_sig(n_bits=8) for _ in range(20)]
        df = run_batch(ForgeryAdversary(strength=1.0), sigs)
        avg_ops_match = df["ops_match_rate"].mean()
        # Random Pauli ops against random ops: ~25% per-bit match chance
        self.assertLess(avg_ops_match, 0.5)


# ── Channel Tamper ───────────────────────────────────────────────────────

class TestChannelTamper(unittest.TestCase):

    def test_zero_strength_preserves(self):
        """strength=0.0 means no tampering — outcomes unchanged."""
        sig = _make_sig()
        adv = ChannelTamperAdversary(strength=0.0)
        result = adv.attack(sig)
        self.assertEqual(result.bell_outcomes, sig.bell_outcomes)

    def test_full_strength_disturbs(self):
        """strength=1.0 should disturb at least some outcomes."""
        sig = _make_sig(n_bits=32)
        adv = ChannelTamperAdversary(strength=1.0)
        result = adv.attack(sig)
        # With 32 pairs all targeted, at least one should differ
        self.assertNotEqual(result.bell_outcomes, sig.bell_outcomes)

    @unittest.skip("Flaky: 2 bits at 50% flip has ~0.3% chance of zero preserves in 20 trials")
    def test_partial_strength(self):
        """strength=0.5 with a short message should sometimes preserve."""
        sig = _make_sig(n_bits=2)
        adv = ChannelTamperAdversary(strength=0.5)
        preserved = 0
        for _ in range(20):
            result = adv.attack(sig)
            if result.bell_outcomes == sig.bell_outcomes:
                preserved += 1
        self.assertGreater(preserved, 0)

    def test_ops_preserved(self):
        """Channel tamper only touches bell_outcomes, not declared_ops."""
        sig = _make_sig()
        adv = ChannelTamperAdversary(strength=1.0)
        result = adv.attack(sig)
        self.assertEqual(result.declared_ops, sig.declared_ops)

    def test_message_preserved(self):
        sig = _make_sig()
        adv = ChannelTamperAdversary(strength=1.0)
        result = adv.attack(sig)
        self.assertEqual(result.message, sig.message)


# ── Impersonation ────────────────────────────────────────────────────────

class TestImpersonation(unittest.TestCase):

    def test_claimed_identity_appears(self):
        sig = _make_sig(signer_id="bob")
        adv = ImpersonationAdversary(claimed_identity="alice")
        result = adv.attack(sig)
        self.assertEqual(result.signer_id, "alice")

    def test_different_key_id(self):
        """Eve doesn't know the real key_id — it should differ."""
        sig = _make_sig(key_id="key-real")
        adv = ImpersonationAdversary()
        result = adv.attack(sig)
        self.assertNotEqual(result.key_id, "key-real")

    def test_message_preserved(self):
        sig = _make_sig(n_bits=8)
        adv = ImpersonationAdversary()
        result = adv.attack(sig)
        self.assertEqual(result.message, sig.message)

    def test_ops_length_matches_message(self):
        sig = _make_sig(n_bits=6)
        adv = ImpersonationAdversary()
        result = adv.attack(sig)
        self.assertEqual(len(result.declared_ops), 6)

    def test_different_ops_each_time(self):
        sig = _make_sig()
        adv = ImpersonationAdversary()
        r1 = adv.attack(sig)
        r2 = adv.attack(sig)
        self.assertNotEqual(r1.declared_ops, r2.declared_ops)


# ── Strength parameter ───────────────────────────────────────────────────

class TestStrengthParameter(unittest.TestCase):

    def test_strength_stored(self):
        adv = ForgeryAdversary(strength=0.7)
        self.assertEqual(adv.strength, 0.7)

    def test_default_strength(self):
        adv = ForgeryAdversary()
        self.assertEqual(adv.strength, 1.0)

    def test_strength_affects_channel_tamper(self):
        sig = _make_sig(n_bits=64)
        # Low strength should preserve more than high strength
        low = ChannelTamperAdversary(strength=0.1)
        high = ChannelTamperAdversary(strength=0.9)
        low_diffs = sum(
            1 for _ in range(50)
            if low.attack(sig).bell_outcomes != sig.bell_outcomes
        )
        high_diffs = sum(
            1 for _ in range(50)
            if high.attack(sig).bell_outcomes != sig.bell_outcomes
        )
        # High strength should tamper more often
        self.assertGreaterEqual(high_diffs, low_diffs)


# ── run_batch ───────────────────────────────────────────────────────────

class TestRunBatch(unittest.TestCase):

    def test_returns_dataframe(self):
        import pandas as pd
        from attacks.utils import run_batch
        sigs = [_make_sig() for _ in range(5)]
        df = run_batch(ForgeryAdversary(), sigs)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 5)

    def test_expected_columns(self):
        from attacks.utils import run_batch
        sigs = [_make_sig() for _ in range(3)]
        df = run_batch(ChannelTamperAdversary(), sigs)
        expected = {
            "trial_id", "attack_type", "strength",
            "original_sig_id", "tampered_sig_id", "n_bits",
            "nonce_changed", "key_id_changed", "signer_id_changed",
            "ops_changed", "ops_diff_count", "ops_match_rate",
            "outcomes_changed", "outcomes_diff_count", "outcomes_match_rate",
        }
        self.assertTrue(expected.issubset(set(df.columns)))

    def test_attack_type_matches(self):
        from attacks.utils import run_batch
        sigs = [_make_sig() for _ in range(3)]
        for adv, expected_type in [
            (ForgeryAdversary(), "forgery"),
            (ReplayAdversary(), "replay"),
            (ChannelTamperAdversary(), "channel_tamper"),
            (ImpersonationAdversary(), "impersonation"),
        ]:
            df = run_batch(adv, sigs)
            self.assertTrue(
                (df["attack_type"] == expected_type).all(),
                f"Expected {expected_type}, got {df['attack_type'].tolist()}",
            )

    def test_trial_ids_sequential(self):
        from attacks.utils import run_batch
        sigs = [_make_sig() for _ in range(8)]
        df = run_batch(ForgeryAdversary(), sigs)
        self.assertEqual(list(df["trial_id"]), list(range(8)))

    def test_replay_does_not_change_ops(self):
        from attacks.utils import run_batch
        sigs = [_make_sig() for _ in range(5)]
        df = run_batch(ReplayAdversary(), sigs)
        self.assertFalse(df["ops_changed"].any())
        self.assertFalse(df["outcomes_changed"].any())

    def test_forgery_changes_ops_and_outcomes(self):
        from attacks.utils import run_batch
        sigs = [_make_sig(n_bits=8) for _ in range(10)]
        df = run_batch(ForgeryAdversary(), sigs)
        self.assertTrue(df["ops_changed"].any())
        self.assertTrue(df["outcomes_changed"].any())

    def test_channel_tamper_changes_outcomes_not_ops(self):
        from attacks.utils import run_batch
        sigs = [_make_sig(n_bits=8) for _ in range(10)]
        df = run_batch(ChannelTamperAdversary(strength=1.0), sigs)
        self.assertFalse(df["ops_changed"].any())
        self.assertTrue(df["outcomes_changed"].any())

    def test_match_rate_between_zero_and_one(self):
        from attacks.utils import run_batch
        sigs = [_make_sig(n_bits=8) for _ in range(10)]
        df = run_batch(ForgeryAdversary(), sigs)
        self.assertTrue((df["ops_match_rate"] >= 0.0).all())
        self.assertTrue((df["ops_match_rate"] <= 1.0).all())
        self.assertTrue((df["outcomes_match_rate"] >= 0.0).all())
        self.assertTrue((df["outcomes_match_rate"] <= 1.0).all())


# ── Partial-key forgery (Phase 4) ─────────────────────────────────────

class TestPartialKeyForgery(unittest.TestCase):

    def test_protocol_conformance(self):
        from attacks.partial_forgery import PartialKeyForgeryAdversary
        adv = PartialKeyForgeryAdversary(key_knowledge=0.5)
        self.assertIsInstance(adv, BaseAdversary)
        self.assertEqual(adv.threat, ThreatType.FORGERY)
        self.assertIsNotNone(adv.name)

    def test_zero_knowledge_matches_full_forgery(self):
        """key_knowledge=0 should be equivalent to ForgeryAdversary."""
        from attacks.partial_forgery import PartialKeyForgeryAdversary
        sig = _make_sig(n_bits=8)
        adv = PartialKeyForgeryAdversary(key_knowledge=0.0)
        result = adv.attack(sig)
        # All ops should be random — none match original
        ops_match = sum(
            1 for o, f in zip(sig.declared_ops, result.declared_ops) if o == f
        )
        self.assertLess(ops_match, 6)  # expect ~2 out of 8

    def test_full_knowledge_matches_original_ops(self):
        """key_knowledge=1.0 should produce correct ops for all bits."""
        from attacks.partial_forgery import PartialKeyForgeryAdversary
        sig = _make_sig(n_bits=8)
        adv = PartialKeyForgeryAdversary(key_knowledge=1.0)
        result = adv.attack(sig)
        # All ops should match original
        self.assertEqual(result.declared_ops, sig.declared_ops)

    def test_match_rate_scales_with_knowledge(self):
        """Higher key_knowledge should produce higher ops match rate."""
        from attacks.partial_forgery import PartialKeyForgeryAdversary
        from attacks.utils import run_batch
        sigs = [_make_sig(n_bits=16) for _ in range(15)]
        low = run_batch(PartialKeyForgeryAdversary(key_knowledge=0.2), sigs)
        high = run_batch(PartialKeyForgeryAdversary(key_knowledge=0.8), sigs)
        self.assertGreater(
            high["ops_match_rate"].mean(),
            low["ops_match_rate"].mean(),
        )

    def test_expected_match_rate_range(self):
        """Match rate should be between ~25% (random) and 100% (full knowledge)."""
        from attacks.partial_forgery import PartialKeyForgeryAdversary
        from attacks.utils import run_batch
        sigs = [_make_sig(n_bits=16) for _ in range(15)]
        df = run_batch(PartialKeyForgeryAdversary(key_knowledge=0.5), sigs)
        mean_rate = df["ops_match_rate"].mean()
        # Expected: 0.5 * 1.0 + 0.5 * 0.25 = 0.625
        self.assertGreater(mean_rate, 0.4)
        self.assertLess(mean_rate, 0.85)

    def test_invalid_knowledge_raises(self):
        from attacks.partial_forgery import PartialKeyForgeryAdversary
        with self.assertRaises(ValueError):
            PartialKeyForgeryAdversary(key_knowledge=1.5)
        with self.assertRaises(ValueError):
            PartialKeyForgeryAdversary(key_knowledge=-0.1)


# ── Strength sweep (Phase 4) ──────────────────────────────────────────

class TestSweep(unittest.TestCase):

    def test_sweep_returns_dataframe(self):
        from attacks.sweep import sweep_strength
        import pandas as pd
        sigs = [_make_sig(n_bits=4) for _ in range(5)]
        df = sweep_strength(ForgeryAdversary, sigs, strengths=[0.0, 0.5, 1.0])
        self.assertIsInstance(df, pd.DataFrame)
        self.assertGreater(len(df), 0)

    def test_sweep_has_all_strengths(self):
        from attacks.sweep import sweep_strength
        sigs = [_make_sig(n_bits=4) for _ in range(5)]
        df = sweep_strength(ForgeryAdversary, sigs, strengths=[0.0, 0.5, 1.0])
        self.assertEqual(set(df["strength"].unique()), {0.0, 0.5, 1.0})

    def test_sweep_summary_groups_correctly(self):
        from attacks.sweep import sweep_strength, summary_by_strength
        sigs = [_make_sig(n_bits=4) for _ in range(5)]
        df = sweep_strength(ForgeryAdversary, sigs, strengths=[0.0, 1.0])
        summary = summary_by_strength(df)
        self.assertEqual(len(summary), 2)
        self.assertIn("mean_ops_match_rate", summary.columns)
        self.assertIn("std_ops_match_rate", summary.columns)

    def test_key_knowledge_sweep_scales(self):
        from attacks.sweep import sweep_key_knowledge, summary_by_key_knowledge
        sigs = [_make_sig(n_bits=8) for _ in range(10)]
        df = sweep_key_knowledge(sigs, knowledge_levels=[0.0, 0.5, 1.0])
        summary = summary_by_key_knowledge(df)
        # Match rate should increase with key knowledge
        rates = summary.sort_values("key_knowledge")["mean_ops_match_rate"].tolist()
        self.assertGreater(rates[-1], rates[0])


if __name__ == "__main__":
    unittest.main()
