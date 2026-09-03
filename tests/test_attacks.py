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

    def test_partial_strength(self):
        """strength=0.5 with a short message should sometimes preserve."""
        sig = _make_sig(n_bits=2)
        adv = ChannelTamperAdversary(strength=0.5)
        preserved = 0
        for _ in range(20):
            result = adv.attack(sig)
            if result.bell_outcomes == sig.bell_outcomes:
                preserved += 1
        # With 2 bits at 50% flip rate, some trials should preserve
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


if __name__ == "__main__":
    unittest.main()
