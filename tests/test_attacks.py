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

    def test_full_forgery_touches_the_real_element_count_not_just_message_length(self):
        """Regression guard: a real Signature's declared_ops is
        message_length*L, far longer than len(message). Sizing off
        len(sig.message) (the old bug, caught in M2 review) would leave
        every element past the first few untouched even at strength=1.0.
        """
        n_elements = 300  # far more than any plausible message length
        realistic_sig = Signature(
            sig_id="sig-real", key_id="key-real", signer_id="alice",
            message=(1, 0, 1),  # 3 bits -- much shorter than n_elements
            declared_ops=(PauliOp.Z,) * n_elements,
            bell_outcomes=((0, 0),) * n_elements,
            nonce="nonce-1", timestamp=1.0,
        )
        adv = ForgeryAdversary(strength=1.0)
        result = adv.attack(realistic_sig)
        self.assertEqual(len(result.declared_ops), n_elements)
        self.assertEqual(len(result.bell_outcomes), n_elements)
        ops_match = sum(
            1 for o, f in zip(realistic_sig.declared_ops, result.declared_ops)
            if o == f
        )
        # Full-strength forgery on 300 random-Pauli elements: ~25% match by
        # chance. The old bug would have left ~297 of 300 untouched (only
        # indices 0..2 were ever forge-eligible), giving ops_match near 300.
        self.assertLess(ops_match, 150)


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

    def test_noise_level_override_reports_strength(self):
        """The real, verify()-visible detection mechanism -- see the module
        docstring on why the bell_outcomes flip above is not enough on its
        own to be caught by M2's verify()."""
        for strength in (0.0, 0.3, 1.0):
            adv = ChannelTamperAdversary(strength=strength)
            self.assertEqual(adv.noise_level_override(), strength)

    def test_other_adversaries_do_not_override_noise_level(self):
        """noise_level_override() defaults to None: only channel tampering
        is a property of the physical channel rather than the Signature."""
        for adv in (ReplayAdversary(), ForgeryAdversary(), ImpersonationAdversary()):
            with self.subTest(adversary=adv.name):
                self.assertIsNone(adv.noise_level_override())

    def test_detectable_through_verify_only_when_noise_level_is_threaded(self):
        """End-to-end: attack(sig) alone is invisible to M2's real verify();
        threading noise_level_override() through is what makes it visible.

        This is the regression guard for the finding that motivated
        noise_level_override() in the first place -- bell_outcomes tampering
        alone produces zero mismatch-rate change because verify() never
        reads that field.
        """
        from detection.statistics import mismatch_rate
        from protocol import MockQuantumCore, QDSConfig, keygen, sign, verify

        L, m = 300, 2
        cfg = QDSConfig(n_copies=L, seed=3)
        core = MockQuantumCore(seed=3)
        key = keygen("alice", L, message_length=m, core=core, config=cfg)
        sig = sign((1, 0), key, core=core, config=cfg)

        adv = ChannelTamperAdversary(strength=0.6)
        tampered = adv.attack(sig)

        blind_records = verify(tampered, key, core=core, config=cfg)
        self.assertEqual(mismatch_rate(blind_records), 0.0,
                          "bell_outcomes tampering alone should NOT be visible")

        threaded_records = verify(
            tampered, key, core=core, config=cfg,
            noise_level=adv.noise_level_override(),
        )
        self.assertGreater(mismatch_rate(threaded_records), 0.05,
                            "threading noise_level_override() should make the "
                            "attack visible")


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

    def test_ops_length_matches_the_real_element_count_not_message_length(self):
        """Regression guard: a real Signature's declared_ops is
        message_length*L, far longer than len(message). Sizing off
        len(sig.message) (the old bug, caught in M2 review) undersized
        both declared_ops and bell_outcomes to the message length."""
        n_elements = 300
        realistic_sig = Signature(
            sig_id="sig-real", key_id="key-real", signer_id="alice",
            message=(1, 0, 1),
            declared_ops=(PauliOp.Z,) * n_elements,
            bell_outcomes=((0, 0),) * n_elements,
            nonce="nonce-1", timestamp=1.0,
        )
        result = ImpersonationAdversary().attack(realistic_sig)
        self.assertEqual(len(result.declared_ops), n_elements)
        self.assertEqual(len(result.bell_outcomes), n_elements)

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
