"""Tests for the M2 protocol API. Track M2 (Shubhang).

These test the SCAFFOLD, and only the scaffold: the public API's shape, the
argument validation, the dependency injection, and the honesty of the
"algorithm not selected" signal.

NOTHING HERE ASSERTS CRYPTOGRAPHIC CORRECTNESS, because there is no
construction to be correct against yet. When one is chosen, the D1 tests
(unforgeability, transferability, deterministic acceptance of legitimate
signatures at the noise floor) get added alongside these -- they do not
replace them.
"""

import dataclasses
import unittest

from contracts import Basis, KeyPair, PauliOp, Signature
from detection.statistics import mismatch_rate
from protocol import (
    MockQuantumCore,
    ProtocolNotSelectedError,
    QDSConfig,
    QDSProtocolError,
    QuantumCoreError,
    keygen,
    sign,
    verify,
)

STRICT = QDSConfig(strict=True, bases=(Basis.Z,))
DEFAULT_BASES = (Basis.Z, Basis.X)


class TestKeygen(unittest.TestCase):
    def test_returns_a_keypair_with_lengths_tracking_l(self):
        """Tuple lengths must equal L, not 1.

        Regression guard: a length-1 placeholder tuple would let `zip(...)`
        in another track silently truncate to one element and still pass that
        track's tests.
        """
        key = keygen("alice", 8)
        self.assertIsInstance(key, KeyPair)
        self.assertEqual(key.n_copies, 8)
        self.assertEqual(len(key.private_bits), 8)
        self.assertEqual(len(key.pauli_map), 8)

    def test_n_copies_defaults_to_config(self):
        """None means "ask the config", and the config's default is the old one."""
        self.assertEqual(keygen("alice").n_copies, QDSConfig().n_copies)
        self.assertEqual(keygen("alice", config=QDSConfig(n_copies=16)).n_copies, 16)

    def test_explicit_n_copies_overrides_config(self):
        self.assertEqual(keygen("alice", 4, config=QDSConfig(n_copies=16)).n_copies, 4)

    def test_positional_call_still_works(self):
        """Five other tracks call keygen(signer_id, n_copies) positionally."""
        self.assertEqual(keygen("alice", 32).n_copies, 32)

    def test_key_ids_are_unique(self):
        self.assertNotEqual(keygen("alice").key_id, keygen("alice").key_id)

    def test_rejects_empty_signer_id(self):
        with self.assertRaises(ValueError):
            keygen("")

    def test_rejects_non_positive_l(self):
        with self.assertRaises(ValueError):
            keygen("alice", 0)


class TestSign(unittest.TestCase):
    def setUp(self):
        self.key = keygen("alice", 8)

    def test_returns_a_signature_carrying_the_key(self):
        sig = sign((1, 0, 1), self.key)
        self.assertIsInstance(sig, Signature)
        self.assertEqual(sig.key_id, self.key.key_id)
        self.assertEqual(sig.signer_id, "alice")
        self.assertEqual(sig.message, (1, 0, 1))

    def test_per_message_bit_fields_have_message_length(self):
        sig = sign((1, 0, 1, 1), self.key)
        self.assertEqual(len(sig.declared_ops), 4)
        self.assertEqual(len(sig.bell_outcomes), 4)

    def test_nonce_and_sig_id_are_unique_per_call(self):
        """Both are load-bearing even in the placeholder.

        A constant nonce makes every signature after the first a replay once
        M4 implements that check; a constant sig_id collides every row in
        M5's event log.
        """
        a, b = sign((1,), self.key), sign((1,), self.key)
        self.assertNotEqual(a.nonce, b.nonce)
        self.assertNotEqual(a.sig_id, b.sig_id)

    def test_rejects_empty_message(self):
        with self.assertRaises(ValueError):
            sign((), self.key)

    def test_rejects_non_bit_message(self):
        """The legitimate path takes bits, so 2 and -1 are caller errors."""
        for message in [(0, 2), (-1,), (0, 1, 7)]:
            with self.subTest(message=message), self.assertRaises(ValueError):
                sign(message, self.key)


class TestVerify(unittest.TestCase):
    def setUp(self):
        self.key = keygen("alice", 8)
        # Message length must equal key.n_copies (L copies, one per message bit)
        self.sig = sign((1, 0, 1, 1, 0, 1, 0, 1), self.key)

    def test_returns_records_for_legitimate_signature(self):
        """Verifier returns measurement records for legitimate signatures."""
        records = verify(self.sig, self.key, config=QDSConfig(bases=DEFAULT_BASES))
        self.assertEqual(len(records), 8)
        for r in records:
            self.assertEqual(r.sig_id, self.sig.sig_id)
            self.assertIn(r.basis, DEFAULT_BASES)

    def test_does_not_validate_the_signature(self):
        """A tampered signature must come back as data, not as an exception.

        Key-id mismatch, wrong signer, wrong length: all of these are M3's
        adversaries at work and M4's job to classify. If verify() raises on
        them, the attack demo throws instead of detecting, and detection has
        leaked into M2.
        """
        forged = Signature(
            sig_id="sig-forged",
            key_id="key-not-alices",
            signer_id="eve",
            message=(1, 0, 1, 1, 0, 1, 0, 1),
            declared_ops=(PauliOp.X,) * 8,
            bell_outcomes=((1, 1),) * 8,
            nonce="reused-nonce",
            timestamp=0.0,
        )
        records = verify(forged, self.key, config=QDSConfig(bases=DEFAULT_BASES))
        self.assertEqual(len(records), 8)

    def test_noise_level_defaults_to_config(self):
        records = verify(self.sig, self.key, config=QDSConfig(noise_level=0.3, bases=DEFAULT_BASES))
        self.assertEqual(len(records), 8)

    def test_explicit_noise_level_is_range_checked(self):
        for level in (-0.1, 1.5):
            with self.subTest(level=level), self.assertRaises(ValueError):
                verify(self.sig, self.key, level, config=QDSConfig(bases=DEFAULT_BASES))


class TestStrictModeReportsTheMissingAlgorithm(unittest.TestCase):
    """strict=True is how "not implemented" is verified rather than asserted.

    The placeholder paths above are reachable by default because M3/M4/M5
    integrate against them. This class is the counterweight: it proves M2 can
    state plainly that it has no construction, so that claim rests on a
    passing test and not on a docstring.
    """

    def test_keygen_raises(self):
        with self.assertRaises(ProtocolNotSelectedError):
            keygen("alice", config=STRICT)

    def test_sign_raises(self):
        key = keygen("alice", 8)
        with self.assertRaises(ProtocolNotSelectedError):
            sign((1, 0), key, config=STRICT)

    def test_verify_raises(self):
        key = keygen("alice", 8)
        sig = sign((1, 0), key)
        with self.assertRaises(ProtocolNotSelectedError):
            verify(sig, key, config=STRICT)

    def test_is_catchable_as_both_qds_error_and_not_implemented(self):
        """Deliberate double inheritance: neither idiom should miss it."""
        with self.assertRaises(QDSProtocolError):
            keygen("alice", config=STRICT)
        with self.assertRaises(NotImplementedError):
            keygen("alice", config=STRICT)

    def test_argument_validation_runs_before_the_strict_refusal(self):
        """A bad argument is a bad argument regardless of protocol status.

        Otherwise strict mode would mask real caller bugs behind "not
        selected", and switching strict off would surface a pile of
        ValueErrors nobody had seen.
        """
        with self.assertRaises(ValueError):
            keygen("", config=STRICT)


class TestDependencyInjection(unittest.TestCase):
    def test_entry_points_accept_a_quantum_core(self):
        core = MockQuantumCore(seed=1)
        key = keygen("alice", 8, core=core)
        sig = sign((1, 0, 1, 1, 0, 1, 0, 1), key, core=core)
        records = verify(sig, key, core=core, config=QDSConfig(bases=DEFAULT_BASES))
        self.assertEqual(len(records), 8)

    def test_core_is_optional_while_the_algorithm_is_unselected(self):
        self.assertIsInstance(keygen("alice", 8), KeyPair)

    def test_bad_core_is_rejected_at_the_entry_point(self):
        """Fail where the wiring is wrong, not deep inside the protocol."""
        key = keygen("alice", 8)
        sig = sign((1,), key)
        calls = {
            "keygen": lambda: keygen("alice", 8, core=object()),
            "sign": lambda: sign((1,), key, core="not a core"),
            "verify": lambda: verify(sig, key, core=object(), config=QDSConfig(bases=DEFAULT_BASES)),
        }
        for entry, call in calls.items():
            with self.subTest(entry=entry), self.assertRaises(QuantumCoreError):
                call()


class TestQDSConfig(unittest.TestCase):
    def test_bases_default_to_empty_not_to_z(self):
        """Choosing measurement bases is a protocol decision, not a default."""
        self.assertEqual(QDSConfig().bases, ())

    def test_no_threshold_fields(self):
        """s_a and s_v are DERIVED by M4 from the noise floor and p_f.

        A threshold field here is the easiest possible way to accidentally
        tune a demo, and it would not survive a judge asking where the number
        came from. This test exists to make adding one an argument.
        """
        for forbidden in ("s_a", "s_v", "threshold", "accept_threshold"):
            self.assertNotIn(forbidden, QDSConfig.__dataclass_fields__)

    def test_is_frozen(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            QDSConfig().n_copies = 128  # type: ignore[misc]

    def test_rejects_invalid_parameters(self):
        for kwargs in [
            {"n_copies": 0},
            {"noise_level": -0.1},
            {"noise_level": 1.1},
            {"target_forgery_prob": 0.0},
            {"target_forgery_prob": 1.5},
        ]:
            with self.subTest(**kwargs), self.assertRaises(ValueError):
                QDSConfig(**kwargs)


if __name__ == "__main__":
    unittest.main()
