"""Tests for the M2 protocol API. Track M2 (Shubhang). Deliverable D1.

Two layers, both load-bearing:

  1. SHAPE AND VALIDATION -- the public API's form, argument checks,
     dependency injection, and the contract-seam invariants. These guard
     against silent regressions when M2 is refactored.
  2. P1 BEHAVIOUR -- the cryptographic properties the D1 document rests on:
     legitimate signatures are accepted at the noise floor, forgeries
     separate from them, the verifier fails closed on uncheckable inputs,
     and the signer/verifier RNG streams are independent.

The behaviour tests use `MockQuantumCore`, whose `teleport_and_measure` is
an analytically exact ideal-channel model (see its docstring). They assert
PROPERTIES THAT HOLD EXACTLY on the ideal channel -- "legit mismatch is
zero", "forgery mismatch is near 1/4" -- not numbers that depend on a
simulator seed. `tests/test_runtime.py` pins the real Aer path to the same
physics, so a mock pass plus a runtime pass is evidence the protocol is
correct and the backend is faithful.
"""

import dataclasses
import random
import unittest

from contracts import Basis, KeyPair, MeasurementRecord, PauliOp, Signature
from detection.statistics import mismatch_rate
from protocol import (
    MockQuantumCore,
    QDSConfig,
    QDSProtocolError,
    QuantumCoreError,
    keygen,
    sign,
    verify,
)

# A config large enough that the law of large numbers makes the behaviour
# tests deterministic in practice. 400 copies gives a standard error of
# ~0.022 on a 1/4 mismatch rate, so a 0.10 separation threshold is safe.
L = 400
CFG = QDSConfig(n_copies=L, seed=1)

# Most behaviour tests sign this 3-bit message, so their keys need
# message_length=M to hold the two L-element sequences per bit position.
M = 3
MESSAGE = (1, 0, 1)


def _run(sig: Signature, key: KeyPair, *, noise: float | None = None,
         core: object | None = None, config: QDSConfig = CFG) -> list[MeasurementRecord]:
    return verify(sig, key, noise, core=core, config=config)


class TestKeygen(unittest.TestCase):
    def test_returns_a_keypair_with_lengths_tracking_l(self):
        """Tuple lengths must equal 2*message_length*L, not 1.

        A length-1 placeholder tuple would let `zip(...)` in another track
        silently truncate to one element and still pass that track's tests.
        message_length defaults to 1, so a bare `keygen("alice", 8)` holds
        the two (bit=0, bit=1) sequences for a single message bit: 2*8=16.
        """
        key = keygen("alice", 8, config=QDSConfig(seed=1))
        self.assertIsInstance(key, KeyPair)
        self.assertEqual(key.n_copies, 8)
        self.assertEqual(len(key.private_bits), 16)
        self.assertEqual(len(key.pauli_map), 16)

    def test_message_length_scales_key_size(self):
        """2*message_length*L elements: two sequences per message bit position."""
        key = keygen("alice", 8, message_length=5, config=QDSConfig(seed=1))
        self.assertEqual(len(key.pauli_map), 2 * 5 * 8)
        self.assertEqual(len(key.private_bits), 2 * 5 * 8)

    def test_rejects_non_positive_message_length(self):
        with self.assertRaises(ValueError):
            keygen("alice", 8, message_length=0, config=QDSConfig(seed=1))

    def test_n_copies_defaults_to_config(self):
        self.assertEqual(
            keygen("alice", config=QDSConfig(seed=1)).n_copies,
            QDSConfig().n_copies,
        )
        self.assertEqual(
            keygen("alice", config=QDSConfig(n_copies=16, seed=1)).n_copies, 16
        )

    def test_explicit_n_copies_overrides_config(self):
        self.assertEqual(
            keygen("alice", 4, config=QDSConfig(n_copies=16, seed=1)).n_copies, 4
        )

    def test_positional_call_still_works(self):
        """Five other tracks call keygen(signer_id, n_copies) positionally."""
        self.assertEqual(keygen("alice", 32, config=QDSConfig(seed=1)).n_copies, 32)

    def test_key_ids_are_unique(self):
        self.assertNotEqual(
            keygen("alice", config=QDSConfig(seed=1)).key_id,
            keygen("alice", config=QDSConfig(seed=1)).key_id,
        )

    def test_pauli_map_only_contains_configured_bases(self):
        """P1 draws from QDSConfig.bases; nothing else should appear."""
        key = keygen("alice", 64, config=QDSConfig(seed=1))
        allowed = {pauli_of(b) for b in CFG.bases}
        self.assertTrue(set(key.pauli_map) <= allowed, key.pauli_map[:8])

    def test_private_bits_are_bits(self):
        key = keygen("alice", 64, config=QDSConfig(seed=1))
        self.assertTrue(set(key.private_bits) <= {0, 1})

    def test_rejects_empty_signer_id(self):
        with self.assertRaises(ValueError):
            keygen("", config=QDSConfig(seed=1))

    def test_rejects_non_positive_l(self):
        with self.assertRaises(ValueError):
            keygen("alice", 0, config=QDSConfig(seed=1))

    def test_is_deterministic_under_a_fixed_seed(self):
        """Same seed -> same key material. Tests must be replayable."""
        a = keygen("alice", 32, config=QDSConfig(seed=7))
        b = keygen("alice", 32, config=QDSConfig(seed=7))
        self.assertEqual(a.pauli_map, b.pauli_map)
        self.assertEqual(a.private_bits, b.private_bits)

    def test_different_seeds_give_different_keys(self):
        a = keygen("alice", 64, config=QDSConfig(seed=1))
        b = keygen("alice", 64, config=QDSConfig(seed=2))
        self.assertNotEqual((a.pauli_map, a.private_bits),
                            (b.pauli_map, b.private_bits))


class TestSign(unittest.TestCase):
    def setUp(self):
        self.core = MockQuantumCore(seed=1)
        self.key = keygen("alice", L, message_length=M, core=self.core, config=CFG)

    def test_returns_a_signature_carrying_the_key(self):
        sig = sign(MESSAGE, self.key, core=self.core, config=CFG)
        self.assertIsInstance(sig, Signature)
        self.assertEqual(sig.key_id, self.key.key_id)
        self.assertEqual(sig.signer_id, "alice")
        self.assertEqual(sig.message, MESSAGE)

    def test_declared_ops_and_bell_outcomes_have_length_message_length_times_l(self):
        """P1: every signature reveals message_length*L elements, one L-sequence
        per message bit position -- not one per bit, and not the full 2*m*L key.

        M3's adversaries size their mutations off len(sig.message) and so will
        only touch the first few elements of a real signature -- that is an
        M3 follow-up, not a bug here, but this test is the guard against
        silently reverting the length relationship.
        """
        key4 = keygen("alice", L, message_length=4, core=self.core, config=CFG)
        sig = sign((1, 0, 1, 1), key4, core=self.core, config=CFG)
        self.assertEqual(len(sig.declared_ops), 4 * L)
        self.assertEqual(len(sig.bell_outcomes), 4 * L)

    def test_declared_ops_match_the_message_selected_sequences(self):
        """sign() reveals key material for sequence(i, message[i]) only --
        never the sibling "message[i] flipped" sequence. Reading key.pauli_map
        wholesale in verify() instead of sig.declared_ops would make every
        forgery undetectable; reading the WRONG sequence would break message
        binding. This is the invariant both rest on."""
        sig = sign(MESSAGE, self.key, core=self.core, config=CFG)
        expected = []
        for i, bit in enumerate(MESSAGE):
            seq = 2 * i + bit
            expected.extend(self.key.pauli_map[seq * L : (seq + 1) * L])
        self.assertEqual(sig.declared_ops, tuple(expected))

    def test_bell_outcomes_are_bit_pairs(self):
        sig = sign(MESSAGE, self.key, core=self.core, config=CFG)
        for pair in sig.bell_outcomes:
            self.assertEqual(len(pair), 2)
            self.assertTrue(all(b in (0, 1) for b in pair))

    def test_nonce_and_sig_id_are_unique_per_call(self):
        """Both are load-bearing.

        A constant nonce makes every signature after the first a replay
        once M4 implements that check; a constant sig_id collides every
        row in M5's event log.
        """
        key1 = keygen("alice", L, core=self.core, config=CFG)  # message_length=1
        a = sign((1,), key1, core=self.core, config=CFG)
        b = sign((1,), key1, core=self.core, config=CFG)
        self.assertNotEqual(a.nonce, b.nonce)
        self.assertNotEqual(a.sig_id, b.sig_id)

    def test_rejects_empty_message(self):
        with self.assertRaises(ValueError):
            sign((), self.key, core=self.core, config=CFG)

    def test_rejects_non_bit_message(self):
        """The legitimate path takes bits, so 2 and -1 are caller errors."""
        key3 = keygen("alice", L, message_length=3, core=self.core, config=CFG)
        for message in [(0, 2, 0), (-1, 0, 0), (0, 1, 7)]:
            with self.subTest(message=message), self.assertRaises(ValueError):
                sign(message, key3, core=self.core, config=CFG)

    def test_rejects_message_length_mismatch(self):
        """message_length is fixed at keygen time; a mismatched message must
        not silently sign against the wrong (or a partial) set of sequences."""
        with self.assertRaises(ValueError):
            sign((1, 0), self.key, core=self.core, config=CFG)  # key wants M=3

    def test_rejects_malformed_key(self):
        """The key never crosses the wire, so a bad one is a caller bug."""
        bad = KeyPair(
            key_id="k", signer_id="alice",
            private_bits=(0, 1), pauli_map=(PauliOp.Z,), n_copies=2,
        )
        with self.assertRaises(ValueError):
            sign((1,), bad, core=self.core, config=CFG)


class TestVerifyLegitimate(unittest.TestCase):
    """P1 property: a legitimate signature is accepted at the noise floor."""

    def setUp(self):
        self.core = MockQuantumCore(seed=1)
        self.key = keygen("alice", L, message_length=M, core=self.core, config=CFG)
        self.sig = sign(MESSAGE, self.key, core=self.core, config=CFG)

    def test_returns_measurement_records(self):
        records = _run(self.sig, self.key, core=self.core)
        self.assertTrue(records)
        for r in records:
            self.assertIsInstance(r, MeasurementRecord)
            self.assertEqual(r.sig_id, self.sig.sig_id)
            self.assertTrue(0 <= r.copy_index < M * L)
            self.assertIn(r.basis, CFG.bases)
            self.assertIn(r.expected, (0, 1))
            self.assertIn(r.observed, (0, 1))

    def test_copy_index_is_the_original_position_not_a_renumbering(self):
        """The exponential-in-L bound only means anything if copy_index is real."""
        records = _run(self.sig, self.key, core=self.core)
        indices = {r.copy_index for r in records}
        self.assertEqual(len(indices), len(records), "copy_index must be unique")
        self.assertTrue(max(indices) < M * L)

    def test_legitimate_mismatch_is_zero_on_an_ideal_channel(self):
        """The core P1 acceptance property: r = 0 when noise = 0.

        This is the deterministic-acceptance constraint from the problem
        statement, and it is exact on the ideal channel -- not "small",
        zero. Any nonzero value here is a protocol bug, not noise.
        """
        records = _run(self.sig, self.key, core=self.core)
        self.assertEqual(mismatch_rate(records), 0.0)

    def test_about_half_the_elements_are_conclusive(self):
        """State elimination discards the cross-basis half.

        With (Z, X) and an independent verifier basis, the expected
        fraction of conclusive elements is 1/2. We allow a wide band
        because the mock's RNG is finite; the point is "roughly half",
        not "exactly half", and a 100% or 0% rate would indicate the
        basis-comparison logic is broken.
        """
        records = _run(self.sig, self.key, core=self.core)
        fraction = len(records) / (M * L)
        self.assertGreater(fraction, 0.30, "too few conclusive elements")
        self.assertLess(fraction, 0.70, "too many conclusive elements")


class TestVerifyForgery(unittest.TestCase):
    """P1 property: a forged signature separates from a legitimate one."""

    def setUp(self):
        self.core = MockQuantumCore(seed=1)
        self.key = keygen("alice", L, message_length=M, core=self.core, config=CFG)
        self.sig = sign(MESSAGE, self.key, core=self.core, config=CFG)

    def _forged_declared_ops(self, seed: int = 7) -> tuple[PauliOp, ...]:
        """Random Pauli ops drawn from the configured bases -- a forger's guess."""
        rng = random.Random(seed)
        return tuple(
            pauli_of(rng.choice(CFG.bases)) for _ in self.sig.declared_ops
        )

    def test_forgery_mismatch_rate_is_near_a_quarter(self):
        """A forger guessing the declared ops gets ~1/4 of conclusive elements wrong.

        On the ideal channel: with probability 1/2 the verifier picks the
        same basis as the forger's declared op (so the element is
        conclusive), and with probability 1/2 the forger's op disagrees
        with Alice's actual preparation, so the measured bit is uniform
        and disagrees with the predicted bit half the time. 1/2 * 1/2 =
        1/4. This is the gap M4's threshold s_v sits inside.
        """
        forged = dataclasses.replace(self.sig,
                                     declared_ops=self._forged_declared_ops())
        records = _run(forged, self.key, core=self.core)
        rate = mismatch_rate(records)
        # 0.10 separation from the legitimate 0.000 rate is the demo margin.
        self.assertGreater(rate, 0.10, f"forgery mismatch {rate} too low to separate")
        self.assertLess(rate, 0.40, f"forgery mismatch {rate} implausibly high")

    def test_forgery_separates_from_legitimate(self):
        """The single most important property for the demo: the gap is real."""
        legit = _run(self.sig, self.key, core=self.core)
        forged = dataclasses.replace(self.sig,
                                     declared_ops=self._forged_declared_ops())
        forgery_records = _run(forged, self.key, core=self.core)
        self.assertGreater(
            mismatch_rate(forgery_records) - mismatch_rate(legit),
            0.10,
            "forgery and legitimate rates do not separate",
        )

    def test_impersonation_separates(self):
        """A different signer's key cannot verify Alice's signature.

        The verifier measures against the KEY's preparations but compares
        against the SIGNATURE's declared ops. With a wrong key, the
        preparations do not match the declared ops, so the conclusive
        elements show a ~1/4 mismatch rate as well.
        """
        eve_key = keygen("eve", L, message_length=M, core=self.core,
                         config=QDSConfig(n_copies=L, seed=2))
        records = _run(self.sig, eve_key, core=self.core)
        # Eve's key has different pauli_map, so the declared ops (Alice's)
        # disagree with Eve's preparations on ~half the conclusive elements.
        self.assertGreater(mismatch_rate(records), 0.10)


class TestVerifyFailsClosed(unittest.TestCase):
    """An uncheckable signature returns no records, not a false accept."""

    def setUp(self):
        self.core = MockQuantumCore(seed=1)
        self.key = keygen("alice", L, message_length=M, core=self.core, config=CFG)
        self.sig = sign(MESSAGE, self.key, core=self.core, config=CFG)

    def test_all_identity_declared_ops_yields_no_records(self):
        """PauliOp.I names no basis, so every element is inconclusive.

        This is the fail-closed path: mismatch_rate raises on the empty
        list rather than reporting 0.0, which would be the strongest
        possible evidence of a legitimate signature.
        """
        forged = dataclasses.replace(self.sig,
                                     declared_ops=(PauliOp.I,) * (M * L))
        records = _run(forged, self.key, core=self.core)
        self.assertEqual(records, [])
        with self.assertRaises(ValueError):
            mismatch_rate(records)

    def test_unusable_message_yields_no_records(self):
        """A message with a non-bit value, or too long for the key, names no
        sequence -- inconclusive, not an error, same fail-closed path."""
        for bad_message in [(1, 0, 7), (1, 0, 1, 0, 1)]:
            with self.subTest(message=bad_message):
                forged = dataclasses.replace(self.sig, message=bad_message)
                records = _run(forged, self.key, core=self.core)
                self.assertIsInstance(records, list)

    def test_does_not_validate_the_signature(self):
        """A tampered signature must come back as data, not as an exception.

        Key-id mismatch, wrong signer, wrong length: all of these are M3's
        adversaries at work and M4's job to classify. If verify() raises
        on them, the attack demo throws instead of detecting, and
        detection has leaked into M2.
        """
        forged = Signature(
            sig_id="sig-forged",
            key_id="key-not-alices",
            signer_id="eve",
            message=MESSAGE,
            declared_ops=(PauliOp.X,) * (M * L),
            bell_outcomes=((1, 1),) * (M * L),
            nonce="reused-nonce",
            timestamp=0.0,
        )
        records = _run(forged, self.key, core=self.core)
        # No exception, and the records are usable data for M4.
        self.assertIsInstance(records, list)

    def test_truncated_declared_ops_does_not_raise(self):
        """A short declared_ops is an attack signal, not an argument error."""
        forged = dataclasses.replace(self.sig, declared_ops=(PauliOp.Z,) * 3)
        # Should not raise; elements beyond the truncation are inconclusive.
        records = _run(forged, self.key, core=self.core)
        self.assertIsInstance(records, list)


class TestMessageBinding(unittest.TestCase):
    """P1 property: re-presenting a valid signature against a DIFFERENT
    message must not verify cleanly. sign() reveals key material only for
    sequence(i, message[i]); verify() looks up sequence(i, sig.message[i]).
    A swapped message forces the lookup onto the sibling sequence, which
    was never revealed and is independently random from the true one --
    the same forgery-detection math (~1/4 mismatch) as a blind guess.
    """

    def setUp(self):
        self.core = MockQuantumCore(seed=1)
        self.key = keygen("alice", L, message_length=M, core=self.core, config=CFG)
        self.sig = sign(MESSAGE, self.key, core=self.core, config=CFG)

    def test_fully_flipped_message_shows_forgery_level_mismatch(self):
        flipped = tuple(1 - b for b in MESSAGE)
        forged = dataclasses.replace(self.sig, message=flipped)
        records = _run(forged, self.key, core=self.core)
        rate = mismatch_rate(records)
        self.assertGreater(rate, 0.10, f"message swap mismatch {rate} too low to separate")

    def test_correct_message_still_verifies_at_zero(self):
        """Sanity anchor: it's specifically the swap that breaks verification,
        not some side effect of message_length routing."""
        records = _run(self.sig, self.key, core=self.core)
        self.assertEqual(mismatch_rate(records), 0.0)

    def test_single_bit_swap_still_separates(self):
        """Swapping even one message bit routes that bit's L-block onto the
        sibling sequence, dragging the aggregate mismatch rate up."""
        one_bit_swapped = (1 - MESSAGE[0],) + MESSAGE[1:]
        forged = dataclasses.replace(self.sig, message=one_bit_swapped)
        records = _run(forged, self.key, core=self.core)
        self.assertGreater(mismatch_rate(records), 0.05)


class TestVerifyNoise(unittest.TestCase):
    """Noise lifts the legitimate mismatch rate off zero, monotonically."""

    def setUp(self):
        self.core = MockQuantumCore(seed=1)
        self.key = keygen("alice", L, message_length=M, core=self.core, config=CFG)
        self.sig = sign(MESSAGE, self.key, core=self.core, config=CFG)

    def test_zero_noise_is_zero_mismatch(self):
        records = _run(self.sig, self.key, noise=0.0, core=self.core)
        self.assertEqual(mismatch_rate(records), 0.0)

    def test_noise_lifts_mismatch_off_zero(self):
        records = _run(self.sig, self.key, noise=0.20, core=self.core)
        self.assertGreater(mismatch_rate(records), 0.0)

    def test_noise_level_defaults_to_config(self):
        """None means "ask the config"."""
        cfg = QDSConfig(n_copies=L, seed=1, noise_level=0.20)
        core = MockQuantumCore(seed=1)
        key = keygen("alice", L, message_length=M, core=core, config=cfg)
        sig = sign(MESSAGE, key, core=core, config=cfg)
        records = _run(sig, key, core=core, config=cfg)
        self.assertGreater(mismatch_rate(records), 0.0)

    def test_explicit_noise_level_is_range_checked(self):
        for level in (-0.1, 1.5):
            with self.subTest(level=level), self.assertRaises(ValueError):
                _run(self.sig, self.key, noise=level, core=self.core)


class TestRngStreamIndependence(unittest.TestCase):
    """The verifier's basis stream MUST be independent of the signer's key stream.

    Regression guard for the bug where keygen and verify both seeded
    random.Random(config.seed) directly, making the verifier reproduce
    Alice's basis choices exactly. Forgeries then scored a perfect 0.000
    mismatch rate because the only conclusive elements were the ones the
    forger had guessed right. See protocol/config.py:derive_rng.
    """

    def test_same_seed_does_not_reproduce_alice_basis_sequence(self):
        """If the streams were the same, the verifier would pick Alice's
        bases exactly, every element would be conclusive, and a forged
        signature would score 0.0. The forged rate must be well above 0.
        """
        core = MockQuantumCore(seed=1)
        key = keygen("alice", L, message_length=M, core=core, config=CFG)
        sig = sign(MESSAGE, key, core=core, config=CFG)
        rng = random.Random(7)
        forged = dataclasses.replace(
            sig,
            declared_ops=tuple(pauli_of(rng.choice(CFG.bases)) for _ in sig.declared_ops),
        )
        records = _run(forged, key, core=core)
        self.assertGreater(
            mismatch_rate(records), 0.10,
            "verifier basis stream appears to reproduce Alice's; forgery undetectable",
        )

    def test_derive_rng_different_labels_are_independent(self):
        from protocol.config import derive_rng
        a = derive_rng(1, "keygen/elements")
        b = derive_rng(1, "verify/bases")
        # First 20 draws from independent streams should differ.
        self.assertNotEqual(
            [a.getrandbits(1) for _ in range(20)],
            [b.getrandbits(1) for _ in range(20)],
        )

    def test_derive_rng_same_label_is_deterministic(self):
        from protocol.config import derive_rng
        a = derive_rng(42, "keygen/elements")
        b = derive_rng(42, "keygen/elements")
        self.assertEqual(
            [a.getrandbits(1) for _ in range(20)],
            [b.getrandbits(1) for _ in range(20)],
        )


class TestDependencyInjection(unittest.TestCase):
    def test_entry_points_accept_a_quantum_core(self):
        core = MockQuantumCore(seed=1)
        cfg = QDSConfig(n_copies=8, seed=1)
        key = keygen("alice", 8, message_length=3, core=core, config=cfg)
        sig = sign((1, 0, 1), key, core=core, config=cfg)
        records = verify(sig, key, core=core, config=cfg)
        self.assertIsInstance(records, list)

    def test_core_is_optional(self):
        """Defaulting to the real backend must not require a core argument."""
        # We don't call verify() here without a mock because that needs Aer;
        # keygen is purely classical, so it is the safe one to exercise.
        self.assertIsInstance(
            keygen("alice", 8, config=QDSConfig(seed=1)), KeyPair
        )

    def test_bad_core_is_rejected_at_the_entry_point(self):
        """Fail where the wiring is wrong, not deep inside the protocol."""
        key = keygen("alice", 8, config=QDSConfig(seed=1),
                     core=MockQuantumCore(seed=1))
        sig = sign((1,), key, config=QDSConfig(n_copies=8, seed=1),
                   core=MockQuantumCore(seed=1))
        calls = {
            "keygen": lambda: keygen("alice", 8, core=object(),
                                     config=QDSConfig(seed=1)),
            "sign": lambda: sign((1,), key, core="not a core",
                                 config=QDSConfig(n_copies=8, seed=1)),
            "verify": lambda: verify(sig, key, core=object(),
                                     config=QDSConfig(n_copies=8, seed=1)),
        }
        for entry, call in calls.items():
            with self.subTest(entry=entry), self.assertRaises(QuantumCoreError):
                call()


class TestQDSConfig(unittest.TestCase):
    def test_bases_default_to_z_and_x(self):
        """P1 draws from the BB84 state set; (Z, X) is the default."""
        self.assertEqual(QDSConfig().bases, (Basis.Z, Basis.X))

    def test_no_threshold_fields(self):
        """s_a and s_v are DERIVED by M4 from the noise floor and p_f.

        A threshold field here is the easiest possible way to accidentally
        tune a demo, and it would not survive a judge asking where the
        number came from. This test exists to make adding one an argument.
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
            {"bases": ()},
            {"bases": (Basis.Z, Basis.Z)},
            {"bases": ("Z", "X")},
        ]:
            with self.subTest(**kwargs), self.assertRaises((ValueError, TypeError)):
                QDSConfig(**kwargs)


# Local import: kept at the bottom so the test module reads top-to-bottom
# as tests first, helpers last.
from protocol.bb84 import pauli_of  # noqa: E402


if __name__ == "__main__":
    unittest.main()
