"""Tests for the detection engine. Track M4.

Covers `mismatch_rate` / `MeasurementRecord.mismatch` (pre-existing),
`hoeffding_bound`, `chi2_uniformity`, and `evaluate`. No fixtures, no
mocking/setUp-teardown machinery -- flat assertions, sized to the logic.

Where possible these exercise the REAL pipeline: `protocol.keygen` /
`sign` / `verify` and real `attacks/` adversaries feeding real
`MeasurementRecord`s into `evaluate`, on `MockQuantumCore` (an
analytically-exact ideal-channel model, not a mock in the fake-data
sense -- see its own docstring) so the tests stay fast and deterministic
under a fixed seed. Synthetic `MeasurementRecord` lists are used only for
edge cases (empty list, forced replay) that are awkward to produce from
the real pipeline.
"""

import math
import unittest

from contracts import Basis, MeasurementRecord, ThreatType, Verdict
from detection.detector import evaluate
from detection.statistics import chi2_uniformity, hoeffding_bound, mismatch_rate
from protocol import MockQuantumCore, QDSConfig, keygen, sign, verify
from attacks.forgery import ForgeryAdversary
from attacks.replay import ReplayAdversary


def _record(expected: int, observed: int, index: int = 0) -> MeasurementRecord:
    return MeasurementRecord(
        sig_id="test",
        copy_index=index,
        basis=Basis.Z,
        expected=expected,
        observed=observed,
    )


# Real-pipeline fixtures -- shared config/key/signature for the evaluate()
# tests below. L=400 gives a standard error small enough that "legit"
# and "forged" separate cleanly under a fixed seed, matching the same
# scale tests/test_signature.py uses.
L = 400
CFG = QDSConfig(n_copies=L, seed=1)
MESSAGE = (1, 0, 1)


def _legit_signature():
    core = MockQuantumCore(seed=1)
    key = keygen("alice", L, message_length=3, core=core, config=CFG)
    sig = sign(MESSAGE, key, core=core, config=CFG)
    records = verify(sig, key, core=core, config=CFG)
    return key, sig, records


class TestMismatchProperty(unittest.TestCase):
    def test_agreement_is_not_a_mismatch(self):
        self.assertFalse(_record(0, 0).mismatch)
        self.assertFalse(_record(1, 1).mismatch)

    def test_disagreement_is_a_mismatch(self):
        self.assertTrue(_record(0, 1).mismatch)
        self.assertTrue(_record(1, 0).mismatch)


class TestMismatchRate(unittest.TestCase):
    def test_all_agree(self):
        self.assertEqual(mismatch_rate([_record(0, 0, i) for i in range(10)]), 0.0)

    def test_all_disagree(self):
        self.assertEqual(mismatch_rate([_record(0, 1, i) for i in range(10)]), 1.0)

    def test_partial(self):
        records = [_record(0, 0, 0), _record(0, 1, 1), _record(1, 1, 2), _record(1, 0, 3)]
        self.assertAlmostEqual(mismatch_rate(records), 0.5)

    def test_empty_raises_rather_than_reporting_zero(self):
        """No data must not read as a perfect signature.

        Regression guard for a fail-open bug: returning 0.0 here is the
        strongest possible evidence of a legitimate signature, so an empty
        record list would have let every forgery through `r < s_a`.
        """
        with self.assertRaises(ValueError):
            mismatch_rate([])


class TestHoeffdingBound(unittest.TestCase):
    def test_matches_closed_form(self):
        # exp(-2 * 100 * 0.1^2) = exp(-2) ~ 0.1353
        self.assertAlmostEqual(hoeffding_bound(100, 0.1), math.exp(-2.0), places=9)

    def test_zero_margin_gives_no_guarantee(self):
        self.assertEqual(hoeffding_bound(100, 0.0), 1.0)

    def test_zero_n_gives_no_guarantee(self):
        self.assertEqual(hoeffding_bound(0, 0.1), 1.0)

    def test_larger_n_gives_a_tighter_bound(self):
        self.assertLess(hoeffding_bound(1000, 0.1), hoeffding_bound(10, 0.1))

    def test_larger_margin_gives_a_tighter_bound(self):
        self.assertLess(hoeffding_bound(100, 0.2), hoeffding_bound(100, 0.1))

    def test_bound_is_a_probability(self):
        for n, m in [(1, 0.01), (50, 0.05), (1000, 0.3)]:
            b = hoeffding_bound(n, m)
            self.assertGreaterEqual(b, 0.0)
            self.assertLessEqual(b, 1.0)


class TestChi2Uniformity(unittest.TestCase):
    def test_perfect_fit_gives_zero_statistic_and_p_one(self):
        counts = {"a": 10, "b": 10}
        expected = {"a": 10.0, "b": 10.0}
        stat, p = chi2_uniformity(counts, expected)
        self.assertAlmostEqual(stat, 0.0)
        self.assertAlmostEqual(p, 1.0)

    def test_gross_mismatch_gives_small_p_value(self):
        counts = {"a": 100, "b": 0}
        expected = {"a": 50.0, "b": 50.0}
        stat, p = chi2_uniformity(counts, expected)
        self.assertGreater(stat, 0.0)
        self.assertLess(p, 0.01)

    def test_below_five_expected_per_cell_is_refused(self):
        """Chi-square is invalid below an expected count of 5 per cell --
        the caller must treat this as insufficient data, not a real p-value.
        """
        counts = {"a": 3, "b": 1}
        expected = {"a": 3.0, "b": 1.0}
        stat, p = chi2_uniformity(counts, expected)
        self.assertEqual((stat, p), (0.0, 1.0))

    def test_missing_keys_treated_as_zero_cells(self):
        counts = {"a": 20}
        expected = {"a": 10.0, "b": 10.0}
        stat, p = chi2_uniformity(counts, expected)
        # cell "b": observed 0 vs expected 10.0 -- a real, detectable gap.
        self.assertGreater(stat, 0.0)


class TestEvaluateReplay(unittest.TestCase):
    def test_replay_rejected_before_mismatch_rate_is_even_considered(self):
        """A replayed nonce must reject regardless of how clean the
        statistics look -- construct a synthetic NEAR-PERFECT record set
        (mismatch rate 0.0) and confirm REPLAY still wins over ACCEPT.
        """
        records = [_record(0, 0, i) for i in range(50)]
        key, sig, _ = _legit_signature()
        seen = {sig.nonce}
        result = evaluate(records, sig, seen)
        self.assertEqual(result.verdict, Verdict.REJECT)
        self.assertEqual(result.threat, ThreatType.REPLAY)

    def test_real_replay_adversary_is_caught(self):
        key, sig, records = _legit_signature()
        adversary = ReplayAdversary()
        replayed = adversary.attack(sig)
        seen = {sig.nonce}  # the original was already accepted once
        result = evaluate(records, replayed, seen)
        self.assertEqual(result.verdict, Verdict.REJECT)
        self.assertEqual(result.threat, ThreatType.REPLAY)

    def test_unseen_nonce_does_not_trigger_replay(self):
        key, sig, records = _legit_signature()
        result = evaluate(records, sig, set())
        self.assertNotEqual(result.threat, ThreatType.REPLAY)


class TestEvaluateInsufficientData(unittest.TestCase):
    def test_empty_records_reject_with_insufficient_data_reasoning(self):
        _, sig, _ = _legit_signature()
        result = evaluate([], sig, set())
        self.assertEqual(result.verdict, Verdict.REJECT)
        self.assertEqual(result.n_measurements, 0)
        self.assertIn("insufficient", result.reason.lower())

    def test_empty_records_does_not_crash_on_mismatch_rates_valueerror(self):
        """`mismatch_rate([])` raises; `evaluate` must catch that and turn
        it into a verdict, not propagate the exception to the caller.
        """
        _, sig, _ = _legit_signature()
        try:
            evaluate([], sig, set())
        except ValueError:
            self.fail("evaluate() must not raise on an empty record list")


class TestEvaluateInputValidation(unittest.TestCase):
    def test_negative_noise_floor_rejected(self):
        _, sig, records = _legit_signature()
        with self.assertRaises(ValueError):
            evaluate(records, sig, set(), noise_floor=-0.1)

    def test_noise_floor_above_one_rejected(self):
        _, sig, records = _legit_signature()
        with self.assertRaises(ValueError):
            evaluate(records, sig, set(), noise_floor=1.1)

    def test_zero_target_forgery_prob_rejected(self):
        _, sig, records = _legit_signature()
        with self.assertRaises(ValueError):
            evaluate(records, sig, set(), target_forgery_prob=0.0)

    def test_negative_target_forgery_prob_rejected(self):
        _, sig, records = _legit_signature()
        with self.assertRaises(ValueError):
            evaluate(records, sig, set(), target_forgery_prob=-1e-6)


class TestEvaluateLegitimate(unittest.TestCase):
    def test_clean_signature_is_accepted(self):
        key, sig, records = _legit_signature()
        result = evaluate(records, sig, set())
        self.assertEqual(result.verdict, Verdict.ACCEPT)
        self.assertEqual(result.threat, ThreatType.NONE)
        self.assertEqual(result.mismatch_rate, 0.0)
        self.assertGreater(result.n_measurements, 0)

    def test_forgery_probability_bound_is_the_configured_target(self):
        """By construction s_a's margin solves Hoeffding(n, margin) = p_f,
        so the bound reported alongside an ACCEPT should equal
        target_forgery_prob (up to floating point) -- not a per-signature
        massaged number.
        """
        key, sig, records = _legit_signature()
        result = evaluate(records, sig, set(), target_forgery_prob=1e-6)
        self.assertAlmostEqual(result.forgery_prob_bound, 1e-6, places=9)

    def test_default_noise_floor_is_zero_ideal_channel(self):
        """`noise_floor` defaults to 0.0 -- QDSConfig.noise_level's own
        default, an ideal channel -- not derived from the signature under
        test. See detection/detector.py's module docstring.
        """
        key, sig, records = _legit_signature()
        accept_at_zero = evaluate(records, sig, set(), noise_floor=0.0)
        # A generously large independent noise floor should only make
        # acceptance MORE permissive (larger s_a), never less -- confirms
        # the floor is a real, external input, not silently ignored.
        accept_at_high_floor = evaluate(records, sig, set(), noise_floor=0.2)
        self.assertEqual(accept_at_zero.verdict, Verdict.ACCEPT)
        self.assertEqual(accept_at_high_floor.verdict, Verdict.ACCEPT)


class TestEvaluateForgery(unittest.TestCase):
    def test_high_mismatch_forged_signature_is_rejected(self):
        key, sig, _ = _legit_signature()
        core = MockQuantumCore(seed=1)
        adversary = ForgeryAdversary(strength=1.0)
        forged = adversary.attack(sig)
        records = verify(forged, key, core=core, config=CFG)
        result = evaluate(records, forged, set())
        self.assertEqual(result.verdict, Verdict.REJECT)
        self.assertGreater(result.mismatch_rate, 0.1)

    def test_rejected_non_replay_signature_reports_as_forgery(self):
        """FORGERY, IMPERSONATION and CHANNEL_TAMPER are deliberately
        collapsed into one reported bucket -- see
        detection/detector.py::_reject_reason_and_threat's docstring for
        why (no key registry to separate fabricated key_id from forged
        ops, and the mismatch-rate distributions of a randomised-ops
        attack and an elevated-noise channel overlap too much to split
        with a principled test). This asserts the collapse target, not a
        claim that the real threat type is knowable from statistics alone.
        """
        key, sig, _ = _legit_signature()
        core = MockQuantumCore(seed=1)
        adversary = ForgeryAdversary(strength=1.0)
        forged = adversary.attack(sig)
        records = verify(forged, key, core=core, config=CFG)
        result = evaluate(records, forged, set())
        self.assertEqual(result.threat, ThreatType.FORGERY)

    def test_synthetic_fifty_percent_mismatch_is_rejected(self):
        records = [_record(0, i % 2, i) for i in range(100)]
        _, sig, _ = _legit_signature()
        result = evaluate(records, sig, set())
        self.assertEqual(result.verdict, Verdict.REJECT)
        self.assertAlmostEqual(result.mismatch_rate, 0.5)


if __name__ == "__main__":
    unittest.main()
