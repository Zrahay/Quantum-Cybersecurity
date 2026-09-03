"""Tests for the detection primitives. Track M4.

Covers the only non-stub logic in the detection layer: mismatch_rate and
MeasurementRecord.mismatch. No fixtures, no scaffolding.
"""

import unittest

from contracts import Basis, MeasurementRecord
from detection.statistics import mismatch_rate


def _record(expected: int, observed: int, index: int = 0) -> MeasurementRecord:
    return MeasurementRecord(
        sig_id="test",
        copy_index=index,
        basis=Basis.Z,
        expected=expected,
        observed=observed,
    )


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


if __name__ == "__main__":
    unittest.main()
