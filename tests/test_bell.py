"""
Tests for the Bell State Experiment
=====================================

These tests verify that the Bell state circuit behaves correctly:
  - Produces exactly 2 qubits and 2 classical bits
  - Only yields correlated outcomes (|00⟩ or |11⟩) — never |01⟩ or |10⟩
  - The ratio of |00⟩ to |11⟩ is approximately 50/50 over many shots

No AI/ML is used. We use standard statistical thresholds.
"""

import unittest

from core.bell import analyze_correlation, create_bell_circuit, run_bell_experiment

# Fixed seed: a failing run can be reproduced with the exact same shots
# instead of guessed at. Matters more once noise models land.
SEED = 20260903
SHOTS = 4096


class TestBellCircuit(unittest.TestCase):
    """Tests for the Bell state circuit construction."""

    def test_circuit_has_two_qubits(self):
        """The Bell circuit must have exactly 2 qubits."""
        qc = create_bell_circuit()
        self.assertEqual(qc.num_qubits, 2)

    def test_circuit_has_two_classical_bits(self):
        """The Bell circuit must have exactly 2 classical bits."""
        qc = create_bell_circuit()
        self.assertEqual(qc.num_clbits, 2)

    def test_circuit_has_measurements(self):
        """The Bell circuit must contain measurement operations."""
        qc = create_bell_circuit()
        # After transpilation, the circuit should have measurement instructions.
        # We check the operation count includes measurements.
        ops = qc.count_ops()
        # The circuit should have 'measure' operations
        self.assertIn("measure", ops)


class TestBellExperiment(unittest.TestCase):
    """Tests for the Bell state measurement results."""

    @classmethod
    def setUpClass(cls):
        """Run the Bell experiment once for all tests in this class."""
        # Use a large number of shots for reliable statistics
        cls.counts = run_bell_experiment(shots=SHOTS, seed=SEED)
        cls.total_shots = sum(cls.counts.values())

    def test_ideal_channel_produces_only_correlated_outcomes(self):
        """
        On an IDEAL (noiseless) channel, |Φ+⟩ produces only |00⟩ or |11⟩.

        NOTE — THIS INVARIANT EXPIRES. It holds only while the simulator is
        noiseless. The next task on this track is a tunable depolarising
        noise model, and at any noise level above zero |01⟩ and |10⟩ WILL
        appear at roughly the noise rate. When that lands, replace this
        assertion with a tolerance on the anti-correlated *rate* against the
        measured noise floor. Do not "fix" a failure here by weakening the
        circuit — a failure after noise is introduced is expected, not a bug.
        """
        allowed = {"00", "11"}
        for outcome in self.counts:
            self.assertIn(
                outcome,
                allowed,
                f"Unexpected outcome |{outcome}⟩ — Bell state should only "
                f"produce |00⟩ or |11⟩",
            )

    def test_ideal_channel_has_no_anti_correlated_outcomes(self):
        """
        On an IDEAL channel, |01⟩ and |10⟩ do not appear at all.

        Same expiry warning as the test above: once channel noise exists,
        these outcomes are the noise floor, not broken entanglement.
        """
        msg = "on a NOISELESS simulator this means the circuit is wrong; " \
              "once a noise model exists, expect these and assert a rate instead"
        self.assertNotIn("01", self.counts, f"Found |01⟩ — {msg}")
        self.assertNotIn("10", self.counts, f"Found |10⟩ — {msg}")

    def test_total_shots_match(self):
        """The sum of all counts must equal the number of shots."""
        self.assertEqual(self.total_shots, SHOTS)

    def test_approximately_50_50_split(self):
        """
        |00⟩ and |11⟩ should each appear close to 50% of the time.

        Bound derivation, so it is defensible rather than eyeballed: for a
        fair binomial at n=4096, sigma = sqrt(n*p*(1-p)) = 32 shots, which
        is 0.78 percentage points. A 3-sigma band is +/- 2.34pp, giving a
        false-failure rate near 0.3% — tight enough to catch a real skew,
        loose enough not to flake. The previous +/- 15pp band was 19 sigma:
        it could not fail for statistical reasons, only for total breakage.
        """
        sigma = (SHOTS * 0.5 * 0.5) ** 0.5 / SHOTS  # 0.0078125
        lo, hi = 0.5 - 3 * sigma, 0.5 + 3 * sigma
        for outcome in ["00", "11"]:
            ratio = self.counts.get(outcome, 0) / self.total_shots
            self.assertGreaterEqual(
                ratio, lo, f"Outcome |{outcome}⟩ appeared {ratio:.2%} — expected ~50% (3-sigma floor {lo:.2%})"
            )
            self.assertLessEqual(
                ratio, hi, f"Outcome |{outcome}⟩ appeared {ratio:.2%} — expected ~50% (3-sigma ceiling {hi:.2%})"
            )


class TestAnalyzeCorrelation(unittest.TestCase):
    """Tests for the correlation analysis function."""

    def test_perfect_correlation(self):
        """100% correlated outcomes should give a 100% correlation rate."""
        counts = {"00": 500, "11": 500}
        result = analyze_correlation(counts)
        self.assertEqual(result["total_shots"], 1000)
        self.assertEqual(result["correlated"], 1000)
        self.assertEqual(result["anti_correlated"], 0)
        self.assertAlmostEqual(result["correlation_rate"], 1.0)

    def test_partial_correlation(self):
        """Mixed correlated and anti-correlated outcomes."""
        counts = {"00": 400, "11": 400, "01": 100, "10": 100}
        result = analyze_correlation(counts)
        self.assertEqual(result["total_shots"], 1000)
        self.assertEqual(result["correlated"], 800)
        self.assertEqual(result["anti_correlated"], 200)
        self.assertAlmostEqual(result["correlation_rate"], 0.8)

    def test_all_anti_correlated(self):
        """100% anti-correlated outcomes."""
        counts = {"01": 300, "10": 300}
        result = analyze_correlation(counts)
        self.assertEqual(result["total_shots"], 600)
        self.assertEqual(result["correlated"], 0)
        self.assertEqual(result["anti_correlated"], 600)
        self.assertAlmostEqual(result["correlation_rate"], 0.0)

    def test_missing_keys_treated_as_zero(self):
        """Missing outcome keys should be treated as zero counts."""
        counts = {"00": 100}
        result = analyze_correlation(counts)
        self.assertEqual(result["total_shots"], 100)
        self.assertEqual(result["correlated"], 100)
        self.assertEqual(result["anti_correlated"], 0)
        self.assertAlmostEqual(result["correlation_rate"], 1.0)

    def test_empty_counts(self):
        """An empty counts dict should not crash and should return zeros."""
        result = analyze_correlation({})
        self.assertEqual(result["total_shots"], 0)
        self.assertEqual(result["correlated"], 0)
        self.assertEqual(result["anti_correlated"], 0)
        self.assertAlmostEqual(result["correlation_rate"], 0.0)

    def test_zero_shots(self):
        """A dict with all zero counts should also return zeros."""
        counts = {"00": 0, "11": 0, "01": 0, "10": 0}
        result = analyze_correlation(counts)
        self.assertEqual(result["total_shots"], 0)
        self.assertAlmostEqual(result["correlation_rate"], 0.0)

    def test_unrecognised_keys_counted_in_total(self):
        """
        An outcome key that is neither correlated nor anti-correlated must
        still count toward total_shots, and be reported separately.

        This is the regression guard for a real bug: total_shots used to be
        computed as correlated + anti_correlated, so any unexpected key was
        silently dropped and the shot count understated. Noise models and
        multi-register circuits both produce such keys.
        """
        result = analyze_correlation({"00": 10, "11": 10, "01": 5, "99": 3})
        self.assertEqual(result["total_shots"], 28)
        self.assertEqual(result["correlated"], 20)
        self.assertEqual(result["anti_correlated"], 5)
        self.assertEqual(result["unrecognised"], 3)
        self.assertAlmostEqual(result["correlation_rate"], 20 / 28)

    def test_unrecognised_is_zero_for_canonical_keys(self):
        """The four canonical outcomes leave nothing unrecognised."""
        result = analyze_correlation({"00": 1, "11": 2, "01": 3, "10": 4})
        self.assertEqual(result["unrecognised"], 0)
        self.assertEqual(result["total_shots"], 10)

    def test_single_outcome(self):
        """A single correlated outcome (only |00>)."""
        counts = {"00": 50}
        result = analyze_correlation(counts)
        self.assertEqual(result["total_shots"], 50)
        self.assertEqual(result["correlated"], 50)
        self.assertEqual(result["anti_correlated"], 0)
        self.assertAlmostEqual(result["correlation_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
