"""
Tests for the Bell State Experiment
=====================================

These tests verify that the Bell state circuit behaves correctly:
  - Produces exactly 2 qubits and 2 classical bits
  - Only yields correlated outcomes (|00⟩ or |11⟩) — never |01⟩ or |10⟩
  - The ratio of |00⟩ to |11⟩ is approximately 50/50 over many shots

No AI/ML is used. We use standard statistical thresholds.
"""

import sys
import os
import unittest

# Add the project root to the Python path so we can import src modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.quantum.bell import create_bell_circuit, run_bell_experiment, analyze_correlation


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
        cls.counts = run_bell_experiment(shots=4096)
        cls.total_shots = sum(cls.counts.values())

    def test_only_correlated_outcomes(self):
        """
        Bell state |Φ+⟩ should only produce |00⟩ or |11⟩.

        The outcomes |01⟩ and |10⟩ should NEVER appear because
        entangled qubits always give the same measurement result.
        """
        allowed = {"00", "11"}
        for outcome in self.counts:
            self.assertIn(
                outcome,
                allowed,
                f"Unexpected outcome |{outcome}⟩ — Bell state should only "
                f"produce |00⟩ or |11⟩",
            )

    def test_no_anti_correlated_outcomes(self):
        """
        Verify that |01⟩ and |10⟩ do not appear at all.

        These outcomes would indicate the qubits are NOT entangled.
        """
        self.assertNotIn("01", self.counts, "Found |01⟩ — qubits are not entangled")
        self.assertNotIn("10", self.counts, "Found |10⟩ — qubits are not entangled")

    def test_total_shots_match(self):
        """The sum of all counts must equal the number of shots."""
        self.assertEqual(self.total_shots, 4096)

    def test_both_outcomes_present(self):
        """
        Both |00⟩ and |11⟩ should appear with reasonable frequency.

        Over 4096 shots, each outcome should appear at least 5% of the time.
        """
        for outcome in ["00", "11"]:
            count = self.counts.get(outcome, 0)
            ratio = count / self.total_shots
            self.assertGreater(
                ratio,
                0.05,
                f"Outcome |{outcome}⟩ appeared only {ratio:.1%} of the time — "
                f"expected ~50%",
            )

    def test_approximately_50_50_split(self):
        """
        The |00⟩ and |11⟩ outcomes should each appear roughly 50% of the time.

        We allow a margin of 15% (i.e., 35%-65%) because quantum measurement
        is probabilistic. With 4096 shots, the law of large numbers ensures
        we converge close to 50/50.
        """
        for outcome in ["00", "11"]:
            count = self.counts.get(outcome, 0)
            ratio = count / self.total_shots
            self.assertGreaterEqual(
                ratio,
                0.35,
                f"Outcome |{outcome}⟩ appeared only {ratio:.1%} — "
                f"expected roughly 50%",
            )
            self.assertLessEqual(
                ratio,
                0.65,
                f"Outcome |{outcome}⟩ appeared {ratio:.1%} — "
                f"expected roughly 50%",
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
        self.assertAlmostEqual(result["correlation_rate"], 100.0)

    def test_partial_correlation(self):
        """Mixed correlated and anti-correlated outcomes."""
        counts = {"00": 400, "11": 400, "01": 100, "10": 100}
        result = analyze_correlation(counts)
        self.assertEqual(result["total_shots"], 1000)
        self.assertEqual(result["correlated"], 800)
        self.assertEqual(result["anti_correlated"], 200)
        self.assertAlmostEqual(result["correlation_rate"], 80.0)

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
        self.assertAlmostEqual(result["correlation_rate"], 100.0)

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

    def test_single_outcome(self):
        """A single correlated outcome (only |00>)."""
        counts = {"00": 50}
        result = analyze_correlation(counts)
        self.assertEqual(result["total_shots"], 50)
        self.assertEqual(result["correlated"], 50)
        self.assertEqual(result["anti_correlated"], 0)
        self.assertAlmostEqual(result["correlation_rate"], 100.0)


if __name__ == "__main__":
    unittest.main()
