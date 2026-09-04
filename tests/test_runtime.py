"""Tests for result-returning runtime helpers (M1).

Shape, bit-order conversion, and ideal Bob Z after |0⟩ teleport. No QDS logic.
"""

from __future__ import annotations

import unittest

from contracts import Basis
from core.runtime import (
    EntanglementBatch,
    bell_bits_from_memory,
    bob_bit_from_memory,
    prepare_batch,
    run_measure_bits,
    run_teleport_bell_outcomes,
)

SEED = 20260903


class TestBitOrderHelpers(unittest.TestCase):
    def test_bell_bits_rightmost_is_clbit0(self):
        # Memory "xyz" -> clbit2=x, clbit1=y, clbit0=z
        self.assertEqual(bell_bits_from_memory("010"), (0, 1))
        self.assertEqual(bell_bits_from_memory("001"), (1, 0))
        self.assertEqual(bell_bits_from_memory("011"), (1, 1))
        self.assertEqual(bell_bits_from_memory("000"), (0, 0))

    def test_bell_bits_swapped_outcomes_differ(self):
        self.assertNotEqual(bell_bits_from_memory("010"), bell_bits_from_memory("001"))

    def test_bob_bit_is_leftmost(self):
        self.assertEqual(bob_bit_from_memory("100"), 1)
        self.assertEqual(bob_bit_from_memory("000"), 0)

    def test_rejects_short_strings(self):
        with self.assertRaises(ValueError):
            bell_bits_from_memory("0")
        with self.assertRaises(ValueError):
            bob_bit_from_memory("01")


class TestPrepareBatch(unittest.TestCase):
    def test_returns_frozen_handle(self):
        batch = prepare_batch(8, noise_level=0.1)
        self.assertIsInstance(batch, EntanglementBatch)
        self.assertEqual(batch.n_pairs, 8)
        self.assertEqual(batch.noise_level, 0.1)

    def test_rejects_non_positive_n(self):
        with self.assertRaises(ValueError):
            prepare_batch(0)

    def test_rejects_noise_outside_unit_interval(self):
        with self.assertRaises(ValueError):
            prepare_batch(4, noise_level=-0.1)
        with self.assertRaises(ValueError):
            prepare_batch(4, noise_level=1.1)


class TestRunTeleportBellOutcomes(unittest.TestCase):
    def test_one_pair_per_copy(self):
        outcomes = run_teleport_bell_outcomes(prepare_batch(12), seed=SEED)
        self.assertEqual(len(outcomes), 12)
        for pair in outcomes:
            self.assertEqual(len(pair), 2)
            self.assertTrue(all(bit in (0, 1) for bit in pair))

    def test_rejects_non_batch(self):
        with self.assertRaises(TypeError):
            run_teleport_bell_outcomes(object())  # type: ignore[arg-type]


class TestRunMeasureBits(unittest.TestCase):
    def test_returns_classical_bits(self):
        bits = run_measure_bits(prepare_batch(10), Basis.Z, seed=SEED)
        self.assertEqual(len(bits), 10)
        self.assertEqual(set(bits) - {0, 1}, set())

    def test_ideal_zero_state_mostly_zero_in_z(self):
        """|0⟩ teleports; Bob Z-measure should read 0 almost always."""
        n = 64
        bits = run_measure_bits(prepare_batch(n), Basis.Z, seed=SEED)
        self.assertGreaterEqual(bits.count(0) / n, 0.95)

    def test_rejects_non_basis(self):
        with self.assertRaises(TypeError):
            run_measure_bits(prepare_batch(4), "Z")  # type: ignore[arg-type]

    def test_call_site_noise_override_is_range_checked(self):
        batch = prepare_batch(4, noise_level=0.0)
        with self.assertRaises(ValueError):
            run_measure_bits(batch, Basis.Z, noise_level=1.5)


if __name__ == "__main__":
    unittest.main()
