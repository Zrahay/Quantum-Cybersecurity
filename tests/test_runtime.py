"""Tests for result-returning runtime helpers (M1).

Shape, bit-order conversion, ideal Bob Z after |0⟩ teleport, and the
prepare/measure round-trip that P1 verification rests on. No QDS logic.

The round-trip tests pin the Aer path to the same two properties the mock
asserts in tests/test_quantum_core.py:

  * same basis -> the prepared bit, with certainty (up to shot noise)
  * cross basis -> uniform

so a mock pass plus a runtime pass is evidence the protocol logic is
correct AND the backend is faithful.
"""

from __future__ import annotations

import unittest

from contracts import Basis
from core.runtime import (
    EntanglementBatch,
    bell_bits_from_memory,
    bob_bit_from_memory,
    prepare_batch,
    prepare_pauli_eigenstate,
    run_measure_bits,
    run_teleport_and_measure,
    run_teleport_bell_outcomes,
)
from qiskit import QuantumCircuit

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

    def test_accepts_real_preparations(self):
        """sign() teleports Alice's real per-element content, not a
        placeholder |0> -- this is the shape it needs (same as
        teleport_and_measure's preparations argument)."""
        n = 12
        preps = [(Basis.Z, i % 2) for i in range(n)]
        outcomes = run_teleport_bell_outcomes(prepare_batch(n), preps, seed=SEED)
        self.assertEqual(len(outcomes), n)
        for pair in outcomes:
            self.assertEqual(len(pair), 2)
            self.assertTrue(all(bit in (0, 1) for bit in pair))

    def test_preparations_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            run_teleport_bell_outcomes(prepare_batch(8), [(Basis.Z, 0)] * 5, seed=SEED)


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


class TestPreparePauliEigenstate(unittest.TestCase):
    """The state-preparation primitive. Must be the exact inverse of measure_in_basis.

    prepare in a basis, measure in the SAME basis, and on an ideal channel
    you get `bit` back with certainty. Measure in a different basis and the
    outcome is uniform. This is the whole mechanism P1 verification rests on.
    """

    def test_z_bit_zero_is_computational_zero(self):
        qc = QuantumCircuit(1, 1)
        prepare_pauli_eigenstate(qc, 0, Basis.Z, 0)
        # No gates applied for |0>; the circuit is empty.
        self.assertEqual(len(qc.data), 0)

    def test_z_bit_one_applies_x(self):
        qc = QuantumCircuit(1, 1)
        prepare_pauli_eigenstate(qc, 0, Basis.Z, 1)
        self.assertEqual(len(qc.data), 1)

    def test_x_applies_hadamard(self):
        qc = QuantumCircuit(1, 1)
        prepare_pauli_eigenstate(qc, 0, Basis.X, 0)
        self.assertEqual(len(qc.data), 1)

    def test_rejects_bad_qubit_index(self):
        qc = QuantumCircuit(1, 1)
        with self.assertRaises(ValueError):
            prepare_pauli_eigenstate(qc, 5, Basis.Z, 0)

    def test_rejects_non_basis(self):
        qc = QuantumCircuit(1, 1)
        with self.assertRaises(TypeError):
            prepare_pauli_eigenstate(qc, 0, "Z", 0)  # type: ignore[arg-type]

    def test_rejects_non_bit(self):
        qc = QuantumCircuit(1, 1)
        with self.assertRaises(ValueError):
            prepare_pauli_eigenstate(qc, 0, Basis.Z, 2)


class TestRunTeleportAndMeasure(unittest.TestCase):
    """The one-shot prepare-teleport-measure runner P1 verification calls.

    Pins the Aer path to the two properties the mock asserts in
    tests/test_quantum_core.py: same-basis certainty and cross-basis
    uniformity. A pass here plus a pass there is evidence the protocol
    logic is correct and the backend is faithful.
    """

    def test_returns_one_result_per_copy(self):
        n = 8
        batch = prepare_batch(n)
        preps = [(Basis.Z, 0)] * n
        bases = [Basis.Z] * n
        results = run_teleport_and_measure(batch, preps, bases, seed=SEED)
        self.assertEqual(len(results), n)
        for bell, bit in results:
            self.assertEqual(len(bell), 2)
            self.assertTrue(all(b in (0, 1) for b in bell))
            self.assertIn(bit, (0, 1))

    def test_same_basis_is_certain_on_ideal_channel(self):
        """|0> teleported and Z-measured reads 0 almost always.

        The mock asserts this exactly; the real backend asserts
        "overwhelmingly" because of finite shot statistics. A 50% rate
        would indicate the endian bug or a broken correction table.
        """
        n = 64
        batch = prepare_batch(n)
        preps = [(Basis.Z, 0)] * n
        bases = [Basis.Z] * n
        results = run_teleport_and_measure(batch, preps, bases, seed=SEED)
        bits = [obs for _bell, obs in results]
        self.assertGreaterEqual(
            bits.count(0) / n, 0.95,
            f"same-basis certainty broken: {bits.count(0)}/{n} zeros",
        )

    def test_cross_basis_is_uniform(self):
        """|0> measured in X is |+> or |-> with equal probability.

        The cross-basis half is what P1's state elimination discards; if
        it were not uniform, the discard would lose information and the
        conclusive fraction would not be the clean L/2 the Hoeffding
        bound is taken over.
        """
        n = 200
        batch = prepare_batch(n)
        preps = [(Basis.Z, 0)] * n
        bases = [Basis.X] * n
        results = run_teleport_and_measure(batch, preps, bases, seed=SEED)
        bits = [obs for _bell, obs in results]
        self.assertGreater(sum(bits), n * 0.30, f"cross-basis too skewed: {sum(bits)}/{n}")
        self.assertLess(sum(bits), n * 0.70, f"cross-basis too skewed: {sum(bits)}/{n}")

    def test_length_mismatch_raises(self):
        batch = prepare_batch(8)
        with self.assertRaises(ValueError):
            run_teleport_and_measure(batch, [(Basis.Z, 0)] * 7, [Basis.Z] * 8, seed=SEED)
        with self.assertRaises(ValueError):
            run_teleport_and_measure(batch, [(Basis.Z, 0)] * 8, [Basis.Z] * 7, seed=SEED)

    def test_rejects_non_batch(self):
        with self.assertRaises(TypeError):
            run_teleport_and_measure(object(), [], [], seed=SEED)

    def test_rejects_non_basis(self):
        batch = prepare_batch(4)
        with self.assertRaises(TypeError):
            run_teleport_and_measure(batch, [(Basis.Z, 0)] * 4, ["Z"] * 4, seed=SEED)


if __name__ == "__main__":
    unittest.main()
