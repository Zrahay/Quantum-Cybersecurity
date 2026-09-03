"""Tests for Pauli teleportation corrections (M1)."""

from __future__ import annotations

import unittest

from qiskit import QuantumCircuit

from contracts import PauliOp
from core.pauli import apply_correction, correction_for


class TestCorrectionFor(unittest.TestCase):
    """Lookup table for Alice's Bell measurement bits."""

    def test_all_four_outcomes(self):
        self.assertIs(correction_for((0, 0)), PauliOp.I)
        self.assertIs(correction_for((0, 1)), PauliOp.X)
        self.assertIs(correction_for((1, 0)), PauliOp.Z)
        self.assertIs(correction_for((1, 1)), PauliOp.Y)

    def test_bit_order_swapped_outcomes_differ(self):
        """(0,1) vs (1,0) must not collapse to the same Pauli.

        That swap is the silent endian bug: half of runs look like noise.
        """
        self.assertIsNot(correction_for((0, 1)), correction_for((1, 0)))
        self.assertIs(correction_for((0, 1)), PauliOp.X)
        self.assertIs(correction_for((1, 0)), PauliOp.Z)

    def test_rejects_non_bit_pairs(self):
        for bad in ((0, 2), (2, 0), (-1, 0), (0, -1), (3, 3)):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    correction_for(bad)

    def test_rejects_wrong_arity(self):
        with self.assertRaises(ValueError):
            correction_for((0,))  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            correction_for((0, 0, 0))  # type: ignore[arg-type]


class TestApplyCorrection(unittest.TestCase):
    """Gate application on a scratch circuit."""

    def test_identity_is_noop(self):
        qc = QuantumCircuit(1)
        apply_correction(qc, 0, PauliOp.I)
        self.assertEqual(qc.count_ops(), {})

    def test_x_inserts_x_gate(self):
        qc = QuantumCircuit(1)
        apply_correction(qc, 0, PauliOp.X)
        self.assertEqual(qc.count_ops(), {"x": 1})

    def test_z_inserts_z_gate(self):
        qc = QuantumCircuit(1)
        apply_correction(qc, 0, PauliOp.Z)
        self.assertEqual(qc.count_ops(), {"z": 1})

    def test_y_inserts_y_gate(self):
        qc = QuantumCircuit(1)
        apply_correction(qc, 0, PauliOp.Y)
        self.assertEqual(qc.count_ops(), {"y": 1})

    def test_targets_requested_qubit(self):
        qc = QuantumCircuit(3)
        apply_correction(qc, 2, PauliOp.X)
        # Only qubit 2 should carry the X; ops count is enough plus data check.
        self.assertEqual(qc.count_ops(), {"x": 1})
        inst = qc.data[0]
        self.assertEqual(inst.operation.name, "x")
        self.assertEqual(qc.find_bit(inst.qubits[0]).index, 2)

    def test_rejects_out_of_range_qubit(self):
        qc = QuantumCircuit(2)
        with self.assertRaises(ValueError):
            apply_correction(qc, 2, PauliOp.X)
        with self.assertRaises(ValueError):
            apply_correction(qc, -1, PauliOp.Z)

    def test_table_then_apply_roundtrip_ops(self):
        """correction_for + apply_correction produce the expected gate set."""
        expected_ops = {
            (0, 0): {},
            (0, 1): {"x": 1},
            (1, 0): {"z": 1},
            (1, 1): {"y": 1},
        }
        for outcome, ops in expected_ops.items():
            with self.subTest(outcome=outcome):
                qc = QuantumCircuit(1)
                apply_correction(qc, 0, correction_for(outcome))
                self.assertEqual(qc.count_ops(), ops)


if __name__ == "__main__":
    unittest.main()
