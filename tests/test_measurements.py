"""Tests for projective measurement helpers (M1).

Gate insertion per basis, and the MeasurementRecord factory that is the
M1→M4 seam. No fixtures.
"""

from __future__ import annotations

import unittest

from qiskit import QuantumCircuit
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_aer import AerSimulator

from contracts import Basis, MeasurementRecord
from core.measurements import measure_in_basis, records_from_shots

SEED = 20260903
SHOTS = 2048


def _op_names(qc: QuantumCircuit) -> list[str]:
    return [inst.operation.name for inst in qc.data]


class TestMeasureInBasisGates(unittest.TestCase):
    """Each basis inserts the documented pre-rotation, then measure."""

    def test_z_measures_without_rotation(self):
        qc = QuantumCircuit(1, 1)
        measure_in_basis(qc, 0, Basis.Z)
        self.assertEqual(_op_names(qc), ["measure"])

    def test_x_applies_h_then_measure(self):
        qc = QuantumCircuit(1, 1)
        measure_in_basis(qc, 0, Basis.X)
        self.assertEqual(_op_names(qc), ["h", "measure"])

    def test_y_applies_sdg_h_then_measure(self):
        qc = QuantumCircuit(1, 1)
        measure_in_basis(qc, 0, Basis.Y)
        self.assertEqual(_op_names(qc), ["sdg", "h", "measure"])

    def test_targets_requested_qubit_and_matching_clbit(self):
        qc = QuantumCircuit(3, 3)
        measure_in_basis(qc, 2, Basis.X)
        self.assertEqual(_op_names(qc), ["h", "measure"])
        h_inst, m_inst = qc.data
        self.assertEqual(qc.find_bit(h_inst.qubits[0]).index, 2)
        self.assertEqual(qc.find_bit(m_inst.qubits[0]).index, 2)
        self.assertEqual(qc.find_bit(m_inst.clbits[0]).index, 2)

    def test_rejects_out_of_range_qubit(self):
        qc = QuantumCircuit(2, 2)
        with self.assertRaises(ValueError):
            measure_in_basis(qc, 2, Basis.Z)
        with self.assertRaises(ValueError):
            measure_in_basis(qc, -1, Basis.Z)

    def test_rejects_missing_matching_clbit(self):
        qc = QuantumCircuit(2, 1)  # qubit 1 has no clbit twin
        with self.assertRaises(ValueError):
            measure_in_basis(qc, 1, Basis.Z)


class TestMeasureInBasisSemantics(unittest.TestCase):
    """Prepared eigenstates collapse to the predicted bit."""

    def _counts(self, prep, basis: Basis) -> dict[str, int]:
        qc = QuantumCircuit(1, 1)
        prep(qc)
        measure_in_basis(qc, 0, basis)
        sim = AerSimulator(seed_simulator=SEED)
        pm = generate_preset_pass_manager(backend=sim, optimization_level=0)
        return sim.run(pm.run(qc), shots=SHOTS).result().get_counts()

    def test_zero_in_z(self):
        counts = self._counts(lambda qc: None, Basis.Z)
        self.assertGreaterEqual(counts.get("0", 0) / SHOTS, 0.99)

    def test_one_in_z(self):
        counts = self._counts(lambda qc: qc.x(0), Basis.Z)
        self.assertGreaterEqual(counts.get("1", 0) / SHOTS, 0.99)

    def test_plus_in_x(self):
        counts = self._counts(lambda qc: qc.h(0), Basis.X)
        self.assertGreaterEqual(counts.get("0", 0) / SHOTS, 0.99)

    def test_plus_i_in_y(self):
        """|+i⟩ = S|+⟩; Y-basis measure (S† H Z) should read 0."""
        counts = self._counts(lambda qc: (qc.h(0), qc.s(0)), Basis.Y)
        self.assertGreaterEqual(counts.get("0", 0) / SHOTS, 0.99)


class TestRecordsFromShots(unittest.TestCase):
    """Factory that turns per-copy bits into MeasurementRecords."""

    def test_builds_one_record_per_copy(self):
        observed = [0, 1, 0]
        expected = [0, 0, 1]
        records = records_from_shots(observed, expected, "sig-1", Basis.X)
        self.assertEqual(len(records), 3)
        for i, rec in enumerate(records):
            self.assertIsInstance(rec, MeasurementRecord)
            self.assertEqual(rec.sig_id, "sig-1")
            self.assertEqual(rec.copy_index, i)
            self.assertIs(rec.basis, Basis.X)
            self.assertEqual(rec.observed, observed[i])
            self.assertEqual(rec.expected, expected[i])

    def test_mismatch_property_follows_bits(self):
        records = records_from_shots([0, 1], [0, 0], "sig", Basis.Z)
        self.assertFalse(records[0].mismatch)
        self.assertTrue(records[1].mismatch)

    def test_empty_sequences_yield_empty_list(self):
        self.assertEqual(records_from_shots([], [], "sig", Basis.Z), [])

    def test_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            records_from_shots([0, 1], [0], "sig", Basis.Z)

    def test_rejects_non_bits(self):
        with self.assertRaises(ValueError):
            records_from_shots([0, 2], [0, 0], "sig", Basis.Z)
        with self.assertRaises(ValueError):
            records_from_shots([0, 0], [0, -1], "sig", Basis.Z)


if __name__ == "__main__":
    unittest.main()
