"""Tests for the M1 <-> M2 seam. Track M2 (Shubhang).

Covers the QuantumCore interface, its validator, and the development mock.

The mock's tests assert DETERMINISM AND SHAPE ONLY. They deliberately assert
nothing about physics, because the mock has none -- it returns seeded
pseudo-random bits. Any test here that started checking correlation rates or
noise floors would be measuring `random.Random`, and would be quoted at us
later as if it meant something.
"""

import importlib.util
import unittest

from contracts import Basis, PauliOp
from protocol import M1QuantumCore, MockQuantumCore, QuantumCore, QuantumCoreError, check_quantum_core

SEED = 20260903


class TestInterfaceConformance(unittest.TestCase):
    def test_mock_satisfies_the_interface(self):
        core = MockQuantumCore()
        self.assertIsInstance(core, QuantumCore)
        check_quantum_core(core)

    def test_real_adapter_satisfies_the_interface(self):
        """M1QuantumCore must conform even while its methods still refuse.

        Conformance and implementedness are separate things: the swap from
        mock to real backend is a one-argument change, and it should fail with
        M1's honest "no entry point yet" message, not an AttributeError.
        """
        self.assertIsInstance(M1QuantumCore(), QuantumCore)
        check_quantum_core(M1QuantumCore())

    def test_validator_names_every_missing_method(self):
        class Partial:
            def bell_pairs(self, n, *, noise_level=0.0): ...
            def teleport(self, resource, *, noise_level=0.0): ...

        with self.assertRaises(QuantumCoreError) as ctx:
            check_quantum_core(Partial())
        message = str(ctx.exception)
        self.assertIn("correction_for", message)
        self.assertIn("measure", message)
        self.assertIn("Partial", message)

    def test_validator_rejects_non_callable_attributes(self):
        """A name that exists but is not callable is not an implementation."""

        class Sabotaged:
            bell_pairs = teleport = correction_for = None
            measure = 3

        with self.assertRaises(QuantumCoreError):
            check_quantum_core(Sabotaged())

    def test_validator_returns_the_core_for_chaining(self):
        core = MockQuantumCore()
        self.assertIs(check_quantum_core(core), core)


class TestMockDeterminism(unittest.TestCase):
    """Same seed, same call sequence, same answers. Tests must be replayable."""

    @staticmethod
    def _sequence(core: MockQuantumCore) -> tuple:
        resource = core.bell_pairs(16)
        return (tuple(core.teleport(resource)), tuple(core.measure(resource, Basis.Z)))

    def test_same_seed_gives_identical_output(self):
        self.assertEqual(
            self._sequence(MockQuantumCore(seed=SEED)),
            self._sequence(MockQuantumCore(seed=SEED)),
        )

    def test_different_seed_gives_different_output(self):
        self.assertNotEqual(
            self._sequence(MockQuantumCore(seed=SEED)),
            self._sequence(MockQuantumCore(seed=SEED + 1)),
        )

    def test_reset_rewinds_the_stream(self):
        core = MockQuantumCore(seed=SEED)
        first = self._sequence(core)
        self.assertNotEqual(self._sequence(core), first, "RNG did not advance between calls")
        core.reset()
        self.assertEqual(self._sequence(core), first)

    def test_default_seed_is_fixed_so_unseeded_use_is_still_reproducible(self):
        self.assertEqual(self._sequence(MockQuantumCore()), self._sequence(MockQuantumCore()))


class TestMockShapeAndValidation(unittest.TestCase):
    def setUp(self):
        self.core = MockQuantumCore(seed=SEED)

    def test_teleport_returns_one_bit_pair_per_copy(self):
        outcomes = self.core.teleport(self.core.bell_pairs(12))
        self.assertEqual(len(outcomes), 12)
        for pair in outcomes:
            self.assertEqual(len(pair), 2)
            self.assertTrue(all(bit in (0, 1) for bit in pair))

    def test_measure_returns_classical_bits_never_eigenvalues(self):
        """0/1, not +1/-1.

        contracts.MeasurementRecord takes measured bits. A core returning -1
        would make `mismatch` true for every record and reject every
        legitimate signature at a 100% mismatch rate -- a failure that looks
        like a broken protocol rather than a broken convention.
        """
        for basis in Basis:
            with self.subTest(basis=basis):
                bits = self.core.measure(self.core.bell_pairs(10), basis)
                self.assertEqual(len(bits), 10)
                self.assertEqual(set(bits) - {0, 1}, set())

    def test_measure_under_noise_still_returns_bits(self):
        bits = self.core.measure(self.core.bell_pairs(10), Basis.Z, noise_level=1.0)
        self.assertEqual(set(bits) - {0, 1}, set())

    def test_correction_for_is_a_pure_lookup(self):
        """No RNG involvement: repeated calls must agree, in any order."""
        first = [self.core.correction_for(o) for o in [(0, 0), (0, 1), (1, 0), (1, 1)]]
        second = [self.core.correction_for(o) for o in [(0, 0), (0, 1), (1, 0), (1, 1)]]
        self.assertEqual(first, second)
        self.assertEqual(len(set(first)), 4, "the four Bell outcomes must map to four distinct ops")
        for op in first:
            self.assertIsInstance(op, PauliOp)

    def test_bell_pairs_rejects_a_non_positive_count(self):
        with self.assertRaises(ValueError):
            self.core.bell_pairs(0)

    def test_noise_level_must_be_a_probability(self):
        for level in (-0.1, 1.5):
            with self.subTest(level=level):
                with self.assertRaises(ValueError):
                    self.core.bell_pairs(4, noise_level=level)
                with self.assertRaises(ValueError):
                    self.core.measure(self.core.bell_pairs(4), Basis.Z, noise_level=level)

    def test_measure_rejects_a_basis_that_is_not_a_basis(self):
        """A bare "Z" string would silently measure the wrong thing."""
        with self.assertRaises(TypeError):
            self.core.measure(self.core.bell_pairs(4), "Z")


@unittest.skipUnless(importlib.util.find_spec("qiskit"), "Qiskit not installed")
class TestM1AdapterDelegatesToCore(unittest.TestCase):
    """Real backend: shape only. Physics fidelity lives in tests/test_runtime.py.

    Skipped without Qiskit so M2's suite can still run where Aer is absent;
    the adapter imports core/ lazily on purpose.
    """

    def setUp(self):
        self.core = M1QuantumCore()

    def test_bell_pairs_returns_a_handle(self):
        resource = self.core.bell_pairs(4)
        self.assertIsNotNone(resource)

    def test_teleport_returns_one_bit_pair_per_copy(self):
        outcomes = self.core.teleport(self.core.bell_pairs(8))
        self.assertEqual(len(outcomes), 8)
        for pair in outcomes:
            self.assertEqual(len(pair), 2)
            self.assertTrue(all(bit in (0, 1) for bit in pair))

    def test_measure_returns_classical_bits(self):
        bits = self.core.measure(self.core.bell_pairs(8), Basis.Z)
        self.assertEqual(len(bits), 8)
        self.assertEqual(set(bits) - {0, 1}, set())

    def test_teleport_rejects_a_non_batch_resource(self):
        with self.assertRaises(TypeError):
            self.core.teleport(object())

    def test_correction_for_delegates_to_m1(self):
        """Shape only -- M1 owns the table."""
        self.assertIsInstance(self.core.correction_for((0, 0)), PauliOp)


if __name__ == "__main__":
    unittest.main()
