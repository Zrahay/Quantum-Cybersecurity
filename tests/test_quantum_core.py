"""Tests for the M1 <-> M2 seam. Track M2 (Shubhang).

Covers the QuantumCore interface, its validator, the development mock, and
the real M1 adapter.

The mock's `teleport_and_measure` is the one exception to "shape only": it
is an analytically exact ideal-channel model (same-basis -> certain
eigenvalue bit, cross-basis -> uniform), so its physics assertions ARE
evidence about the protocol logic. They are NOT evidence about the real
channel -- `tests/test_runtime.py` pins the Aer path to the same physics,
and the mock's noise model is a per-bit flip, not a depolarising error.
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


class TestMockTeleportAndMeasure(unittest.TestCase):
    """The mock's `teleport_and_measure` is an analytically exact ideal channel.

    Same basis -> the prepared bit, with certainty. Cross basis -> uniform.
    These assertions are about the PROTOCOL LOGIC the mock exists to test,
    not about real quantum mechanics; `tests/test_runtime.py` pins the Aer
    path to the same two properties.
    """

    def setUp(self):
        self.core = MockQuantumCore(seed=SEED)

    def test_same_basis_returns_prepared_bit_with_certainty(self):
        """The core P1 acceptance property, in closed form.

        On an ideal channel, an eigenstate of P measured in P's basis
        returns its eigenvalue bit with certainty. Any deviation here is a
        mock bug, and the same deviation in the real backend would reject
        every legitimate signature.
        """
        n = 64
        resource = self.core.bell_pairs(n)
        preparations = [(Basis.Z, bit) for bit in [0, 1] * (n // 2)]
        bases = [Basis.Z] * n
        results = self.core.teleport_and_measure(resource, preparations, bases)
        self.assertEqual(len(results), n)
        for (prep_basis, prep_bit), meas_basis, (_bell, observed) in zip(
            preparations, bases, results
        ):
            self.assertEqual(observed, prep_bit)

    def test_cross_basis_outcome_is_uniform(self):
        """A different-basis measurement carries no information about the bit.

        Over enough copies, the 0/1 split should be roughly even. This is
        the property that makes state elimination work: the cross-basis
        half is discarded because it is pure noise.
        """
        n = 200
        resource = self.core.bell_pairs(n)
        preparations = [(Basis.Z, 0)] * n  # all |0>
        bases = [Basis.X] * n              # measure in X
        results = self.core.teleport_and_measure(resource, preparations, bases)
        bits = [obs for _bell, obs in results]
        # Expect roughly 50/50; allow a wide band for finite-sample noise.
        self.assertGreater(sum(bits), n * 0.30, f"cross-basis too skewed: {sum(bits)}/{n}")
        self.assertLess(sum(bits), n * 0.70, f"cross-basis too skewed: {sum(bits)}/{n}")

    def test_returns_bell_outcome_and_bit_from_same_shot(self):
        """Each result is ((clbit0, clbit1), bob_bit), both halves from one shot."""
        resource = self.core.bell_pairs(8)
        preparations = [(Basis.Z, 0)] * 8
        bases = [Basis.Z] * 8
        results = self.core.teleport_and_measure(resource, preparations, bases)
        for bell, bit in results:
            self.assertEqual(len(bell), 2)
            self.assertTrue(all(b in (0, 1) for b in bell))
            self.assertIn(bit, (0, 1))

    def test_length_mismatch_raises(self):
        resource = self.core.bell_pairs(8)
        with self.assertRaises(ValueError):
            self.core.teleport_and_measure(resource, [(Basis.Z, 0)] * 7, [Basis.Z] * 8)
        with self.assertRaises(ValueError):
            self.core.teleport_and_measure(resource, [(Basis.Z, 0)] * 8, [Basis.Z] * 7)

    def test_rejects_non_probability_noise(self):
        resource = self.core.bell_pairs(4)
        preps = [(Basis.Z, 0)] * 4
        bases = [Basis.Z] * 4
        with self.assertRaises(ValueError):
            self.core.teleport_and_measure(resource, preps, bases, noise_level=1.5)

    def test_rejects_non_basis_argument(self):
        resource = self.core.bell_pairs(4)
        with self.assertRaises(TypeError):
            self.core.teleport_and_measure(
                resource, [("Z", 0)] * 4, [Basis.Z] * 4
            )
        with self.assertRaises(TypeError):
            self.core.teleport_and_measure(
                resource, [(Basis.Z, 0)] * 4, ["Z"] * 4
            )

    def test_rejects_non_bit_preparation(self):
        resource = self.core.bell_pairs(4)
        with self.assertRaises(ValueError):
            self.core.teleport_and_measure(
                resource, [(Basis.Z, 2)] * 4, [Basis.Z] * 4
            )

    def test_noise_can_flip_a_same_basis_bit(self):
        """At noise_level=1.0 every bit flips, so same-basis reads the opposite."""
        n = 32
        resource = self.core.bell_pairs(n)
        preparations = [(Basis.Z, 0)] * n
        bases = [Basis.Z] * n
        results = self.core.teleport_and_measure(
            resource, preparations, bases, noise_level=1.0
        )
        bits = [obs for _bell, obs in results]
        self.assertEqual(set(bits), {1}, f"noise=1.0 should flip every bit, got {bits}")


@unittest.skipUnless(importlib.util.find_spec("qiskit"), "Qiskit not installed")
class TestM1AdapterTeleportAndMeasure(unittest.TestCase):
    """Real backend: shape and the same-basis certainty property.

    Pins the Aer path to the same physics the mock asserts in
    TestMockTeleportAndMeasure, so a mock pass plus a runtime pass is
    evidence the protocol logic is correct AND the backend is faithful.
    """

    def setUp(self):
        self.core = M1QuantumCore(seed=SEED)

    def test_returns_one_result_per_copy(self):
        n = 8
        resource = self.core.bell_pairs(n)
        preparations = [(Basis.Z, 0)] * n
        bases = [Basis.Z] * n
        results = self.core.teleport_and_measure(resource, preparations, bases)
        self.assertEqual(len(results), n)
        for bell, bit in results:
            self.assertEqual(len(bell), 2)
            self.assertTrue(all(b in (0, 1) for b in bell))
            self.assertIn(bit, (0, 1))

    def test_same_basis_is_certain_on_ideal_channel(self):
        """|0> teleported and Z-measured reads 0 almost always.

        We allow a small error band for Aer shot noise and any residual
        gate infidelity; the mock asserts exactness, the real backend
        asserts "overwhelmingly". A 50% rate here would indicate the
        endian bug or a broken correction table.
        """
        n = 64
        resource = self.core.bell_pairs(n)
        preparations = [(Basis.Z, 0)] * n
        bases = [Basis.Z] * n
        results = self.core.teleport_and_measure(resource, preparations, bases)
        bits = [obs for _bell, obs in results]
        self.assertGreaterEqual(
            bits.count(0) / n, 0.95,
            f"same-basis certainty broken: {bits.count(0)}/{n} zeros",
        )

    def test_rejects_non_batch_resource(self):
        with self.assertRaises(TypeError):
            self.core.teleport_and_measure(object(), [], [])


if __name__ == "__main__":
    unittest.main()
