"""Tests for the teleportation circuit (M1).

Ideal channel: an arbitrary prep on qubit 0 is recovered on qubit 2.
Noise dial: depolarising on Bob's half raises the mismatch rate.
"""

from __future__ import annotations

import unittest

from qiskit import QuantumCircuit
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_aer import AerSimulator

from core.teleportation import teleportation_circuit

SEED = 20260903
SHOTS = 4096


def _bob_bit_counts(counts: dict[str, int]) -> tuple[int, int]:
    """Split shot counts by Bob's clbit (index 2 = leftmost in Qiskit keys)."""
    zeros = ones = 0
    for key, n in counts.items():
        if key[0] == "0":
            zeros += n
        else:
            ones += n
    return zeros, ones


def _run_teleport(
    prep,
    *,
    measure_basis: str = "Z",
    noise_level: float = 0.0,
    shots: int = SHOTS,
    seed: int = SEED,
) -> dict[str, int]:
    """Prep on q0, teleport, measure Bob (q2) into c2."""
    qc = QuantumCircuit(3, 3)
    prep(qc)
    qc.compose(teleportation_circuit(noise_level), inplace=True)
    if measure_basis == "Z":
        qc.measure(2, 2)
    elif measure_basis == "X":
        qc.h(2)
        qc.measure(2, 2)
    else:
        raise ValueError(f"unsupported measure_basis: {measure_basis}")

    sim = AerSimulator(seed_simulator=seed)
    pm = generate_preset_pass_manager(backend=sim, optimization_level=0)
    return sim.run(pm.run(qc), shots=shots).result().get_counts()


class TestTeleportationCircuitShape(unittest.TestCase):
    def test_three_qubits_three_clbits(self):
        qc = teleportation_circuit()
        self.assertEqual(qc.num_qubits, 3)
        self.assertEqual(qc.num_clbits, 3)

    def test_rejects_noise_outside_unit_interval(self):
        with self.assertRaises(ValueError):
            teleportation_circuit(-0.1)
        with self.assertRaises(ValueError):
            teleportation_circuit(1.1)


class TestIdealTeleportation(unittest.TestCase):
    """noise_level=0: state on q0 is recovered on q2."""

    def test_zero_state(self):
        counts = _run_teleport(lambda qc: None, measure_basis="Z")
        zeros, ones = _bob_bit_counts(counts)
        # Ideal teleport of |0>: allow a few Aer flukes, not a broken circuit.
        self.assertGreaterEqual(zeros / SHOTS, 0.99)
        self.assertEqual(zeros + ones, SHOTS)

    def test_one_state(self):
        counts = _run_teleport(lambda qc: qc.x(0), measure_basis="Z")
        zeros, ones = _bob_bit_counts(counts)
        self.assertGreaterEqual(ones / SHOTS, 0.99)

    def test_plus_state_in_x_basis(self):
        """|+⟩ = H|0⟩ teleports; X-basis measure of Bob should read 0."""
        counts = _run_teleport(lambda qc: qc.h(0), measure_basis="X")
        zeros, ones = _bob_bit_counts(counts)
        self.assertGreaterEqual(zeros / SHOTS, 0.99)


class TestNoisyTeleportation(unittest.TestCase):
    """Depolarising dial on Bob's half must hurt fidelity."""

    def test_noise_raises_mismatch_for_zero_state(self):
        ideal = _run_teleport(lambda qc: None, noise_level=0.0)
        noisy = _run_teleport(lambda qc: None, noise_level=0.3, seed=SEED + 1)
        ideal_zeros, _ = _bob_bit_counts(ideal)
        noisy_zeros, _ = _bob_bit_counts(noisy)
        self.assertGreater(ideal_zeros, noisy_zeros)


if __name__ == "__main__":
    unittest.main()
