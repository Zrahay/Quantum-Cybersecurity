"""Quantum teleportation circuit. Track M1 (Ashab).

STUB -- importable and correctly typed. Real implementation is M1's.
"""

from __future__ import annotations

from qiskit import QuantumCircuit


def teleportation_circuit(noise_level: float = 0.0) -> QuantumCircuit:
    """Three-qubit teleportation: Bell pair, Bell measurement, correction.

    `noise_level` is the depolarising channel parameter. 0.0 is an ideal
    channel; M3 turns this dial up to simulate channel tampering.
    """
    # TODO(M1): real teleportation. Placeholder keeps the shape (3q, 3c).
    return QuantumCircuit(3, 3)
