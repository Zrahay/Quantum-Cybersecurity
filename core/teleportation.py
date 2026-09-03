"""Quantum teleportation circuit. Track M1 (Ashab).

Qubit roles (frozen for this module):
  0 -- message: starts as |ψ⟩ to teleport
  1 -- Alice's half of the Bell pair
  2 -- Bob's half: ends as |ψ⟩ after correction

Classical bits:
  0, 1 -- Alice's Bell measurement in circuit order (clbit0, clbit1),
          matching contracts.Signature.bell_outcomes
  2 -- reserved for the caller (e.g. measuring Bob)

`noise_level` is a depolarising probability on Bob's qubit after the Bell
pair is shared (the channel Alice→Bob). 0.0 is ideal; M3 raises it.
"""

from __future__ import annotations

from qiskit import QuantumCircuit
from qiskit_aer.noise import depolarizing_error

from contracts import PauliOp
from core.pauli import apply_correction


def teleportation_circuit(noise_level: float = 0.0) -> QuantumCircuit:
    """Three-qubit teleportation: Bell pair, Bell measurement, correction.

    `noise_level` is the depolarising channel parameter. 0.0 is an ideal
    channel; M3 turns this dial up to simulate channel tampering.
    """
    if not 0.0 <= noise_level <= 1.0:
        raise ValueError(f"noise_level must be in [0, 1]; got {noise_level}")

    qc = QuantumCircuit(3, 3)

    # 1. Share |Φ+⟩ between Alice (q1) and Bob (q2).
    qc.h(1)
    qc.cx(1, 2)

    # Channel noise on Bob's half after distribution.
    if noise_level > 0.0:
        qc.append(depolarizing_error(noise_level, 1).to_instruction(), [2])

    # 2. Alice Bell-measure message (q0) with her half (q1).
    qc.cx(0, 1)
    qc.h(0)
    qc.measure(0, 0)
    qc.measure(1, 1)

    # 3. Bob undoes the Pauli twist: Z^{c0} then X^{c1}
    #    (== correction_for((c0, c1)), including Y when both bits are 1).
    with qc.if_test((qc.clbits[0], 1)):
        apply_correction(qc, 2, PauliOp.Z)
    with qc.if_test((qc.clbits[1], 1)):
        apply_correction(qc, 2, PauliOp.X)

    return qc
