"""Pauli operators and teleportation corrections. Track M1 (Ashab).

STUB -- importable and correctly typed so other tracks can code against it.
Returns fixed placeholder values. Real implementation is M1's.
"""

from __future__ import annotations

from qiskit import QuantumCircuit

from contracts import PauliOp


def correction_for(bell_outcome: tuple[int, int]) -> PauliOp:
    """Pauli correction implied by a teleportation Bell measurement."""
    # TODO(M1): real correction table.
    return PauliOp.I


def apply_correction(circuit: QuantumCircuit, qubit: int, op: PauliOp) -> None:
    """Apply a Pauli correction to `qubit` of `circuit`, in place."""
    # TODO(M1): real gate application.
    return None
