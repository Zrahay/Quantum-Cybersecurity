"""Pauli operators and teleportation corrections. Track M1 (Ashab).

Standard teleportation: Alice's Bell measurement leaves Bob's qubit in one
of four Pauli-twisted states. The classical bits (clbit0, clbit1) select
the undoing operator:

    Z^{clbit0}  and  X^{clbit1}

Bit order is circuit order (control / message bit first), matching
contracts.Signature.bell_outcomes -- not Qiskit little-endian count strings.
"""

from __future__ import annotations

from qiskit import QuantumCircuit

from contracts import PauliOp

# (clbit0, clbit1) -> correction. Exhaustive; anything else is a bug at the
# call site (or a corrupted signature), not a fifth Pauli.
_CORRECTION_TABLE: dict[tuple[int, int], PauliOp] = {
    (0, 0): PauliOp.I,  # nothing
    (0, 1): PauliOp.X,  # X^{1}
    (1, 0): PauliOp.Z,  # Z^{1}
    (1, 1): PauliOp.Y,  # X then Z (Y up to global phase)
}


def correction_for(bell_outcome: tuple[int, int]) -> PauliOp:
    """Pauli correction implied by a teleportation Bell measurement."""
    if bell_outcome not in _CORRECTION_TABLE:
        raise ValueError(
            f"bell_outcome must be a pair of bits (0|1, 0|1); got {bell_outcome!r}"
        )
    return _CORRECTION_TABLE[bell_outcome]


def apply_correction(circuit: QuantumCircuit, qubit: int, op: PauliOp) -> None:
    """Apply a Pauli correction to `qubit` of `circuit`, in place."""
    if qubit < 0 or qubit >= circuit.num_qubits:
        raise ValueError(
            f"qubit index {qubit} out of range for circuit with "
            f"{circuit.num_qubits} qubits"
        )
    if op is PauliOp.I:
        return
    if op is PauliOp.X:
        circuit.x(qubit)
        return
    if op is PauliOp.Z:
        circuit.z(qubit)
        return
    if op is PauliOp.Y:
        circuit.y(qubit)
        return
    raise ValueError(f"unknown PauliOp: {op!r}")
