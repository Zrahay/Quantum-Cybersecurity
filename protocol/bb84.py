"""Signature-element encoding. Track M2 (Shubhang).

A P1 signature element is a BB84 state, and every BB84 state is a Pauli
eigenstate:

    |0>  = +1 eigenstate of Z        |1>  = -1 eigenstate of Z
    |+>  = +1 eigenstate of X        |->  = -1 eigenstate of X

So an element is exactly (which Pauli, which eigenvalue), and that is how it
is stored in the frozen contract:

    KeyPair.pauli_map[i]     -- the Pauli:      PauliOp.Z or PauliOp.X
    KeyPair.private_bits[i]  -- the eigenvalue: 0 for +1, 1 for -1

NOTE ON THE CONTRACT. `contracts.KeyPair.pauli_map` is commented "message
bit -> required correction", which is a different reading of the same field.
The TYPE is unchanged and no other track reads `pauli_map`, so nothing
breaks -- but the comment is now wrong and correcting it is a Decision Log
item, not a unilateral edit. See protocol/README.md.

The eigenvalue convention matches contracts.MeasurementRecord exactly: bit 0
means the protocol predicts the +1 eigenstate, so `expected=0`. Writing -1
would make every record a mismatch and reject every legitimate signature.
"""

from __future__ import annotations

from contracts import Basis, PauliOp

_PAULI_TO_BASIS: dict[PauliOp, Basis] = {
    PauliOp.Z: Basis.Z,
    PauliOp.X: Basis.X,
    PauliOp.Y: Basis.Y,
}
_BASIS_TO_PAULI: dict[Basis, PauliOp] = {b: p for p, b in _PAULI_TO_BASIS.items()}


def basis_of(op: PauliOp) -> Basis | None:
    """The basis whose eigenstates `op` labels, or None if it labels none.

    `PauliOp.I` maps to None, and that is a RETURN VALUE, not an error.
    `declared_ops` arrives on the wire and an adversary may put anything in
    it; the identity names no measurement basis, so an element declared `I`
    is one the recipient can never find conclusive. Raising here would turn
    an M3 attack into an M2 exception and move detection into the wrong
    track -- see the note at the top of verifier.py.
    """
    return _PAULI_TO_BASIS.get(op)


def pauli_of(basis: Basis) -> PauliOp:
    """The Pauli whose eigenstates live in `basis`. Total on Basis."""
    try:
        return _BASIS_TO_PAULI[basis]
    except KeyError:  # pragma: no cover -- unreachable while Basis has 3 members
        raise ValueError(f"no Pauli for basis {basis!r}") from None
