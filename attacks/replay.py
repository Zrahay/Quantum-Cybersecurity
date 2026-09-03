"""replay adversary. Track M3 (Nikita). Deliverable D4.

Attacks go through M2's public API only. An adversary that reaches into
internals proves nothing.

STUB -- importable and correctly typed. Real implementation is M3's.
"""

from __future__ import annotations

from contracts import Signature, ThreatType


class ReplayAdversary:
    name = "replay"
    threat = ThreatType.REPLAY

    def __init__(self, strength: float = 1.0) -> None:
        # Parameterised, not hardcoded -- strength as a dial is what
        # produces the graded detection curves in Phase 4.
        self.strength = strength

    def attack(self, sig: Signature) -> Signature:
        # TODO(M3): real attack.
        return sig
