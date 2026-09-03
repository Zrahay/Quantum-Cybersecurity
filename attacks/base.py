"""Shared adversary scaffolding. Track M3 (Nikita). Deliverable D4.

Attacks go through M2's public API only. An adversary that reaches into
internals proves nothing.
"""

from __future__ import annotations

from contracts import Signature, ThreatType


class BaseAdversary:
    """Subclasses set `threat` and override `attack`."""

    threat: ThreatType

    def __init__(self, strength: float = 1.0) -> None:
        # Parameterised, not hardcoded -- strength as a dial is what
        # produces the graded detection curves in Phase 4.
        self.strength = strength

    @property
    def name(self) -> str:
        # Derived from `threat` so the two can never drift apart and show
        # a wrong label on the dashboard.
        return self.threat.value

    def attack(self, sig: Signature) -> Signature:
        raise NotImplementedError
