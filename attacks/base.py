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

    def noise_level_override(self) -> float | None:
        """A channel noise_level this adversary wants `verify()` run at, or
        None to leave the caller's default untouched.

        Most adversaries tamper with the SIGNATURE and have nothing to say
        about the channel, so None is correct for them. ChannelTamperAdversary
        is the one exception: real channel tampering is a property of the
        physical channel, not of the Signature object (see the note at the
        bottom of contracts.py), so its attack has to travel out-of-band from
        `attack()`'s return value. A caller who wants that adversary's attack
        to actually be detectable must read this and pass it to
        `verify(sig, key, noise_level=adversary.noise_level_override())`.
        """
        return None
