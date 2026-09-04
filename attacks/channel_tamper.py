"""channel_tamper adversary. Track M3 (Nikita). Deliverable D4.

Eve intercepts a signature in transit, disturbs the quantum channel, and
retransmits it.

TWO SEPARATE THINGS THIS ATTACK REPORTS, kept deliberately apart:

1. ``attack(sig)`` flips bits in ``bell_outcomes`` — a classical,
   benchmark-visible marker that something happened to the transcript in
   transit; ``attacks.utils.run_batch`` reports it via ``outcomes_changed``
   / ``outcomes_diff_count``. ON ITS OWN THIS PRODUCES NO DETECTABLE SIGNAL
   THROUGH ``verify()``: M2's real ``verify()`` re-derives the recipient's
   measurement from scratch against the KEY material on every call and
   never reads ``sig.bell_outcomes`` at all (see protocol/verifier.py), so
   mutating it here is causally disconnected from anything ``verify()``
   reports. Confirmed empirically in review before this fix landed — see
   the Decision Log.
2. ``noise_level_override()`` reports the physically real mechanism: a
   depolarising disturbance on the quantum channel, which is exactly
   ``verify()``'s ``noise_level`` parameter and independently confirmed
   monotonic in the resulting mismatch rate (0% → 0.0, 10% → ~0.04,
   30% → ~0.14, 50% → ~0.25 on the ideal-channel baseline). A caller who
   wants this attack to actually be caught must read it and pass it on:
   ``verify(sig, key, noise_level=adversary.noise_level_override())``.
   ``attack(sig)``'s return value is not enough by itself — the channel is
   not a property of the Signature object (see the note at the bottom of
   contracts.py).

``strength`` drives both: the bell_outcomes flip probability (1) and the
noise_level passed to verify() (2), so one dial raises the transcript-diff
signal and the real detection signal together
(0.0 = no tampering, 1.0 = maximum of both).

No AI/ML is used.
"""

from __future__ import annotations

import random

from attacks.base import BaseAdversary
from contracts import Signature, ThreatType


class ChannelTamperAdversary(BaseAdversary):
    """Flip bits in ``bell_outcomes`` (benchmark marker) and report a
    ``noise_level`` (the real, verify()-visible mechanism) — see the
    module docstring for why both exist and only one is evidence.
    """

    threat = ThreatType.CHANNEL_TAMPER

    def attack(self, sig: Signature) -> Signature:
        tampered_outcomes: list[tuple[int, int]] = []
        for c0, c1 in sig.bell_outcomes:
            if random.random() < self.strength:
                if random.random() < 0.5:
                    c0 = 1 - c0
                else:
                    c1 = 1 - c1
            tampered_outcomes.append((c0, c1))

        return Signature(
            sig_id=sig.sig_id,
            key_id=sig.key_id,
            signer_id=sig.signer_id,
            message=sig.message,
            declared_ops=sig.declared_ops,
            bell_outcomes=tuple(tampered_outcomes),
            nonce=uuid.uuid4().hex,
            timestamp=sig.timestamp,
        )

    def noise_level_override(self) -> float:
        """The channel noise_level a caller should verify() this signature
        at. `strength` doubles as both the bell_outcomes flip probability
        and the depolarising channel parameter -- see the module docstring.
        """
        return self.strength
