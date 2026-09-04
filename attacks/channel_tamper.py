"""channel_tamper adversary. Track M3 (Nikita). Deliverable D4.

Eve intercepts a signature in transit, disturbs the quantum information,
and re-signs with a fresh nonce.

At the ``Signature`` level this is modelled as randomly flipping bits in
``bell_outcomes`` — a simplification of the real intercept-resend physics
(noise acts on Bob's qubit, not Alice's bell_outcomes), but structurally
correct: each bit flip is an independent disturbance that raises the
mismatch rate downstream.  The real channel-tampering effect will become
wirable once M2's ``verify()`` measures Bob's qubit.

``strength`` controls the fraction of outcome pairs Eve flips
(0.0 = no tampering, 1.0 = every pair flipped).  Intermediate values
produce graded detection curves.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import Signature, ThreatType


class ChannelTamperAdversary(BaseAdversary):
    """Flip bits in ``bell_outcomes`` to simulate intercept-resend.

    Each pair ``(clbit0, clbit1)`` is independently targeted with
    probability ``strength``.  A targeted pair has one of its two bits
    flipped uniformly at random — this is the minimal disturbance that
    produces a detectable mismatch while keeping the attack model
    honest (Eve cannot control which bit she disturbs; the quantum
    measurement collapses randomly).
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
