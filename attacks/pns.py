"""Photon-Number-Splitting (PNS) adversary. Track M3 (Nikita). Deliverable D4.

Source: Brassard, Lütkenhaus, Mor & Sanders, "Limitations on Practical
Quantum Cryptography", Phys. Rev. Lett. 85, 1330 (2000).

When the signal source occasionally emits multiple photons per pulse,
Eve splits off the extra copy, keeps it, and forwards the rest
untouched — gaining partial key information with zero disturbance.

Model: Eve intercepts ``k`` out of ``L`` copies of bell_outcomes
cleanly (no error introduced on those), and has to guess the remaining
``L - k`` copies.  This directly demonstrates why the L-copy design
matters — the security argument says forgery probability decays
exponentially in L because Eve can only hold onto a fraction of the
copies.

``strength`` controls the fraction of copies Eve successfully splits
(0.0 = no PNS, 1.0 = Eve intercepts all copies).  At full strength
Eve has perfect information on every element — she can reproduce the
signature exactly, so mismatch rate → 0.  At partial strength the
mismatch rate scales as ``(1 - strength) * 0.75`` because the
un-intercepted copies are guessed randomly (25% match by chance).

Detection signal: zero disturbance on intercepted copies means the
mismatch rate is LOWER than a blind forgery, not higher.  This attack
is caught by the SAME threshold that catches forgery, but at a lower
mismatch rate — which is exactly the point: PNS is the attack that
motivates making L large enough that even partial interception
leaves detectable evidence.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType


class PNSAdversary(BaseAdversary):
    """Photon-Number-Splitting attack: intercept k/L copies cleanly,
    guess the rest.

    The returned ``Signature`` has:
    - ``declared_ops`` that match the original on intercepted copies
      (Eve learned them) and are random on the rest.
    - ``bell_outcomes`` copied verbatim from the original (Eve forwards
      them untouched — zero disturbance on the copies she keeps).
    - Fresh ``nonce`` and ``sig_id`` (Eve resubmits, not replay).

    Detection signals:
    - Mismatch rate is ``(1 - strength) * 0.75`` — lower than blind
      forgery's ~0.25 because intercepted copies match perfectly.
    - The chi-square goodness-of-fit test detects that the mismatch
      distribution is non-uniform: intercepted positions always match,
      non-intercepted always mismatch.

    Why this matters for the security argument:
    PNS is the attack that forces the L-copy design.  If L is small,
    Eve intercepts a large fraction and the remaining mismatches fall
    below s_a.  As L grows, the fraction Eve can intercept per pulse
    shrinks (multi-photon pulses are rare in weak coherent sources),
    and the exponential bound kicks in.  This adversary demonstrates
    that relationship directly.
    """

    threat = ThreatType.FORGERY

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.declared_ops)
        n_intercepted = max(0, round(n * self.strength))

        # Which copies Eve intercepted: she knows the real ops for these.
        intercepted_indices = set(random.sample(range(n), n_intercepted))

        # Ops: real on intercepted copies, random on the rest.
        forged_ops = tuple(
            sig.declared_ops[i] if i in intercepted_indices
            else random.choice(list(PauliOp))
            for i in range(n)
        )

        # Bell outcomes: copied verbatim from the original.
        # Eve forwards them untouched — zero disturbance on intercepted copies.
        # This is what makes PNS fundamentally different from blind forgery:
        # the bell_outcomes are CORRECT for the intercepted elements.
        forged_outcomes = sig.bell_outcomes

        return Signature(
            sig_id=f"pns-{uuid.uuid4().hex[:8]}",
            key_id=sig.key_id,
            signer_id=sig.signer_id,
            message=sig.message,
            declared_ops=forged_ops,
            bell_outcomes=forged_outcomes,
            nonce=uuid.uuid4().hex,
            timestamp=sig.timestamp,
        )
