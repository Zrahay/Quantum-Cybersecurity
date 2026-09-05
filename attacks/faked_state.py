"""Faked-state / detector-control attack adversary. Track M3 (Nikita).
Deliverable D4.

Source: Lydersen, Wiechers, Wittmann, Elser, Skaar & Makarov,
"Hacking commercial quantum cryptography systems by tailored bright
illumination", Nature Photonics 4, 686 (2010).

Eve forces the verifier's detector to click on an outcome of her
choosing, bypassing the expected disturbance statistics that
intercept-resend normally produces.  This is the attack that has
actually broken commercial QKD systems in the lab.

Model: Eve fabricates a signature where the bell_outcomes are chosen
to match her declared_ops perfectly — she "fakes" the detector into
registering the outcome she wants.  On a real detector this would be
done by blinding the detector with bright light and then sending
tailored pulses; in our simulation the equivalent is that Eve's
bell_outcomes are CORRELATED with her declared_ops (not random like
in ForgeryAdversary).

``strength`` controls how many bell_outcomes Eve forces to match
her declared_ops (0.0 = no faking, 1.0 = all outcomes forced).

Why this is valuable, not just extra:
Your current ChannelTamperAdversary is detectable because it raises
the error rate.  This attack specifically DEFEATS that assumption —
Eve's bell_outcomes are chosen to be consistent with her ops, so the
mismatch rate can be near zero even though the ops are fabricated.
Detection requires looking beyond the mismatch rate at the
STATISTICAL DISTRIBUTION of outcomes (biased vs. truly random).

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType


# Mapping from PauliOp to the bell_outcome (c0, c1) that would be
# "expected" if the detector registered the corresponding measurement
# outcome.  This models Eve forcing the detector to click on the
# outcome matching her declared op.
_PAULI_TO_FORCED_OUTCOME: dict[PauliOp, tuple[int, int]] = {
    PauliOp.Z: (0, 0),   # Z-basis: |0> → (0,0), |1> → (1,1)
    PauliOp.X: (0, 1),   # X-basis: |+> → (0,1), |-> → (1,0)
    PauliOp.Y: (1, 0),   # Y-basis: |+i> → (1,0), |-i> → (0,1)
    PauliOp.I: (0, 0),   # I names no basis; default to (0,0)
}


class FakedStateAdversary(BaseAdversary):
    """Faked-state attack: Eve forces bell_outcomes to match her declared_ops.

    The returned ``Signature`` has:
    - ``declared_ops`` that are random (Eve has no key material).
    - ``bell_outcomes`` that are CORRELATED with her declared_ops
      (Eve forces the detector to register the matching outcome).
    - Fresh ``nonce`` and ``sig_id``.

    Detection signals:
    - The bell_outcomes distribution is BIASED (not uniformly random).
      A legitimate signer's bell_outcomes come from real teleportation,
      which produces (0,0) and (1,1) with equal probability and (0,1)
      and (1,0) with equal probability — bell state symmetry.
    - Eve's forced outcomes break this symmetry: each outcome is
      determined by her declared op, creating a non-uniform distribution
      that chi-square can detect.
    - The mismatch rate itself can be LOW (near 0) because Eve's
      outcomes match her ops — this defeats error-rate-only detection.

    Why this matters:
    This is the attack that has ACTUALLY broken commercial QKD systems.
    Lydersen et al. showed that threshold detectors can be blinded and
    then driven to click on demand.  Our framework catches it not
    through the mismatch rate (which looks fine) but through the
    statistical distribution of bell_outcomes (which is biased).
    """

    threat = ThreatType.FORGERY

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.declared_ops)
        n_forced = max(0, round(n * self.strength))

        # Which outcomes Eve forces: she picks positions to control.
        forced_indices = set(random.sample(range(n), n_forced))

        # Ops: random (Eve has no key material).
        forged_ops = tuple(random.choice(list(PauliOp)) for _ in range(n))

        # Bell outcomes: forced to match Eve's declared ops on controlled
        # positions, random on the rest.
        forged_outcomes: list[tuple[int, int]] = []
        for i, op in enumerate(forged_ops):
            if i in forced_indices:
                # Eve forces the detector to register the outcome
                # matching her declared op.
                forged_outcomes.append(_PAULI_TO_FORCED_OUTCOME[op])
            else:
                # Random outcome on uncontrolled positions.
                forged_outcomes.append((random.randint(0, 1), random.randint(0, 1)))

        return Signature(
            sig_id=f"faked-{uuid.uuid4().hex[:8]}",
            key_id=sig.key_id,
            signer_id=sig.signer_id,
            message=sig.message,
            declared_ops=forged_ops,
            bell_outcomes=tuple(forged_outcomes),
            nonce=uuid.uuid4().hex,
            timestamp=sig.timestamp,
        )
