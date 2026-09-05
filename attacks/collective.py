"""Collective / Coherent attack adversary. Track M3 (Nikita). Deliverable D4.

Source: Yin, Fu & Chen, "Quantum digital signatures based on
quantum-key-distribution", Phys. Rev. A 91, 042332 (2015) —
arXiv:1502.03045, Section II.A, collective forgery attack bound.

Also: Gottesman & Chuang, "Quantum digital signatures",
arXiv:0105104 (2001).

Instead of a single per-element measurement, Eve applies a JOINT
operation across all L copies to extract maximum information before
guessing. The information-theoretic bound says Eve's information per
element is bounded by the Holevo quantity χ ≤ S(ρ) - Σ p_i S(ρ_i).

``strength`` (0.0-1.0) is Eve's information advantage: the fraction of
elements she can predict correctly from the joint measurement, keeping
those and guessing the rest. At 0.0 this is exactly ForgeryAdversary
(zero information, mismatch rate ~0.20-0.28 empirically -- see
`detection/detector.py`'s `_reject_reason_and_threat` docstring for
where that figure comes from). At 1.0 she reproduces the signature
exactly (mismatch rate 0.0). Note this is the record-level mismatch
rate `evaluate()` measures after `verify()`'s basis-agreement
filtering, not a raw ops-comparison stat -- the two are different
quantities and the latter is roughly 3x the former in this codebase.

HONEST NOTE ON WHAT THIS SIMULATION CAN AND CANNOT DISTINGUISH: the
distinguishing feature from PNS in the literature is *how* Eve gets her
partial information (a joint measurement across L copies vs. splitting
photons one at a time) and *which* elements she ends up knowing (global
key correlations here vs. specific intercepted copies for PNS) — not a
different statistical footprint. This adversary and PNSAdversary both
model "know a `strength`-fraction of elements exactly, guess the rest",
because that is what `evaluate()` can actually see: a mismatch rate,
compared against s_a/s_v (see `detection/detector.py`). Neither
`verify()` nor `evaluate()` inspects *which* positions mismatch or the
shape of the bell_outcomes distribution, so a claim that chi-square
tells Collective and PNS apart here would be false — both attacks are
reported identically, as FORGERY, on mismatch rate alone. The physical
distinction between the two attack mechanisms belongs in the D1 writeup
as a conceptual point, not as a live discriminator in this codebase.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType


class CollectiveAttackAdversary(BaseAdversary):
    """Collective attack: Eve applies a joint measurement across L copies
    to extract information, then forges with that knowledge.

    ``strength`` (0.0-1.0) controls Eve's information advantage:
    - 0.0: zero information -> equivalent to ForgeryAdversary
      (mismatch rate ~0.20-0.28, this codebase's measured blind-forgery
      rate -- see module docstring)
    - 1.0: full information -> mismatch rate 0.0 (legitimate signature)
    - intermediate: mismatch rate scales roughly with (1 - strength),
      scaled to the ~0.25 baseline above rather than a clean formula --
      she matches perfectly on the fraction she knows and inherits the
      blind-forgery rate on the rest.

    Detection signal: mismatch rate compared against s_a/s_v, same
    mechanism as every other adversary here -- see this module's
    docstring for why a claim of a distinguishing chi-square signature
    against PNS would be false in this codebase.
    """

    threat = ThreatType.FORGERY

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.declared_ops)

        # Eve's information determines how many ops she can predict.
        n_known = round(n * self.strength)
        known_indices = set(random.sample(range(n), n_known))

        forged_ops = tuple(
            sig.declared_ops[i] if i in known_indices
            else random.choice(list(PauliOp))
            for i in range(n)
        )

        # Bell outcomes: Eve guesses randomly (she doesn't have the
        # real quantum states — she only extracted classical info).
        # Note: `verify()` never reads `bell_outcomes` back off the
        # signature (it re-measures independently), so this field has
        # no effect on the detection outcome. Kept for structural
        # completeness of the Signature.
        forged_outcomes = tuple(
            (random.randint(0, 1), random.randint(0, 1))
            for _ in range(n)
        )

        return Signature(
            sig_id=f"collective-{uuid.uuid4().hex[:8]}",
            key_id=sig.key_id,
            signer_id=sig.signer_id,
            message=sig.message,
            declared_ops=forged_ops,
            bell_outcomes=forged_outcomes,
            nonce=uuid.uuid4().hex,
            timestamp=sig.timestamp,
        )
