"""Man-in-the-Middle on classical announcement channel. Track M3 (Nikita).
Deliverable D4.

Source: Yin, Fu & Chen, "Quantum digital signatures based on
quantum-key-distribution", Phys. Rev. A 91, 042332 (2015) —
Section I: "QDS protocols assume an authenticated classical channel."
Also: Wallden, Dunjko, Kent & Andersson, Phys. Rev. A 91, 042304
(2015) — Section II: "the classical channel must be authenticated."

Eve intercepts and modifies the signer's ``declared_ops`` announcement
in transit, rather than fabricating a whole new signature from scratch.

This is DISTINCT from ForgeryAdversary:
- Forgery: Eve has NO key material, fabricates everything from zero.
- MitM: Eve has a REAL intercepted signature from Alice, but modifies
  the classical announcement (declared_ops) in transit before it
  reaches the verifier.

The distinction matters because:
1. Eve starts with a LEGITIMATE signature (real bell_outcomes,
   real message, real key_id).
2. She selectively modifies declared_ops to shift the verification
   outcome in her favour.
3. The bell_outcomes are still from real teleportation — they are
   CORRECT for Alice's original ops, not for Eve's modified ops.

``strength`` controls the fraction of declared_ops Eve modifies
(0.0 = no modification, 1.0 = full replacement).

Detection signals:
- Mismatch rate: elevated because Eve's modified ops don't match
  the real bell_outcomes (which were produced for Alice's original
  ops, not Eve's modifications).
- The pattern is different from forgery: bell_outcomes are still
  from real teleportation (physically plausible), but declared_ops
  are partially corrupted.  This creates a mismatch rate BETWEEN
  0.0 and 0.25 (partial modification), vs forgery's ~0.25 (full
  randomisation).
- Key_id and signer_id remain unchanged (Eve is modifying a real
  signature, not fabricating one) — this distinguishes MitM from
  Impersonation in the batch statistics (utils.py).

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType


class MitmClassicalAdversary(BaseAdversary):
    """Man-in-the-Middle: intercept a real signature, modify declared_ops.

    The returned ``Signature`` has:
    - ``key_id`` and ``signer_id`` UNCHANGED (Eve is tampering with a
      real signature, not fabricating one).
    - ``declared_ops`` partially replaced with random ops (Eve's
      modifications).
    - ``bell_outcomes`` UNCHANGED from the original (still from real
      teleportation — Eve doesn't have quantum resources to re-teleport).
    - Fresh ``nonce`` (Eve resubmits with a new nonce).

    Detection signals:
    - Elevated mismatch rate: Eve's modified ops don't match the
      real bell_outcomes.
    - Bell_outcomes are still "physically real" (from teleportation),
      unlike forgery where they're random — this is visible in
      utils.py's ``outcomes_match_rate`` (MitM: 1.0, Forgery: ~0.0).
    - Key_id unchanged — distinguishable from Impersonation in batch
      statistics.

    Why this is distinct from forgery:
    Forgery is "Eve has nothing and builds from scratch."
    MitM is "Eve has a real intercepted signature and tampers with
    the classical part in transit."  The starting point (real vs.
    fabricated) and the modification pattern (partial vs. full) are
    different, producing distinguishable statistics.
    """

    threat = ThreatType.FORGERY

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.declared_ops)
        n_modified = max(0, round(n * self.strength))

        # Which ops Eve modifies: she picks positions to corrupt.
        modified_indices = set(random.sample(range(n), n_modified))

        # Ops: original on unmodified positions, random on modified ones.
        modified_ops = tuple(
            random.choice(list(PauliOp)) if i in modified_indices else op
            for i, op in enumerate(sig.declared_ops)
        )

        # Bell outcomes: UNCHANGED from the original.
        # Eve doesn't have quantum resources to re-teleport.
        # This is the key distinguishing feature from forgery:
        # the bell_outcomes are still from real teleportation.
        # The mismatch comes from the ops being partially wrong,
        # not from the outcomes being fabricated.

        return Signature(
            sig_id=f"mitm-{uuid.uuid4().hex[:8]}",
            key_id=sig.key_id,          # UNCHANGED — real signature
            signer_id=sig.signer_id,    # UNCHANGED — real signature
            message=sig.message,
            declared_ops=modified_ops,
            bell_outcomes=sig.bell_outcomes,  # UNCHANGED — real teleportation
            nonce=uuid.uuid4().hex,
            timestamp=sig.timestamp,
        )
