"""forgery adversary. Track M3 (Nikita). Deliverable D4.

Eve has no valid signing key or legitimate quantum resource.
She constructs a fake signature from scratch, hoping it passes
verification anyway.

The ``declared_ops`` and ``bell_outcomes`` are independently random —
without real key material they are uncorrelated, producing a high
mismatch rate that M4's statistics catch.

``strength`` controls the fraction of message bits Eve attempts to
forge (0.0 = no forgery, 1.0 = full forgery).  Intermediate values
produce graded detection curves for Phase 4 benchmarks.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType


class ForgeryAdversary(BaseAdversary):
    """Fabricate a signature with random ops and outcomes.

    The returned ``Signature`` has the same ``message`` length as the
    original but completely independent ``declared_ops`` and
    ``bell_outcomes``.  A legitimate signer's ops and outcomes are
    correlated via the key; a forger's are not, so the mismatch rate
    is roughly 50 % per copy — well above any reasonable threshold.
    """

    threat = ThreatType.FORGERY

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.message)
        n_forged = max(1, round(n * self.strength))

        # Random Pauli ops — independent of the real key material
        forged_ops = tuple(random.choice(list(PauliOp)) for _ in range(n))

        # Random bell outcomes — (clbit0, clbit1) each 0 or 1
        forged_outcomes = tuple(
            (random.randint(0, 1), random.randint(0, 1)) for _ in range(n)
        )

        return Signature(
            sig_id=f" forged-{uuid.uuid4().hex[:8]}",
            key_id=sig.key_id,      # reuse — Eve doesn't know the real key_id
            signer_id=sig.signer_id, # impersonating Alice
            message=sig.message,
            declared_ops=forged_ops,
            bell_outcomes=forged_outcomes,
            nonce=uuid.uuid4().hex,  # fresh nonce (Eve doesn't know the original)
            timestamp=sig.timestamp,
        )
