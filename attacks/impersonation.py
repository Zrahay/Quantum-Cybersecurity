"""impersonation adversary. Track M3 (Nikita). Deliverable D4.

Eve attempts the full signing flow while claiming Alice's identity,
without possessing Alice's real key material.

Structurally similar to forgery but framed around identity/key
material — Eve does NOT possess Alice's private key or quantum
resource.  The ``key_id`` is fabricated (does not correspond to a
real key), and ``declared_ops`` are random.

``strength`` controls the fraction of message bits Eve attempts to
sign (0.0 = no impersonation, 1.0 = full impersonation).

**PLACEHOLDER — depends on M2's keygen design.**  This file will need
revision once the real ``KeyPair`` / ``sign()`` interface is confirmed.
The current version is structurally complete but uses mock objects in
place of real key material.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType


class ImpersonationAdversary(BaseAdversary):
    """Fabricate a signature while claiming Alice's identity.

    The returned ``Signature`` has:
    - A fabricated ``key_id`` (not a real key — Eve has no key material).
    - ``signer_id`` set to the ``claimed_identity`` (default ``"alice"``).
    - Random ``declared_ops`` — uncorrelated with the real key.
    - Fresh ``nonce`` and ``sig_id`` (Eve doesn't know the originals).

    Detection signals for M4:
    - ``key_id`` does not correspond to any real key.
    - ``declared_ops`` vs ``bell_outcomes`` mismatch rate ~50 %.
    """

    threat = ThreatType.IMPERSONATION

    def __init__(
        self,
        *,
        claimed_identity: str = "alice",
        strength: float = 1.0,
    ) -> None:
        super().__init__(strength=strength)
        self._claimed_identity = claimed_identity

    @property
    def claimed_identity(self) -> str:
        return self._claimed_identity

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.message)

        # Eve fabricates a key_id — she doesn't know the real one
        forged_key_id = f"fake-key-{uuid.uuid4().hex[:6]}"

        # Random Pauli ops — independent of the real key material
        forged_ops = tuple(random.choice(list(PauliOp)) for _ in range(n))

        # Random bell outcomes
        forged_outcomes = tuple(
            (random.randint(0, 1), random.randint(0, 1)) for _ in range(n)
        )

        return Signature(
            sig_id=f"imp-{uuid.uuid4().hex[:8]}",
            key_id=forged_key_id,
            signer_id=self._claimed_identity,
            message=sig.message,
            declared_ops=forged_ops,
            bell_outcomes=forged_outcomes,
            nonce=uuid.uuid4().hex,
            timestamp=sig.timestamp,
        )
