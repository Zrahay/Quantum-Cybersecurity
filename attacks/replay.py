"""replay adversary. Track M3 (Nikita). Deliverable D4.

Resubmits a previously-used valid signature with the same nonce.
The defence is nonce + timestamp freshness at the protocol layer.
No-cloning means the quantum state cannot be copied, so replay is
necessarily a reused CLASSICAL transcript.

No AI/ML is used.
"""

from __future__ import annotations

from attacks.base import BaseAdversary
from contracts import Signature, ThreatType


class ReplayAdversary(BaseAdversary):
    """Return the exact same signature — nonce reuse is the detection signal.

    The attack is deliberately trivial: the entire point is that replay
    detection is NOT quantum.  No-cloning forces the defence to be
    nonce + freshness at the protocol layer, and the judge should hear
    that stated explicitly.
    """

    threat = ThreatType.REPLAY

    def __init__(
        self,
        *,
        seen_nonces: set[str] | None = None,
        strength: float = 1.0,
    ) -> None:
        super().__init__(strength=strength)
        self._seen_nonces: set[str] = seen_nonces if seen_nonces is not None else set()

    @property
    def seen_nonces(self) -> set[str]:
        """Nonces this adversary has already replayed (read-only view)."""
        return frozenset(self._seen_nonces)

    def attack(self, sig: Signature) -> Signature:
        """Return *sig* unchanged — the nonce is the same as the original.

        M4's ``evaluate`` checks ``nonce in seen_nonces`` and rejects.
        The caller must add the nonce to ``seen_nonces`` AFTER evaluation,
        not before (see the caller protocol in ``detection.detector``).
        """
        self._seen_nonces.add(sig.nonce)
        return sig
