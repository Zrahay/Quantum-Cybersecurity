"""channel_tamper adversary. Track M3 (Nikita). Deliverable D4.

STUB -- returns the signature unchanged. The detector fails closed, so an
unimplemented attack shows as REJECT/stub on the dashboard rather than as
a silently successful one.
"""

from __future__ import annotations

from attacks.base import BaseAdversary
from contracts import Signature, ThreatType


class ChannelTamperAdversary(BaseAdversary):
    threat = ThreatType.CHANNEL_TAMPER

    def attack(self, sig: Signature) -> Signature:
        # TODO(M3): real attack.
        return sig
