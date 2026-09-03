"""channel_tamper adversary. Track M3 (Nikita). Deliverable D4.

Eve intercepts a signature in transit and re-transmits it through a
noisy channel.  The ``strength`` parameter maps directly to Ashab's
``noise_level`` on the teleportation circuit — a depolarising channel
on Bob's qubit that produces physically correlated bit errors, not
independent random flips.

``strength`` controls the depolarising probability (0.0 = clean
channel, 1.0 = fully depolarised).  Intermediate values produce
graded detection curves.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from qiskit_aer import AerSimulator

from attacks.base import BaseAdversary
from contracts import Signature, ThreatType
from core.teleportation import teleportation_circuit


class ChannelTamperAdversary(BaseAdversary):
    """Re-run teleportation through a noisy channel to simulate intercept-resend.

    Eve re-transmits each message bit through a depolarising channel
    with probability ``strength``.  The resulting bell_outcomes are
    correlated (both bits affected by the same channel instance),
    matching real intercept-resend physics rather than independent
    random flips.
    """

    threat = ThreatType.CHANNEL_TAMPER

    def _run_tampered_teleport(self, message_bit: int) -> tuple[int, int]:
        """Run teleportation with Eve's noisy channel, return (c0, c1)."""
        qc = teleportation_circuit(noise_level=self.strength)
        if message_bit:
            qc.x(0)
        qc.measure(2, 2)
        result = AerSimulator().run(qc, shots=1, memory=True).result()
        bits = result.get_memory()[0]
        return (int(bits[0]), int(bits[1]))

    def attack(self, sig: Signature) -> Signature:
        if self.strength == 0.0:
            return Signature(
                sig_id=sig.sig_id,
                key_id=sig.key_id,
                signer_id=sig.signer_id,
                message=sig.message,
                declared_ops=sig.declared_ops,
                bell_outcomes=sig.bell_outcomes,
                nonce=sig.nonce,
                timestamp=sig.timestamp,
            )

        tampered_outcomes = tuple(
            self._run_tampered_teleport(int(m)) for m in sig.message
        )

        return Signature(
            sig_id=sig.sig_id,
            key_id=sig.key_id,
            signer_id=sig.signer_id,
            message=sig.message,
            declared_ops=sig.declared_ops,
            bell_outcomes=tampered_outcomes,
            nonce=uuid.uuid4().hex,
            timestamp=sig.timestamp,
        )
