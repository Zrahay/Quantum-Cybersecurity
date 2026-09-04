"""Partial-knowledge forgery adversary. Track M3 (Nikita). Phase 4.

Eve has *partial* knowledge of the signing key — she knows the correct
Pauli corrections for some message bits but not others.  This produces
a match rate that scales linearly with ``key_knowledge``, giving M4 a
clean graded-detection curve to show off.

At ``key_knowledge=0.0`` this is equivalent to ``ForgeryAdversary``.
At ``key_knowledge=1.0`` Eve has the full key — she produces a
legitimate signature (ops match outcomes perfectly).  Intermediate
values are the interesting ones: detection degrades gracefully rather
than falling off a cliff.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from qiskit_aer import AerSimulator

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType
from core.teleportation import teleportation_circuit


class PartialKeyForgeryAdversary(BaseAdversary):
    """Forge a signature with partial key knowledge.

    ``key_knowledge`` (0.0–1.0) controls the fraction of message bits
    for which Eve knows the correct Pauli correction.  The remaining
    bits get random ops.

    Bell outcomes are produced by running the real teleportation circuit
    (Eve has the message).  The detection signal is the mismatch
    between ops (partially known, partially random) and outcomes
    (physically real).

    Expected match rate per bit:
        key_knowledge * 1.0 + (1 - key_knowledge) * 0.25
    because known bits match perfectly and random bits match with
    probability 1/4 (four Pauli operators).
    """

    threat = ThreatType.FORGERY

    def __init__(
        self,
        *,
        key_knowledge: float = 0.5,
        strength: float = 1.0,
    ) -> None:
        super().__init__(strength=strength)
        if not 0.0 <= key_knowledge <= 1.0:
            raise ValueError(f"key_knowledge must be in [0, 1]; got {key_knowledge}")
        self.key_knowledge = key_knowledge

    def _run_teleport(self, message_bit: int) -> tuple[int, int]:
        """Run one teleportation shot and return (clbit0, clbit1)."""
        qc = teleportation_circuit(noise_level=0.0)
        if message_bit:
            qc.x(0)
        qc.measure(2, 2)
        result = AerSimulator().run(qc, shots=1, memory=True).result()
        bits = result.get_memory()[0]
        return (int(bits[-1]), int(bits[-2]))

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.message)
        n_known = round(n * self.key_knowledge)

        # Bell outcomes from real teleportation
        forged_outcomes = tuple(
            self._run_teleport(int(m)) for m in sig.message
        )

        # Which bits Eve knows: she gets the real ops for those.
        known_indices = set(random.sample(range(n), n_known))

        forged_ops = tuple(
            sig.declared_ops[i] if i in known_indices
            else random.choice(list(PauliOp))
            for i in range(n)
        )

        return Signature(
            sig_id=f"partial-forged-{uuid.uuid4().hex[:8]}",
            key_id=sig.key_id,
            signer_id=sig.signer_id,
            message=sig.message,
            declared_ops=forged_ops,
            bell_outcomes=forged_outcomes,
            nonce=uuid.uuid4().hex,
            timestamp=sig.timestamp,
        )
