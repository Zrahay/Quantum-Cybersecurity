"""forgery adversary. Track M3 (Nikita). Deliverable D4.

Eve has no valid signing key or legitimate quantum resource.
She constructs a fake signature from scratch, hoping it passes
verification anyway.

``strength`` controls the fraction of message bits Eve randomises
(0.0 = no forgery, 1.0 = full forgery).  Intermediate values
produce graded detection curves for Phase 4 benchmarks.

Bell outcomes are produced by running Ashab's teleportation circuit
(core.teleportation) — Eve has the message but not the key, so her
declared_ops are random while her bell_outcomes are physically
real.  The mismatch between ops and outcomes is what M4 catches.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from qiskit_aer import AerSimulator

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType
from core.teleportation import teleportation_circuit


class ForgeryAdversary(BaseAdversary):
    """Fabricate a signature with random ops and real bell outcomes.

    Bell outcomes are produced by running the teleportation circuit
    with Eve's message qubit — physically realistic, since Eve can
    prepare the message state.  declared_ops are random because Eve
    has no key material, so the ops-outcomes correlation that a
    legitimate signer relies on is absent.
    """

    threat = ThreatType.FORGERY

    def _run_teleport(self, message_bit: int, noise: float) -> tuple[int, int]:
        """Run one teleportation shot and return (clbit0, clbit1).

        `get_memory()` returns Qiskit's little-endian count-string order --
        the LAST character is clbit0, not the first. Reading `bits[0]`
        would silently grab clbit2 (Bob's measured qubit) paired with
        clbit1, not the frozen (clbit0, clbit1) Bell-outcome convention.
        See contracts.Signature.bell_outcomes.
        """
        qc = teleportation_circuit(noise_level=noise)
        if message_bit:
            qc.x(0)
        qc.measure(2, 2)
        result = AerSimulator().run(qc, shots=1, memory=True).result()
        bits = result.get_memory()[0]
        return (int(bits[-1]), int(bits[-2]))

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.message)
        n_forged = max(1, round(n * self.strength))

        # Bell outcomes from real teleportation — Eve runs the circuit
        # with her copy of the message.  noise=0.0 because Eve has a
        # perfect quantum channel to herself; the tampering adversary
        # is the one that raises noise.
        forged_outcomes = tuple(
            self._run_teleport(int(m), noise=0.0) for m in sig.message
        )

        # Which message bits to forge: pick n_forged indices at random.
        forged_indices = set(random.sample(range(n), n_forged))

        # Ops: keep the original on non-forged bits, random on forged bits.
        forged_ops = tuple(
            random.choice(list(PauliOp)) if i in forged_indices else op
            for i, op in enumerate(sig.declared_ops)
        )

        return Signature(
            sig_id=f"forged-{uuid.uuid4().hex[:8]}",
            key_id=sig.key_id,
            signer_id=sig.signer_id,
            message=sig.message,
            declared_ops=forged_ops,
            bell_outcomes=forged_outcomes,
            nonce=uuid.uuid4().hex,
            timestamp=sig.timestamp,
        )
