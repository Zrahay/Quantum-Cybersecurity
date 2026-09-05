"""forgery adversary. Track M3 (Nikita). Deliverable D4.

Eve has no valid signing key or legitimate quantum resource.
She constructs a fake signature from scratch, hoping it passes
verification anyway.

``strength`` controls the fraction of SIGNATURE ELEMENTS Eve randomises
(0.0 = no forgery, 1.0 = full forgery).  Intermediate values produce
graded detection curves for Phase 4 benchmarks. Sized off
``len(sig.declared_ops)`` -- the real element count a signature carries,
``message_length * L`` -- not ``len(sig.message)``: a real signature's
message is short (e.g. 3 bits) while its element count is in the
hundreds, and sizing off the message length would leave the vast
majority of elements untouched by "full forgery". See the M2 review
that caught this: ImpersonationAdversary had the same bug.

Bell outcomes are produced by running Ashab's teleportation circuit
(core.teleportation) — Eve has no key material, so she teleports a
fixed |0> per element (the same simplification M2's sign() uses, since
neither party has anything more meaningful to prepare without the real
per-element eigenstate). Her declared_ops are random, so the
ops-outcomes correlation that a legitimate signer relies on is absent.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType
from core.runtime import run_circuit
from core.teleportation import teleportation_circuit


class ForgeryAdversary(BaseAdversary):
    """Fabricate a signature with random ops and real bell outcomes.

    Bell outcomes are produced by running the teleportation circuit --
    physically realistic in that they come from a real teleportation, not
    invented tuples.  declared_ops are random because Eve has no key
    material, so the ops-outcomes correlation that a legitimate signer
    relies on is absent.
    """

    threat = ThreatType.FORGERY

    def _run_teleport(self, noise: float) -> tuple[int, int]:
        """Run one teleportation shot of |0> and return (clbit0, clbit1).

        `get_memory()` returns Qiskit's little-endian count-string order --
        the LAST character is clbit0, not the first. Reading `bits[0]`
        would silently grab clbit2 (Bob's measured qubit) paired with
        clbit1, not the frozen (clbit0, clbit1) Bell-outcome convention.
        See contracts.Signature.bell_outcomes.
        """
        def _build():
            qc = teleportation_circuit(noise_level=noise)
            qc.measure(2, 2)
            return qc
        bits = run_circuit(_build)
        return (int(bits[-1]), int(bits[-2]))

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.declared_ops)
        n_forged = max(1, round(n * self.strength))

        # Bell outcomes from real teleportation — Eve runs the circuit
        # once per element.  noise=0.0 because Eve has a perfect quantum
        # channel to herself; the tampering adversary is the one that
        # raises noise.
        forged_outcomes = tuple(self._run_teleport(noise=0.0) for _ in range(n))

        # Which elements to forge: pick n_forged indices at random.
        forged_indices = set(random.sample(range(n), n_forged))

        # Ops: keep the original on non-forged elements, random on forged ones.
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
