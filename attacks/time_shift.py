"""Time-shift attack adversary. Track M3 (Nikita). Deliverable D4.

Source: Qi, Fung, Lo & Ma, "Time-shift attack in practical quantum
cryptosystems", Quantum Inf. Comput. 7, 73 (2007).

Also: Zhao, Qi & Lo, "Practical quantum key distribution with
coherent states", Phys. Rev. A 78, 052325 (2008) — detector timing
mismatch exploitation.

Eve exploits detector timing/efficiency mismatch by shifting photon
arrival time, biasing which outcome the verifier's detector registers
without touching the quantum state Alice sent.

HONEST NOTE ON WHAT THIS SIMULATION CAN AND CANNOT SHOW: real
detector-timing exploitation would need a timing model inside
`core.teleport_and_measure`, which this simulation does not have.
`protocol/verifier.py::verify()` never reads `sig.bell_outcomes` or
`sig.timestamp` back off the signature at all — only `declared_ops` is
checked. So the earlier version of this adversary (which left
`declared_ops` untouched and only perturbed the unread fields) was
undetectable by construction, but not for the reason the physics
suggests — it would have been undetectable *because it never actually
attacked anything checkable*, which is a different claim than "defeats
timing-based detection".

What is modelled here instead: an efficiency mismatch that causes the
verifier's detector to occasionally misattribute the basis it measured
in, which surfaces as a `strength`-proportional fraction of `declared_ops`
disagreeing with what a legitimate signer would have declared for those
elements. That IS visible to `verify()`/`evaluate()`, through the same
mismatch-rate-vs-threshold mechanism as every other adversary here — not
via `bell_outcomes` bias or a timestamp check (`evaluate()` does not
inspect timestamp freshness; that would be a `detection/detector.py`
change, out of scope for this file).

``strength`` controls the fraction of elements affected (0.0 = no
effect, 1.0 = fully corrupted).

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import PauliOp, Signature, ThreatType

# Maximum time shift in seconds (model parameter, carried on the
# signature for a future timestamp-freshness check — not currently
# consumed by `evaluate()`).
_MAX_TIME_SHIFT = 10.0


class TimeShiftAdversary(BaseAdversary):
    """Time-shift attack: detector efficiency mismatch corrupts a fraction
    of the declared bases the verifier ends up comparing against.

    The returned ``Signature`` has:
    - ``timestamp`` shifted by ``strength * _MAX_TIME_SHIFT`` seconds
      (forward or backward randomly) — carried for a possible future
      freshness check, not consumed by the current detection path.
    - ``declared_ops`` with a ``strength``-fraction of elements replaced
      by a random Pauli op, modelling the elements where the timing
      exploit caused a basis misattribution.

    Detection signal: mismatch rate vs. s_a/s_v, same mechanism as
    every other adversary here — see the module docstring for why a
    claim of detection via `bell_outcomes` bias or timestamp checking
    would be false in this codebase.
    """

    threat = ThreatType.FORGERY

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.declared_ops)

        shift = self.strength * _MAX_TIME_SHIFT
        if random.random() < 0.5:
            shift = -shift
        shifted_timestamp = sig.timestamp + shift

        n_corrupted = max(0, round(n * self.strength))
        corrupted_indices = set(random.sample(range(n), n_corrupted))
        forged_ops = tuple(
            random.choice(list(PauliOp)) if i in corrupted_indices else op
            for i, op in enumerate(sig.declared_ops)
        )

        return Signature(
            sig_id=f"timeshift-{uuid.uuid4().hex[:8]}",
            key_id=sig.key_id,
            signer_id=sig.signer_id,
            message=sig.message,
            declared_ops=forged_ops,
            bell_outcomes=sig.bell_outcomes,
            nonce=uuid.uuid4().hex,
            timestamp=shifted_timestamp,
        )
