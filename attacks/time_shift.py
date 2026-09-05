"""Time-shift attack adversary. Track M3 (Nikita). Deliverable D4.

Source: Qi, Fung, Lo & Ma, "Time-shift attack in practical quantum
cryptosystems", Quantum Inf. Comput. 7, 73 (2007).

Also: Zhao, Qi & Lo, "Practical quantum key distribution with
coherent states", Phys. Rev. A 78, 052325 (2008) — detector timing
mismatch exploitation.

Eve exploits detector timing/efficiency mismatch by shifting photon
arrival time, biasing which outcome gets recorded without touching
the quantum state itself.

Model: Eve perturbs the ``timestamp`` field and introduces a
systematic bias in the ``bell_outcomes`` distribution.  The
timestamp shift models the timing attack (Eve delays or advances
photons to exploit detector dead time or afterpulsing), and the
biased bell_outcomes model the resulting detector efficiency mismatch.

``strength`` controls the magnitude of the time shift (0.0 = no
shift, 1.0 = maximum shift).  The bell_outcomes bias scales with
strength: at full strength, one outcome combination (e.g., (0,0))
becomes significantly more probable than the others.

Detection signals:
- Timestamp outside normal range (classical check).
- Bell_outcomes distribution is biased (chi-square detects
  non-uniformity across the four possible outcomes).
- This is caught by the SAME chi-square test that catches
  faked-state attacks, but the mechanism is different: faked-state
  correlates outcomes with ops, time-shift biases outcomes globally.

Why this matters:
Your Signature already has a ``timestamp`` field sitting unused for
attack purposes — this is a direct, clean use of it.  Time-shift
attacks are a real vulnerability in practical QKD systems where
detectors have timing-dependent efficiency.

No AI/ML is used.
"""

from __future__ import annotations

import random
import uuid

from attacks.base import BaseAdversary
from contracts import Signature, ThreatType


# Maximum time shift in seconds (model parameter).
_MAX_TIME_SHIFT = 10.0


class TimeShiftAdversary(BaseAdversary):
    """Time-shift attack: bias bell_outcomes via detector timing exploit.

    The returned ``Signature`` has:
    - ``timestamp`` shifted by ``strength * _MAX_TIME_SHIFT`` seconds
      (forward or backward randomly).
    - ``bell_outcomes`` with a systematic bias: one outcome
      combination is ``strength``-times more likely than the others.
    - Original ``declared_ops`` (Eve doesn't need to change them —
      the timing exploit affects detection, not the declaration).

    Detection signals:
    - Timestamp anomaly: the shifted timestamp may fall outside the
      freshness window, triggering a freshness check failure.
    - Biased bell_outcomes: chi-square goodness-of-fit detects that
      the four outcome combinations are not equally likely.  A
      legitimate signer's bell_outcomes come from Bell pair symmetry,
      which produces all four combinations with equal probability.
    - The bias pattern is characteristic: one outcome dominates,
      unlike channel tampering (which flips outcomes randomly) or
      forgery (which has no correlation between ops and outcomes).

    Why this matters:
    Time-shift attacks exploit a PHYSICAL property of single-photon
    detectors — their efficiency varies with arrival time.  By
    shifting when photons arrive, Eve can bias which detector clicks
    without introducing errors.  This is a real vulnerability in
    deployed QKD systems, and modelling it here demonstrates that
    our detection framework catches timing-based attacks, not just
    error-rate-based ones.
    """

    threat = ThreatType.FORGERY

    def attack(self, sig: Signature) -> Signature:
        n = len(sig.bell_outcomes)

        # Timestamp shift: Eve delays or advances the signature.
        shift = self.strength * _MAX_TIME_SHIFT
        if random.random() < 0.5:
            shift = -shift
        shifted_timestamp = sig.timestamp + shift

        # Bell outcomes bias: one combination becomes dominant.
        # The "favored" outcome is chosen randomly per attack.
        favored = random.choice([(0, 0), (0, 1), (1, 0), (1, 1)])
        biased_outcomes: list[tuple[int, int]] = []
        for _ in range(n):
            if random.random() < self.strength:
                # Eve's timing exploit forces this outcome.
                biased_outcomes.append(favored)
            else:
                # Random outcome (untouched by timing exploit).
                biased_outcomes.append((random.randint(0, 1), random.randint(0, 1)))

        return Signature(
            sig_id=sig.sig_id,
            key_id=sig.key_id,
            signer_id=sig.signer_id,
            message=sig.message,
            declared_ops=sig.declared_ops,
            bell_outcomes=tuple(biased_outcomes),
            nonce=uuid.uuid4().hex,
            timestamp=shifted_timestamp,
        )
