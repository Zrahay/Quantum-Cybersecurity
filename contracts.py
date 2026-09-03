"""Frozen shared types for SIH26141.

Every track codes against this file. Changing it costs five other people
their afternoon, so changes go through the Decision Log in Notion first.

Two seams matter:
  MeasurementRecord  -- the only type crossing quantum -> statistics
  DetectionResult    -- the only type crossing statistics -> UI

Keep those clean and integration is painless.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class Basis(Enum):
    """Measurement basis. Y is here for completeness; drop it if the
    protocol never measures in it (M2's call)."""

    Z = "Z"  # computational
    X = "X"
    Y = "Y"


class PauliOp(Enum):
    I = "I"
    X = "X"
    Y = "Y"
    Z = "Z"


class ThreatType(Enum):
    NONE = "none"
    FORGERY = "forgery"
    IMPERSONATION = "impersonation"
    REPLAY = "replay"
    CHANNEL_TAMPER = "channel_tamper"


class Verdict(Enum):
    ACCEPT = "accept"                          # r < s_a
    ACCEPT_NO_TRANSFER = "accept_no_transfer"  # s_a <= r < s_v
    REJECT = "reject"                          # r >= s_v


@dataclass(frozen=True)
class KeyPair:
    """Output of quantum public key distribution. M2 owns this."""

    key_id: str
    signer_id: str
    private_bits: tuple[int, ...]   # classical seed the signer keeps
    pauli_map: tuple[PauliOp, ...]  # message bit -> required correction
    n_copies: int                   # L, copies given to each verifier


@dataclass(frozen=True)
class Signature:
    """What travels signer -> verifier. M3's attacks produce mutated versions."""

    sig_id: str
    key_id: str
    signer_id: str
    message: tuple[int, ...]
    declared_ops: tuple[PauliOp, ...]           # correction the signer claims
    bell_outcomes: tuple[tuple[int, int], ...]  # teleportation measurement bits
    nonce: str                                  # freshness, replay defence
    timestamp: float


@dataclass(frozen=True)
class MeasurementRecord:
    """One projective measurement. The atom of everything M4 does."""

    sig_id: str
    copy_index: int  # 0 .. L-1
    basis: Basis
    expected: int    # eigenvalue the protocol predicts: 0 or 1
    observed: int    # what was actually measured

    @property
    def mismatch(self) -> bool:
        return self.expected != self.observed


@dataclass(frozen=True)
class DetectionResult:
    """M4's output. M5 renders exactly this and recomputes nothing."""

    sig_id: str
    verdict: Verdict
    threat: ThreatType
    mismatch_rate: float        # 0.0 - 1.0, never a percentage
    n_measurements: int
    forgery_prob_bound: float   # Hoeffding bound at this L
    chi2_stat: float
    chi2_p_value: float
    reason: str                 # human-readable, shown on the dashboard
    timestamp: float


class Adversary(Protocol):
    """M3 owns. Four implementations, dispatched by dashboard buttons.

    Attacks go through the public API of the module they attack -- an
    adversary that reaches into internals proves nothing. Adversaries keep
    their own state; there is no shared context bag.
    """

    name: str
    threat: ThreatType

    def attack(self, sig: Signature) -> Signature: ...


# Deliberately NOT interfaces -- each has exactly one implementation:
#   detection.detector.evaluate(records, sig, seen_nonces) is a plain function.
#   The channel is a noise parameter on core/, not a class. M3 turns the dial up.
