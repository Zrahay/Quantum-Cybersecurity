"""M2 -- QDS protocol. Track M2 (Shubhang). Deliverable D1.

Implements protocol P1 from Wallden, Dunjko, Kent & Andersson, Phys. Rev. A
91, 042304 (2015), with the distribution stage carried by teleportation over
Bell pairs. Signature elements are Pauli eigenstates; verification is
projective measurement and mismatch counting; security is
information-theoretic and exponential in L.

Public API. Other tracks should import from `protocol`, not from
`protocol.signer` / `protocol.verifier`, so that M2 can reorganise its
internals without breaking five people:

    from protocol import keygen, sign, verify

    key = keygen("alice", n_copies=64)
    sig = sign((1, 0, 1), key)
    records = verify(sig, key)          # -> list[MeasurementRecord] for M4

M2 does NOT own, and must not start doing:
  * accept/reject decisions, thresholds, or any statistics -- M4
  * the quantum primitives themselves -- M1, behind the QuantumCore seam
  * adversarial mutation of signatures -- M3

See protocol/README.md for the protocol, the mapping onto the frozen
contracts, and the two stated limitations.
"""

from .bb84 import basis_of, pauli_of
from .config import DEFAULT_BASES, QDSConfig
from .exceptions import QDSProtocolError, QuantumCoreError
from .mock_quantum_core import MockQuantumCore
from .quantum_interface import M1QuantumCore, QuantumCore, check_quantum_core
from .signer import keygen, sign
from .verifier import verify

__all__ = [
    "DEFAULT_BASES",
    "M1QuantumCore",
    "MockQuantumCore",
    "QDSConfig",
    "QDSProtocolError",
    "QuantumCore",
    "QuantumCoreError",
    "basis_of",
    "check_quantum_core",
    "keygen",
    "pauli_of",
    "sign",
    "verify",
]
