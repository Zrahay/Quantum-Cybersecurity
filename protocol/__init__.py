"""M2 -- QDS protocol. Track M2 (Shubhang). Deliverable D1.

Public API. Other tracks should import from `protocol`, not from
`protocol.signer` / `protocol.verifier`, so that M2 can reorganise its
internals without breaking five people:

    from protocol import keygen, sign, verify

STATUS: SCAFFOLD. The teleportation-based QDS construction has not been
selected, so keygen/sign/verify return correctly shaped placeholder data and
`QDSConfig(strict=True)` makes them raise ProtocolNotSelectedError instead.
See protocol/README.md for what is real, what is deliberately absent, and
where the algorithm plugs in.

M2 does NOT own, and must not start doing:
  * accept/reject decisions, thresholds, or any statistics -- M4
  * the quantum primitives themselves -- M1, behind the QuantumCore seam
  * adversarial mutation of signatures -- M3
"""

from .config import QDSConfig
from .exceptions import ProtocolNotSelectedError, QDSProtocolError, QuantumCoreError
from .mock_quantum_core import MockQuantumCore
from .quantum_interface import M1QuantumCore, QuantumCore, check_quantum_core
from .signer import keygen, sign
from .verifier import verify

__all__ = [
    "M1QuantumCore",
    "MockQuantumCore",
    "ProtocolNotSelectedError",
    "QDSConfig",
    "QDSProtocolError",
    "QuantumCore",
    "QuantumCoreError",
    "check_quantum_core",
    "keygen",
    "sign",
    "verify",
]
