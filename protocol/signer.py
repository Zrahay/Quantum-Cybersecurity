"""QDS key generation and signing. Track M2 (Shubhang).

STUB -- importable and correctly typed. Real implementation is M2's.
"""

from __future__ import annotations

import time
import uuid

from contracts import KeyPair, PauliOp, Signature


def keygen(signer_id: str, n_copies: int = 64) -> KeyPair:
    """Simulate quantum public key distribution."""
    # TODO(M2): real QPKD. Lengths track n_copies even in the stub -- a
    # length-1 tuple would let `zip(...)` in another track silently
    # truncate to one element and still pass that track's tests.
    return KeyPair(
        key_id=f"key-{uuid.uuid4().hex[:8]}",
        signer_id=signer_id,
        private_bits=(0,) * n_copies,
        pauli_map=(PauliOp.I,) * n_copies,
        n_copies=n_copies,
    )


def sign(message: tuple[int, ...], key: KeyPair) -> Signature:
    """Produce a signature over `message`."""
    # TODO(M2): real signing. sig_id and nonce must be UNIQUE per call even
    # in the stub: a constant nonce makes every signature after the first a
    # replay once M4 implements that check, and a constant sig_id collides
    # every row in M5's event log.
    return Signature(
        sig_id=f"sig-{uuid.uuid4().hex[:8]}",
        key_id=key.key_id,
        signer_id=key.signer_id,
        message=message,
        declared_ops=(PauliOp.I,) * len(message),
        bell_outcomes=((0, 0),) * len(message),
        nonce=uuid.uuid4().hex,
        timestamp=time.time(),
    )
