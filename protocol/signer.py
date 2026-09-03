"""QDS key generation and signing. Track M2 (Shubhang).

STUB -- importable and correctly typed. Real implementation is M2's.
"""

from __future__ import annotations

from contracts import KeyPair, PauliOp, Signature


def keygen(signer_id: str, n_copies: int = 64) -> KeyPair:
    """Simulate quantum public key distribution."""
    # TODO(M2): real QPKD.
    return KeyPair(
        key_id="stub-key",
        signer_id=signer_id,
        private_bits=(0,),
        pauli_map=(PauliOp.I,),
        n_copies=n_copies,
    )


def sign(message: tuple[int, ...], key: KeyPair) -> Signature:
    """Produce a signature over `message`."""
    # TODO(M2): real signing.
    return Signature(
        sig_id="stub-sig",
        key_id=key.key_id,
        signer_id=key.signer_id,
        message=message,
        declared_ops=(PauliOp.I,),
        bell_outcomes=((0, 0),),
        nonce="stub-nonce",
        timestamp=0.0,
    )
