"""QDS key generation and signing. Track M2 (Shubhang).

SCAFFOLD -- the teleportation-based QDS construction has NOT been selected
(see the Decision Log in Notion), so there is no signing equation here yet.
The architecture, types and seams are real; the cryptography is absent and
says so.

WHY THE PLACEHOLDER RETURNS VALUES INSTEAD OF RAISING
-----------------------------------------------------
Because M3, M4 and M5 already import these functions and need a correctly
shaped KeyPair and Signature to build against, and serialising four tracks
behind one undecided algorithm costs more than the placeholder does. The
placeholder is therefore reachable BY DEFAULT and honest about it:

  * it performs no cryptographic operation of any kind -- no XOR, no hash,
    no invented signing equation. Nothing here could be mistaken for a
    construction, because there is nothing here.
  * `QDSConfig(strict=True)` turns every entry point into a
    ProtocolNotSelectedError. M2's tests assert both branches, so the
    "unimplemented" claim is verified rather than merely written down.

WHERE THE REAL ALGORITHM GOES
-----------------------------
Each function has one block marked `ALGORITHM GOES HERE`, between the
validation above it and the placeholder return below it. Filling those two
blocks in, plus the one in verifier.py, is the whole of the D1 model. No
caller signature has to change: `core` and `config` are already threaded in.
"""

from __future__ import annotations

import time
import uuid

from contracts import KeyPair, PauliOp, Signature

from .config import QDSConfig, resolve_dependencies
from .exceptions import ProtocolNotSelectedError


def keygen(
    signer_id: str,
    n_copies: int | None = None,
    *,
    core: object | None = None,
    config: QDSConfig | None = None,
) -> KeyPair:
    """Simulate quantum public key distribution: (Ks, Kv) <- KeyGen(...).

    Args:
        signer_id: identity the key is issued to.
        n_copies: L. `None` means take it from `config`, whose default (64)
            is the value this parameter used to default to -- so existing
            positional callers are unaffected.
        core: quantum backend satisfying `QuantumCore`. Optional only while
            the algorithm is unselected; real QPKD cannot run without one.
        config: protocol parameters. Defaults to `QDSConfig()`.

    Raises:
        ProtocolNotSelectedError: if `config.strict`.
        QuantumCoreError: if `core` does not satisfy the interface.
        ValueError: on an empty `signer_id` or n_copies < 1.
    """
    _core, config = resolve_dependencies(core, config)
    if not signer_id:
        raise ValueError("signer_id must be a non-empty string")
    n_copies = config.n_copies if n_copies is None else n_copies
    if n_copies < 1:
        raise ValueError(f"n_copies (L) must be at least 1, got {n_copies}")
    if config.strict:
        raise ProtocolNotSelectedError(
            "keygen: no teleportation-based QDS construction has been selected, "
            "so quantum public key distribution cannot be performed"
        )

    # ----------------------- ALGORITHM GOES HERE -----------------------
    # TODO(M2): real QPKD, once the construction is chosen. It must decide:
    #   * what `private_bits` is -- the classical seed the signer keeps, and
    #     what distribution it is drawn from.
    #   * how `pauli_map` is derived, i.e. the message bit -> required
    #     correction mapping, and via which of `_core`'s primitives.
    #   * whether L copies are prepared here or lazily at signing time. This
    #     matters beyond bookkeeping: M4's Hoeffding bound assumes the L
    #     outcomes are INDEPENDENT, and justifying that assumption is M2's
    #     job (it is called out in D1). Preparation order is the evidence.
    # -------------------------------------------------------------------

    # Placeholder. Lengths track n_copies even in the stub -- a length-1
    # tuple would let `zip(...)` in another track silently truncate to one
    # element and still pass that track's tests.
    return KeyPair(
        key_id=f"key-{uuid.uuid4().hex[:8]}",
        signer_id=signer_id,
        private_bits=(0,) * n_copies,
        pauli_map=(PauliOp.I,) * n_copies,
        n_copies=n_copies,
    )


def sign(
    message: tuple[int, ...],
    key: KeyPair,
    *,
    core: object | None = None,
    config: QDSConfig | None = None,
) -> Signature:
    """Produce a signature over `message`: signature <- Sign(message, Ks).

    Args:
        message: classical message as a tuple of BITS (0 or 1).
        key: the signer's KeyPair from `keygen`.
        core: quantum backend satisfying `QuantumCore`. Optional only while
            the algorithm is unselected.
        config: protocol parameters. Defaults to `QDSConfig()`.

    Raises:
        ProtocolNotSelectedError: if `config.strict`.
        QuantumCoreError: if `core` does not satisfy the interface.
        ValueError: on an empty message or any element outside {0, 1}.
    """
    _core, config = resolve_dependencies(core, config)
    # Validated here and not in contracts.py: the dataclass is frozen and
    # M3's adversaries construct mutated Signatures directly, which must stay
    # possible. This checks only what enters through the legitimate path.
    if not message:
        raise ValueError("cannot sign an empty message")
    bad = [(i, b) for i, b in enumerate(message) if b not in (0, 1)]
    if bad:
        raise ValueError(f"message must be bits (0 or 1); offending (index, value): {bad}")
    if config.strict:
        raise ProtocolNotSelectedError(
            "sign: no teleportation-based QDS construction has been selected, "
            "so there is no signing operation to perform"
        )

    # ----------------------- ALGORITHM GOES HERE -----------------------
    # TODO(M2): real signing. It must decide:
    #   * how `declared_ops` is computed from `message` and `key` -- the
    #     correction the signer CLAIMS, which is what a forger has to guess.
    #   * how `bell_outcomes` is obtained: `_core.bell_pairs(...)` then
    #     `_core.teleport(...)`. Emit them in the frozen (clbit0, clbit1)
    #     circuit order; see the ordering note on QuantumCore.teleport.
    #   * nothing about replay. Replay defence is nonce + timestamp
    #     freshness, checked by M4, and it is NOT quantum: no-cloning means
    #     the state cannot be copied and resent, so a replay is necessarily a
    #     reused CLASSICAL transcript. Say so in D1 rather than implying the
    #     quantum layer catches it.
    # -------------------------------------------------------------------

    # Placeholder. sig_id and nonce must be UNIQUE per call even in the stub:
    # a constant nonce makes every signature after the first a replay once M4
    # implements that check, and a constant sig_id collides every row in M5's
    # event log.
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
