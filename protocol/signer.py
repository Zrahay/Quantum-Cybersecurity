"""QDS key generation and signing. Track M2 (Shubhang). Deliverable D1.

PROTOCOL: P1, from Wallden, Dunjko, Kent & Andersson, "Quantum digital
signatures with quantum-key-distribution components", Phys. Rev. A 91,
042304 (2015) -- arXiv:1403.5551 -- with the distribution stage carried by
teleportation over Bell pairs rather than by direct transmission.

WHY THIS PROTOCOL
-----------------
It is the only family that satisfies the problem statement without inventing
mathematics. Signature elements are Pauli eigenstates; verification is
projective measurement plus mismatch counting; the forging bound
exp[-2(1/8 - s_v L/K)^2 K] and the repudiation bound
exp[-(s_v - s_a)^2 L / 2] both decay exponentially in L; the security is
information-theoretic and proven against COHERENT forging attacks, the
strongest class. Teleportation-native alternatives (the arbitrated-quantum-
signature family) have been broken repeatedly since Gao et al., Phys. Rev. A
84, 022344 (2011), most recently in eprint 2026/558, and have no comparable
proof. See the Decision Log.

Teleportation is not decoration here: P1 assumes an authenticated quantum
channel for distribution and says nothing about how the state gets there,
and teleportation over a Bell pair IS such a channel. Channel noise enters
as a depolarising error on the recipient's half, which is exactly the
mechanism that forces s_a > 0.

WHAT ALICE HOLDS
----------------
For each element i of L, a Pauli eigenstate: `pauli_map[i]` names the Pauli
(Z or X) and `private_bits[i]` the eigenvalue bit. Together they are one of
the four BB84 states -- see bb84.py for the encoding and its one wrinkle
against the frozen contract's comments.

Signing reveals that classical description. Security rests on a forger being
unable to reproduce it from the quantum states alone.

KNOWN DEVIATION, AND IT IS DELIBERATE
-------------------------------------
P1 is a ONE-TIME signature: Alice needs an independent L-element sequence for
each (message bit position, bit value) pair, so signing an m-bit message
consumes 2*m sequences. `contracts.KeyPair` holds exactly one sequence, so
one KeyPair here signs one message, and the message is bound to the
signature classically rather than by which key sequence is revealed.

Consequence, stated plainly: **key reuse across messages is not prevented by
this implementation**, and per-message-bit key material is the change that
would fix it. It needs a `contracts.KeyPair` able to hold 2*m*L elements,
which is a Decision Log item. Until then, one key, one message. This is
written up in protocol/README.md and belongs in D1 as a stated limitation --
it is not a hole to be quietly left out of the deck.
"""

from __future__ import annotations

import time
import uuid

from contracts import KeyPair, Signature

from .bb84 import basis_of, pauli_of
from .config import QDSConfig, derive_rng, resolve_dependencies

#: RNG stream labels. Alice's key material and the recipient's measurement
#: basis MUST come from independent streams -- see `derive_rng`.
KEY_MATERIAL_STREAM = "keygen/elements"


def keygen(
    signer_id: str,
    n_copies: int | None = None,
    *,
    core: object | None = None,
    config: QDSConfig | None = None,
) -> KeyPair:
    """Generate Alice's private key: L Pauli eigenstates. (Ks, Kv) <- KeyGen().

    Purely classical: Alice is choosing which states she will later prepare,
    and that choice is a coin flip per element. No quantum operation happens
    until those states are teleported in `sign`, so `core` is accepted (for
    interface symmetry and validation) but not called.

    Independence is the point, not an implementation detail. M4's Hoeffding
    bound assumes the L outcomes are independent, and the justification is
    right here: each element's basis and bit are drawn independently, so the
    recipient's L measurement outcomes are independent too. Correlating them
    -- deriving element i+1 from element i, say -- would invalidate the
    bound while leaving every test passing.

    Args:
        signer_id: identity the key is issued to.
        n_copies: L. `None` takes it from `config`.
        core: quantum backend. Validated, unused; see above.
        config: protocol parameters. Defaults to `QDSConfig()`.

    Raises:
        QuantumCoreError: if `core` does not satisfy the interface.
        ValueError: on an empty `signer_id` or n_copies < 1.
    """
    _core, config = resolve_dependencies(core, config)
    if not signer_id:
        raise ValueError("signer_id must be a non-empty string")
    n_copies = config.n_copies if n_copies is None else n_copies
    if n_copies < 1:
        raise ValueError(f"n_copies (L) must be at least 1, got {n_copies}")

    rng = derive_rng(config.seed, KEY_MATERIAL_STREAM)
    pauli_map = tuple(pauli_of(rng.choice(config.bases)) for _ in range(n_copies))
    private_bits = tuple(rng.getrandbits(1) for _ in range(n_copies))

    return KeyPair(
        key_id=f"key-{uuid.uuid4().hex[:8]}",
        signer_id=signer_id,
        private_bits=private_bits,
        pauli_map=pauli_map,
        n_copies=n_copies,
    )


def sign(
    message: tuple[int, ...],
    key: KeyPair,
    *,
    core: object | None = None,
    config: QDSConfig | None = None,
) -> Signature:
    """Sign `message`: distribute the elements and declare their description.

    Two things travel to the recipient:

      * `declared_ops` -- the Pauli of each element, which together with the
        key's `private_bits` is the classical description P1 calls PrivKey.
        This is what a forger has to reproduce and cannot.
      * `bell_outcomes` -- Alice's Bell-measurement results from teleporting
        the elements, which the recipient needs to apply the right Pauli
        correction.

    Both are per ELEMENT, so both have length L -- not `len(message)`, which
    is what the earlier scaffold returned. M3's adversaries size their
    mutations off `len(sig.message)` and so will only touch the first few
    elements of a real signature; that is an M3 follow-up, not a bug here.

    Raises:
        QuantumCoreError: if `core` does not satisfy the interface.
        ValueError: on an empty message, a non-bit element, or a malformed key.
    """
    core, config = resolve_dependencies(core, config)
    # Validated here and not in contracts.py: the dataclass is frozen and
    # M3's adversaries construct mutated Signatures directly, which must stay
    # possible. This checks only what enters through the legitimate path.
    if not message:
        raise ValueError("cannot sign an empty message")
    bad = [(i, b) for i, b in enumerate(message) if b not in (0, 1)]
    if bad:
        raise ValueError(f"message must be bits (0 or 1); offending (index, value): {bad}")
    n_elements = _validated_element_count(key)

    # Teleport the L elements to the recipient and keep Alice's Bell
    # outcomes. The recipient's own measurement happens in verify(); see the
    # note there on why the two halves are not one shot.
    resource = core.bell_pairs(n_elements, noise_level=config.noise_level)
    bell_outcomes = tuple(core.teleport(resource, noise_level=config.noise_level))
    if len(bell_outcomes) != n_elements:
        raise ValueError(
            f"core returned {len(bell_outcomes)} Bell outcomes for {n_elements} elements"
        )

    return Signature(
        sig_id=f"sig-{uuid.uuid4().hex[:8]}",
        key_id=key.key_id,
        signer_id=key.signer_id,
        message=message,
        declared_ops=key.pauli_map,
        bell_outcomes=bell_outcomes,
        # Unique per call. A constant nonce makes every signature after the
        # first a replay once M4 checks it; a constant sig_id collides every
        # row in M5's event log. Replay defence is nonce + timestamp
        # freshness at this layer and is NOT quantum -- no-cloning means the
        # state cannot be copied and resent, so a replay is necessarily a
        # reused CLASSICAL transcript.
        nonce=uuid.uuid4().hex,
        timestamp=time.time(),
    )


def _validated_element_count(key: KeyPair) -> int:
    """Length of the key's element sequences, or raise.

    The key is ours, not the adversary's -- it never crosses the wire -- so
    a malformed one is a caller bug and raising is right. Contrast
    verifier.py, which must never raise on a malformed SIGNATURE.
    """
    if len(key.pauli_map) != len(key.private_bits):
        raise ValueError(
            f"malformed key: pauli_map has {len(key.pauli_map)} elements but "
            f"private_bits has {len(key.private_bits)}"
        )
    if not key.pauli_map:
        raise ValueError("malformed key: no signature elements")
    for i, op in enumerate(key.pauli_map):
        if basis_of(op) is None:
            raise ValueError(
                f"malformed key: pauli_map[{i}] is {op!r}, which names no "
                f"measurement basis; expected one of Z, X, Y"
            )
    bad = [(i, b) for i, b in enumerate(key.private_bits) if b not in (0, 1)]
    if bad:
        raise ValueError(f"malformed key: private_bits must be bits; offending: {bad}")
    if key.n_copies != len(key.pauli_map):
        raise ValueError(
            f"malformed key: n_copies is {key.n_copies} but there are "
            f"{len(key.pauli_map)} elements"
        )
    return len(key.pauli_map)
