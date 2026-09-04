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
P1 is a ONE-TIME signature: for an m-bit message, Alice needs an independent
L-element sequence for EACH (message bit position, bit value) pair -- 2*m
sequences, 2*m*L elements total. `keygen(..., message_length=m)` generates
all of them up front; `KeyPair.pauli_map` / `.private_bits` are the flat
concatenation, laid out sequence-by-sequence:

    sequence(i, v) occupies elements [ (2*i+v)*L : (2*i+v)*L + L ]
    for message bit position i in 0..m-1, claimed bit value v in {0, 1}

`n_copies` keeps its original meaning -- L, copies per sequence -- and
`message_length` (recovered as `len(pauli_map) // (2 * n_copies)`, see
`_validated_element_count`) is the new second dimension. This is additive:
`contracts.KeyPair`'s fields are unchanged, only the length relationship
between `pauli_map`/`private_bits` and `n_copies` does, so no frozen-type
edit and no Decision Log item for the schema itself.

THIS IS THE MESSAGE-BINDING MECHANISM, not decoration. `sign` reveals
`declared_ops`/eigenvalue data for ONLY the m sequences matching the actual
message bit values -- `sequence(i, message[i])` -- never the other m
"the bit was flipped" sequences. A party who tries to re-verify the same
transcript against a DIFFERENT message forces `verify` to compare the
REVEALED classical data against the OTHER, never-revealed sequence at each
position: two independently-drawn random sequences, so the same ~1/4
mismatch rate that catches a blind forger catches a message swap. See
`tests/test_signature.py::TestMessageBinding`.
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
    message_length: int = 1,
    core: object | None = None,
    config: QDSConfig | None = None,
) -> KeyPair:
    """Generate Alice's private key: 2*message_length independent L-element
    sequences, one pair per message bit position. (Ks, Kv) <- KeyGen().

    Purely classical: Alice is choosing which states she will later prepare,
    and that choice is a coin flip per element. No quantum operation happens
    until those states are teleported in `sign`, so `core` is accepted (for
    interface symmetry and validation) but not called.

    Independence is the point, not an implementation detail. M4's Hoeffding
    bound assumes the outcomes are independent, and the justification is
    right here: every element's basis and bit -- across all 2*message_length
    sequences -- are drawn independently from one continuous stream, so the
    recipient's measurement outcomes are independent too. Correlating them
    -- deriving element i+1 from element i, or one sequence from its sibling
    -- would invalidate the bound while leaving every test passing.

    Args:
        signer_id: identity the key is issued to.
        n_copies: L, copies per sequence. `None` takes it from `config`.
        message_length: m, the number of message bits this key can sign.
            Must match `len(message)` at `sign` time. Defaults to 1.
        core: quantum backend. Validated, unused; see above.
        config: protocol parameters. Defaults to `QDSConfig()`.

    Raises:
        QuantumCoreError: if `core` does not satisfy the interface.
        ValueError: on an empty `signer_id`, n_copies < 1, or message_length < 1.
    """
    _core, config = resolve_dependencies(core, config)
    if not signer_id:
        raise ValueError("signer_id must be a non-empty string")
    n_copies = config.n_copies if n_copies is None else n_copies
    if n_copies < 1:
        raise ValueError(f"n_copies (L) must be at least 1, got {n_copies}")
    if message_length < 1:
        raise ValueError(f"message_length (m) must be at least 1, got {message_length}")

    n_elements = 2 * message_length * n_copies
    rng = derive_rng(config.seed, KEY_MATERIAL_STREAM)
    pauli_map = tuple(pauli_of(rng.choice(config.bases)) for _ in range(n_elements))
    private_bits = tuple(rng.getrandbits(1) for _ in range(n_elements))

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
    """Sign `message`: reveal the message-matching sequences and distribute them.

    For each message bit position i, Alice reveals classical data for
    EXACTLY ONE of her two pre-distributed sequences: `sequence(i,
    message[i])`. The sibling sequence `sequence(i, 1 - message[i])` is
    never touched by this call. That selective revelation is what binds the
    signature to `message` -- see the module docstring and
    `tests/test_signature.py::TestMessageBinding`.

    Two things travel to the recipient, both length `message_length * L`:

      * `declared_ops` -- the Pauli of each revealed element, which together
        with the key's `private_bits` for those same elements is the
        classical description P1 calls PrivKey. This is what a forger has
        to reproduce and cannot -- and, for a message-swap attempt, what an
        attacker would have to reproduce for the SIBLING sequence, which was
        never revealed either.
      * `bell_outcomes` -- Alice's Bell-measurement results from teleporting
        the revealed elements' REAL prepared eigenstates (not a placeholder
        |0>; `core.teleport` takes the same `preparations` shape as
        `teleport_and_measure`), which the recipient needs to apply the
        right Pauli correction. Note that today's `verify()` still
        re-derives its own measurement from the key material rather than
        consuming this value -- see protocol/verifier.py -- so this field
        is honest data, not yet something verify() is causally driven by.

    Raises:
        QuantumCoreError: if `core` does not satisfy the interface.
        ValueError: on an empty message, a non-bit element, a message whose
            length does not match the key's `message_length`, or a
            malformed key.
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
    n_copies, message_length = _validated_element_count(key)
    if len(message) != message_length:
        raise ValueError(
            f"message has {len(message)} bits but key was generated for "
            f"message_length={message_length}"
        )

    declared_ops: list = []
    preparations: list = []
    for i, bit in enumerate(message):
        seq = 2 * i + bit
        start, end = seq * n_copies, (seq + 1) * n_copies
        declared_ops.extend(key.pauli_map[start:end])
        preparations.extend(
            (basis_of(op), b)
            for op, b in zip(key.pauli_map[start:end], key.private_bits[start:end])
        )
    n_revealed = len(declared_ops)

    # Teleport the revealed elements -- Alice's REAL per-element content,
    # not a placeholder -- and keep her Bell outcomes. The recipient's own
    # measurement happens in verify(); see the note there on why the two
    # halves are not one shot.
    resource = core.bell_pairs(n_revealed, noise_level=config.noise_level)
    bell_outcomes = tuple(
        core.teleport(resource, preparations, noise_level=config.noise_level)
    )
    if len(bell_outcomes) != n_revealed:
        raise ValueError(
            f"core returned {len(bell_outcomes)} Bell outcomes for {n_revealed} elements"
        )

    return Signature(
        sig_id=f"sig-{uuid.uuid4().hex[:8]}",
        key_id=key.key_id,
        signer_id=key.signer_id,
        message=message,
        declared_ops=tuple(declared_ops),
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


def _validated_element_count(key: KeyPair) -> tuple[int, int]:
    """(n_copies, message_length) for the key's element sequences, or raise.

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
    if key.n_copies < 1:
        raise ValueError(f"malformed key: n_copies must be at least 1, got {key.n_copies}")
    total = len(key.pauli_map)
    # Total elements must be 2*m*L for some integer m -- two sequences
    # (bit=0, bit=1) per message position, L elements each.
    if total % (2 * key.n_copies) != 0:
        raise ValueError(
            f"malformed key: {total} elements is not a multiple of "
            f"2 * n_copies ({2 * key.n_copies}); key was not built by keygen()"
        )
    message_length = total // (2 * key.n_copies)
    return key.n_copies, message_length
