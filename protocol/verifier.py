"""QDS verification. Track M2 (Shubhang). Deliverable D1.

P1's messaging stage: measure each signature element, and count how many
measurements CONTRADICT the classical description Alice declared.

    M1 quantum primitives      core/  (bell pairs, teleport, Pauli, measure)
              |
              v
    M2 verify()                measures the elements, predicts each outcome
              |
              |  list[MeasurementRecord]     <-- the only type crossing here
              v
    M4 evaluate()              thresholds, Hoeffding, chi-square, verdict
              |
              |  DetectionResult
              v
    M5 dashboard               renders, recomputes nothing

verify() produces measurement records. It does NOT decide accept or reject
-- that is M4's job, and `Verdict` is M4's to return. Comparing the mismatch
rate against s_a and s_v happens there.

MESSAGE BINDING: WHICH KEY SEQUENCE GETS CHECKED
-------------------------------------------------
The key holds TWO independent L-element sequences per message bit position
-- one for "the bit is 0", one for "the bit is 1" -- see signer.py. For
message bit position i, `sig.message[i]` selects WHICH of the two the
recipient prepares against: `sequence(i, sig.message[i])`. This is the
message-binding mechanism: a signature re-presented against a different
message forces this lookup onto the SIBLING sequence, which Alice's
`declared_ops` (revealed for the true message only) was never drawn to
match -- so a message swap gets caught by the same ~1/4 mismatch-rate gap
that catches a blind forger. See `_conclusive_candidates` below.

STATE ELIMINATION, AND WHY HALF THE ELEMENTS ARE DISCARDED
----------------------------------------------------------
The recipient measures each element in a basis chosen at random, without
knowing which basis Alice used. Two cases:

  * SAME basis as Alice declared. On an ideal channel the outcome equals
    Alice's eigenvalue bit with certainty, so a disagreement is a genuine
    contradiction -- the element is CONCLUSIVE and becomes a record.
  * DIFFERENT basis. The outcome is uniformly random and carries no
    information about what Alice sent. INCONCLUSIVE, and it produces no
    record at all.

Keeping the inconclusive half would inject a 50% coin flip into the
mismatch rate and reject every legitimate signature. Discarding it is what
makes acceptance deterministic up to the noise floor. On average K/2
elements survive per signature, where K = message_length * L is the total
number of elements a signature reveals -- P1's K is the n that M4's
Hoeffding bound is taken over.

WHY VERIFY DOES NOT VALIDATE THE SIGNATURE
------------------------------------------
Tempting, and wrong. A mismatched `key_id`, a `declared_ops` of the wrong
length, an op of `PauliOp.I` that names no basis, an implausible
`timestamp` -- these are exactly what M3's adversaries produce, and they are
DETECTION SIGNALS, not argument errors. Raising on them would move detection
into M2, make the attack demo throw instead of classify, and duplicate M4.
So verify() validates its own arguments and the KEY (which never crosses the
wire), lets the statistics speak for the SIGNATURE, and fails closed by
returning no records when nothing is checkable.
"""

from __future__ import annotations

from contracts import KeyPair, MeasurementRecord, Signature

from .bb84 import basis_of
from .config import QDSConfig, derive_rng, resolve_dependencies
from .signer import _validated_element_count

#: RNG stream label. MUST differ from signer.KEY_MATERIAL_STREAM: if the
#: recipient draws bases from the same stream as Alice drew her key, it
#: reproduces her sequence exactly and forgeries score a perfect 0.000
#: mismatch rate. See config.derive_rng.
MEASUREMENT_BASIS_STREAM = "verify/bases"


def verify(
    sig: Signature,
    key: KeyPair,
    noise_level: float | None = None,
    *,
    core: object | None = None,
    config: QDSConfig | None = None,
) -> list[MeasurementRecord]:
    """Measure the signature elements and return one record per conclusive one.

    Args:
        sig: the signature as received -- possibly mutated by an adversary.
        key: the verifier's copy of Alice's key material. Modelling note: in
            P1 the recipient learns this only in the messaging stage, when
            Alice declares it. The frozen `Signature` has no field to carry
            the declared eigenvalue bits, so passing the KeyPair here IS the
            declaration channel. See protocol/README.md.
        noise_level: depolarising channel parameter. `None` takes it from
            `config`. M3's channel-tamper adversary raises it.
        core: quantum backend. Defaults to the real one, seeded from config.
        config: protocol parameters. Defaults to `QDSConfig()`.

    Returns:
        One MeasurementRecord per CONCLUSIVE element, `copy_index` being the
        element's position in 0..(message_length*L - 1) within THIS
        SIGNATURE's own `declared_ops`/`bell_outcomes` -- not a renumbering
        of the survivors, and not an index into the key (which holds twice
        as many elements). The exponential-in-L bound only means anything if
        that index is real.

        May be EMPTY, which fails closed rather than open:
        `detection.statistics.mismatch_rate` raises ValueError on an empty
        list precisely so "no data" cannot read as a zero mismatch rate,
        which is the strongest possible evidence of a legitimate signature.
        An adversary who declares every element `PauliOp.I`, or who presents
        a `message` that names no sequence in the key (wrong length, or a
        non-bit value), gets exactly this -- no conclusive elements, no
        records, insufficient data, rejected. Do not "fix" that ValueError
        by fabricating records.

    Raises:
        QuantumCoreError: if `core` does not satisfy the interface.
        ValueError: on a noise level outside 0..1, or a malformed KEY.
    """
    core, config = resolve_dependencies(core, config)
    noise_level = config.noise_level if noise_level is None else noise_level
    if not 0.0 <= noise_level <= 1.0:
        raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {noise_level}")
    n_copies, key_message_length = _validated_element_count(key)

    # (sig_idx, key_idx) for every element `sig.message` can even name a key
    # sequence for. sig_idx addresses THIS signature's own declared_ops /
    # bell_outcomes / MeasurementRecord.copy_index; key_idx addresses the
    # SPECIFIC sequence -- sequence(i, sig.message[i]) -- that message bit
    # value selects. A malformed message (wrong length, non-bit value)
    # simply produces fewer or zero candidates; never an error, per the
    # module docstring on why verify() never raises on the SIGNATURE.
    candidates: list[tuple[int, int]] = []
    for i, bit in enumerate(sig.message):
        if i >= key_message_length or bit not in (0, 1):
            continue
        seq = 2 * i + bit
        sig_base, key_base = i * n_copies, seq * n_copies
        candidates.extend((sig_base + j, key_base + j) for j in range(n_copies))

    if not candidates:
        return []

    # The recipient's basis choice. Independent per element and independent
    # of Alice -- that independence is what a forger cannot work around, and
    # it is also what M4's Hoeffding bound assumes. Drawn in sig_idx order,
    # which depends only on which message POSITIONS are checkable, not on
    # the bit VALUES at those positions -- so the verifier's basis choices
    # don't themselves leak anything about which sequence got selected.
    rng = derive_rng(config.seed, MEASUREMENT_BASIS_STREAM)
    measurement_bases = [rng.choice(config.bases) for _ in candidates]

    # What Alice actually distributed for the message-matching sequences,
    # from her key material -- NOT the whole key.
    preparations = [
        (basis_of(key.pauli_map[key_idx]), key.private_bits[key_idx])
        for _sig_idx, key_idx in candidates
    ]

    resource = core.bell_pairs(len(candidates), noise_level=noise_level)
    outcomes = core.teleport_and_measure(
        resource, preparations, measurement_bases, noise_level=noise_level
    )
    if len(outcomes) != len(candidates):
        raise ValueError(
            f"core returned {len(outcomes)} outcomes for {len(candidates)} elements"
        )

    records: list[MeasurementRecord] = []
    for (sig_idx, key_idx), basis, (_bell_outcome, observed) in zip(
        candidates, measurement_bases, outcomes
    ):
        # Compare against what Alice DECLARED, not against her key. A forger
        # who guesses the wrong Pauli (or picks the sibling sequence via a
        # message swap) sends the recipient looking in the wrong basis, and
        # the uniform outcome that follows is what shows up as a mismatch.
        declared = _declared_basis(sig, sig_idx)
        if declared is None or declared is not basis:
            continue  # inconclusive: no information, so no record
        records.append(
            MeasurementRecord(
                sig_id=sig.sig_id,
                copy_index=sig_idx,
                basis=basis,
                # The bit the protocol predicts: the KEY's eigenvalue for the
                # message-selected sequence. 0 means the +1 eigenstate, per
                # contracts.MeasurementRecord.
                expected=key.private_bits[key_idx],
                observed=observed,
            )
        )
    return records


def _declared_basis(sig: Signature, index: int):
    """The basis Alice declared for element `index`, or None if unusable.

    None covers all three ways a signature can fail to declare a usable
    basis -- too few ops, an op that names no basis (`PauliOp.I`), or a
    non-PauliOp entirely. Each is an adversary's doing and each makes the
    element inconclusive rather than an error; see the module docstring.
    """
    if index >= len(sig.declared_ops):
        return None
    try:
        return basis_of(sig.declared_ops[index])
    except TypeError:
        # declared_ops[index] is not hashable, so not a PauliOp either.
        return None
