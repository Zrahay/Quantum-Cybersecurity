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
makes acceptance deterministic up to the noise floor. On average L/2
elements survive, which is P1's K -- the n that M4's Hoeffding bound is
taken over.

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
        element's original position in 0..L-1 -- not a renumbering of the
        survivors. The contract says `copy_index` is the copy's index and the
        exponential-in-L bound only means anything if that index is real.

        May be EMPTY, which fails closed rather than open:
        `detection.statistics.mismatch_rate` raises ValueError on an empty
        list precisely so "no data" cannot read as a zero mismatch rate,
        which is the strongest possible evidence of a legitimate signature.
        An adversary who declares every element `PauliOp.I` gets exactly
        this -- no conclusive elements, no records, insufficient data,
        rejected. Do not "fix" that ValueError by fabricating records.

    Raises:
        QuantumCoreError: if `core` does not satisfy the interface.
        ValueError: on a noise level outside 0..1, or a malformed KEY.
    """
    core, config = resolve_dependencies(core, config)
    noise_level = config.noise_level if noise_level is None else noise_level
    if not 0.0 <= noise_level <= 1.0:
        raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {noise_level}")
    n_elements = _validated_element_count(key)

    # The recipient's basis choice. Independent per element and independent
    # of Alice -- that independence is what a forger cannot work around, and
    # it is also what M4's Hoeffding bound assumes.
    rng = derive_rng(config.seed, MEASUREMENT_BASIS_STREAM)
    measurement_bases = [rng.choice(config.bases) for _ in range(n_elements)]

    # What Alice actually distributed, from her key material.
    preparations = [
        (basis_of(op), bit)
        for op, bit in zip(key.pauli_map, key.private_bits)
    ]

    resource = core.bell_pairs(n_elements, noise_level=noise_level)
    outcomes = core.teleport_and_measure(
        resource, preparations, measurement_bases, noise_level=noise_level
    )
    if len(outcomes) != n_elements:
        raise ValueError(
            f"core returned {len(outcomes)} outcomes for {n_elements} elements"
        )

    records: list[MeasurementRecord] = []
    for index, (_bell_outcome, observed) in enumerate(outcomes):
        # Compare against what Alice DECLARED, not against her key. A forger
        # who guesses the wrong Pauli sends the recipient looking in the
        # wrong basis, and the uniform outcome that follows is what shows up
        # as a mismatch. Reading key.pauli_map here instead would make every
        # forgery undetectable.
        declared = _declared_basis(sig, index)
        if declared is None or declared is not measurement_bases[index]:
            continue  # inconclusive: no information, so no record
        records.append(
            MeasurementRecord(
                sig_id=sig.sig_id,
                copy_index=index,
                basis=measurement_bases[index],
                # The bit the protocol predicts: Alice's eigenvalue. 0 means
                # the +1 eigenstate, per contracts.MeasurementRecord.
                expected=key.private_bits[index],
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
