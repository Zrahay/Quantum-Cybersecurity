"""QDS verification. Track M2 (Shubhang).

SCAFFOLD -- no QDS construction has been selected, so no verification
equation exists here yet. What is real is the seam, and the seam is the part
other tracks integrate against:

    M1 quantum primitives      core/  (bell pairs, teleport, Pauli, measure)
              |
              v
    M2 verify()                measures the copies, predicts each outcome
              |
              |  list[MeasurementRecord]     <-- the only type crossing here
              v
    M4 evaluate()              thresholds, Hoeffding, chi-square, verdict
              |
              |  DetectionResult
              v
    M5 dashboard               renders, recomputes nothing

verify() produces measurement records. It does NOT decide accept or reject
-- that is M4's job, and `Verdict` is M4's to return. Keeping this seam clean
stops the two tracks duplicating logic and then disagreeing live in front of
a judge.

WHY VERIFY DOES NOT VALIDATE THE SIGNATURE
------------------------------------------
Tempting, and wrong. A mismatched `key_id`, a `message` whose length
disagrees with `pauli_map`, an implausible `timestamp` -- these are exactly
what M3's impersonation and replay adversaries produce, and they are
DETECTION SIGNALS, not argument errors. Raising on them here would move
detection into M2, make the attack demo throw instead of classify, and
duplicate M4. So verify() validates only its own well-formedness (is the core
usable, is the config sane) and lets the statistics speak.
"""

from __future__ import annotations

from contracts import KeyPair, MeasurementRecord, Signature

from .config import QDSConfig, resolve_dependencies
from .exceptions import ProtocolNotSelectedError


def verify(
    sig: Signature,
    key: KeyPair,
    noise_level: float | None = None,
    *,
    core: object | None = None,
    config: QDSConfig | None = None,
) -> list[MeasurementRecord]:
    """Measure the signature copies and return one record per measurement.

    Args:
        sig: the signature as received -- possibly mutated by an adversary.
        key: the verifier's KeyPair.
        noise_level: depolarising channel parameter. `None` means take it
            from `config`, whose default (0.0) is the value this parameter
            used to default to, so existing positional callers are unaffected.
        core: quantum backend satisfying `QuantumCore`. Optional only while
            the algorithm is unselected; real verification needs one.
        config: protocol parameters. Defaults to `QDSConfig()`.

    Returns:
        One MeasurementRecord per projective measurement, `copy_index`
        running 0..L-1 in measurement order.

        CURRENTLY ALWAYS EMPTY, and that FAILS CLOSED rather than open:
        `detection.statistics.mismatch_rate` raises ValueError on an empty
        list precisely so that "no data" cannot be read as a zero mismatch
        rate, which is the strongest possible evidence of a legitimate
        signature. An unimplemented verifier must not be able to accept
        anything. Do not "fix" that ValueError by returning fabricated
        records; it is the scaffold working as intended.

    Raises:
        ProtocolNotSelectedError: if `config.strict`.
        QuantumCoreError: if `core` does not satisfy the interface.
    """
    _core, config = resolve_dependencies(core, config)
    noise_level = config.noise_level if noise_level is None else noise_level
    if not 0.0 <= noise_level <= 1.0:
        raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {noise_level}")
    if config.strict:
        raise ProtocolNotSelectedError(
            "verify: no teleportation-based QDS construction has been selected, "
            "so there is no outcome to predict and nothing to measure against"
        )

    # ----------------------- ALGORITHM GOES HERE -----------------------
    # TODO(M2): real verification. It must decide:
    #   * which basis each copy is measured in. `config.bases` is empty by
    #     design -- populating it is a protocol decision, and this block
    #     should refuse to run on an empty tuple rather than defaulting to Z.
    #   * `expected`: the bit the protocol PREDICTS for that copy, derived
    #     from `key.pauli_map`, `sig.declared_ops` and `sig.bell_outcomes`.
    #     It must be a classical bit -- "the protocol predicts the +1
    #     eigenstate" maps to expected=0. Writing -1 makes every record a
    #     mismatch and rejects 100% of legitimate signatures.
    #   * `observed`: from `_core.measure(resource, basis, noise_level=...)`,
    #     PER-COPY ORDER PRESERVED. `core.measurements.records_from_shots`
    #     exists to do the expansion and explains why a Qiskit counts dict
    #     cannot be used here -- it is aggregated, so `copy_index` would be
    #     invented by enumerate() and the exponential-in-L forgery bound
    #     would be resting on a fiction.
    #
    # Constraint to honour while writing it: this must stay cheap. Low
    # computational complexity for verify() is one of the problem
    # statement's requirements, and we have to be able to show it -- so keep
    # it O(L) in measurements with no per-copy re-derivation of the key.
    # -------------------------------------------------------------------

    return []
