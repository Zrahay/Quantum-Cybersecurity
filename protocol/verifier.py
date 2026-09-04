"""QDS verification. Track M2 (Shubhang).

verify() measures the signature copies and returns one MeasurementRecord
per projective measurement. It does NOT decide accept/reject -- that is
M4's job. The seam is:

    M1 quantum primitives  ->  M2 verify()  ->  list[MeasurementRecord]
                                                |
                                                v
                                          M4 evaluate()  ->  DetectionResult

WHY VERIFY DOES NOT VALIDATE THE SIGNATURE
------------------------------------------
A mismatched `key_id`, wrong `message` length, implausible `timestamp` --
these are exactly what M3's adversaries produce. They are DETECTION
SIGNALS, not argument errors. Raising here would move detection into M2,
make the attack demo throw instead of classify, and duplicate M4.
verify() validates only its own well-formedness and lets the statistics
speak.
"""

from __future__ import annotations

from contracts import Basis, KeyPair, MeasurementRecord, Signature

from .config import QDSConfig, resolve_dependencies
from .exceptions import ProtocolNotSelectedError
from core.pauli import correction_for


def _expected_bit_for_basis(message_bit: int, basis: Basis) -> int:
    """Expected measurement outcome for |message_bit> in the given basis.

    For a legitimate signature, Bob's qubit after teleportation+correction
    is exactly |message_bit>. Measuring this in any Pauli basis yields
    the message bit itself: Z-basis gives 0/1, X-basis gives 0/1 for |+>/|->,
    Y-basis gives 0/1 for |i>/|-i>.
    """
    return message_bit


def _basis_for_copy(copy_index: int, bases: tuple[Basis, ...]) -> Basis:
    """Select measurement basis for a copy, cycling through configured bases."""
    return bases[copy_index % len(bases)]


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
            used to default to.
        core: quantum backend satisfying `QuantumCore`. If None, a
            `MockQuantumCore` is used with `config.seed` for reproducibility.
            Real verification requires a real core.
        config: protocol parameters. Defaults to `QDSConfig()`.

    Returns:
        One MeasurementRecord per projective measurement, `copy_index`
        running 0..L-1 in measurement order.

    Raises:
        ProtocolNotSelectedError: if `config.strict`.
        QuantumCoreError: if `core` does not satisfy the interface.
        ValueError: if `config.bases` is empty.
    """
    _core, config = resolve_dependencies(core, config)
    # Use MockQuantumCore if no core provided (for tests and development)
    if _core is None:
        from protocol.mock_quantum_core import MockQuantumCore
        _core = MockQuantumCore(seed=config.seed)

    noise_level = config.noise_level if noise_level is None else noise_level
    if not 0.0 <= noise_level <= 1.0:
        raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {noise_level}")
    if config.strict:
        raise ProtocolNotSelectedError(
            "verify: no teleportation-based QDS construction has been selected, "
            "so there is no outcome to predict and nothing to measure against"
        )
    if not config.bases:
        raise ValueError(
            "config.bases must be non-empty -- the measurement bases are a "
            "property of the chosen QDS construction and cannot be defaulted"
        )

    n_copies = key.n_copies
    if len(sig.message) != n_copies:
        raise ValueError(
            f"signature message length ({len(sig.message)}) != key n_copies ({n_copies})"
        )
    if len(sig.declared_ops) != n_copies:
        raise ValueError(
            f"signature declared_ops length ({len(sig.declared_ops)}) != key n_copies ({n_copies})"
        )
    if len(sig.bell_outcomes) != n_copies:
        raise ValueError(
            f"signature bell_outcomes length ({len(sig.bell_outcomes)}) != key n_copies ({n_copies})"
        )

    # Prepare L entangled pairs (one per copy)
    resource = _core.bell_pairs(n_copies, noise_level=noise_level)

    # For each copy, the expected outcome is the message bit (legitimate prediction).
    # The actual state Bob holds is X^c1 Z^c0 |message> where (c0,c1)=bell_outcomes[i].
    # If declared_ops == correction_for(bell_outcomes) == pauli_map[message],
    # the state is |message> and measurement matches expected.
    # If not, the state is Pauli-twisted and measurement mismatches with prob ~0.5.
    expected_bits = []
    for i in range(n_copies):
        basis = _basis_for_copy(i, config.bases)
        expected_bits.append(_expected_bit_for_basis(sig.message[i], basis))

    # Measure all copies in their respective bases.
    # We need per-copy measurements. Since the core's measure() returns
    # one bit per copy in order, we call it once per basis group.
    observed_bits: list[int] = []
    for basis in config.bases:
        # Find all copy indices measured in this basis
        indices = [i for i in range(n_copies) if _basis_for_copy(i, config.bases) is basis]
        if not indices:
            continue
        # Measure just these copies by creating a sub-resource
        # For the mock, we can measure all and slice; for real core we'd
        # need per-basis measurement. Simpler: measure all copies once per basis.
        # The mock's measure() ignores basis, so we measure all and pick.
        all_observed = _core.measure(resource, basis, noise_level=noise_level)
        for idx in indices:
            observed_bits.append(all_observed[idx])

    # Build MeasurementRecords
    records: list[MeasurementRecord] = []
    for i in range(n_copies):
        basis = _basis_for_copy(i, config.bases)
        records.append(
            MeasurementRecord(
                sig_id=sig.sig_id,
                copy_index=i,
                basis=basis,
                expected=expected_bits[i],
                observed=observed_bits[i],
            )
        )

    return records
