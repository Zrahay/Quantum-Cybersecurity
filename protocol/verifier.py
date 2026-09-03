"""QDS verification. Track M2 (Shubhang).

STUB -- importable and correctly typed. Real implementation is M2's.

verify() produces measurement records. It does NOT decide accept or reject
-- that is M4's job. Keeping this seam clean stops the two tracks
duplicating logic and then disagreeing.
"""

from __future__ import annotations

from contracts import KeyPair, MeasurementRecord, Signature


def verify(sig: Signature, key: KeyPair, noise_level: float = 0.0) -> list[MeasurementRecord]:
    """Measure the signature copies and return one record per measurement."""
    # TODO(M2): real verification.
    return []
