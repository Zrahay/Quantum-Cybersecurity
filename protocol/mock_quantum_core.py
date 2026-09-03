"""DEVELOPMENT AND TEST MOCK. Track M2 (Shubhang).

*** THIS IS NOT A QUANTUM SIMULATION. ***

It does not model superposition, entanglement, decoherence or measurement
back-action. It returns seeded pseudo-random bits of the right shape. Its
only job is to satisfy the QuantumCore interface so that M2's architecture
can be tested while every primitive in core/ is still a stub.

Consequences, stated plainly because they matter for the submission:

  * No output of this module is evidence of anything. Not a mismatch rate,
    not a noise floor, not a forgery probability. Nothing from here goes in
    the deck, on the dashboard, or into a benchmark.
  * The real backend is `M1QuantumCore`. Swapping this for that is a
    one-argument change at the call site -- that is the whole point of the
    interface.
  * Nothing in the detection path depends on this file. It exists on the
    test side of the seam only.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from contracts import Basis, PauliOp

#: Arbitrary fixed default so an un-seeded mock is still reproducible across
#: runs. A `None` default would make M2's tests flaky for no gain.
DEFAULT_SEED = 20260903


@dataclass(frozen=True)
class MockResource:
    """Stand-in for whatever M1 will hand back from `bell_pairs`.

    M2 treats this as opaque (see `EntanglementResource`) -- it is public
    only so the mock's own tests can assert the mock is behaving. If M2 code
    outside this module ever reads `.n_pairs`, that is a bug: it means M2 has
    started depending on the resource representation, which is M1's to
    choose.
    """

    n_pairs: int
    noise_level: float


class MockQuantumCore:
    """Seeded placeholder implementation of the QuantumCore interface.

    Determinism is per-instance and per-CALL-SEQUENCE: one RNG advances
    across all methods, so `MockQuantumCore(seed=1)` replayed with the same
    sequence of calls gives the same answers, while interleaving calls
    differently gives different ones. That is enough for reproducible tests
    and honest about what it is. Use `reset()` to rewind.
    """

    def __init__(self, seed: int = DEFAULT_SEED) -> None:
        self.seed = seed
        self._rng = random.Random(seed)

    def reset(self) -> None:
        """Rewind the RNG to the seed, so a call sequence can be replayed."""
        self._rng = random.Random(self.seed)

    def bell_pairs(self, n: int, *, noise_level: float = 0.0) -> MockResource:
        """Record the request. No state is prepared -- there is no state."""
        if n < 1:
            raise ValueError(f"need at least one Bell pair, got {n}")
        if not 0.0 <= noise_level <= 1.0:
            raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {noise_level}")
        return MockResource(n_pairs=n, noise_level=noise_level)

    def teleport(
        self, resource: MockResource, *, noise_level: float = 0.0
    ) -> list[tuple[int, int]]:
        """Uniform random (clbit0, clbit1) pairs, one per pair in `resource`.

        Uniform over the four outcomes is the one statistical property of a
        real Bell measurement this reproduces, and it is reproduced because
        an unbalanced mock would make M4's chi-square scaffolding look broken
        during development -- not because it makes the mock physical.
        """
        return [(self._rng.getrandbits(1), self._rng.getrandbits(1)) for _ in range(resource.n_pairs)]

    def correction_for(self, bell_outcome: tuple[int, int]) -> PauliOp:
        """Standard |Phi+> correction lookup.

        This follows the textbook convention (00 -> I, 01 -> X, 10 -> Z,
        11 -> Y) rather than returning noise, so that mock output is
        self-consistent. It is NOT authoritative: `core.pauli.correction_for`
        is, M1 owns it, and if the two ever disagree M1 wins and this changes.
        """
        b0, b1 = bell_outcome
        if b0 not in (0, 1) or b1 not in (0, 1):
            raise ValueError(f"Bell outcome must be two bits, got {bell_outcome!r}")
        return ((PauliOp.I, PauliOp.X), (PauliOp.Z, PauliOp.Y))[b0][b1]

    def measure(
        self, resource: MockResource, basis: Basis, *, noise_level: float = 0.0
    ) -> list[int]:
        """Uniform random bits, one per copy, optionally flipped by noise.

        `basis` is validated and then IGNORED -- distinguishing Z from X
        requires the physics this mock does not have. The flip is an
        independent per-bit coin at rate `noise_level`; a depolarising
        channel it is not.

        Returns classical bits (0/1), never +/-1 eigenvalues, per
        contracts.MeasurementRecord.
        """
        if not isinstance(basis, Basis):
            raise TypeError(f"basis must be a contracts.Basis, got {type(basis).__name__}")
        if not 0.0 <= noise_level <= 1.0:
            raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {noise_level}")
        bits = []
        for _ in range(resource.n_pairs):
            bit = self._rng.getrandbits(1)
            if noise_level > 0.0 and self._rng.random() < noise_level:
                bit ^= 1
            bits.append(bit)
        return bits
