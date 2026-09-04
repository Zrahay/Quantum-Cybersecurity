"""Analytic reference core. Track M2 (Shubhang). Tests and development only.

*** NOT A QUANTUM SIMULATOR. ***

It builds no circuits, tracks no state vector, and models no entanglement.
What it does do -- and the reason it is still here now that `M1QuantumCore`
works -- is reproduce the ONE physical fact the signature protocol depends
on, in closed form:

    An eigenstate of a Pauli, teleported without error and then measured
    in the SAME Pauli basis, returns its eigenvalue bit with certainty.
    Measured in a DIFFERENT Pauli basis, the outcome is uniform.

That is exact quantum mechanics for the states this protocol uses, not an
approximation, and `tests/test_runtime.py` pins the real Aer path to the
same behaviour. So `teleport_and_measure` here is a faithful ideal-channel
model, which makes it possible to test the protocol logic -- key material,
basis agreement, mismatch counting -- deterministically and without Aer.

What it is NOT faithful about, and must never be quoted on:

  * **Noise.** `noise_level` is an independent per-bit flip. The real
    channel is a depolarising error on the recipient's half of the Bell
    pair, applied before the Bell measurement, and its induced mismatch
    rate is NOT equal to `noise_level` -- measure it, do not assume it.
    Every noise-floor number in the deck must come from `M1QuantumCore`.
  * **Bell outcomes.** Uniform random draws, not the actual measurement of
    an entangled pair. Nothing about `bell_outcomes` from here is evidence.
  * Anything at all about security. It cannot forge and cannot be forged.

Bottom line: use it to test protocol LOGIC, never to produce a number.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from collections.abc import Sequence

from contracts import Basis, PauliOp

#: Arbitrary fixed default so an un-seeded core is still reproducible across
#: runs. A `None` default would make M2's tests flaky for no gain.
DEFAULT_SEED = 20260903


@dataclass(frozen=True)
class MockResource:
    """Stand-in for `core.runtime.EntanglementBatch`.

    Mirrors that class's fields on purpose so the adapter swap is
    mechanical. M2 treats it as opaque (see `EntanglementResource`); it is
    public only so this module's own tests can assert on it.
    """

    n_pairs: int
    noise_level: float


class MockQuantumCore:
    """Seeded, closed-form implementation of the QuantumCore interface.

    Determinism is per-instance and per-CALL-SEQUENCE: one RNG advances
    across all methods, so `MockQuantumCore(seed=1)` replayed with the same
    sequence of calls gives the same answers, while interleaving calls
    differently gives different ones. Use `reset()` to rewind.
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
        _require_probability(noise_level)
        return MockResource(n_pairs=n, noise_level=noise_level)

    def teleport(
        self,
        resource: MockResource,
        preparations: Sequence[tuple[Basis, int]] | None = None,
        *,
        noise_level: float = 0.0,
    ) -> list[tuple[int, int]]:
        """Uniform random (clbit0, clbit1) pairs, one per pair in `resource`.

        Uniform over the four outcomes is the one statistical property of a
        real Bell measurement this reproduces, and it is reproduced because
        an unbalanced draw would make M4's chi-square scaffolding look
        broken during development -- not because it makes this physical.

        `preparations`, when given, is validated for shape but otherwise
        IGNORED: a real Bell outcome is independent of what's teleported
        (no-signaling), which is exactly why this uniform draw is correct
        physics regardless of `preparations` -- see the real Aer path,
        pinned to the same independence in tests/test_runtime.py.
        """
        if preparations is not None:
            if len(preparations) != resource.n_pairs:
                raise ValueError(
                    f"preparations length {len(preparations)} does not match "
                    f"batch size {resource.n_pairs}"
                )
            for i, (basis, bit) in enumerate(preparations):
                _require_basis(basis, f"preparations[{i}][0]")
                if bit not in (0, 1):
                    raise ValueError(f"preparations[{i}][1] must be a bit; got {bit!r}")
        return [
            (self._rng.getrandbits(1), self._rng.getrandbits(1))
            for _ in range(resource.n_pairs)
        ]

    def correction_for(self, bell_outcome: tuple[int, int]) -> PauliOp:
        """Standard |Phi+> correction lookup.

        Follows the textbook convention (00 -> I, 01 -> X, 10 -> Z,
        11 -> Y) so that output is self-consistent. NOT authoritative:
        `core.pauli.correction_for` is, M1 owns it, and if the two ever
        disagree M1 wins and this changes.
        """
        b0, b1 = bell_outcome
        if b0 not in (0, 1) or b1 not in (0, 1):
            raise ValueError(f"Bell outcome must be two bits, got {bell_outcome!r}")
        return ((PauliOp.I, PauliOp.X), (PauliOp.Z, PauliOp.Y))[b0][b1]

    def measure(
        self, resource: MockResource, basis: Basis, *, noise_level: float = 0.0
    ) -> list[int]:
        """Uniform random bits, one per copy, optionally flipped by noise.

        `basis` is validated then IGNORED: with no prepared state there is
        nothing for the basis to be relative to. `teleport_and_measure` is
        the method that respects it.
        """
        _require_basis(basis, "basis")
        _require_probability(noise_level)
        return [self._noisy(self._rng.getrandbits(1), noise_level) for _ in range(resource.n_pairs)]

    def teleport_and_measure(
        self,
        resource: MockResource,
        preparations: Sequence[tuple[Basis, int]],
        bases: Sequence[Basis],
        *,
        noise_level: float = 0.0,
    ) -> list[tuple[tuple[int, int], int]]:
        """Closed-form ideal teleportation of Pauli eigenstates.

        Same basis -> the prepared bit, with certainty. Different basis ->
        a uniform bit. Then a per-bit flip at `noise_level`, which is a
        stand-in for the channel and not a model of it (see module
        docstring).
        """
        if len(preparations) != resource.n_pairs:
            raise ValueError(
                f"preparations length {len(preparations)} does not match batch "
                f"size {resource.n_pairs}"
            )
        if len(bases) != resource.n_pairs:
            raise ValueError(
                f"bases length {len(bases)} does not match batch size {resource.n_pairs}"
            )
        _require_probability(noise_level)

        results: list[tuple[tuple[int, int], int]] = []
        for i, ((prep_basis, prep_bit), meas_basis) in enumerate(zip(preparations, bases)):
            _require_basis(prep_basis, f"preparations[{i}][0]")
            _require_basis(meas_basis, f"bases[{i}]")
            if prep_bit not in (0, 1):
                raise ValueError(f"preparations[{i}][1] must be a bit; got {prep_bit!r}")
            bell = (self._rng.getrandbits(1), self._rng.getrandbits(1))
            bit = prep_bit if meas_basis is prep_basis else self._rng.getrandbits(1)
            results.append((bell, self._noisy(bit, noise_level)))
        return results

    def _noisy(self, bit: int, noise_level: float) -> int:
        if noise_level > 0.0 and self._rng.random() < noise_level:
            return bit ^ 1
        return bit


def _require_basis(value: object, name: str) -> None:
    if not isinstance(value, Basis):
        raise TypeError(f"{name} must be a contracts.Basis, got {type(value).__name__}")


def _require_probability(value: float) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {value}")
