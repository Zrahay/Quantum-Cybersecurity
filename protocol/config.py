"""Protocol parameters for M2. Track M2 (Shubhang).

Deliberately NOT in contracts.py: nothing outside M2 needs to read these,
and contracts.py is frozen. If another track ever does need one of these
fields, that is a Decision Log conversation, not a copy-paste.

WHAT IS NOT IN HERE, AND WILL NOT BE
------------------------------------
The acceptance thresholds s_a and s_v. Those are DERIVED by M4 from the
measured noise floor and the target forgery probability, per the working
agreement -- they are not configuration, and a hardcoded threshold field
here would be the easiest possible way to accidentally tune a demo. M2
carries `target_forgery_prob` as an input to that derivation and stops
there.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from contracts import Basis

from .quantum_interface import M1QuantumCore, QuantumCore, check_quantum_core

#: The bases P1 draws signature elements from. Z and X give the four BB84
#: states, which is the state set the coherent-forging proof is written for.
DEFAULT_BASES: tuple[Basis, ...] = (Basis.Z, Basis.X)


@dataclass(frozen=True)
class QDSConfig:
    """Parameters M2 needs to run the protocol."""

    n_copies: int = 64
    """L -- signature elements per signature, and copies each verifier measures.

    The security parameter: both the forging and the repudiation bound decay
    exponentially in L. 64 is a demo-scale figure chosen so the suite runs in
    seconds, NOT a security recommendation -- P1's forging bound only bites
    once L is large enough that exp[-2(1/8 - s_v L/K)^2 K] is small, and the
    L needed for a given p_f is a D1 calculation.
    """

    noise_level: float = 0.0
    """Depolarising channel parameter handed to M1. 0.0 is an ideal channel.

    A dial, not a class -- see the note at the bottom of contracts.py. M3
    turns it up to simulate channel tampering.

    NOT the mismatch rate. The depolarising error acts on the recipient's
    half of the Bell pair before the Bell measurement, so the mismatch rate
    it induces is some monotonic function of this number that must be
    MEASURED, not assumed. That measurement is the noise floor M4 derives
    s_a from.
    """

    target_forgery_prob: float = 1e-6
    """p_f -- the forgery probability the protocol is being sized for.

    CARRIED, NOT USED. M2 never compares anything against this; M4 combines
    it with the measured noise floor to derive s_a and s_v. It lives here
    because it is a property of the protocol being run, and both M2's choice
    of L and M4's thresholds have to be sized against the same number.
    """

    bases: tuple[Basis, ...] = DEFAULT_BASES
    """Bases signature elements are drawn from, and measured in.

    (Z, X) gives the four BB84 states. Adding Y is not free: P1's proof
    against coherent forging is written specifically for the BB84 state set
    and the paper says outright that it does not generalise to other state
    sets. Changing this changes the security argument, so it is a D1
    question, not a tuning knob.
    """

    seed: int | None = None
    """RNG seed for key material and basis choice. Set one in tests.

    Threaded into the default quantum core as well, so a whole run is
    reproducible from this one field.
    """

    def __post_init__(self) -> None:
        if self.n_copies < 1:
            raise ValueError(f"n_copies (L) must be at least 1, got {self.n_copies}")
        if not 0.0 <= self.noise_level <= 1.0:
            raise ValueError(f"noise_level must be a probability in 0.0-1.0, got {self.noise_level}")
        # Strictly positive: p_f = 0 asks for a bound of exp(-2 L m^2) == 0,
        # which no finite L satisfies, and p_f > 1 is not a probability.
        if not 0.0 < self.target_forgery_prob <= 1.0:
            raise ValueError(
                f"target_forgery_prob (p_f) must be in (0.0, 1.0], got {self.target_forgery_prob}"
            )
        if not self.bases:
            raise ValueError("bases must name at least one measurement basis")
        for basis in self.bases:
            if not isinstance(basis, Basis):
                raise TypeError(f"bases must contain contracts.Basis members, got {basis!r}")
        if len(set(self.bases)) != len(self.bases):
            # A repeated basis silently reweights the random draw, which
            # skews the fraction of conclusive elements and therefore the
            # threshold derivation. Almost certainly a typo.
            raise ValueError(f"bases must not repeat a basis, got {self.bases}")


def derive_rng(seed: int | None, label: str) -> random.Random:
    """An RNG stream for `label`, independent of every other label.

    THIS EXISTS BECAUSE OF A REAL BUG. `keygen` and `verify` both seeded
    `random.Random(config.seed)` directly and both then drew basis choices
    first, so the verifier's "random" basis sequence was bit-for-bit Alice's.
    Every element came out conclusive instead of half of them, and a forged
    signature scored a 0.000 mismatch rate -- perfect marks -- because the
    only elements that survived elimination were the ones the forger had
    guessed right.

    Nothing about that failure looks like a seeding mistake from the
    outside: the physics is fine, the types are fine, and the numbers are
    plausible until you notice L/2 elements should have been discarded.
    Independence of Alice's preparation basis from the recipient's
    measurement basis is a SECURITY property of P1, not a convenience, so
    the streams are derived separately and named.

    A `None` seed gives a fresh nondeterministic stream, which is
    independent anyway.
    """
    if seed is None:
        return random.Random()
    return random.Random(f"{seed}/{label}")


def resolve_dependencies(
    core: object | None, config: QDSConfig | None
) -> tuple[QuantumCore, QDSConfig]:
    """Normalise the two injected dependencies every M2 entry point takes.

    Lives here rather than in signer.py so verifier.py does not have to reach
    across for a private helper.

    `core=None` means the REAL backend, seeded from the config. Defaulting to
    the mock would be the wrong way round -- a caller who forgets to inject
    would silently get closed-form fake data and never know. Constructing
    `M1QuantumCore` is free and imports no Qiskit; only calling it does.

    Validating the core here, rather than at first use, means a bad
    injection fails with a message that names the problem instead of an
    AttributeError from deep inside the protocol, whose traceback would
    point at M2 for what is an M1 wiring mistake.
    """
    config = config if config is not None else QDSConfig()
    if core is None:
        return M1QuantumCore(seed=config.seed), config
    return check_quantum_core(core), config
