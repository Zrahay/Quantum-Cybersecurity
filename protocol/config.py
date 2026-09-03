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

from dataclasses import dataclass, field

from contracts import Basis

from .quantum_interface import QuantumCore, check_quantum_core


@dataclass(frozen=True)
class QDSConfig:
    """Parameters M2 needs to run the protocol.

    Defaults are chosen to be *safe and boring*, not scientific. Any value
    whose meaning depends on the unselected QDS construction defaults to
    something inert (0.0, empty, None) rather than to an invented constant.
    """

    n_copies: int = 64
    """L -- copies of the signature handed to each verifier.

    The one parameter with a real, protocol-independent meaning: the
    information-theoretic forgery bound decays exponentially in L, so L is
    the security parameter. 64 matches the existing keygen default and is a
    demo-scale figure, not a security recommendation.
    """

    noise_level: float = 0.0
    """Depolarising channel parameter handed to M1. 0.0 is an ideal channel.

    A dial, not a class -- see the note at the bottom of contracts.py. M3
    turns this up to simulate channel tampering.
    """

    target_forgery_prob: float = 1e-6
    """p_f -- the forgery probability the protocol is being sized for.

    CARRIED, NOT USED. M2 never compares anything against this; M4 combines
    it with the measured noise floor to derive s_a and s_v. It lives here
    because it is a property of the protocol being run, and both M2's choice
    of L and M4's thresholds have to be sized against the same number.
    """

    bases: tuple[Basis, ...] = field(default_factory=tuple)
    """Measurement bases verification uses. EMPTY BY DESIGN.

    Which Pauli bases a verifier measures in, and in what proportion, is a
    property of the chosen QDS construction. Defaulting this to (Z,) or
    (Z, X) would be inventing protocol semantics, so it defaults to empty
    and verify() will demand a non-empty choice once the algorithm lands.
    """

    seed: int | None = None
    """RNG seed. Set one in tests so a failure can be reproduced exactly."""

    strict: bool = False
    """Refuse to run at all while the QDS algorithm is unselected.

    False by default: the placeholder keygen/sign paths are what M3, M4 and
    M5 currently integrate against, and breaking five tracks to make a point
    is not a trade worth making. Set True -- as the M2 tests do -- to assert
    that the protocol honestly reports itself unimplemented rather than
    quietly handing back placeholder data.
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


def resolve_dependencies(
    core: object | None, config: QDSConfig | None
) -> tuple[QuantumCore | None, QDSConfig]:
    """Normalise the two injected dependencies every M2 entry point takes.

    Lives here rather than in signer.py so verifier.py does not have to reach
    across for a private helper.

    Validating the core at the top of each entry point, instead of at first
    use, means a bad injection fails with a message that names the problem --
    not with an AttributeError from somewhere deep inside the protocol, whose
    traceback would point at M2 for what is an M1 wiring mistake.
    """
    config = config if config is not None else QDSConfig()
    return (check_quantum_core(core) if core is not None else None), config
