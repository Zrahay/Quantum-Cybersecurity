"""The seam between M2 and M1. Track M2 (Shubhang), consumed from M1 (Ashab).

WHY THIS FILE EXISTS AT ALL
---------------------------
The working agreement says not to add an interface with one implementation.
This one has two -- `M1QuantumCore` (the real thing, thin) and
`MockQuantumCore` (deterministic, for tests) -- and it earns its keep for a
specific reason: every quantum primitive in `core/` is currently a stub that
returns `[]`, `PauliOp.I` or an empty circuit. Without a mock, M2 cannot be
exercised at all until M1 lands, and the two tracks serialise. With one, M2
develops in parallel and the integration is a one-line swap.

If M1 finishes and the mock stops being useful, delete the mock and collapse
this file into direct `core.*` imports. That is a cheap change and it is the
right one to make -- do not keep an abstraction out of sentiment.

EVERYTHING BELOW IS PROVISIONAL
-------------------------------
These method names and signatures are M2's *guess* at what it will need,
written against M1's current stubs. They are not agreed with M1 and they are
not in contracts.py, precisely so that they can be changed without a
Decision Log entry. Two known gaps:

  * M1 currently exposes circuit BUILDERS (`teleportation_circuit`) while M2
    wants measurement RESULTS. Somebody has to run the circuit and preserve
    per-shot ordering; `core.measurements.records_from_shots` says that is
    the caller's job. Until M1 exposes a result-returning entry point,
    `M1QuantumCore` raises on those methods rather than guessing.
  * Whether M2 holds an entanglement resource across calls, or re-prepares
    per signature, is a property of the QDS construction nobody has chosen.
    Hence `EntanglementResource` is opaque -- see below.

WHAT THIS FILE MUST NEVER CONTAIN
---------------------------------
QDS logic. This is the quantum-primitive layer: Bell pairs, teleportation,
Pauli corrections, projective measurement, and a noise dial. Anything that
knows what a *signature* is belongs in signer.py or verifier.py.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from contracts import Basis, PauliOp

from .exceptions import QuantumCoreError

# Opaque by design. Whatever M1 hands back to represent shared entanglement
# -- a QuantumCircuit, a Statevector, a register handle, an integer id -- M2
# only ever passes it straight back in. M2 must not inspect it, index it, or
# assume it is picklable; doing so would hard-code an assumption about how
# Bell pairs are used, which is exactly the decision that has not been made.
EntanglementResource = Any

#: The methods `check_quantum_core` requires. Single source of truth so the
#: validator cannot drift from the Protocol below.
_REQUIRED_METHODS = ("bell_pairs", "teleport", "correction_for", "measure")


@runtime_checkable
class QuantumCore(Protocol):
    """What M2 expects M1 to provide.

    Structural (`typing.Protocol`), not an ABC, matching `contracts.Adversary`:
    M1's modules are plain functions today, and a nominal base class would
    force Ashab to inherit from an M2-owned type to satisfy M2's tests.

    `noise_level` is a keyword parameter on every operation that touches the
    channel rather than a Channel object, per the note at the bottom of
    contracts.py. 0.0 is ideal; M3 turns the dial up.
    """

    def bell_pairs(self, n: int, *, noise_level: float = 0.0) -> EntanglementResource:
        """Prepare `n` entangled pairs and return an opaque handle to them.

        M2 expects: a handle it can pass to `teleport` and `measure`. M2 does
        not interpret it. PROVISIONAL -- if the chosen protocol prepares
        resources per message bit rather than per signature, this grows a
        second argument.
        """
        ...

    def teleport(
        self, resource: EntanglementResource, *, noise_level: float = 0.0
    ) -> list[tuple[int, int]]:
        """Teleport through `resource`, returning the Bell-measurement outcomes.

        M2 expects: one (clbit0, clbit1) pair per teleported qubit, in
        CIRCUIT ORDER -- control qubit's bit FIRST. That is the frozen
        ordering of `Signature.bell_outcomes` and it is deliberately NOT
        Qiskit's little-endian count-string order. Converting at this
        boundary is M1's job; see the ordering note in core/bell.py. Getting
        it backwards produces wrong Pauli corrections on exactly the (0,1)
        and (1,0) outcomes, which looks indistinguishable from channel noise.
        """
        ...

    def correction_for(self, bell_outcome: tuple[int, int]) -> PauliOp:
        """The Pauli correction implied by one Bell-measurement outcome.

        M2 expects: a pure lookup, no channel involvement, hence no
        `noise_level`. This is the one method M1 already implements the shape
        of (`core.pauli.correction_for`).
        """
        ...

    def measure(
        self, resource: EntanglementResource, basis: Basis, *, noise_level: float = 0.0
    ) -> list[int]:
        """Projectively measure `resource` in `basis`, one bit per copy.

        M2 expects: MEASURED CLASSICAL BITS (0 or 1), never the +/-1 Pauli
        eigenvalues, and PER-COPY ORDER PRESERVED -- position i is copy i.
        Both requirements come straight from contracts.MeasurementRecord:
        writing -1 there makes every record a mismatch and rejects every
        legitimate signature, and an aggregated counts dict destroys the
        `copy_index` that the exponential-in-L forgery bound depends on.
        """
        ...


def check_quantum_core(core: object) -> QuantumCore:
    """Validate an injected core, returning it unchanged, or raise.

    Fails loudly at the injection point instead of with an AttributeError
    somewhere deep inside verification, where the traceback would point at
    M2 for what is an M1 wiring mistake.

    Only method PRESENCE is checked -- that is all `runtime_checkable`
    Protocols can do, and all this can do. Signature mismatches still
    surface as TypeError at the call site. Static checking is the real
    defence here; this is just a better error message.
    """
    missing = [name for name in _REQUIRED_METHODS if not callable(getattr(core, name, None))]
    if missing:
        raise QuantumCoreError(
            f"{type(core).__name__} does not satisfy the QuantumCore interface; "
            f"missing or non-callable: {', '.join(missing)}"
        )
    return core  # type: ignore[return-value]


class M1QuantumCore:
    """Thin adapter over `core/`. The real QuantumCore backend.

    Holds no state and owns no logic -- every method delegates to core.runtime
    or core.pauli. `core.*` is imported lazily so `import protocol` still works
    without Qiskit/Aer; *calling* these methods requires them.
    """

    def bell_pairs(self, n: int, *, noise_level: float = 0.0) -> EntanglementResource:
        from core.runtime import prepare_batch

        return prepare_batch(n, noise_level)

    def teleport(
        self, resource: EntanglementResource, *, noise_level: float = 0.0
    ) -> list[tuple[int, int]]:
        from core.runtime import run_teleport_bell_outcomes

        # Call-site noise wins over the batch default (verify threads it in).
        return run_teleport_bell_outcomes(resource, noise_level=noise_level)

    def correction_for(self, bell_outcome: tuple[int, int]) -> PauliOp:
        from core.pauli import correction_for

        return correction_for(bell_outcome)

    def measure(
        self, resource: EntanglementResource, basis: Basis, *, noise_level: float = 0.0
    ) -> list[int]:
        from core.runtime import run_measure_bits

        return run_measure_bits(resource, basis, noise_level=noise_level)
