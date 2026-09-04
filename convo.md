# M2 Working Session — Conversation Summary

Scratchpad of the M2 (QDS Protocol) working session. Shubhang's questions,
answered. Dated 2026-09-03/04.

---

## Q1. Implement the M2 scaffold — the QDS algorithm is NOT selected yet.

PR #5 (branch `d2`, commit `eb4301a`). Built inside the existing `protocol/`
package, not a new `m2_qds/` — and reusing the frozen `contracts.py` types
(`KeyPair`, `Signature`, `MeasurementRecord`) instead of parallel M2 models,
because `contracts.py` is the frozen seam five other tracks code against.

Created:

- `protocol/exceptions.py` — `QDSProtocolError` base, `ProtocolNotSelectedError`
  (also a `NotImplementedError` so either `except` idiom catches it),
  `QuantumCoreError`.
- `protocol/config.py` — frozen `QDSConfig` (`n_copies`/L, `noise_level`,
  `target_forgery_prob`, `bases` — empty by design, `seed`, `strict` flag) with
  validation. Deliberately NO threshold fields: s_a / s_v are M4's to derive
  from the noise floor and p_f.
- `protocol/quantum_interface.py` — `QuantumCore` `typing.Protocol` (4 methods:
  `bell_pairs`, `teleport`, `correction_for`, `measure`), a validator
  (`check_quantum_core`), and `M1QuantumCore`, a thin adapter over `core/`.
- `protocol/mock_quantum_core.py` — seeded deterministic mock for dev/tests.
  Loudly labelled: not a quantum simulation, no output of it is evidence of
  anything.
- `protocol/signer.py`, `protocol/verifier.py` — `keygen` / `sign` / `verify`
  gain optional `core` and `config` injection plus argument validation; three
  `ALGORITHM GOES HERE` blocks mark where the real construction plugs in.
  Backward compatible: old positional calls still work.
- `protocol/README.md` — architecture, responsibilities, non-responsibilities,
  M1 seam, plug-in points, open TODOs.
- 48 tests (`tests/test_signature.py`, `tests/test_quantum_core.py`).

Key decisions:

1. **Placeholder returns values by default** because M3/M4/M5 integrate against
   these functions today; `QDSConfig(strict=True)` makes every entry point raise
   `ProtocolNotSelectedError`, and tests assert both branches.
2. **`verify()` validates nothing about the signature** — a wrong key_id or stale
   nonce is a detection signal for M4, not an argument error. Raising would move
   detection into M2 and break the attack demo.
3. **`verify()` returns `[]`, which fails closed** — M4's `mismatch_rate` raises
   on empty input so "no data" can never read as a zero mismatch rate.
4. Environment had no pip/pytest; tests ran via `python3 -m unittest` — 48
   passed, 1 skipped (Qiskit not installed; lazy imports keep the suite
   Qiskit-free).

## Q2. PR description for #5?

Supplied a title and body covering: what's in (config, seam, injection,
exceptions, tests, README), what's deliberately absent (no signing equation, no
`VerificationResult` — that's M4's `DetectionResult`), and that `contracts.py`
was untouched with no new dependencies. Also flagged the branch name `d2` vs the
`m2-protocol` convention — `d2` reads as M4's detection deliverable.

## Q3. Do we need the algorithm now?

Not for what's in flight — M1 (circuits/noise), M3 (attack mutation through
public API), M4 (statistics), and the M2 scaffold's own tests all proceed
without it.

Blocked until selection:

- The three `ALGORITHM GOES HERE` blocks (`keygen`, `sign`, `verify`)
- `QDSConfig.bases`
- **D1, the maths document** — the forgery bound in L, the independence argument
  M2 owes M4's Hoeffding bound, the `verify()` complexity count
- Any real demo number (until real `MeasurementRecord`s flow, everything is
  placeholder data)

Practical answer: selection should land at least half a day before D1 is due —
that document cannot be written in a panic.

## Q4. What did PR #5 implement, and what is left?

PR #5 = the merge of branch `d2` into master — the M2 scaffold above.

Left to do in M2:

1. The three `ALGORITHM GOES HERE` blocks — needs the construction chosen.
2. `QDSConfig.bases` — stays empty till then.
3. The M1 adapter: M1's `core/` is now real (circuits, corrections, measurement
   helpers) but still only *builds* circuits — nobody runs one and returns
   per-shot results. One agreement with Ashab closes this.
4. Retire `MockQuantumCore` once the adapter works.
5. Maintenance: story continues on branch `d2_phase1`.

## Q5. PR #6 and PR #2 — what did they contain? (Both Ashab's, M1.)

**PR #2** — `core/pauli.py` made real: the four-entry correction table in frozen
circuit order (`(0,0)→I, (0,1)→X, (1,0)→Z, (1,1)→Y`), `apply_correction` with
bounds checks, plus `tests/test_pauli.py`. Review spawned PR #4 (rewrote the
"no elaborate suites" wording) and the physics was independently verified: 20
random states × 4 Bell outcomes simulated through teleportation.

**PR #6** — two halves of M1 made real:

- `core/teleportation.py`: 3-qubit teleportation (q0 message → q1 Alice →
  q2 Bob), depolarising noise dial on Bob's half, conditional corrections.
  Tested on Aer with seeds.
- `core/measurements.py`: `measure_in_basis` (Z direct, X: H, Y: S†H) and
  `records_from_shots` — the M1→M4 seam factory.
- `core/__init__.py`: first public export surface.

M2 compatibility check: everything is compatible; M1's correction table matches
the mock's; nothing in `protocol/` needs changing.

## Q6. What do you mean by "running the circuit"?

A Qiskit circuit is a recipe, not a result — building it produces no data.
"Running" means handing it to the Aer simulator, which plays it out and returns
measured bits. Ashab's functions return recipes (circuit builders); M2's
`sign`/`verify` need the actual bits (claimed corrections, measured outcomes).
Somebody must run the circuit and return per-shot results in order — that
"somebody" is the one missing five-line function to agree on with Ashab.

## Q7. What QDS algorithms are available to us?

General landscape:

| Family | Teleportation? | Security proof? |
|---|---|---|
| Gottesman–Chuang (2001), the original | No | Cleanest, canonical; verification via swap test (not Pauli projective measurement) |
| Clarke / Collins et al. (coherent states, state elimination) | No | Good, but optics-based — does not fit a qubit simulator |
| Dunjko–Wallden–Andersson 2014 / Wallden et al. 2015 (BB84 qubits, measure-at-distribution, L copies, s_a/s_v) | No | Strongest proofs incl. coherent forging attacks; `Verdict` enum already matches its two-threshold shape |
| Arbitrated quantum signatures (AQS) — the teleportation-native family | Yes, central | See Q8 — repeatedly broken |

## Q8. Teleportation-only options?

All teleportation-native signature schemes come from the AQS family:

1. Zeng & Keitel 2002 (GHZ + quantum one-time pad) — the first; analysis shown
   wrong, receiver can disavow.
2. Li et al. 2009 (Bell states, cheaper) — broken within a year.
3. GHZ-teleportation AQS 2020 — closest structural match to our setup; no
   formal proof.
4. Controlled-teleportation AQS 2022 — 5-qubit cluster channel, decoy particles;
   informal analysis.
5. Quantum-walk-based teleportation AQS — variant.
6. Superdense-teleportation QDS 2023 — only arbitrator-free one found; single
   unexamined paper.

The family warning: Gao et al. (PRA 2011) broke the AQS family wholesale
(receiver forgery, signer disavowal); the patch–publish–broken cycle has run for
fifteen years; an eprint from March 2026 broke four AQS schemes published this
year (forgeries, repudiation). Conclusion: no published teleportation-native QDS
has a solid information-theoretic proof.

Recommendation (team + Decision Log decide): **P1's proven verification
mathematics (BB84 qubits, Pauli projective measurements, L copies, s_a/s_v
thresholds) with teleportation as the distribution mechanism** — teleport the
public-key/signature states over Ashab's Bell channel. Teleportation does real
work, every primitive already exists in M1, the security proof is citable, and
the honest framing goes in D1: *teleportation-native schemes lack rigorous
proofs, so teleportation is used where it is sound (distribution) with the
proven measurement-statistics verification of Wallden et al. for signing.*

## Q9. Check whether something Kimi said is right?

Nothing from Kimi was ever provided. Awaiting the text to check.

---

Current repo state at end of session: branch `d2_phase1` off updated master;
master is at `6ee7578` (PR #7, M3 attacks wired to the real quantum core).
