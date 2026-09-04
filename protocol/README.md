# M2 — QDS Protocol

Track M2 (Shubhang). Deliverable D1.

**Status: implemented.** The protocol is P1, from Wallden, Dunjko, Kent &
Andersson, "Quantum digital signatures with quantum-key-distribution
components", Phys. Rev. A 91, 042304 (2015) — arXiv:1403.5551 — with the
distribution stage carried by teleportation over Bell pairs rather than by
direct transmission. `keygen`, `sign` and `verify` are real; the
`ALGORITHM GOES HERE` blocks are gone.

## Responsibilities

M2 owns three operations and the D1 mathematical model behind them:

| Operation | Signature | Returns |
|---|---|---|
| `keygen` | `keygen(signer_id, n_copies=None, *, core=None, config=None)` | `contracts.KeyPair` |
| `sign` | `sign(message, key, *, core=None, config=None)` | `contracts.Signature` |
| `verify` | `verify(sig, key, noise_level=None, *, core=None, config=None)` | `list[contracts.MeasurementRecord]` |

Import them from the package, not the submodules:

```python
from protocol import keygen, sign, verify, QDSConfig, MockQuantumCore
```

## What M2 is *not* responsible for

Getting these wrong means two tracks implement the same thing and then disagree
about it in front of a judge.

- **Accept/reject.** `verify()` produces measurement records; it does not return
  a verdict. `Verdict`, thresholds, Hoeffding bounds and chi-square all belong to
  M4 (`detection/`).
- **The thresholds `s_a` / `s_v`.** Derived by M4 from the measured noise floor
  and `p_f`. `QDSConfig` deliberately has no threshold field, and there is a test
  asserting it never gains one.
- **Quantum primitives.** Bell pairs, teleportation, Pauli corrections and
  projective measurement are M1's (`core/`), reached through the `QuantumCore`
  seam.
- **Adversarial mutation.** M3 (`attacks/`) builds mutated `Signature` objects.
  Note that `verify()` therefore does *not* validate the signature it is given —
  a wrong `key_id` or a stale nonce is a detection signal, not an argument error,
  and raising on it would move detection into M2.

## Architecture

```
M1  core/            bell pairs · teleportation · Pauli correction · measurement
      |
      |  QuantumCore interface  (protocol/quantum_interface.py)
      |    M1QuantumCore    -- thin adapter over core/, the real backend
      |    MockQuantumCore  -- analytic ideal-channel model, tests only
      v
M2  protocol/        keygen · sign · verify        <- P1, implemented
      |
      |  list[MeasurementRecord]   the only type crossing this seam
      v
M4  detection/       thresholds · Hoeffding · chi-square · classification
      |
      |  DetectionResult
      v
M5  app/             dashboard — renders, recomputes nothing
```

`contracts.py` is frozen and already defines `KeyPair`, `Signature` and
`MeasurementRecord`. M2 adds **no parallel models** — a `QDSKeyPair` alongside
`KeyPair`, or a `VerificationResult` alongside `DetectionResult`, would duplicate
frozen types and drift from the other five tracks. The only new model here is
`QDSConfig`, which nothing outside M2 reads.

## The protocol, in one paragraph

For each of `L` signature elements, Alice holds a Pauli eigenstate — a
`(pauli_map[i], private_bits[i])` pair naming one of the four BB84 states.
Signing declares that classical description and teleports the states to the
recipient. Verification is **state elimination**: the recipient measures each
element in a basis chosen independently of Alice, and keeps only the elements
where their basis matches the declared Pauli. On those, a disagreement is a
genuine contradiction. About `L/2` elements survive (P1's `K`), and the
mismatch rate over them is the statistic M4 thresholds against `s_a` and `s_v`.

## The M1 → M2 interface

`protocol/quantum_interface.py` defines `QuantumCore`, a `typing.Protocol`
(structural, matching `contracts.Adversary`) with five methods:

| Method | M2 expects back |
|---|---|
| `bell_pairs(n, *, noise_level)` | an **opaque** handle, passed straight back in — M2 never inspects it |
| `teleport(resource, *, noise_level)` | `(clbit0, clbit1)` per qubit, control bit **first**, circuit order |
| `correction_for(bell_outcome)` | a `PauliOp`; pure lookup, no channel |
| `measure(resource, basis, *, noise_level)` | classical bits `0`/`1`, **per-copy order preserved** |
| `teleport_and_measure(resource, preparations, bases, *, noise_level)` | `((clbit0, clbit1), bob_bit)` per copy, **both halves from the same shot** |

`teleport_and_measure` is the method the signature protocol actually runs.
`teleport` and `measure` remain because they are cheaper when only one half of
the process is needed, and because M3 already uses the teleport path. The
single-shot requirement on `teleport_and_measure` is the whole reason it
exists separately: calling `teleport` then `measure` runs two independent
shots, so the Bell outcome and the measured bit describe *different copies*,
and legitimate signatures show a ~50% mismatch rate — a failure that looks
like broken physics rather than a broken call sequence.

Three details are load-bearing and each has a comment in `contracts.py` behind it:

- **Bit order.** `Signature.bell_outcomes` is frozen as circuit order, *not*
  Qiskit's little-endian count-string order. Reversed, it only shows up on the
  `(0,1)` / `(1,0)` outcomes — about half of runs — as wrong Pauli corrections
  that are indistinguishable from channel noise.
- **Bits, not eigenvalues.** `MeasurementRecord` takes `0`/`1`. "Predicts the +1
  eigenstate" is `expected=0`. Returning `-1` makes every record a mismatch and
  rejects 100% of legitimate signatures.
- **Per-copy order.** A Qiskit counts dict is aggregated, so `copy_index` would
  have to be invented by `enumerate()` — and the forgery bound's exponential
  decay in `L` would be resting on a fiction.

`noise_level` is a keyword parameter, not a `Channel` object: the channel is a
dial, per the note at the bottom of `contracts.py`.

### Why the interface still has two implementations

The working agreement says not to add an interface with one implementation. This
one has two, and it earns them:

- **`M1QuantumCore`** is the real backend, a thin adapter over `core/runtime.py`
  and `core/pauli.py`. It imports `core.*` lazily so `import protocol` works
  without Qiskit/Aer; *calling* its methods requires them.
- **`MockQuantumCore`** is an analytically exact ideal-channel model: same-basis
  measurement returns the prepared bit with certainty, cross-basis is uniform.
  It is NOT a quantum simulator — it builds no circuits — but for the states P1
  uses, its `teleport_and_measure` is faithful to the ideal physics, which makes
  it possible to test protocol *logic* (key material, basis agreement, mismatch
  counting) deterministically and without Aer. `tests/test_runtime.py` pins the
  real Aer path to the same two properties, so a mock pass plus a runtime pass
  is evidence the protocol is correct and the backend is faithful.

**What is NOT faithful about the mock, and must never be quoted on:**

- **Noise.** `noise_level` is an independent per-bit flip. The real channel is a
  depolarising error on the recipient's half of the Bell pair, applied before
  the Bell measurement, and its induced mismatch rate is NOT equal to
  `noise_level` — measure it, do not assume it. Every noise-floor number in the
  deck must come from `M1QuantumCore`.
- **Bell outcomes.** Uniform random draws, not the actual measurement of an
  entangled pair. Nothing about `bell_outcomes` from the mock is evidence.
- Anything at all about security. It cannot forge and cannot be forged.

## Mapping onto the frozen contracts

| Contract field | P1 meaning | Notes |
|---|---|---|
| `KeyPair.private_bits[i]` | eigenvalue bit of element `i`: 0 for +1, 1 for -1 | matches `MeasurementRecord.expected` convention |
| `KeyPair.pauli_map[i]` | which Pauli element `i` is an eigenstate of: `Z` or `X` | the contract comment says "message bit -> required correction", which is a different reading of the same field; the TYPE is unchanged and no other track reads it, so nothing breaks, but the comment is now wrong — correcting it is a Decision Log item |
| `KeyPair.n_copies` | `L`, the number of signature elements | the security parameter |
| `Signature.declared_ops` | the Pauli of each element, which together with `private_bits` is the classical description P1 calls `PrivKey` | length `L`, not `len(message)` |
| `Signature.bell_outcomes` | Alice's Bell-measurement results from teleporting the `L` elements | length `L`; the recipient needs these to apply the right Pauli correction |
| `MeasurementRecord.copy_index` | the element's original position in `0..L-1` | not a renumbering of the survivors — the exponential-in-`L` bound only means anything if the index is real |
| `MeasurementRecord.expected` | Alice's eigenvalue bit for that element | 0 means +1 eigenstate, per the contract |
| `MeasurementRecord.observed` | the bit the recipient measured | 0/1, never +1/-1 |

## RNG stream independence

`protocol/config.py:derive_rng(seed, label)` derives independent `random.Random`
streams from `(seed, label)`. The signer draws key material from
`KEY_MATERIAL_STREAM = "keygen/elements"`; the verifier draws measurement bases
from `MEASUREMENT_BASIS_STREAM = "verify/bases"`. The labels MUST differ.

This exists because of a real bug: `keygen` and `verify` both originally seeded
`random.Random(config.seed)` directly, so the verifier reproduced Alice's basis
choices exactly. Every element came out conclusive, and a forged signature
scored a perfect 0.000 mismatch rate — undetectable. Independence of Alice's
preparation basis from the recipient's measurement basis is a SECURITY property
of P1, not a convenience. `tests/test_signature.py::TestRngStreamIndependence`
is the regression guard.

## Tests

```
python3 -m unittest tests.test_signature tests.test_quantum_core tests.test_runtime -v
```

Three layers, all load-bearing:

1. **`test_signature.py`** — API shape and validation, plus P1 behaviour:
   legitimate mismatch is exactly 0 on the ideal channel, forgery mismatch is
   ~1/4 and separates from legitimate, impersonation separates, fail-closed on
   `PauliOp.I`, RNG stream independence.
2. **`test_quantum_core.py`** — the `QuantumCore` interface, validator, mock
   determinism, and the analytically exact `teleport_and_measure` properties on
   both the mock and the real Aer adapter.
3. **`test_runtime.py`** — `core/runtime.py`: bit-order conversion, the
   prepare/measure round-trip, and the same two physics properties pinned to
   the real Aer path.

## Stated limitations (belong in D1, openly)

1. **One-time key, one message.** P1 is a one-time signature: Alice needs an
   independent `L`-element sequence for each `(message bit position, bit value)`
   pair, so signing an `m`-bit message consumes `2m` sequences. The frozen
   `KeyPair` holds exactly one sequence, so one `KeyPair` here signs one
   message, and the message is bound to the signature classically rather than
   by which key sequence is revealed. **Key reuse across messages is not
   prevented by this implementation.** Fixing it needs a `KeyPair` able to hold
   `2mL` elements — a Decision Log item. Until then, one key, one message.

2. **Replay detection is not quantum.** No-cloning means the quantum state
   cannot be copied and resent, so a replay is necessarily a reused *classical*
   transcript, and the defence is nonce plus timestamp freshness at the
   protocol layer. No-cloning *forces* this — say so.

3. **Hoeffding assumes independent measurement outcomes**, and chi-square needs
   an expected count of at least 5 per cell. The independence is justified here:
   each element's basis and bit are drawn independently in `keygen`, so the
   recipient's `L` measurement outcomes are independent too. Correlating them
   would invalidate the bound while leaving every test passing. Both
   assumptions belong in D1, stated explicitly, not buried.

4. **`verify()` is `O(L)`** in measurements, with no per-copy re-derivation of
   the key. Low computational complexity is a stated requirement of the problem
   statement; put the count in D1.

## Open items

1. **M3 coordination.** `sign()` returns `L`-length `declared_ops` and
   `bell_outcomes`, but M3's adversaries currently size their mutations off
   `len(sig.message)`. A real signature's `message` is short (e.g. `(1, 0, 1)`)
   while its `declared_ops` is length `L`, so M3's forgery only touches the
   first few elements. That is an M3 follow-up, not an M2 bug, but it needs
   agreeing before the demo.
2. **`contracts.KeyPair.pauli_map` comment.** Says "message bit -> required
   correction"; P1 uses it as "which Pauli this element is an eigenstate of".
   The type is unchanged; correcting the comment is a Decision Log item.
3. **Per-message-bit key material.** See limitation 1 above.
