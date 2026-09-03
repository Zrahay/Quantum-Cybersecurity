# M2 — QDS Protocol

Track M2 (Shubhang). Deliverable D1.

**Status: scaffold.** The architecture, types, seams and tests are real. The
teleportation-based QDS construction has **not been selected**, so there is no
signing equation, no key-generation algorithm and no verification predicate in
here yet. Nothing in this module performs a cryptographic operation.

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
      |    MockQuantumCore  -- seeded placeholder, tests only
      v
M2  protocol/        keygen · sign · verify        <- YOU ARE HERE
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

## The M1 → M2 interface

`protocol/quantum_interface.py` defines `QuantumCore`, a `typing.Protocol`
(structural, matching `contracts.Adversary`) with four methods:

| Method | M2 expects back |
|---|---|
| `bell_pairs(n, *, noise_level)` | an **opaque** handle, passed straight back in — M2 never inspects it |
| `teleport(resource, *, noise_level)` | `(clbit0, clbit1)` per qubit, control bit **first**, circuit order |
| `correction_for(bell_outcome)` | a `PauliOp`; pure lookup, no channel |
| `measure(resource, basis, *, noise_level)` | classical bits `0`/`1`, **per-copy order preserved** |

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

### Why the interface exists

The working agreement says not to add an interface with one implementation. This
one has two, and it earns them: every primitive in `core/` currently returns
`[]`, `PauliOp.I` or an empty circuit, so without a mock M2 cannot be exercised
at all and the two tracks serialise. `M1QuantumCore` conforms today but raises
`QuantumCoreError` from `bell_pairs`, `teleport` and `measure`, because M1
exposes circuit *builders* while M2 needs *results* — an unagreed gap, and
guessing at it would be worse than the error message.

**When M1 lands, delete `MockQuantumCore` and collapse this file into direct
`core.*` imports.** That is the correct end state; do not keep the abstraction
out of sentiment. `tests/test_quantum_core.py::TestM1AdapterRefusesRatherThanGuesses`
starts failing as each M1 entry point appears — that failure is the signal to
implement the adapter method, not a regression.

### MockQuantumCore

Development and tests only. It is **not a quantum simulation** — seeded
pseudo-random bits of the right shape, with no superposition, entanglement or
decoherence. No output of it is evidence of anything: not a mismatch rate, not a
noise floor, not a forgery probability. Nothing from it goes in the deck, on the
dashboard, or into a benchmark, and nothing in the detection path imports it.

## Where the algorithm plugs in

There are exactly three places, each marked `ALGORITHM GOES HERE`:

| File | Function | Must decide |
|---|---|---|
| `signer.py` | `keygen` | what `private_bits` is; how `pauli_map` is derived; whether the `L` copies are prepared here or at signing time |
| `signer.py` | `sign` | how `declared_ops` is computed — the correction the signer *claims*, which is what a forger must guess; how `bell_outcomes` is obtained |
| `verifier.py` | `verify` | which basis each copy is measured in; how `expected` is predicted; how `observed` is collected in per-copy order |

No caller signature changes when they are filled in: `core` and `config` are
already threaded through, and `QDSConfig` is already the place for new
parameters. A separate `QDSAlgorithm` interface was considered and rejected for
now — it would have zero implementations, which is the interface-with-no-users
failure mode. Add it when a construction is chosen *and* a second one is needed
for comparison.

### The placeholder, and why it returns values

`keygen` and `sign` return correctly shaped `KeyPair` / `Signature` objects by
default because M3, M4 and M5 already integrate against them, and serialising
four tracks behind one undecided algorithm costs more than the placeholder does.
Two guardrails make that defensible:

- The placeholder performs **no** cryptographic operation — no XOR, no hash, no
  invented signing equation. There is nothing there to mistake for a
  construction.
- `QDSConfig(strict=True)` makes all three entry points raise
  `ProtocolNotSelectedError`, and the tests assert it. The "not implemented"
  claim rests on a passing test rather than on a docstring.

`verify()` returns `[]`, which **fails closed**:
`detection.statistics.mismatch_rate` raises `ValueError` on an empty list
precisely so "no data" cannot read as a zero mismatch rate — the strongest
possible evidence of a legitimate signature. Do not "fix" that `ValueError` by
fabricating records.

## Tests

```
python3 -m unittest tests.test_signature tests.test_quantum_core -v
```

Or, with the pinned dev environment installed (`pip install -e .`), `pytest`
collects them along with everything else.

These test the scaffold only: API shape, argument validation, dependency
injection, mock determinism, and the honesty of the unimplemented signal. **No
test here claims cryptographic correctness**, because there is no construction
to be correct against. When one is selected, the D1 tests — unforgeability,
transferability, deterministic acceptance at the noise floor — get added
alongside these rather than replacing them.

## Open TODOs blocked on protocol selection

1. `keygen` — real quantum public key distribution.
2. `sign` — the signing operation and `declared_ops`.
3. `verify` — basis choice, outcome prediction, record construction.
4. `QDSConfig.bases` — empty by design until the protocol says which Pauli bases
   a verifier uses, and in what proportion.
5. **Justify the independence of the `L` outcomes.** M4's Hoeffding bound assumes
   it; whether it holds follows from how the copies are prepared, which makes it
   M2's argument to make in D1, explicitly.
6. Show `verify()` is cheap. Low computational complexity is a stated requirement
   of the problem statement — keep it `O(L)` in measurements with no per-copy
   re-derivation of the key, and put the count in D1.
7. Agree the `QuantumCore` method set with M1, and replace `MockQuantumCore` in
   any non-test caller.

Two things D1 must state openly rather than bury:

- **Replay detection is not quantum.** No-cloning means the state cannot be
  copied and resent, so a replay is necessarily a reused *classical* transcript,
  and the defence is nonce plus timestamp freshness at the protocol layer.
  No-cloning *forces* this — say so.
- **Hoeffding assumes independent outcomes** and chi-square needs an expected
  count of at least 5 per cell. Both assumptions belong in D1, stated, not
  buried.
