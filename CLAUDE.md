# SIH26141 — Quantum-Inspired Threat Detection for QDS

Simulation of a teleportation-based Quantum Digital Signature (QDS) protocol, plus a
threat detection engine that catches forgery, impersonation, replay and channel
tampering from quantum measurement statistics alone.

Smart India Hackathon, problem statement 5, Egreen Quanta LLP. Team of six, one
track each. Pure Python simulation — no quantum hardware, no dataset.

## Hard constraints

From the problem statement. Breaking any one of these can invalidate the submission.

1. **No AI/ML anywhere in the detection path.** No classifier, no neural net, no
   clustering, no "anomaly detection model", and no library that quietly contains
   one. Every decision must be a threshold or a hypothesis test you could write on
   a whiteboard. Do not add `sklearn`, `torch`, `tensorflow`, `keras` or `xgboost`
   to this project for any reason.
2. Detection uses **Pauli eigenstates, projective measurements, and statistical
   analysis of measurement outcomes**.
3. The security argument is **information-theoretic**, never computational. We
   prove forgery probability decays exponentially in the number of copies `L`. We
   never argue that something is "hard to brute force".
4. Legitimate signatures are accepted **deterministically**, up to the noise floor.
5. `verify()` must be low computational complexity, and we must be able to show it.

## Planning docs

Live in Notion. The Notion MCP is connected, so read them directly.

- [Hub](https://app.notion.com/p/3cf9a2de957f8117b7e8d1b4a140a110) — constraints, ownership, working agreement
- [Roadmap and Deliverables](https://app.notion.com/p/3cf9a2de957f81d7a3aef005a88a247c) — phases, deliverables D1–D5, demo script, differentiators
- [Knowledge Base](https://app.notion.com/p/3cf9a2de957f8171983bcdabe219c394) — glossary, the maths, **the Interface Contract**, decision log

**Read the Interface Contract before writing anything that crosses a track boundary.**
At the end of a work session, append a dated entry to your track's Notion page.

## Tracks

Six people, six modules. Stay in your own unless you have agreed otherwise.

| Module | Track | Owner | Owns |
|---|---|---|---|
| `core/` | M1 Quantum Core | Ashab | Bell pairs, teleportation, Pauli corrections, channel noise |
| `protocol/` | M2 QDS Protocol | Shubhang | keygen, sign, verify, the D1 maths model |
| `attacks/` | M3 Attack Simulator | Nikita | the four adversaries |
| `detection/` | M4 Detection Engine | Hemang | thresholds, Hoeffding bound, chi-square, classification |
| `app/` | M5 Dashboard | Yuvraj | Streamlit UI, event log, plots |
| `docs/`, `bench/` | M6 Docs and Benchmarks | Anurag | documentation, deck, metrics |
| `contracts.py` | shared | — | frozen dataclasses — see below |

## Stack

Python 3.12, Qiskit + Aer, numpy, scipy, Streamlit, pytest. Pin every version.

Adding any other dependency requires an entry in the Notion Decision Log first.
The dependency list is the evidence for constraint 1, so keep it short and boring.

## Conventions

- `contracts.py` is **frozen**. Six people code against it. Changing it needs
  agreement in the Decision Log, not a unilateral edit.
- `MeasurementRecord` is the only type crossing from the quantum half to the
  statistics half. `DetectionResult` is the only type crossing from the statistics
  half to the UI. Keep those two seams clean and integration is painless.
- `evaluate(records, sig, seen_nonces)` is **pure**. Replay state is passed in, not
  held at module level. Same inputs, same output, every time.
- Thresholds `s_a` and `s_v` are **derived** from the measured noise floor and
  `p_f`. Never hardcode them, and never tune them to make a demo look better — the
  derivation has to survive a judge asking about it.
- Attacks go through the public API of the module they attack. An adversary that
  reaches into internals proves nothing.
- Non-trivial logic leaves a runnable check behind — a `test_*.py` that fails if
  the logic breaks, sized to the logic: one function usually needs one or two
  cases, a small lookup table or validation function can earn a handful. What
  "no fixtures, no elaborate suites" actually bans is framework weight —
  mocking, `setUp`/`tearDown` chains, parametrize plugins, page-object-style
  abstractions — not a proportionate number of plain assertions. A dozen
  one-line `assert`s in flat functions is not an elaborate suite.
- One branch per track (`m1-core`, `m2-protocol`, …). Merge to `master` when your
  module works against the stubs. CI runs on every branch, so you get a
  test result before you open a PR.

## Do not

This project is on a 36-hour clock. These are the ways it goes wrong.

- **Do not add an interface with one implementation.** The detector is a function.
  The channel is a noise parameter. Only `Adversary` has four implementations and
  earns a `Protocol`.
- Do not build a custom frontend. Streamlit was decided; a React build costs a
  person fifteen hours and scores nothing.
- Do not add features beyond the four required attack classes. Depth on four beats
  breadth on eight.
- Do not add databases, user accounts, auth or deployment. Zero marks.
- Do not leave the D1 maths document to the last four hours. It carries real weight
  and it cannot be written in a panic.
- Do not claim anything in the deck that has no plot or number behind it.

## Honest framing

Two things to state openly rather than hide. Judges reward the honesty and punish
the hand-waving.

- **Replay detection is not quantum.** No-cloning means the quantum state cannot be
  copied and resent, so replay means reusing a *classical* transcript, and the
  defence is nonce plus timestamp freshness at the protocol layer. No-cloning
  *forces* this; say so.
- **Hoeffding assumes independent measurement outcomes**, and chi-square needs an
  expected count of at least 5 per cell. Both assumptions belong in D1, stated
  explicitly, not buried.
