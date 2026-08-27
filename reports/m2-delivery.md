# ZCG #332 — Milestone 2 Delivery Report

> Batch-vs-Single Verification Equivalence for Zebra's shielded verifiers
> Milestone 2 of 3 · delivered 2026-08-27 · repo: `https://github.com/robustfengbin/zebra-batch-equivalence`
> Base: Zebra **v6.3.0** (`f5c5277fe41eba9c74f37098738f93f35dd70d60`), pinned by git rev
> Measurements and method: `reports/m2-coverage.md`. This report maps deliverables to the grant text and states what was found.
>
> **Where a number comes from.** Every *coverage* figure quoted here is measured in
> `reports/m2-coverage.md` and reproduced from there; no coverage measurement
> originates in this document or in a forum post — those two cite, they do not
> produce. The test counts and corpus sizes come from `cargo test` and from the
> committed corpus, reproducible with the commands under *Reproducing this*.
> Each figure has exactly one place it is produced, because a stale copy reads
> exactly like a current one.

## Summary

Milestone 1 delivered a differential verification oracle for Zebra's **Orchard**
pipeline: every input runs down both the production **batch** path and the
**single** path, and the two verdicts must agree — on accept and on reject —
permanently, in CI. A batch accepting what single verification rejects is a
counterfeiting-class soundness failure, and nothing in Zebra re-checks that the
two agree.

Milestone 2 does three things to that machine:

1. extends the oracle to **every batch verifier Zebra has**, under one trait;
2. adds an **adversarial corpus generator** that hides one invalid item among
   valid ones, which is where a false-accept in the aggregation glue would live;
3. **measures** how much of the batch glue layer the whole suite reaches —
   including, for the first time, Zebra's own batching middleware rather than
   batches this harness groups itself.

Result: **zero disagreements, zero false-accepts** across the real mainnet
corpora, and one behaviour surfaced by the adversarial generator that is
reported below as evidence the instrument works.

## Deliverables, against the grant's own wording

Each clause is quoted verbatim, with what answers it directly underneath. Two rows
are easy to misread: one of the named targets was delivered in M1, and one named
object is not a verifier at all.

### 1. *"adversarial corpus generators (valid base + single-element tamper + batch-composition)"*

`src/adversarial.rs` produces exactly those three classes: a valid base drawn
from real mainnet items, single-element tampering, and batch composition —
`AdversarialBatch::mostly_valid_plus_one_invalid`, which records the index of the
invalid item so a per-item report can be checked against it.

Two properties are enforced rather than hoped for:

- `TamperTarget::is_discriminating` marks whether a damage class can be told
  apart by the two paths at all. Some cannot: both paths run the same consensus
  check, so a tamper aimed there produces agreement whatever the input was.
- `check_shape` fails loudly when a "tamper" did not actually invalidate
  anything. **A tamper that quietly failed looks identical to one that worked**,
  and the batch it produces would pass every assertion while demonstrating
  nothing.

The milestone's user story names the point of the exercise: *"As a security
engineer, I want adversarial inputs that hide one invalid item among valid ones,
so false-accepts in the aggregation glue are actually reached."*

### 2. *"equivalence oracle extended to Sapling/Sprout Groth16 and Orchard RedPallas / Sapling RedJubjub"*

| Named in the grant | Where it lives | Delivered |
|---|---|---|
| Sapling Groth16 | `src/sapling.rs` | M2 |
| Sprout Groth16 | `src/sprout.rs` | M2 |
| Orchard RedPallas | `src/lib.rs` — `Orchard`, `NAME = "orchard (halo2 + RedPallas)"` | **M1**; folded into the shared trait in M2 |
| Sapling RedJubjub | `src/redjubjub.rs` | M2, split out of Sapling |

M1's Orchard verifier already checked the RedPallas signature batch alongside the
halo2 proof batch, and it had to: `BatchValidator` queues both for the same
bundle and accepts only if both batches pass, so comparing a proof-only
independent check against a proof-and-signature batch would not be asking the
same question. M2's contribution there is not new verification but a common
shape.

All four implement one `BatchVerifier` trait (`src/verifier.rs`), which requires
each verifier to expose three paths:

- the production **batch** path;
- the **single** path, mirroring that pool's own `verify_single`;
- a **layer-2** path reaching the same verdict by a genuinely different
  algorithm. A pool without one returns `None` rather than running layer 1 twice
  and calling the result independent.

Verdicts are compared **per item**, not per batch. The question worth asking is
whether one bad item can change a *neighbour's* verdict, and a single boolean for
the whole batch cannot express it. Upstream's own comment at
`zebra-consensus/src/primitives/halo2.rs` states the intent this checks —
*"Reject the item on its own without poisoning the rest of the batch."*

**RedJubjub is split out for an attribution reason, not to raise a count.**
Sapling's own validation runs the signature batch first and returns on failure
without touching the proof batch, so a `false` from a combined Sapling run cannot
be pinned to either side. The grant names RedJubjub separately; reporting it as
"covered by Sapling" would mean that attribution never gets made.

### 3. *"region-coverage report on `tower-batch-control` + `BatchValidator` + reddsa batch"*

`reports/m2-coverage.md`.

These are three **measurement objects** — crates and modules — not three further
verifiers. `tower-batch-control` in particular is Zebra's batching middleware,
the component that decides which items share a batch; the grant names it in this
clause and again in Success Metrics, both times as an object of the coverage
report.

`src/tower.rs` is what drives it. Everywhere else in this project the batch
boundaries are ours — we pick the grouping, the permutation, the size. Here they
are decided by the scheduler from arrival timing, a `tokio::select!` race between
"another item arrived" and "the batch timer fired". That is the only path that
reaches those 754 lines, and it asks a different question: batch membership is
partly decided by the network, so the property worth proving is that **it does
not matter** — no item's verdict may depend on which items it shared a batch
with. No Zebra source is modified; `Batch`, `BatchControl` and `RequestWeight`
are that crate's public API.

### Acceptance criteria

> *"all four verifiers under the equivalence oracle; adversarial generators produce mostly-valid-plus-one-invalid batches; coverage report delivered."*

| Criterion | Status |
|---|---|
| All four verifiers under the equivalence oracle | ✅ §2 above — Sapling Groth16, Sprout Groth16, Sapling RedJubjub in M2; Orchard RedPallas from M1, now under the same trait |
| Adversarial generators produce mostly-valid-plus-one-invalid batches | ✅ §1 above — `AdversarialBatch::mostly_valid_plus_one_invalid`, shape-checked |
| Coverage report delivered | ✅ §3 above — all three named objects measured |

## Coverage

MERGED column (region % / line %) — the union of the deterministic suite and the
fuzz seed replay, and the column the acceptance criterion is judged on. The
fuzz-only and test-only columns are kept separate in `reports/m2-coverage.md`,
because a reader who sees only the merged number cannot tell whether the reject
paths were reached on purpose or by a lucky mutation.

| Surface | Object | M2 final |
|---|---|---|
| orchard `bundle/batch.rs` | `BatchValidator` | **100.00 / 100.00** |
| sapling-crypto `verifier/batch.rs` | `BatchValidator` | **89.08 / 86.96** |
| reddsa `src/batch.rs` | reddsa batch | **98.97 / 100.00** |
| redjubjub `src/batch.rs` | reddsa batch | **100.00 / 100.00** |
| `tower-batch-control/src/service.rs` | `tower-batch-control` | **76.36 / 81.20** |
| `tower-batch-control/src/worker.rs` | `tower-batch-control` | **59.43 / 65.90** |
| halo2 `plonk/verifier/batch.rs` | supporting | 100.00 / 100.00 |
| halo2 `plonk/verifier.rs` | supporting | 95.11 / 98.37 |
| sapling-crypto `verifier/single.rs` | supporting | 100.00 / 100.00 |
| sapling-crypto `verifier.rs` | supporting | 97.09 / 96.34 |
| bellman `groth16/verifier.rs` | supporting | 97.67 / 96.88 |
| bellman `groth16/verifier/batch.rs` | supporting | 94.59 / 94.63 |

Three readings the numbers support:

- **`tower-batch-control` went from `not driven` to measured.** At M1 nothing in
  this repository linked it. It is now driven by exactly one suite, which
  `scripts/coverage-attribution.sh` shows by running one test binary at a time
  rather than arguing it from the dependency graph.
- **bellman `groth16/verifier/batch.rs`: 56.31 → 94.59 when Sprout landed.** That
  row was Sapling's alone at mid-build; Sprout added 38 points of regions Sapling
  never reaches, so the two Groth16 consumers overlap far less than a shared
  crate name suggests. Measured one suite at a time, Sapling's reaches 56.31 and
  Sprout's 44.59: neither accounts for the merged figure.
- **A crate is not a verifier.** `reddsa/src/batch.rs` is reached by *both*
  signature verifiers through one compiled file — RedPallas directly from
  `orchard`, RedJubjub through a 127-line wrapper — so its merged number is a
  union that belongs to neither, and it is **not comparable to M1's**, where the
  same figure described RedPallas alone.

The attribution matrix also shows the negative controls staying dark: the textual
drift anchor and the library's own unit tests link these crates and report 0.00
across every surface. A row that stayed dark where it should be dark is what
makes the lit rows worth believing.

**Re-measured at the base bump.** The whole table was produced again when the pin
moved from v6.2.3 to v6.3.0, on different hardware, with the toolchain held
fixed: **all twelve rows came back identical to the digit, in all three
columns.** One row was expected to move and did not — `worker.rs`, whose batch
boundaries come from a scheduler race, was flagged in advance as the most likely
to drift and returned 59.43 / 65.90 from a machine with four times the cores
under a competing workload. That is two measurements, not a distribution, so it
does not prove the row cannot drift; it establishes that the figure is not an
artefact of one machine's timing.

## What the oracle found

The headline result is **agreement**. Across the real mainnet corpora —
including the 249 post-activation NU6.3 verification items — batch and single
verdicts matched on every item, with **zero false-accepts**. The grant names that
outcome directly:

> *"Zero findings is an accepted, valuable outcome — the property is then under continuous machine-checked assertion, proven by corpus and CI."*

Those two statements describe different inputs, and the distinction is worth
making before the next section rather than after it. The agreement result is over
**real mainnet data**, none of which contains an invalid bundle. The behaviour
below appears only under a **deliberately constructed** carrier, and when it does
appear it is a divergence in the *reject* direction — valid items in a shared
batch coming back rejected when they would pass individually. It is a liveness
effect, not a false-accept, and no real-mainnet input has produced one.

The oracle also surfaced one behaviour worth reporting, and it is reported as
**evidence that the instrument works**, not as a vulnerability claim.

### Rejected bundles leave residue in a shared Sapling batch

`sapling_crypto::BatchValidator::check_bundle` validates and enqueues in the same
pass. If a later item fails a consensus check the function returns, and
everything queued before that point is already in the shared batch and cannot be
withdrawn. Upstream documents this plainly:

> *"some or all of the proofs and signatures from this bundle may have already been added to the batch even if it fails other consensus rules."*

**So the residue itself is documented and intended.** What this milestone adds is
a measurement of its consequence one layer up, where Zebra drives that validator:
the failing item errors on its own, but the batch continues, and the flushed
batch — residue included — has its result broadcast to every other item that
shared it. No upstream discussion of that combination was found.

The evidence is a controlled experiment, not an inference.
`tests/adversarial_generator.rs` builds two carriers that differ in exactly one
respect; both are themselves rejected, and both sit beside three valid
neighbours:

| Carrier | Construction | `check_bundle` behaviour | Verdicts of the three valid neighbours |
|---|---|---|---|
| **A** | spend0 a decodable-but-wrong proof, spend1 undecodable | queues spend0's bad proof, then returns at spend1 | **`[false, false, false]`** |
| **B** | spend0 undecodable | returns immediately, queues nothing | **`[true, true, true]`** |

The only variable is whether residue entered the shared batch.

### What it is, and what it is not

**It is not a soundness problem**, and that is structural rather than merely
unobserved: residue can only come from a bundle already judged invalid, and it
can only add proofs that may fail. It can make a batch reject more; it cannot
make one accept more. Zebra's `Fallback` then re-verifies individually — where no
other bundle's residue is present — so affected transactions do pass. The cost is
that the batch degrades into one-at-a-time verification.

That guarantee rests on one specific composition order —
`Fallback::new(Batch::new(...), verify_single)`, with the fallback *outside* the
batch. Single verification succeeds, the request returns `Ok`, and no misbehaviour
score is ever reached. **Reverse the two and the same residue stops being a
delay**: a batch failure would surface as a verification error, and honest peers
would score one another for traffic that is valid. Nothing enforces that order
today, so it is recorded here.

The cost is a range, not a number: **4.5x–7.8x** across ten runs of
`examples/batch_speedup.rs` over the same corpus and seed, on two machines; wall
clock, debug build. Machine load is the one dispersion source that has been
isolated; the rest has not been, so this report quotes the range and the
magnitude and does not explain any individual measurement. **The range is the
correct form for this quantity, not a hedge about measurement quality**: a single
figure would be one draw from that spread, and a reader reproducing it would get
a different one. No individual run is in doubt.

Amplification is linear and bounded: `MAX_BATCH_SIZE` is 64 and Sapling weights
one unit per bundle, so one crafted transaction reaches at most the 64 bundles
sharing its batch. A fix exists and is cheap — validate in two passes, queueing
nothing until every check has passed; the extra pass only decodes and
range-checks, so the number of proof verifications is unchanged. Orchard's
`add_bundle` is already this shape.

**Not filed upstream as part of this milestone.** The underlying behaviour is
already documented by the library that exhibits it, together with a workaround,
so a report of it alone would be answered by a citation. It is carried to M3,
where a release-build figure and a concrete patch can accompany it, and where the
grant's upstream contributions land.

## Test suite

**82 passed · 0 failed · 1 ignored**, `cargo test` exit code 0, no warnings — 19
inline unit tests plus 64 entries across 15 integration binaries. The ignored one
is the full-corpus deep tier, run with `--ignored`. Verified independently on two
machines at the v6.3.0 base, binary by binary, with identical counts.

`redjubjub_agreement` 8 · `v6_pool_dimensions` 7 · `strategy_equivalence` 6 ·
`deep_invariants` 6 · `add_reject_equivalence` 5 · `adversarial_generator` 5 ·
`sprout_agreement` 5 · `tower_batching` 5 · `sapling_agreement` 4 ·
`baseline_agreement` 3 · `nu6_3_agreement` 3 · `era_routing_anchor` 2 ·
`mutation_smoke` 2 · `nu6_2_agreement` 2 · `corpus_agreement` 1.

## Corpus

M2's new corpus is `seeds-real/historical_419200_1046400/`: **2,032 mainnet
transactions** carrying Groth16 JoinSplits and/or Sapling spends and outputs,
extracted from 2,509 blocks sampled every 250 heights across the window from
Sapling activation to Canopy — 687 Sprout JoinSplits, 1,261 Sapling spends, 1,779
Sapling outputs.

Groth16 is expensive enough that the suites sample it, and the directory's README
records why the sampling is stratified rather than a prefix: pool composition
drifts monotonically across this window — about 21 JoinSplits to 1 Sapling spend
at the start, 2 to 22 at the end — so **a prefix of this corpus is not a sample of
it**. It would be almost pure Sprout, perfectly reproducibly. That constraint is
enforced in the loader rather than left as a note.

The repository now carries **3,007 corpus files** across five directories,
including M1's Orchard corpora and the NU6.3 activation-window corpus delivered
with the August monthly update.

## Reproducing this

```sh
git clone --branch m2 https://github.com/robustfengbin/zebra-batch-equivalence
cd zebra-batch-equivalence
cargo test                                   # the full suite

rustup toolchain install nightly-2026-07-03
NIGHTLY=nightly-2026-07-03 ./scripts/coverage.sh --with-tests   # the three columns  (~1h)
./scripts/coverage-attribution.sh                               # the attribution matrix
```

The nightly pin applies to the coverage tables only. The test suite is a set of
behavioural assertions and reproduces on any toolchain that builds the tree;
region *counts* do not, because inlining decisions belong to the compiler. Note
that rustup names a dated channel by its *release* date, one day after the commit
date `rustc -vV` prints — `nightly-2026-07-03` is the channel whose compiler
reports `2026-07-02`, and both are called 1.98.0-nightly.

Two dependency deltas against upstream Zebra are stated and settled in
`reports/m2-coverage.md` by comparing the surface actually used rather than the
crate: `reddsa` 0.5.1 → 0.5.2, whose `batch.rs` is identical, and `tokio-util`
0.7.18 → 0.7.19, where `tower-batch-control` uses exactly one item —
`PollSemaphore` — whose source file is byte-for-byte identical between the two
versions.

## Scope and honest limitations

- **Sapling `verifier/batch.rs` at 89.08 / 86.96 is the lowest `BatchValidator`
  row, and we are not closing it by padding.** `check_bundle` has five rejection points
  and the adversarial generator reaches one. Three of the other four live in the
  private context that the batch validator and the single validator **both**
  delegate to, so a tamper tripping any of them makes *both* paths reject and the
  oracle reports agreement whatever the input was. They are enumerated as
  *reachable but non-discriminating*. What would raise the number *and* mean
  something is a tamper that makes `check_bundle` reject **after** it has queued
  part of a bundle.
- **`worker.rs` at 59.43 will not move by adding batch tests.** Its uncovered
  regions are shutdown paths, channel-closure handling and error propagation,
  reachable only by *faulting* the service; this harness's `poll_ready` returns
  `Ready(Ok)` unconditionally, so there is no failure state to fault. Named as
  future work.
- **Sprout is implemented and measured, but Zebra does not batch-verify Sprout
  today, and has no active plan to.** `JOINSPLIT_VERIFIER` is a per-item
  `service_fn`; upstream's own comment says *"there is no batch verification for
  JoinSplits"* and links
  [#3127](https://github.com/ZcashFoundation/zebra/issues/3127) — which was
  **closed as `not planned` in 2022**, on the grounds that most JoinSplits sit
  below the checkpoint verifier and the gain would be small, with the closing note
  redirecting to the general performance tracker
  [#3153](https://github.com/ZcashFoundation/zebra/issues/3153): *"can be done if
  we detect it's a bottleneck"*. The Sprout rows therefore measure `bellman`'s
  batch path as this harness drives it, not a path Zebra runs or intends to; if
  JoinSplit batching is ever switched on, the equivalence gate for it already
  exists. In this pool the two layers also swap significance: layer 2 *is* Zebra's
  production path, so a layer-2 disagreement here would be live while a layer-1
  disagreement would be a bug in code that is not scheduled to run.
- **The four surfaces M2 added have deterministic-test coverage only.** All four
  fuzz targets are Orchard, so M2's adversarial input is *designed* — four
  enumerable tamper classes — not *evolved*. Evolved input against the M2
  surfaces is M3 work, where the acceptance criterion is *"CI integration green
  and self-running"*.
- **Coverage is not additive.** Where a per-suite number is given it is a separate
  measurement, never a subtraction of one merged figure from another.

## Upstreaming

The harnesses land upstream at **M3**. M1 and M2 build the pieces — the oracle,
the four verifiers, the adversarial generators; M3 is where they become one
continuously-running contribution rather than three partial ones, which is the
merge point the proposal names:

> *"Timeline: harnesses upstreamed incrementally as milestones land — M1 (Orchard), M2 (all four verifiers), M3 (Ironwood + CI integration, the natural merge point). Ironwood-specific targets follow its testnet/activation timeline (late July 2026). All PRs are issue-first."*

Zebra contributes issue-first, so M3 opens with issues rather than PRs.
Upstreaming is not among the deliverables or acceptance criteria of any
milestone; it is a separate commitment in the proposal, and nothing has been
upstreamed yet.

If maintainers or ZCG would prefer any part of it landing sooner, say so now
rather than at M3 review and we will re-plan.

## Next

- **M3**: the Ironwood verifier under the oracle; the turnstile/migration
  soundness target (conservation, no double-migration, no forged residual value
  crossing); the full suite in continuous CI via ClusterFuzzLite / OSS-Fuzz with
  a permanent regression corpus; and the final security report.
- The Sapling residue behaviour above is carried there with a release-build
  measurement and a patch, alongside the upstream work.
- **Monthly updates** continue in the grant thread.

*Contact: robustfengbin (GitHub / Zcash forum)*
