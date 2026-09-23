# zebra-batch-equivalence

A differential **soundness** oracle for Zcash **Zebra**'s shielded verification:
assert that the **batch** verification path and the **single** verification path
always agree. Milestone 1 covered the **Orchard** verifier; Milestone 2 extends
the same assertion to **every batch verifier Zebra has** — Sapling Groth16,
Sprout Groth16, Orchard RedPallas and Sapling RedJubjub — adds an adversarial
corpus generator, and drives Zebra's own batching middleware
(`tower-batch-control`) rather than only batches this harness groups itself.
Milestone 3 extends it to the **Ironwood** pool (NU6.3), adds a soundness target
for the Orchard → Ironwood **turnstile**, and runs the whole suite as daily
**ClusterFuzzLite** fuzzing with a permanent corpus.

The final report — what the suite covers, what it found across all three
milestones, and what it does not establish — is
[`reports/m3-final-security-report.md`](reports/m3-final-security-report.md).
The earlier milestone reports are [`reports/m2-delivery.md`](reports/m2-delivery.md)
(coverage measurements and the attribution matrix) and
[`reports/m1-delivery.md`](reports/m1-delivery.md).

## The property, and why it is unguarded

Zebra verifies shielded proofs with a *batch-first, single-fallback* pattern:
a whole batch is verified at once, and only if the batch fails does it fall back
to verifying each item alone. That self-heals a **false-reject** (batch wrongly
rejects → fallback corrects it) but is **blind to a false-accept**: if a batch
wrongly *accepts* a set containing an invalid proof, the per-item fallback never
runs and the invalid item is admitted. A batch false-accept is a **soundness**
failure — the same class that underlies counterfeiting, and the same unguarded
surface as the June 5, 2026 Orchard incident (a circuit under-constraint that
survived audits for years, fixed in the NU6.2 hard fork).

The existing coverage-guided harness (ZCG #234's) only checks for panics — it explicitly
does *not* assert `verify == Ok`. This project adds the missing assertion,
seeded from real mainnet data, and runs it continuously in CI.

## What the oracle checks

Every verifier implements one `BatchVerifier` trait (`src/verifier.rs`), which
requires three paths from each: the production **batch** path, the **single**
path that mirrors that pool's own `verify_single`, and — where the pool has one
— a **layer-2** path reaching the same verdict by a genuinely different
algorithm. A pool without a second algorithm returns `None` rather than running
the first one twice and calling the result independent.

Verdicts are compared **per item**, not per batch: the question worth asking is
whether one bad item can change a *neighbour's* verdict, and a single boolean
for the whole batch cannot express it.

For a set of Orchard bundles verified under one circuit-era key:

* **Base equivalence** — the batch result must equal the AND of the single
  results. `batch Ok / some single rejects` is a **false-accept** (critical);
  `batch rejects / all singles Ok` is a **false-reject** (liveness).
* **Order-independence** — the batch boolean must not depend on the order
  bundles were added (orchard draws random scalars per position; a flip is
  unsound aggregation).
* **Duplicate-consistency** — duplicating bundles must not change agreement.
* **Sub-batch compositionality** — a sound whole cannot hide an unsound part.
* **Era-routing / not-fail-open** — the three Orchard circuit eras (pre-NU6.2 /
  NU6.2 / NU6.3-onward) each have their own verifying key; a bundle under the
  *wrong* era key must be rejected by **both** paths, never accepted.

Everything drives the existing verifiers through **public APIs only**
(`orchard::bundle::BatchValidator`, zebra-chain transaction/sighash) with a
seeded, `CryptoRng` for reproducibility. **No Zebra consensus/verification source
is modified.**

## Milestone status

**Milestone 1 (Orchard)** — [`reports/m1-delivery.md`](reports/m1-delivery.md)

| Acceptance criterion | Status |
| --- | --- |
| Harness builds and runs in CI | ✅ (GitHub Actions: build + bounded smoke run) |
| Batch/single agreement on the valid corpus, zero spurious disagreements | ✅ (real pre-NU6.2 corpus; base + deep invariants) |
| Reproducible coverage of the Orchard batch path | ✅ (`cargo fuzz coverage` over real-proof seeds) |

**Milestone 2 (all four verifiers + adversarial corpus + coverage report)**

| Acceptance criterion | Status |
| --- | --- |
| All four verifiers under the equivalence oracle | ✅ Sapling Groth16 (`src/sapling.rs`), Sprout Groth16 (`src/sprout.rs`), Sapling RedJubjub (`src/redjubjub.rs`); Orchard RedPallas shipped in M1 (`src/lib.rs`, `NAME = "orchard (halo2 + RedPallas)"`) and is now folded into the shared trait |
| Adversarial generators produce mostly-valid-plus-one-invalid batches | ✅ `src/adversarial.rs` — valid base, single-element tamper, batch composition, with `check_shape` failing loudly when a tamper did not actually invalidate anything |
| Coverage report delivered | ✅ [`reports/m2-delivery.md`](reports/m2-delivery.md), *Coverage* — the three objects the grant names (`tower-batch-control`, `BatchValidator`, reddsa batch) all measured, with a per-suite attribution matrix |

**Milestone 3 (Ironwood + turnstile + continuous CI + final report)** — [`reports/m3-final-security-report.md`](reports/m3-final-security-report.md)

| Acceptance criterion | Status |
| --- | --- |
| Ironwood verifier covered by the oracle | ✅ on all five surfaces: base equivalence (`tests/nu6_3_agreement.rs`, incl. mixed Orchard/Ironwood batches), deep invariants, adversarial (`tests/cross_pool_adversarial.rs`), turnstile, and fuzz |
| Turnstile soundness target runs against testnet/activated code | ✅ against real **mainnet** post-activation transactions (`seeds-real/nu6_3_activation`, 172 transactions); conservation and no double-migration on that corpus, no forged residual value on constructed runs (`src/turnstile.rs`, `tests/turnstile_soundness.rs`, fuzz target `turnstile_order_independence`) |
| CI integration green and self-running | ✅ ClusterFuzzLite runs every target daily on a schedule, from a permanent corpus in [`zebra-batch-equivalence-corpora`](https://github.com/robustfengbin/zebra-batch-equivalence-corpora); a `fuzz-health` job reports per target whether it fuzzed or only replayed its corpus |
| Final report delivered | ✅ [`reports/m3-final-security-report.md`](reports/m3-final-security-report.md) |

Two limits the reports state and this file repeats rather than leaves to be
discovered: **no disagreement found is not equivalence proven** — the suite is
empirical assurance under permanent assertion, not a formal proof — and **Zebra
does not batch-verify Sprout
today, and has no active plan to** — `JOINSPLIT_VERIFIER` is a per-item service,
and the issue proposing batch support,
[#3127](https://github.com/ZcashFoundation/zebra/issues/3127), was closed as *not
planned* in 2022. So the Sprout rows measure `bellman`'s batch path as this
harness drives it, not a path Zebra runs.

## Layout

```
src/verifier.rs       the BatchVerifier trait: batch / single / layer-2, per-item reports
src/lib.rs            Orchard (halo2 + RedPallas), the M1 oracle, now the reference impl
src/sapling.rs        Sapling Groth16 — spend and output sub-batches
src/sprout.rs         Sprout JoinSplit Groth16
src/redjubjub.rs      Sapling RedJubjub, split out so a signature verdict is attributable
src/tower.rs          drives tower-batch-control: batch boundaries set by the scheduler
src/turnstile.rs      the Orchard → Ironwood turnstile: conservation, double migration, residual value
src/fuzz_input.rs     turns fuzzer bytes into transactions and items, shared by the targets
src/adversarial.rs    adversarial corpus generator + tamper-discriminability checks
src/era.rs            three circuit eras, cached keys, production routing
src/invariants.rs     deep batching invariants + classification
src/bin/              corpus extraction from block dumps (Orchard, and historical Groth16)
fuzz/                 nine cargo-fuzz targets; fuzz/regressions/ keeps every crash found
tests/                18 integration suites, one per question
.clusterfuzzlite/     ClusterFuzzLite build: Dockerfile, build.sh, seed packing
.github/workflows/    CI, and the ClusterFuzzLite daily / weekly / PR workflows
examples/             seed dumping, pool surveys, batch-vs-single speedup measurement
scripts/coverage.sh   the three coverage columns; coverage-attribution.sh the per-suite matrix
scripts/prep-fuzz-corpus.sh   fuzz seeds, chosen by what reaches each verifier (REACHES.txt)
scripts/cflite-health.py      per-target "did it fuzz" check on the daily run's log
seeds-real/           real mainnet corpora: Orchard eras, NU6.3 activation window, historical Groth16
reports/              m3-final-security-report.md — the final report; m2-, m1-delivery.md
```

## Fuzz targets

Nine targets, all asserting soundness, not just panic-freedom. Four stress the
Orchard batch path — which also carries Ironwood, since the two pools share the
Action and halo2 machinery:

- **`orchard_batch_equivalence`** — the full batch under every invariant (base
  equivalence, order-independence, duplicate-consistency, era-routing).
- **`orchard_batch_composition`** — batch reshaping: empty / singleton / prefix
  sub-batches / permutation / duplication, each `batch ⟺ single`.
- **`orchard_era_routing`** — the circuit-era key matrix: no key may false-accept,
  and a valid set is accepted by at most one era key (key-confusion guard).
- **`orchard_single_deep`** — single-bundle granularity × era keys, with the
  layered extraction depth of ZCG#234's `orchard_bundle_verify` plus the
  soundness assertions it lacked.

Four cover the other verifiers and the batching layer:

- **`sapling_batch_equivalence`**, **`redjubjub_batch_equivalence`**,
  **`sprout_batch_equivalence`** — batch against single for Sapling Groth16,
  Sapling RedJubjub and Sprout Groth16.
- **`tower_partition_equivalence`** — the same items under different batch
  partitions in `tower-batch-control`: no partition may turn a rejected item into
  an accepted one, and where every item is valid, no partition may reject.

And one checks a different property:

- **`turnstile_order_independence`** — the turnstile has no second path to compare
  against, so this target checks every double-spend report against a reference
  model, under several arrival orders.

**Continuous fuzzing.** ClusterFuzzLite runs all nine every day: it prunes the
permanent corpus, fuzzes each target for an equal share of three hours, and then
checks the log to report, per target, whether it got past its stored corpus into new
inputs. New inputs go to
[`zebra-batch-equivalence-corpora`](https://github.com/robustfengbin/zebra-batch-equivalence-corpora),
so each run starts from what the previous ones found. A weekly job publishes a
coverage report from that corpus. Scheduled runs on GitHub are best-effort, and on
this repository they start hours after their set time.

## Building & running

This harness pins upstream Zebra as a **git dependency** at
`f5c5277fe41eba9c74f37098738f93f35dd70d60` (Zebra v6.3.0, the grant base — plain
upstream, driven through public APIs only). Cargo fetches and pins it during the
build, so this repository builds from a single clone with no local Zebra checkout:

```bash
# The full suite: all four verifiers, real mainnet corpora, adversarial batches
cargo test

# A fuzz target, seeded the way CI seeds it
./scripts/prep-fuzz-corpus.sh
cargo +nightly fuzz run orchard_batch_equivalence fuzz/corpus/orchard_batch_equivalence

# Coverage of the Orchard batch path
cargo +nightly fuzz coverage orchard_batch_equivalence

# The coverage tables in reports/m2-delivery.md (~1h each)
rustup toolchain install nightly-2026-07-03
NIGHTLY=nightly-2026-07-03 ./scripts/coverage.sh --with-tests
./scripts/coverage-attribution.sh
```

The nightly pin is not decoration: the test suite reproduces on any toolchain
that builds the tree, but *region counts* do not — inlining decisions belong to
the compiler. Note also that rustup names a dated channel by its release date,
one day after the commit date `rustc -vV` prints.

## License

MIT OR Apache-2.0.
