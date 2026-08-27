# zebra-batch-equivalence

A differential **soundness** oracle for Zcash **Zebra**'s shielded verification:
assert that the **batch** verification path and the **single** verification path
always agree. Milestone 1 covered the **Orchard** verifier; Milestone 2 extends
the same assertion to **every batch verifier Zebra has** — Sapling Groth16,
Sprout Groth16, Orchard RedPallas and Sapling RedJubjub — adds an adversarial
corpus generator, and drives Zebra's own batching middleware
(`tower-batch-control`) rather than only batches this harness groups itself.

Coverage of the batch glue layer is measured in
[`reports/m2-coverage.md`](reports/m2-coverage.md).

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

The existing coverage-guided fuzz harness only checks for panics — it explicitly
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
| Coverage report delivered | ✅ [`reports/m2-coverage.md`](reports/m2-coverage.md) — the three objects the grant names (`tower-batch-control`, `BatchValidator`, reddsa batch) all measured |

Two limits the report states and this file repeats rather than leaves to be
discovered: the four surfaces M2 added have **deterministic-test coverage only**
(all four fuzz targets are Orchard), and **Zebra does not batch-verify Sprout
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
src/adversarial.rs    adversarial corpus generator + tamper-discriminability checks
src/era.rs            three circuit eras, cached keys, production routing
src/invariants.rs     deep batching invariants + classification
src/bin/              corpus extraction from block dumps (Orchard, and historical Groth16)
fuzz/                 four cargo-fuzz targets, all Orchard
tests/                15 integration suites, one per question (see reports/m2-coverage.md §4)
examples/             seed dumping, pool surveys, batch-vs-single speedup measurement
scripts/coverage.sh   the three coverage columns; coverage-attribution.sh the per-suite matrix
seeds-real/           real mainnet corpora: Orchard eras, NU6.3 activation window, historical Groth16
reports/              m2-coverage.md — the milestone's coverage and findings report
```

## Fuzz targets

Four Orchard batch-path targets, each stressing a different facet — all assert
soundness, not just panic-freedom. **They are Orchard-only**: M2's adversarial
input for the other verifiers is designed rather than evolved, which the coverage
report states as a limitation rather than a reading note.

- **`orchard_batch_equivalence`** — the full batch under every invariant (base
  equivalence, order-independence, duplicate-consistency, era-routing).
- **`orchard_batch_composition`** — batch reshaping: empty / singleton / prefix
  sub-batches / permutation / duplication, each `batch ⟺ single`.
- **`orchard_era_routing`** — the circuit-era key matrix: no key may false-accept,
  and a valid set is accepted by at most one era key (key-confusion guard).
- **`orchard_single_deep`** — single-bundle granularity × era keys, with the
  layered extraction depth of ZCG#234's `orchard_bundle_verify` plus the
  soundness assertions it lacked.

## Building & running

This harness pins upstream Zebra as a **git dependency** at
`f5c5277fe41eba9c74f37098738f93f35dd70d60` (Zebra v6.3.0, the grant base — plain
upstream, driven through public APIs only). Cargo fetches and pins it during the
build, so this repository builds from a single clone with no local Zebra checkout:

```bash
# The full suite: all four verifiers, real mainnet corpora, adversarial batches
cargo test

# Fuzz target
cargo +nightly fuzz build orchard_batch_equivalence
cargo +nightly fuzz run   orchard_batch_equivalence

# Coverage of the Orchard batch path
cargo +nightly fuzz coverage orchard_batch_equivalence

# The coverage tables in reports/m2-coverage.md (~1h each)
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
