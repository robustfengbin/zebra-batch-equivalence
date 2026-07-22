# zebra-batch-equivalence

A differential **soundness** oracle for Zcash **Zebra**'s shielded verification:
assert that the **batch** verification path and the **single** verification path
always agree. Milestone 1 covers the **Orchard** verifier.

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

## Milestone 1 status (Orchard)

| Acceptance criterion | Status |
| --- | --- |
| Harness builds and runs in CI | ✅ (GitHub Actions: build + bounded smoke run) |
| Batch/single agreement on the valid corpus, zero spurious disagreements | ✅ (real pre-NU6.2 corpus; base + deep invariants) |
| Reproducible coverage of the Orchard batch path | ✅ (`cargo fuzz coverage` over real-proof seeds) |

The full delivery report — evidence, the coverage table, and how to reproduce
every number — is in [`reports/m1-delivery.md`](reports/m1-delivery.md).
Dependencies are pinned at Zebra **v6.2.0**
(`135c1361914cf1759d63953e5175b36b195f0873`), the release that activates
Ironwood (NU6.3) on mainnet; extraction, era routing, and the fuzz input model
are already v6-aware (see the report's readiness section).

## Layout

```
src/lib.rs            core oracle: check_equivalence, OrchardItem, EquivReport
src/era.rs            three circuit eras, cached keys, production routing
src/invariants.rs     deep batching invariants + classification
fuzz/                 four cargo-fuzz targets (see "Fuzz targets" below)
tests/                baseline agreement + deep invariants over real proofs
examples/dump_seeds   dump in-tree Orchard txs as fuzz seeds
seeds-real/           real mainnet Orchard proofs (seed corpus)
```

## Fuzz targets

Four Orchard batch-path targets, each stressing a different facet — all assert
soundness, not just panic-freedom:

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

This harness pins upstream Zebra as a path dependency at `../zebra` (plain
upstream — drives it through public APIs only). Fetch it first:

```bash
git clone --filter=blob:none https://github.com/ZcashFoundation/zebra.git ../zebra
git -C ../zebra checkout 135c1361914cf1759d63953e5175b36b195f0873    # Zebra v6.2.0 (grant base)

# Unit + baseline + deep-invariant tests (real pre-NU6.2 proofs)
cargo test

# Fuzz target
cargo +nightly fuzz build orchard_batch_equivalence
cargo +nightly fuzz run   orchard_batch_equivalence

# Coverage of the Orchard batch path
cargo +nightly fuzz coverage orchard_batch_equivalence
```

## License

MIT OR Apache-2.0.
