# ZCG #332 — Milestone 1 Delivery Report

> Batch-vs-Single Verification Equivalence for Zebra's Orchard pipeline
> Milestone 1 of 3 · delivered 2026-07-22 · repo: `https://github.com/robustfengbin/zebra-batch-equivalence`

## Summary

Milestone 1 delivers a **differential verification oracle** for Zebra's Orchard
proof pipeline: every input is driven down the production *batch* path
(`orchard::BatchValidator`, the aggregate randomised-linear-combination path
`zebra-consensus` runs) and the *single* path (batch-of-one, exactly
`halo2::Item::verify_single`'s semantics), and the two verdicts are asserted to
agree — on accept **and** on reject. A batch that accepts what single
verification rejects is the counterfeiting-class soundness failure this grant
exists to guard against; a batch that rejects what singles accept is a
liveness/DoS finding.

Across everything we have thrown at it — 415 real mainnet Orchard proofs
replayed through 803 corpus seeds, four coverage-guided fuzz targets, three
circuit eras, mechanical mutations of real proofs, and synthetic NU6.3-era
vectors — **the two paths have never disagreed.** That is the result we want to
be able to keep saying, and the harness now says it as a permanent, replayable
assertion rather than a one-off audit claim.

## Deliverables

| Grant commitment | Delivered as |
|---|---|
| Differential batch⟺single oracle | `src/lib.rs` (`check_equivalence*`, seeded/deterministic RNG so any disagreement reproduces) |
| Real-corpus baseline | `seeds-real/` — 803 seeds: 3 in-tree + 550 pre-NU6.2 + 250 NU6.2 node-extracted mainnet transactions (415 Orchard proofs) |
| Coverage-guided fuzzing | 4 targets: batch equivalence, batch composition, era routing, single-deep |
| Era coverage | Three circuit eras (pre-NU6.2 / NU6.2 / NU6.3-onward) with era-routing assertions: wrong-key acceptance is a panic, and at most one era may accept a given set |
| Deeper batch invariants | Order-independence, duplicate-consistency, empty/singleton boundaries, sub-batch compositionality — each a differential, fuzz-driven over real bundles; the full-corpus sweep (412 real proofs × 4 invariants, windows folded to keep it tractable) runs in ~37 min with zero violations |
| Reject-side assurance | Mutation smoke vectors (proof bit-flip / truncation / sighash mismatch / binding-signature bit-flip over real proofs) + add-time rejection equivalence over the NU6.3 cross-address gate |
| Strategy-level differential (second layer) | Both production paths ultimately drive each backend's *batch* strategy (Zebra's "single" is a batch-of-one). Each backend also ships a genuinely distinct single-verification strategy (halo2 `SingleVerifier`, reddsa per-item verify): the suite pins pairwise agreement between the batch strategy and its backend's single strategy, on real proofs (accept) and damaged inputs (reject) — the same oracle, one layer down |
| CI | GitHub Actions: full test suite + all four fuzz targets seed-replayed on every push |
| Public repository | This repo (clean-room export, dependencies pinned at Zebra v6.2.0 `135c1361914cf1759d63953e5175b36b195f0873` — the release that activates Ironwood on mainnet) |

## Evidence and how to reproduce it

Every number below is one command on a checkout of this repo.

**Zero divergence over the real corpus** — `cargo test` replays the committed
corpus through both paths (accept side), and the mutation/rejection suites pin
the reject side; the fuzz targets extend the same assertions under input
mutation (`.github/workflows/ci.yml` is the exact recipe).

**Coverage of the components under test** (merged fuzz-replay + test-suite
line coverage, `scripts/coverage.sh --with-tests`):

| Component | Line coverage | Floor |
|---|---|---|
| halo2 proof batch verifier (`plonk/verifier/batch.rs`) | **100.0%** | ≥95% ✅ |
| halo2 plonk verifier (`plonk/verifier.rs`) | **98.4%** | ≥95% ✅ |
| RedPallas signature batch (`reddsa/src/batch.rs`) | **100.0%** | ≥90% ✅ |
| Orchard `BatchValidator` (`bundle/batch.rs`) | **100.0%** | ≥90% ✅ |

The reject arms that an all-valid mainnet corpus can never reach are covered by
deterministic adversarial vectors (tampered real proofs, unsupported-key
bundles). The line-by-line audit of the remaining gap produced a structural
insight rather than padding: the uncovered lines concentrated in each backend's
*native single-verification* strategy — code Zebra's production paths never
call, because Zebra's "single" verification is a batch-of-one. Instead of
chasing lines, the suite mirrors the equivalence oracle down onto that layer
(batch strategy ⟺ backend single strategy, accept and reject) — so a
divergence in either layer is caught.

Every gain over the fuzz-replay baseline comes from **deterministic**
adversarial vectors (mutation vectors, strategy-level differentials, add-time
rejection, the v6 pool suite) — reject-side coverage is asserted, not
stumbled into. The four lines that remain uncovered (halo2 plonk verifier,
98.4%) are each documented with source-level reasoning for why they are
unreachable through the public API (shape/size guards structurally satisfied
by the type layer above, a keygen invariant panic, and a circuit-evaluation
branch the Orchard gates never take) — documented honestly rather than padded
over.

**Determinism** — both paths run under the same seeded RNG; soundness must hold
for any RNG, the seed exists so that any disagreement is a citable, replayable
artifact rather than an anecdote.

## NU6.3 / Ironwood readiness (v6-ready)

Ironwood activates on mainnet at height 3,428,143 (~2026-07-28). M1 ships ahead
of activation with the pipeline already v6-aware:

- **Extraction** understands v6's two-bundle shape: one v6 transaction may
  carry an Orchard-pool *and* an Ironwood-pool bundle (same bundle type, same
  PostNu6_3 circuit, same batch stack); extraction yields one verification item
  per bundle, pool-annotated, sharing the transaction's ZIP-244 sighash.
- **Pool-dimension differentials**: cross-pool mixed batches (either order,
  every era key), the two bundles of one transaction verified apart vs
  together, and a wire-level parse differential pinning that the
  `enableCrossAddress` bit is rejected on the Orchard pool — on real v5
  mainnet bytes and the v6 codec alike — while round-tripping on Ironwood.
- **Fuzz input model** gained a pool dimension (control-byte selected:
  mixed / Orchard-only / Ironwood-only) with byte-for-byte backward-compatible
  era selection, so the existing 803-seed corpus and CI seeds keep their
  meaning.

**Provenance is labelled honestly:** until activation there is no real NU6.3
traffic, so NU6.3-era accept-true vectors are **builder-synthesized real
proofs** (a cross-address-disabled Orchard-pool bundle and an Ironwood-pool
bundle, proven under the PostNu6_3 circuit and binding-signed like production
items — synthetic provenance, not stubs). **The real NU6.3 corpus lands ~1
week post-activation (≈2026-08-04) as the first monthly update**, extracted at
T+0 from our standing mainnet node, including activation-boundary blocks kept
as separate era-routing material.

## Why this matters now

- `zcashd` reached end-of-support on 2026-07-18 and halts automatically: Zcash
  is now effectively a single-implementation network. Cross-implementation
  differential checking is no longer available as a background safety net;
  runtime verification redundancy has to be built deliberately. This harness is
  one such redundancy for the Orchard batch path.
- Zebra's batch path has no independent runtime second opinion of its own. When
  a batch *fails*, its fallback re-checks each item individually — but that
  fallback is the same `BatchValidator` at batch-of-one, not a separate
  verifier, and the policy is `OnError`: a batch that *accepts* is final, with
  no re-verification on success. v6.2.0 — the exact release running at Ironwood
  activation — adds an opt-in hook (`tower-fallback::new_with_policy`) that
  *could* re-verify on success, but none of Zebra's five production proof
  verifiers wire it in. So batch acceptance is the last word at runtime, and an
  independent cross-check on that acceptance — the batch⟺single equivalence and
  its strategy-level layer — exists in exactly one place: this harness.
- The April 2026 zcashd⟷Zebra consensus divergence (disclosed alongside a
  CVSS 9.2 Orchard-crash CVE) is a concrete, recent instance of the bug class
  a differential oracle catches.
- The verification-layer fix window around the 2026-06-05 incident addressed
  the circuit layer; the batch-verification glue above it is exactly what this
  grant covers.

We state these as context, not as claims that a bug exists in current Zebra:
across everything measured so far, the batch and single paths agree.

## Scope and honest limitations

- **No divergence found ≠ equivalence proven.** This is empirical assurance
  with permanent assertions, not a formal proof.
- The mainnet corpus is all-accept by construction; reject-side coverage comes
  from deterministic adversarial vectors, and the *systematic* adversarial
  generators (single-element tamper families, mostly-valid-plus-one batches)
  are Milestone 2's deliverable, not smuggled into M1.
- Synthetic NU6.3 vectors carry real proofs but synthetic provenance, labelled
  as such above; the real-corpus third era arrives with the first monthly
  update.
- The Tower `Batch<Verifier, Item>` glue layer is exercised indirectly;
  mirroring it over public `tower-batch-control` is scheduled work (M2).

## Next

- **M2**: adversarial generators (tamper families over proofs, signatures,
  public inputs; batch-composition attacks), four-verifier extension, tower
  glue-layer mirroring with region-coverage targets. The real-corpus expansion
  toward ~10k+ Orchard proofs rides here too — extracted from higher mainnet
  blocks alongside the NU6.3 corpus, sampled into the repo with the full set
  reproducible via `src/bin/blocks_to_orchard_corpus.rs`.
- **M3**: Ironwood verifier equivalence (shares the PostNu6_3 circuit and batch
  stack — the pool-dimension work above is its runway) and turnstile soundness.
- **Monthly updates** in this thread, starting with the real NU6.3 corpus
  (~2026-08-04).

*Contact: robustfengbin (GitHub / Zcash forum)*
