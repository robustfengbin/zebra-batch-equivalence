//! Batch⟺single agreement over the real **NU6.3 (Ironwood) mainnet** corpus
//! (ZCG #332 · M1 oracle, real post-activation data).
//!
//! M1 shipped NU6.3 vectors that were builder-synthesized and labelled as such,
//! because Ironwood had not activated and no such traffic existed. It activated
//! 2026-07-28 at height 3,428,143; `seeds-real/nu6_3_activation/` is 172 real
//! transactions sampled from the chain after that. This is the first time the
//! oracle runs against them, and it is the point of having extracted them: a
//! corpus nothing verifies is an input, not a result.
//!
//! **The loader here does not use `common::seeds_real_corpus`, deliberately.**
//! That helper calls `item_from_tx`, which returns *at most one* item per
//! transaction — correct for the v5 eras it was written for, silently wrong
//! here. A v6 transaction may carry an Orchard-pool *and* an Ironwood-pool
//! bundle, and 77 of these do. Using the single-item loader would yield 172
//! items instead of 249, verify zero Ironwood bundles, and still pass — a green
//! run whose conclusion does not cover the pool this corpus exists to exercise.
//! So: `items_from_tx`, plus an assertion that both pools are actually present.

use std::fs;
use zebra_batch_equivalence::{
    check_equivalence, check_equivalence_refs, items_from_tx, CircuitEra, EquivReport, OrchardItem,
    Pool,
};
use zebra_chain::{serialization::ZcashDeserialize, transaction::Transaction};

const BATCH_SIZE: usize = 16;
const CORPUS: &str = "nu6_3_activation";

/// Every verification item in the committed NU6.3 corpus, both pools, in
/// file-name order so a run is reproducible.
fn nu6_3_corpus() -> Vec<OrchardItem> {
    let dir = format!("{}/seeds-real/{CORPUS}", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("NU6.3 seed corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    let mut items = Vec::new();
    for path in &files {
        let bytes = fs::read(path).expect("read corpus file");
        // Committed bytes: a decode failure is a broken corpus, not a filtered
        // seed. Panic rather than `continue` — a silently shrinking corpus is
        // how a run stays green while covering less than it claims.
        let tx = Transaction::zcash_deserialize(&bytes[..]).unwrap_or_else(|e| {
            panic!("corpus file {} failed to deserialize: {e}", path.display())
        });
        items.extend(items_from_tx(&tx));
    }
    items
}

/// The corpus carries both pools, and enough of each to mean something. Runs
/// first because every assertion below is only as good as what got loaded.
#[test]
fn nu6_3_corpus_carries_both_pools() {
    let items = nu6_3_corpus();
    let orchard = items.iter().filter(|i| i.pool == Pool::Orchard).count();
    let ironwood = items.iter().filter(|i| i.pool == Pool::Ironwood).count();

    eprintln!(
        "NU6.3 corpus: {} items total — {orchard} Orchard-pool, {ironwood} Ironwood-pool",
        items.len()
    );

    assert!(!items.is_empty(), "committed NU6.3 corpus must load");
    assert!(
        ironwood > 0,
        "no Ironwood-pool items loaded — the single-item loader trap: this corpus is \
         the reason the pool dimension exists, and a run that verifies zero of them \
         would still pass every equivalence assertion below"
    );
    assert!(orchard > 0, "no Orchard-pool items loaded");
}

/// Real post-activation mainnet bundles: batch and single agree, and both accept.
#[test]
fn nu6_3_real_mainnet_proofs_agree_and_accept() {
    let items = nu6_3_corpus();
    // Cached key: `verifying_key` rebuilds it, a multi-second cold start per call.
    let vk = CircuitEra::Nu6_3Onward.key();

    let mut batches = 0usize;
    let mut non_accept = 0usize;
    let mut disagreements = 0usize;

    for group in items.chunks(BATCH_SIZE) {
        batches += 1;
        match check_equivalence(group, vk, 0xF00D) {
            EquivReport::Agree(true) => {}
            EquivReport::Agree(false) => non_accept += 1,
            other => {
                disagreements += 1;
                eprintln!("EQUIVALENCE VIOLATION (NU6.3 key) batch {batches}: {other:?}");
            }
        }
    }

    eprintln!(
        "NU6.3 mainnet: {} items, {batches} batches, {non_accept} non-accept, \
         {disagreements} disagreements",
        items.len()
    );

    assert_eq!(
        disagreements, 0,
        "batch/single must agree on every batch of the real NU6.3 corpus"
    );
    assert_eq!(
        non_accept, 0,
        "real NU6.3 mainnet proofs must be ACCEPTED under the PostNu6_3 key"
    );
}

/// Mixed-pool batches: Orchard-pool and Ironwood-pool items verified in one
/// batch must reach the same verdict as one at a time. The pools share a circuit
/// and a batch stack, so nothing structural forces this — it is asserted on real
/// dual-pool transactions rather than assumed.
#[test]
fn nu6_3_mixed_pool_batches_agree() {
    let items = nu6_3_corpus();
    // Cached key: `verifying_key` rebuilds it, a multi-second cold start per call.
    let vk = CircuitEra::Nu6_3Onward.key();

    // `OrchardItem` is not `Clone` (it owns an authorized bundle), so interleave
    // references and use the by-ref entry point.
    let orchard: Vec<&OrchardItem> = items.iter().filter(|i| i.pool == Pool::Orchard).collect();
    let ironwood: Vec<&OrchardItem> = items.iter().filter(|i| i.pool == Pool::Ironwood).collect();

    // Interleave, so a mixed batch is the common case rather than a boundary one.
    let mut mixed: Vec<&OrchardItem> = Vec::new();
    let mut o = orchard.iter();
    let mut i = ironwood.iter();
    loop {
        match (o.next(), i.next()) {
            (None, None) => break,
            (a, b) => {
                mixed.extend(a.copied());
                mixed.extend(b.copied());
            }
        }
    }

    let mut batches = 0usize;
    for group in mixed.chunks(BATCH_SIZE) {
        batches += 1;
        let report = check_equivalence_refs(group, vk, 0xBEEF);
        assert_eq!(
            report,
            EquivReport::Agree(true),
            "mixed-pool batch {batches} must agree-accept; got {report:?}"
        );
    }
    eprintln!("NU6.3 mixed-pool: {} items over {batches} interleaved batches", mixed.len());
}
