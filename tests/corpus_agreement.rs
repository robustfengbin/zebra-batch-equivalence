//! Batch⟺single agreement over the committed real-mainnet Orchard corpus (ZCG #332 · M1).
//!
//! Complements `baseline_agreement.rs` (3 in-tree vectors) with a **larger real mainnet** corpus
//! extracted from a synced Zebra node (pre-NU6.2 Orchard, `seeds-real/orchard_v5_pre_nu6_2/`).
//! Every corpus transaction is parsed, its Orchard bundle collected, and the bundles are folded
//! into multi-item batches. The oracle must report **no disagreement** on any batch — the M1
//! soundness invariant: over real valid mainnet data the batch path never accepts what the single
//! path rejects (or vice-versa), for any batch composition.
//!
//! Agreement may be on `true` (shielded-only txs) or `false` (txs whose ZIP-244 sighash needs
//! transparent prevouts absent here) — either way batch and single must agree.

use std::fs;

use zebra_batch_equivalence::{check_equivalence, item_from_tx, pre_nu6_2_key, OrchardItem};
use zebra_chain::{serialization::ZcashDeserialize, transaction::Transaction};

/// Largest batch fed to one `check_equivalence` call. Keeps each halo2 aggregate to a sane size
/// while still exercising genuine multi-bundle batching.
const BATCH_SIZE: usize = 16;

#[test]
fn no_disagreement_over_real_mainnet_orchard_corpus() {
    let dir = format!(
        "{}/seeds-real/orchard_v5_pre_nu6_2",
        env!("CARGO_MANIFEST_DIR")
    );

    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "real seed corpus must be committed under seeds-real/");

    // Parse each corpus file as one transaction; collect every Orchard bundle.
    let mut txs_parsed = 0usize;
    let mut items: Vec<OrchardItem> = Vec::new();
    for path in &files {
        let bytes = fs::read(path).expect("read corpus file");
        let Ok(tx) = Transaction::zcash_deserialize(&bytes[..]) else {
            continue;
        };
        txs_parsed += 1;
        if let Some(item) = item_from_tx(&tx) {
            items.push(item);
        }
    }

    assert!(
        !items.is_empty(),
        "corpus must yield real Orchard bundles (parsed {txs_parsed} txs)"
    );

    // Fold all real Orchard bundles into multi-item batches and assert agreement on each.
    let vk = pre_nu6_2_key();
    let mut batches = 0usize;
    let mut disagreements = 0usize;
    for group in items.chunks(BATCH_SIZE) {
        batches += 1;
        let report = check_equivalence(group, &vk, 0xF00D);
        if report.is_disagreement() {
            disagreements += 1;
            eprintln!("EQUIVALENCE VIOLATION in batch {batches}: {report:?}");
        }
    }

    eprintln!(
        "real-corpus check: {} txs parsed, {} Orchard bundles, {} batches (≤{}/batch), {} disagreements",
        txs_parsed,
        items.len(),
        batches,
        BATCH_SIZE,
        disagreements,
    );
    assert_eq!(
        disagreements, 0,
        "batch/single must agree on every batch from the real mainnet corpus \
         (a disagreement is a false-accept or false-reject finding)"
    );
}
