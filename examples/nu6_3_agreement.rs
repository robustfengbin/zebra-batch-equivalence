//! Batch⟺single agreement over the **real** NU6.3 (Ironwood) activation corpus.
//!
//! M1 delivered this oracle against builder-synthesized NU6.3 vectors, because no
//! such traffic existed before the 2026-07-28 activation. This runs the same M1
//! oracle over the real post-activation corpus in `seeds-real/nu6_3_activation/`,
//! so the monthly update can report a result rather than an input: extracting a
//! corpus is our raw material, agreeing on it is the deliverable.
//!
//! Both pools go through one batch on purpose. Orchard and Ironwood verify under
//! the same NU6.3 era key (`OrchardItem::pool` is an annotation, not a separate
//! verification path), so a mixed batch is the honest shape of post-activation
//! mainnet traffic — and dual-pool transactions contribute an item to each.
//!
//!   cargo run --example nu6_3_agreement

use std::fs;

use zebra_batch_equivalence::{check_equivalence, items_from_tx, CircuitEra, OrchardItem, Pool};
use zebra_chain::{serialization::ZcashDeserialize, transaction::Transaction};

/// Same width M1's corpus agreement test uses, so the two runs are comparable.
const BATCH_SIZE: usize = 16;

fn main() {
    let dir = format!("{}/seeds-real/nu6_3_activation", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "corpus must be committed under {dir}");

    let mut txs = 0usize;
    let mut items: Vec<OrchardItem> = Vec::new();
    for path in &files {
        let bytes = fs::read(path).expect("read corpus file");
        let Ok(tx) = Transaction::zcash_deserialize(&bytes[..]) else {
            continue;
        };
        txs += 1;
        items.extend(items_from_tx(&tx));
    }
    assert!(!items.is_empty(), "corpus must yield verification items");

    let orchard = items.iter().filter(|i| i.pool == Pool::Orchard).count();
    let ironwood = items.iter().filter(|i| i.pool == Pool::Ironwood).count();
    println!(
        "corpus:        {} files, {} txs parsed, {} items ({} orchard / {} ironwood)",
        files.len(),
        txs,
        items.len(),
        orchard,
        ironwood
    );

    let vk = CircuitEra::Nu6_3Onward.key();
    let mut batches = 0usize;
    let mut disagreements = 0usize;
    let mut false_accepts = 0usize;
    let started = std::time::Instant::now();

    for group in items.chunks(BATCH_SIZE) {
        batches += 1;
        let report = check_equivalence(group, vk, 0xF00D);
        if report.is_disagreement() {
            disagreements += 1;
            if report.is_false_accept() {
                false_accepts += 1;
            }
            eprintln!("DISAGREEMENT in batch {batches}: {report:?}");
        }
    }

    println!(
        "batches:       {} (<={} items each), {:.1}s",
        batches,
        BATCH_SIZE,
        started.elapsed().as_secs_f64()
    );
    println!("disagreements: {disagreements}  (false-accepts: {false_accepts})");

    // The M1 soundness invariant, restated on real third-era data: over valid
    // mainnet items the batch path must never accept what the single path
    // rejects, or the reverse, for any batch composition.
    assert_eq!(
        disagreements, 0,
        "batch/single must agree on every batch of the real NU6.3 corpus"
    );
    println!("\nRESULT: batch and single agree on all {} items.", items.len());
}
