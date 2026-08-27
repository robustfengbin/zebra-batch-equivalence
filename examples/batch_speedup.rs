//! How much speed does a batch actually buy?
//!
//! The residue behaviour costs a batch its aggregation and sends every member
//! back through individual verification. That is only worth reporting if the
//! amplification is known, so this measures it rather than asserting it: the
//! same bundles verified as one batch, then one at a time, at Zebra's own batch
//! size.
//!
//! Individual verification here is a batch of one, which is exactly what Zebra's
//! fallback runs (`sapling.rs`: `Fallback::new(Batch::new(..), verify_single)`,
//! and `verify_single` is itself a batch of one).
//!
//! Run with: `cargo run --release --example batch_speedup` — or in debug, where
//! the ratio is what matters rather than the absolute numbers.

use std::time::Instant;

use zebra_batch_equivalence::sapling::{item_from_tx_with_nu, Sapling, SaplingItem, SaplingKeys};
use zebra_batch_equivalence::BatchVerifier;
use zebra_chain::block::Height;
use zebra_chain::parameters::{Network, NetworkUpgrade};
use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::Transaction;

/// Zebra's `MAX_BATCH_SIZE`. For Sapling this counts bundles, each carrying an
/// unbounded number of proofs.
const BATCH: usize = 64;

const SEED: u64 = 0xF00D;

fn corpus() -> Vec<SaplingItem> {
    let dir = format!(
        "{}/seeds-real/historical_419200_1046400",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("corpus dir")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    let mut items = Vec::new();
    for path in &files {
        let name = path.file_name().and_then(|n| n.to_str()).expect("utf-8");
        let height: u32 = name
            .split('_')
            .nth(1)
            .and_then(|h| h.parse().ok())
            .expect("height in filename");
        let nu = NetworkUpgrade::current(&Network::Mainnet, Height(height));
        let bytes = std::fs::read(path).expect("read");
        let tx = Transaction::zcash_deserialize(&bytes[..]).expect("corpus must deserialize");
        if !tx.has_sapling_shielded_data() || !tx.inputs().is_empty() {
            continue;
        }
        if let Some(item) = item_from_tx_with_nu(&tx, nu) {
            items.push(item);
        }
        if items.len() == BATCH {
            break;
        }
    }
    items
}

fn main() {
    let keys = SaplingKeys::bundled();
    let items = corpus();
    assert_eq!(items.len(), BATCH, "need a full batch");
    let refs: Vec<&SaplingItem> = items.iter().collect();
    let proofs: usize = items.iter().map(|i| i.proof_count()).sum();

    // Warm anything lazy before timing.
    let _ = Sapling::validate_one(refs[0], keys, SEED);

    let t0 = Instant::now();
    let batched = Sapling::validate_batch(&refs, keys, SEED);
    let batch_time = t0.elapsed();
    assert!(batched.iter().all(|&ok| ok), "corpus must be valid");

    let t1 = Instant::now();
    for item in &refs {
        assert!(Sapling::validate_one(item, keys, SEED));
    }
    let single_time = t1.elapsed();

    println!("Sapling, {BATCH} bundles ({proofs} Groth16 proofs + signatures)");
    println!("  one batch          : {batch_time:?}");
    println!("  one at a time      : {single_time:?}");
    println!(
        "  ratio              : {:.2}x  <- what a poisoned batch costs the node",
        single_time.as_secs_f64() / batch_time.as_secs_f64()
    );
}
