//! Shared helpers for the integration-test suite.
//!
//! (`tests/common/` is the cargo-blessed pattern for cross-test-file helpers: it is
//! compiled into each test crate that declares `mod common;`, not run as its own suite.)

// Compiled into every test binary that declares `mod common;`; most use only a
// subset, so unused items are expected, not a smell.
#[allow(dead_code)]
pub mod synth;

use zebra_batch_equivalence::{item_from_tx, item_from_tx_with_nu, OrchardItem};
use zebra_chain::{
    block::Block,
    parameters::NetworkUpgrade,
    serialization::{ZcashDeserialize, ZcashDeserializeInto},
    transaction::Transaction,
};

/// Every transparent-input-free pre-NU6.2 Orchard item from the in-tree mainnet vectors
/// (`zebra_test::vectors::MAINNET_BLOCKS`, blocks 1,687,107 / 118 / 121).
///
/// Transparent-input transactions are excluded: their ZIP-244 sighash folds in prevouts the
/// block vectors do not carry, so an empty-prevout sighash would not match and the bundle
/// would (correctly) fail to verify — that belongs to the adversarial path, not a valid
/// baseline.
#[allow(dead_code)] // not every test binary that declares `mod common;` reads the corpus
pub fn pre_nu6_2_corpus() -> Vec<OrchardItem> {
    let mut items = Vec::new();
    for bytes in zebra_test::vectors::MAINNET_BLOCKS.values() {
        let block: Block = bytes
            .zcash_deserialize_into()
            .expect("hard-coded mainnet test vector must deserialize");
        for tx in &block.transactions {
            if tx.orchard_shielded_data().is_none() || !tx.inputs().is_empty() {
                continue;
            }
            if let Some(item) = item_from_tx_with_nu(tx, NetworkUpgrade::Nu5) {
                items.push(item);
            }
        }
    }
    items
}

/// Every oracle-usable item from one committed `seeds-real/<dir>` era directory:
/// shielded-only transactions (the corpus tool's filter), loaded in file-name
/// order so sampled prefixes and folded windows are reproducible run-to-run.
/// The network upgrade (and so the sighash) comes from each transaction's own
/// consensus branch id.
#[allow(dead_code)] // not every test binary that compiles `common` uses this loader
pub fn seeds_real_corpus(dir_name: &str) -> Vec<OrchardItem> {
    let dir = format!("{}/seeds-real/{dir_name}", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    let mut items = Vec::new();
    for path in &files {
        let bytes = std::fs::read(path).expect("read corpus file");
        let Ok(tx) = Transaction::zcash_deserialize(&bytes[..]) else {
            continue;
        };
        if !tx.inputs().is_empty() {
            continue;
        }
        if let Some(item) = item_from_tx(&tx) {
            items.push(item);
        }
    }
    items
}
