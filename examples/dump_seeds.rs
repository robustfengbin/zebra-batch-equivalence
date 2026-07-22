//! Dump the in-tree pre-NU6.2 Orchard transactions as fuzz seed inputs.
//!
//! Each transparent-input-free Orchard V5 transaction's wire bytes — plus a
//! trailing control byte (0 => pre-NU6.2 era, order-invariance sample) matching
//! the fuzz target's input model — is written as one seed. These are real
//! mainnet proofs, so they drive the actual RedPallas + halo2 batch-verification
//! paths the coverage report measures (grant AC3). The richer node-extracted
//! corpus supersedes/augments these as it lands.
//!
//! Run: `cargo run --example dump_seeds -- seeds-real/orchard_pre_nu6_2`

use std::fs;
use std::path::PathBuf;

use zebra_chain::block::Block;
use zebra_chain::serialization::{ZcashDeserializeInto, ZcashSerialize};

fn main() {
    let out: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "seeds-real/orchard_pre_nu6_2".to_string())
        .into();
    fs::create_dir_all(&out).expect("create seed dir");

    let mut count = 0usize;
    for bytes in zebra_test::vectors::MAINNET_BLOCKS.values() {
        let block: Block = bytes
            .zcash_deserialize_into()
            .expect("hard-coded mainnet test vector must deserialize");
        for tx in &block.transactions {
            // Same filter as the valid baseline: Orchard, no transparent inputs.
            if tx.orchard_shielded_data().is_none() || !tx.inputs().is_empty() {
                continue;
            }
            let mut wire = tx
                .zcash_serialize_to_vec()
                .expect("a deserialized tx re-serializes");
            // Trailing control byte: era index 0 (pre-NU6.2) + invariant sample 0.
            wire.push(0u8);
            fs::write(out.join(format!("seed_pre_nu6_2_{count:03}")), &wire).expect("write seed");
            count += 1;
        }
    }

    println!("wrote {count} pre-NU6.2 Orchard seed(s) to {}", out.display());
}
