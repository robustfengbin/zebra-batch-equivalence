//! Corpus tool — extract oracle-usable shielded transactions from raw block files (ZCG #332 M1).
//!
//! Reads block wire-bytes dumped from a synced Zebra node (`extract-v5-from-db blocks`), and
//! writes each **shielded-only** transaction the oracle can consume — one that [`items_from_tx`]
//! turns into at least one `OrchardItem`: a v5 Orchard bundle, or either/both pools of a v6
//! transaction (a v6 carrying Orchard *and* Ironwood bundles is one seed file yielding two
//! items) — out as its own `v<n>_<height>_<txid>.bin` corpus seed. Transactions with
//! transparent inputs are skipped: their ZIP-244 sighash needs prevouts absent from a bare
//! block dump, so the oracle cannot use them for a clean agreement check.
//!
//! Usage: `blocks_to_orchard_corpus <blocks_dir> <out_dir>`

use std::env;
use std::fs;

use zebra_batch_equivalence::items_from_tx;
use zebra_chain::block::Block;
use zebra_chain::serialization::{ZcashDeserialize, ZcashSerialize};

/// Mainnet activation heights bucketing saved seeds into the three circuit eras
/// (mirrors the `seeds-real/` directory convention). NU6.3 = Ironwood activation.
const NU6_2_HEIGHT: u32 = 3_364_600;
const NU6_3_HEIGHT: u32 = 3_428_143;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <blocks_dir> <out_dir>", args[0]);
        std::process::exit(2);
    }
    let (blocks_dir, out_dir) = (&args[1], &args[2]);
    fs::create_dir_all(out_dir).expect("create out dir");

    let mut block_paths: Vec<_> = fs::read_dir(blocks_dir)
        .expect("read blocks dir")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    block_paths.sort();

    let mut blocks_ok = 0usize;
    let mut shielded_txs = 0usize;
    let mut saved = 0usize;
    let mut saved_items = 0usize;
    // Saved-seed counts per circuit era, bucketed by block height.
    let mut per_era = [0usize; 3];

    for path in &block_paths {
        let bytes = fs::read(path).expect("read block file");
        let Ok(block) = Block::zcash_deserialize(&bytes[..]) else {
            continue;
        };
        blocks_ok += 1;
        let height = block.coinbase_height().map(|h| h.0).unwrap_or(0);

        for tx in &block.transactions {
            if tx.orchard_shielded_data().is_none() && tx.ironwood_shielded_data().is_none() {
                continue;
            }
            shielded_txs += 1;
            // Keep only transactions the oracle can cleanly verify: no transparent inputs (so the
            // empty-prevout ZIP-244 sighash is the *real* sighash and the proofs actually accept),
            // and the extractor yields at least one item (two for a dual-bundle v6).
            if !tx.inputs().is_empty() {
                continue;
            }
            let items = items_from_tx(tx);
            if items.is_empty() {
                continue;
            }
            let mut ser = Vec::new();
            tx.zcash_serialize(&mut ser).expect("serialize tx");
            let txid = tx.hash().to_string();
            let name = format!(
                "{out_dir}/v{}_{height}_{}.bin",
                tx.version(),
                &txid[..16.min(txid.len())]
            );
            fs::write(&name, &ser).expect("write corpus seed");
            saved += 1;
            saved_items += items.len();
            per_era[match height {
                h if h >= NU6_3_HEIGHT => 2,
                h if h >= NU6_2_HEIGHT => 1,
                _ => 0,
            }] += 1;
        }
    }

    eprintln!(
        "blocks_deserialized={blocks_ok} shielded_txs={shielded_txs} \
         shielded_only_saved={saved} items={saved_items} \
         eras: pre_nu6_2={} nu6_2={} nu6_3_onward={}",
        per_era[0], per_era[1], per_era[2]
    );
}
