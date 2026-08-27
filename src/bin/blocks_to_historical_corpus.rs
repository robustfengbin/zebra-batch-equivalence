//! Corpus tool — extract Sapling/Sprout-era shielded transactions from raw block files
//! (ZCG #332 M2).
//!
//! Counterpart to `blocks_to_orchard_corpus` for the historical window: Sapling activation
//! (419,200) through Canopy (1,046,400), where JoinSplits carry Groth16 proofs — the ones
//! Zebra's `JOINSPLIT_VERIFIER` accepts. Earlier JoinSplits carry BCTV14 and are unusable.
//!
//! **One directory per height window, not per pool.** The same transaction routinely carries
//! both a JoinSplit and Sapling spends/outputs, so splitting by pool would store it twice.
//! Storage keeps one copy per transaction; the loader filters per verifier — the storage-layer
//! form of "split the stream by verifier, not by pool".
//!
//! **No transparent-input filter here, deliberately.** That filter exists to keep transactions
//! whose sighash can be reconstructed from a bare block dump, and whether it applies depends on
//! the verifier, not on the transaction: Sprout's Groth16 proof is not bound to a sighash at all
//! (`groth16::Item::verify_single` takes only the prepared key), while Sapling's binding
//! signature is. Applying it at write time would silently discard usable Sprout corpus.
//!
//! **The height in the filename is load-bearing, not decoration.** Sapling sighashes need the
//! network upgrade at that height, and this window spans four of them (Sapling → Blossom →
//! Heartwood → Canopy). The v2/v3/v4 transactions here cannot report their own branch id, so a
//! seed that loses its height loses its Sapling usability.
//!
//! **Heights are zero-padded to 7 digits, and blocks are read in numeric height order.** This
//! window is the first corpus to span a digit-count boundary — 419,200 is six digits, 1,046,400
//! is seven — so plain lexicographic order puts `1000950` *before* `419201`. Both sides matter:
//! the loader sorts seed filenames and documents that prefix sampling and folded windows depend
//! on that order (`tests/common/mod.rs`), and this tool's own `max_blocks` sample would
//! otherwise silently draw from the high end of the window instead of the start. Neither
//! failure reports anything — the sample is simply skewed. M1's corpus never hit this because
//! all its heights were seven digits, so lexicographic order happened to equal numeric order.
//!
//! Usage: `blocks_to_historical_corpus <blocks_dir> <out_dir> [max_blocks]`

use std::env;
use std::fs;

use zebra_chain::block::Block;
use zebra_chain::serialization::{ZcashDeserialize, ZcashSerialize};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!("usage: {} <blocks_dir> <out_dir> [max_blocks]", args[0]);
        std::process::exit(2);
    }
    let (blocks_dir, out_dir) = (&args[1], &args[2]);
    // Optional cap so a naming/format change can be reviewed on a small sample before
    // committing tens of megabytes in the shape it would have to be undone from.
    let max_blocks: usize = args
        .get(3)
        .map(|s| s.parse().expect("max_blocks must be a number"))
        .unwrap_or(usize::MAX);
    fs::create_dir_all(out_dir).expect("create out dir");

    // Sort by parsed height, not by filename: `block-1000950.bin` sorts before
    // `block-419201.bin` lexicographically, which would make `max_blocks` sample the end of the
    // window while looking like it sampled the start.
    let mut block_paths: Vec<(u32, std::path::PathBuf)> = fs::read_dir(blocks_dir)
        .expect("read blocks dir")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .map(|p| {
            let height = p
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix("block-"))
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            (height, p)
        })
        .collect();
    block_paths.sort_by_key(|(h, _)| *h);

    let mut blocks_ok = 0usize;
    let mut saved = 0usize;
    let (mut joinsplits, mut spends, mut outputs) = (0usize, 0usize, 0usize);
    let mut with_transparent_inputs = 0usize;

    for (_, path) in block_paths.iter().take(max_blocks) {
        let bytes = fs::read(path).expect("read block file");
        let Ok(block) = Block::zcash_deserialize(&bytes[..]) else {
            continue;
        };
        blocks_ok += 1;
        let height = block.coinbase_height().map(|h| h.0).unwrap_or(0);

        for tx in &block.transactions {
            // Groth16 JoinSplits only — `sprout_groth16_joinsplits` already excludes the
            // BCTV14-proof JoinSplits of the pre-Sapling era, which no shipping verifier accepts.
            let js = tx.sprout_groth16_joinsplits().count();
            let ss = tx.sapling_spends_per_anchor().count();
            let so = tx.sapling_outputs().count();
            if js + ss + so == 0 {
                continue;
            }

            let mut ser = Vec::new();
            tx.zcash_serialize(&mut ser).expect("serialize tx");
            let txid = tx.hash().to_string();
            let name = format!(
                "{out_dir}/v{}_{height:07}_{}.bin",
                tx.version(),
                &txid[..16.min(txid.len())]
            );
            fs::write(&name, &ser).expect("write corpus seed");

            saved += 1;
            joinsplits += js;
            spends += ss;
            outputs += so;
            if !tx.inputs().is_empty() {
                with_transparent_inputs += 1;
            }
        }
    }

    eprintln!(
        "blocks_deserialized={blocks_ok} seeds_saved={saved} \
         joinsplits={joinsplits} sapling_spends={spends} sapling_outputs={outputs} \
         (of the saved seeds, {with_transparent_inputs} carry transparent inputs — kept on \
         purpose: usable for Sprout's sighash-free proof path, filtered by the loader for \
         verifiers that need a reconstructable sighash)"
    );
}
