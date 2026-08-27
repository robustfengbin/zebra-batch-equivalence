//! Survey the shielded content of Zebra's in-tree mainnet block vectors (ZCG #332 · M2).
//!
//! M2 extends the equivalence oracle from Orchard to the remaining three batch verifiers
//! (Sapling spend/output Groth16, Sprout Groth16, RedJubjub). Before designing the extraction
//! layer we need a hard number for the question "how much of each pool actually ships in-tree?",
//! because the in-tree vectors are the one corpus source that needs no node snapshot — they are
//! what lets M2 start while the corpus node is unavailable.
//!
//! This is a measurement tool, not a test: it prints per-block counts of Sprout JoinSplits,
//! Sapling spends/outputs and Orchard actions across `zebra_test::vectors::MAINNET_BLOCKS`,
//! plus the shielded-only subset (no transparent inputs) that the oracle can actually bind a
//! sighash for — the same filter `baseline_agreement` applies to the Orchard corpus.
//!
//! Run with `cargo run --example survey_shielded` for the in-tree vectors, or
//! `cargo run --example survey_shielded -- <dir>` to survey a directory of raw
//! block files (`block-<height>.bin`, as produced by extracting from a node) —
//! that is how a candidate corpus window is sized before any of it is committed.

use std::{env, fs, path::Path};

use zebra_chain::{block::Block, serialization::ZcashDeserializeInto};

#[derive(Default)]
struct Counts {
    txs: usize,
    sprout_joinsplits: usize,
    sapling_spends: usize,
    sapling_outputs: usize,
    orchard_actions: usize,
    /// Ironwood (NU6.3) actions, counted separately from Orchard. A v6
    /// transaction may carry one bundle of *each* pool, and the two share the
    /// bundle type and the NU6.3-onward verifying key — so a survey that only
    /// called `orchard_actions()` would silently report an Ironwood-bearing
    /// block as pure Orchard.
    ironwood_actions: usize,
    /// Transactions carrying both pools at once — the turnstile-migration shape
    /// M3 targets, and the reason pool must be a corpus dimension rather than a
    /// property of the block height.
    dual_pool_txs: usize,
}

impl Counts {
    fn is_empty(&self) -> bool {
        self.sprout_joinsplits == 0
            && self.sapling_spends == 0
            && self.sapling_outputs == 0
            && self.orchard_actions == 0
            && self.ironwood_actions == 0
    }

    fn add(&mut self, other: &Counts) {
        self.txs += other.txs;
        self.sprout_joinsplits += other.sprout_joinsplits;
        self.sapling_spends += other.sapling_spends;
        self.sapling_outputs += other.sapling_outputs;
        self.orchard_actions += other.orchard_actions;
        self.ironwood_actions += other.ironwood_actions;
        self.dual_pool_txs += other.dual_pool_txs;
    }
}

/// Count the shielded items in one block. `shielded_only` restricts the tally to transactions
/// with no transparent inputs — those are the ones whose ZIP-244 / pre-v5 sighash the oracle can
/// reconstruct from the block alone (block vectors do not carry the spent prevouts).
fn survey_block(block: &Block, shielded_only: bool) -> Counts {
    let mut c = Counts::default();
    for tx in &block.transactions {
        if shielded_only && !tx.inputs().is_empty() {
            continue;
        }
        let js = tx.sprout_groth16_joinsplits().count();
        let ss = tx.sapling_spends_per_anchor().count();
        let so = tx.sapling_outputs().count();
        let oa = tx.orchard_actions().count();
        let ia = tx.ironwood_actions().count();
        if js + ss + so + oa + ia > 0 {
            c.txs += 1;
        }
        if oa > 0 && ia > 0 {
            c.dual_pool_txs += 1;
        }
        c.sprout_joinsplits += js;
        c.sapling_spends += ss;
        c.sapling_outputs += so;
        c.orchard_actions += oa;
        c.ironwood_actions += ia;
    }
    c
}

/// `(height, raw block bytes)` pairs from either source. A directory is read as
/// `block-<height>.bin`; anything else in it is skipped rather than guessed at.
fn blocks_from(dir: Option<&Path>) -> Vec<(u32, Vec<u8>)> {
    let Some(dir) = dir else {
        return zebra_test::vectors::MAINNET_BLOCKS
            .iter()
            .map(|(h, b)| (*h, b.to_vec()))
            .collect();
    };

    let mut out = Vec::new();
    for entry in fs::read_dir(dir).expect("block directory must be readable") {
        let path = entry.expect("directory entry must be readable").path();
        let Some(height) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("block-"))
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        out.push((height, fs::read(&path).expect("block file must be readable")));
    }
    out.sort_by_key(|(h, _)| *h);
    out
}

fn main() {
    let arg = env::args().nth(1);
    let dir = arg.as_deref().map(Path::new);
    let blocks = blocks_from(dir);

    let mut all = Counts::default();
    let mut shielded_only_total = Counts::default();
    let mut blocks_with_content = 0usize;

    println!(
        "{:>10}  {:>6} {:>9} {:>8} {:>8} {:>8} {:>8} {:>5}   (shielded-only subset in parens)",
        "height", "txs", "joinsplt", "sap_spnd", "sap_outp", "orch_act", "iron_act", "dual"
    );
    println!("{}", "-".repeat(112));

    for (height, bytes) in blocks.iter() {
        let block: Block = bytes
            .as_slice()
            .zcash_deserialize_into()
            .expect("block must deserialize");

        let total = survey_block(&block, false);
        let shielded_only = survey_block(&block, true);

        all.add(&total);
        shielded_only_total.add(&shielded_only);

        if total.is_empty() {
            continue;
        }
        blocks_with_content += 1;
        println!(
            "{:>10}  {:>6} {:>4}({:>3}) {:>4}({:>2}) {:>4}({:>2}) {:>4}({:>2}) {:>4}({:>2}) {:>5}",
            height,
            total.txs,
            total.sprout_joinsplits,
            shielded_only.sprout_joinsplits,
            total.sapling_spends,
            shielded_only.sapling_spends,
            total.sapling_outputs,
            shielded_only.sapling_outputs,
            total.orchard_actions,
            shielded_only.orchard_actions,
            total.ironwood_actions,
            shielded_only.ironwood_actions,
            total.dual_pool_txs,
        );
    }

    println!("{}", "-".repeat(112));
    println!(
        "blocks: {} surveyed ({}), {} carry shielded content",
        blocks.len(),
        dir.map_or("in-tree vectors".to_string(), |d| d.display().to_string()),
        blocks_with_content
    );
    println!(
        "TOTAL          all: joinsplits={} sapling_spends={} sapling_outputs={} orchard_actions={} ironwood_actions={} dual_pool_txs={}",
        all.sprout_joinsplits,
        all.sapling_spends,
        all.sapling_outputs,
        all.orchard_actions,
        all.ironwood_actions,
        all.dual_pool_txs
    );
    println!(
        "TOTAL shielded-only: joinsplits={} sapling_spends={} sapling_outputs={} orchard_actions={} ironwood_actions={}",
        shielded_only_total.sprout_joinsplits,
        shielded_only_total.sapling_spends,
        shielded_only_total.sapling_outputs,
        shielded_only_total.orchard_actions,
        shielded_only_total.ironwood_actions,
    );
}
