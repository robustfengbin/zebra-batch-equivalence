//! Pool inventory across every corpus source the oracle can currently reach.
//!
//! M1 only ever asked one question of a transaction — "does it carry an Orchard
//! bundle?" — so the committed seed corpus was never audited for the pools M2
//! has to cover (Sapling Groth16 + RedJubjub, Sprout Groth16 + Ed25519). This
//! counts what is actually there, per source, so the M2 extraction layer is
//! designed against measured content rather than an assumption about which
//! pools were live at the heights we sampled.
//!
//! Run: `cargo run --example scan_pools`

use std::collections::BTreeMap;

use zebra_chain::{
    block::Block,
    serialization::{ZcashDeserialize, ZcashDeserializeInto},
    transaction::Transaction,
};

#[derive(Default, Debug)]
struct Tally {
    txs: usize,
    parse_failures: usize,

    orchard_txs: usize,
    orchard_actions: usize,

    sapling_txs: usize,
    sapling_spends: usize,
    sapling_outputs: usize,

    sprout_txs: usize,
    sprout_joinsplits: usize,
    sprout_groth16_txs: usize,
    sprout_groth16_joinsplits: usize,

    ironwood_txs: usize,

    // Oracle-usable subset: M1 excludes transparent-input transactions because
    // their ZIP-243/244 sighash folds in prevouts a bare transaction (or a bare
    // block vector) does not carry, so the sighash we could reconstruct would
    // not be the one the bundle was signed under. The same constraint applies
    // to every pool, so these are the counts M2 can actually verify against.
    sapling_txs_usable: usize,
    sapling_spends_usable: usize,
    sapling_outputs_usable: usize,
    sprout_txs_usable: usize,
    sprout_joinsplits_usable: usize,
}

impl Tally {
    fn ingest(&mut self, tx: &Transaction) {
        self.txs += 1;
        let shielded_only = tx.inputs().is_empty();

        if tx.has_orchard_shielded_data() {
            self.orchard_txs += 1;
            self.orchard_actions += tx.orchard_actions().count();
        }
        if tx.has_sapling_shielded_data() {
            let (spends, outputs) = (
                tx.sapling_spends_per_anchor().count(),
                tx.sapling_outputs().count(),
            );
            self.sapling_txs += 1;
            self.sapling_spends += spends;
            self.sapling_outputs += outputs;
            if shielded_only {
                self.sapling_txs_usable += 1;
                self.sapling_spends_usable += spends;
                self.sapling_outputs_usable += outputs;
            }
        }
        if tx.has_sprout_joinsplit_data() {
            let joinsplits = tx.joinsplit_count();
            // Only Groth16 JoinSplits reach Zebra's JOINSPLIT_VERIFIER. Pre-Sapling
            // (< 419,200) JoinSplits carry BCTV14 proofs, which no current batch
            // verifier consumes — counting them inflates the usable Sprout corpus.
            let groth16 = tx.sprout_groth16_joinsplits().count();
            self.sprout_txs += 1;
            self.sprout_joinsplits += joinsplits;
            self.sprout_groth16_joinsplits += groth16;
            if groth16 > 0 {
                self.sprout_groth16_txs += 1;
            }
            if shielded_only {
                self.sprout_txs_usable += 1;
                self.sprout_joinsplits_usable += joinsplits;
            }
        }
        if tx.ironwood_shielded_data().is_some() {
            self.ironwood_txs += 1;
        }
    }

    fn report(&self, label: &str) {
        println!("\n=== {label} ===");
        println!(
            "  transactions: {} (parse failures: {})",
            self.txs, self.parse_failures
        );
        println!(
            "  Orchard  : {:>5} txs / {:>6} actions   [M1 covered]",
            self.orchard_txs, self.orchard_actions
        );
        println!(
            "  Sapling  : {:>5} txs / {:>6} spends / {:>6} outputs   [M2 target]",
            self.sapling_txs, self.sapling_spends, self.sapling_outputs
        );
        println!(
            "     └ oracle-usable (no transparent inputs): {} txs / {} spends / {} outputs",
            self.sapling_txs_usable, self.sapling_spends_usable, self.sapling_outputs_usable
        );
        println!(
            "  Sprout   : {:>5} txs / {:>6} joinsplits (ALL proof systems)",
            self.sprout_txs, self.sprout_joinsplits
        );
        println!(
            "     └ Groth16 only (what JOINSPLIT_VERIFIER consumes): {} txs / {} joinsplits   [M2 target]",
            self.sprout_groth16_txs, self.sprout_groth16_joinsplits
        );
        println!(
            "     └ oracle-usable (no transparent inputs): {} txs / {} joinsplits",
            self.sprout_txs_usable, self.sprout_joinsplits_usable
        );
        println!(
            "  Ironwood : {:>5} txs   [M3 target]",
            self.ironwood_txs
        );
    }
}

/// Committed `seeds-real/<dir>` corpus: one raw transaction per `.bin` file.
fn scan_seed_dir(dir_name: &str) -> Tally {
    let dir = format!("{}/seeds-real/{dir_name}", env!("CARGO_MANIFEST_DIR"));
    let mut tally = Tally::default();

    let Ok(entries) = std::fs::read_dir(&dir) else {
        println!("  (missing dir {dir})");
        return tally;
    };

    let mut files: Vec<_> = entries
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    for path in &files {
        let bytes = std::fs::read(path).expect("read corpus file");
        match Transaction::zcash_deserialize(&bytes[..]) {
            Ok(tx) => tally.ingest(&tx),
            Err(_) => tally.parse_failures += 1,
        }
    }
    tally
}

/// In-tree mainnet block vectors — the M2 bootstrap corpus that needs no node.
fn scan_in_tree_blocks() -> (Tally, BTreeMap<u32, (usize, usize)>) {
    let mut tally = Tally::default();
    // height -> (sapling txs, sprout txs), so we can name the blocks worth using.
    let mut per_height = BTreeMap::new();

    for (height, bytes) in zebra_test::vectors::MAINNET_BLOCKS.iter() {
        let block: Block = bytes
            .zcash_deserialize_into()
            .expect("hard-coded mainnet test vector must deserialize");

        let (mut sap, mut spr) = (0, 0);
        for tx in &block.transactions {
            tally.ingest(tx);
            if tx.has_sapling_shielded_data() {
                sap += 1;
            }
            if tx.has_sprout_joinsplit_data() {
                spr += 1;
            }
        }
        if sap > 0 || spr > 0 {
            per_height.insert(*height, (sap, spr));
        }
    }
    (tally, per_height)
}

fn main() {
    println!("Corpus pool inventory — what M2's four verifiers actually have to work with.");

    let mut committed = Tally::default();
    for dir in ["orchard_v5_pre_nu6_2", "orchard_v5_nu6_2"] {
        let t = scan_seed_dir(dir);
        t.report(&format!("seeds-real/{dir}"));
        committed.txs += t.txs;
        committed.parse_failures += t.parse_failures;
        committed.orchard_txs += t.orchard_txs;
        committed.orchard_actions += t.orchard_actions;
        committed.sapling_txs += t.sapling_txs;
        committed.sapling_spends += t.sapling_spends;
        committed.sapling_outputs += t.sapling_outputs;
        committed.sprout_txs += t.sprout_txs;
        committed.sprout_joinsplits += t.sprout_joinsplits;
        committed.sprout_groth16_txs += t.sprout_groth16_txs;
        committed.sprout_groth16_joinsplits += t.sprout_groth16_joinsplits;
        committed.ironwood_txs += t.ironwood_txs;
        committed.sapling_txs_usable += t.sapling_txs_usable;
        committed.sapling_spends_usable += t.sapling_spends_usable;
        committed.sapling_outputs_usable += t.sapling_outputs_usable;
        committed.sprout_txs_usable += t.sprout_txs_usable;
        committed.sprout_joinsplits_usable += t.sprout_joinsplits_usable;
    }
    committed.report("COMMITTED SEED CORPUS (total)");

    let (in_tree, per_height) = scan_in_tree_blocks();
    in_tree.report("IN-TREE zebra_test::vectors::MAINNET_BLOCKS");

    println!("\n  blocks carrying Sapling/Sprout (height: sapling_txs, sprout_txs):");
    if per_height.is_empty() {
        println!("    (none)");
    }
    for (h, (sap, spr)) in &per_height {
        println!("    {h:>9}: sapling={sap}, sprout={spr}");
    }

    println!(
        "\n  in-tree vector heights available: {}",
        zebra_test::vectors::MAINNET_BLOCKS.len()
    );
    let heights: Vec<_> = zebra_test::vectors::MAINNET_BLOCKS.keys().collect();
    println!("  height range: {:?} .. {:?}", heights.first(), heights.last());
}
