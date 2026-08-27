//! Count what a corpus directory actually contains, so published figures are
//! measured rather than restated.
//!
//! Written because a figure in the first monthly-update draft did not match the
//! corpus: three of four numbers agreed and the fourth did not, which is the
//! case worth having a tool for — several correct numbers give the wrong one
//! credibility, and they usually come from the same count, so the others cannot
//! catch it.
//!
//! Counts twice, by deliberately different routes: once through the oracle's own
//! extraction (`items_from_tx`), once by reading the bundles straight off the
//! transaction. Sharing code between the two would mean a bug in it produces the
//! same wrong answer twice — and "measured twice, same result" would then be
//! taken as evidence. The run asserts the two agree.
//!
//! **Run this before quoting any corpus figure. Do not copy figures out of the
//! survey logs.** The survey tool reports on the *source blocks* and prints both
//! an `all` and a `shielded-only` line — that is correct behaviour for what it
//! does. The mistake was using a source-block statistic to describe what got
//! stored, which is a different set. Two tools, two jobs; the damage came from
//! mixing them.
//!
//! Usage: `cargo run --example verify_corpus [dir-name]`
//!        (default `nu6_3_activation`)
use std::fs;
use zebra_batch_equivalence::{items_from_tx, Pool};
use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::Transaction;

fn main() {
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nu6_3_activation".to_string());
    let dir = format!("{}/seeds-real/{name}", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = fs::read_dir(&dir)
        .expect("dir")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    let (mut txs, mut items, mut orchard_act, mut ironwood_act, mut dual) = (0, 0, 0, 0, 0);
    for path in &files {
        let bytes = fs::read(path).expect("read");
        let tx = Transaction::zcash_deserialize(&bytes[..])
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        txs += 1;
        let extracted = items_from_tx(&tx);
        items += extracted.len();
        let mut has_o = false;
        let mut has_i = false;
        for it in &extracted {
            match it.pool {
                Pool::Orchard => {
                    orchard_act += it.action_count();
                    has_o = true;
                }
                Pool::Ironwood => {
                    ironwood_act += it.action_count();
                    has_i = true;
                }
            }
        }
        if has_o && has_i {
            dual += 1;
        }
    }
    // Second route: read the bundles directly, sharing no code with the above.
    let (mut o2, mut i2) = (0usize, 0usize);
    for path in &files {
        let bytes = fs::read(path).expect("read");
        let tx = Transaction::zcash_deserialize(&bytes[..]).expect("parse");
        if let Some(d) = tx.orchard_shielded_data() {
            o2 += d.actions().count();
        }
        if let Some(d) = tx.ironwood_shielded_data() {
            i2 += d.actions().count();
        }
    }

    println!("corpus            : seeds-real/{name}");
    println!("transactions      : {txs}");
    println!("verification items: {items}");
    println!("orchard actions   : {orchard_act}   (second route: {o2})");
    println!("ironwood actions  : {ironwood_act}   (second route: {i2})");
    println!("dual-pool txs     : {dual}");

    assert_eq!(
        orchard_act, o2,
        "the two counting routes disagree on Orchard actions"
    );
    assert_eq!(
        ironwood_act, i2,
        "the two counting routes disagree on Ironwood actions"
    );
    println!("\nboth routes agree.");
}
