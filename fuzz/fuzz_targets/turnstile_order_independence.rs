//! Turnstile soundness under evolved input: under every arrival order, each
//! double-spend report must name the right pair of transactions.
//!
//! **This target does not fit the shape of the other eight, and the reason is
//! worth stating.** They all compare two verification paths over the same items
//! — `batch ⟺ single`. The turnstile has no second path: it is an accumulator,
//! not a verifier, and there is nothing to run it against. So this target
//! supplies one: a reference model of what the reports must be, written without
//! the turnstile's bookkeeping, and compared report for report.
//!
//! **Why the comparison is per order, and not across orders.** The properties
//! M3 names (conservation, no double-migration, no forged residual value
//! crossing) are decided over a *run* of transactions, and a run has an order.
//! An earlier version of this target asked only that the *set* of flagged
//! `(pool, nullifier)` pairs be the same in three orders. For an accumulator
//! that only ever inserts, that set is the nullifiers seen at least twice —
//! a count, which no permutation can change — so the assertion could not fail
//! for this implementation. It also excluded the one part of a report that does
//! move with the order, `first_seen`, and that is where the module's one real
//! bug lived: `HashMap::insert` replaces the value it returns, so a third
//! sighting named the second transaction as the first. Putting that bug back
//! leaves the set comparison green.
//!
//! The model walks the same order, remembers where each `(pool, nullifier)`
//! was first seen, and emits one report for every later sighting naming that
//! first one. The turnstile must produce exactly those reports — no more, no
//! fewer, same names. The set of flagged pairs then agrees across orders as a
//! consequence rather than as the thing checked.
//!
//! **Input model**: concatenated transaction wire bytes, same as the other
//! targets, parsed by the shared `items_from_tx_stream_with` so the parsing
//! rules (stop at the first undecodable transaction, extract under
//! `catch_unwind`, cap the count) are not restated here. The run is fed three
//! times over, so every nullifier has a third sighting — the case the bug
//! above needed, and one real transactions never supply on their own.
//!
//! Three fixed permutations rather than a shuffle keyed off the input: a
//! failure should be reported against orders a reader can reconstruct from the
//! reproducer, not against a permutation that has to be re-derived from a hash.

#![no_main]

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;

use zebra_batch_equivalence::items_from_tx_stream_with;
use zebra_batch_equivalence::turnstile::Transaction;
use zebra_batch_equivalence::turnstile::{Pool, TurnstileState, TurnstileViolation};

/// One double-spend report: pool, nullifier, where it was first seen, where
/// it was seen again. Pool as its `Debug` name so reports sort.
type Report = (String, [u8; 32], String, String);

fn label(position: usize) -> String {
    format!("tx@{position}")
}

/// Each transaction's nullifiers per pool, in the order the turnstile reads
/// them. Extraction is shared with the turnstile deliberately: what is under
/// test is the bookkeeping, not how nullifiers come out of a transaction.
fn nullifiers(tx: &Transaction) -> [(Pool, Vec<[u8; 32]>); 2] {
    [
        (Pool::Orchard, tx.orchard_nullifiers().copied().map(Into::into).collect()),
        (Pool::Ironwood, tx.ironwood_nullifiers().map(Into::into).collect()),
    ]
}

/// What the turnstile reports as double spends when `txs` arrive in `order`.
fn reported(txs: &[Transaction], order: &[usize]) -> Vec<Report> {
    let mut state = TurnstileState::mid_chain();
    let mut out = Vec::new();
    for (position, &k) in order.iter().enumerate() {
        for v in state.admit(&txs[k], &label(position)) {
            if let TurnstileViolation::DoubleSpend {
                pool,
                nullifier,
                first_seen,
                again_in,
            } = v
            {
                out.push((format!("{pool:?}"), nullifier, first_seen, again_in));
            }
        }
    }
    out.sort();
    out
}

/// What it must report, from first sightings alone.
fn expected(txs: &[Transaction], order: &[usize]) -> Vec<Report> {
    let mut first: HashMap<(Pool, [u8; 32]), String> = HashMap::new();
    let mut out = Vec::new();
    for (position, &k) in order.iter().enumerate() {
        for (pool, nfs) in nullifiers(&txs[k]) {
            for n in nfs {
                match first.entry((pool, n)) {
                    Entry::Vacant(e) => {
                        e.insert(label(position));
                    }
                    Entry::Occupied(e) => {
                        out.push((format!("{pool:?}"), n, e.get().clone(), label(position)))
                    }
                }
            }
        }
    }
    out.sort();
    out
}

fuzz_target!(|data: &[u8]| {
    // `Transaction` is `Clone`, so the shared stream parser doubles as a
    // transaction reader: this target consumes whole transactions rather than
    // extracted verification items, because the turnstile's state spans them.
    let txs = items_from_tx_stream_with(data, |tx| vec![tx.clone()]);
    if txs.is_empty() {
        return;
    }

    let run: Vec<Transaction> = txs.iter().chain(&txs).chain(&txs).cloned().collect();
    let n = run.len();

    let forward: Vec<usize> = (0..n).collect();
    let reverse: Vec<usize> = (0..n).rev().collect();
    let evens_then_odds: Vec<usize> = (0..n)
        .filter(|k| k % 2 == 0)
        .chain((0..n).filter(|k| k % 2 == 1))
        .collect();

    for (name, order) in [
        ("forward", &forward),
        ("reverse", &reverse),
        ("evens-then-odds", &evens_then_odds),
    ] {
        let got = reported(&run, order);
        let want = expected(&run, order);
        if got != want {
            let missing: Vec<_> = want.iter().filter(|r| !got.contains(r)).take(4).collect();
            let extra: Vec<_> = got.iter().filter(|r| !want.contains(r)).take(4).collect();
            panic!(
                "TURNSTILE MISREPORT: order {name}, {} transactions fed three times; \
                 {} report(s) expected, {} made. expected-but-missing={missing:?} \
                 made-but-unexpected={extra:?}",
                txs.len(),
                want.len(),
                got.len(),
            );
        }
    }
});
