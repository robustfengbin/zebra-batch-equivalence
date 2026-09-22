//! Can the tower layer be fuzzed at a useful rate? (ZCG #332 · M3)
//!
//! The tower surface is the fourth of the four M2 added, and the only one whose
//! batch boundaries are drawn by a real scheduler rather than by us. That makes
//! it worth covering — and it is also what makes a fuzz target there doubtful,
//! for a reason that has nothing to do with how hard it is to write:
//!
//! `tower-batch-control`'s worker flushes on exactly two events — the batch
//! reaching `max_weight`, or the latency timer firing. Closing the channel does
//! *not* flush; the worker simply returns (`worker.rs:285` at our pinned
//! revision). So a partly-full final batch has only the timer, and every fuzz
//! input would pay it. At the 30-second timer the existing suite uses, that is
//! 0.03 executions per second — a target that runs, and covers nothing.
//!
//! The way out is to make the last batch full rather than to make the timer
//! short: a short timer buys speed by letting the *clock* decide who shares a
//! batch, which is the one property a fuzz target here must not have (a crash
//! whose reproducer needs the same scheduling accident is not a reproducer).
//! Truncating the item list to a multiple of `max_weight` keeps the partition a
//! pure function of the input and removes the timer from the path entirely.
//!
//! This measures what that costs, so the decision to build the target — or to
//! say in the delivery report why it stays a deterministic test — rests on a
//! number rather than on either of our intuitions.
//!
//! ```text
//! cargo run --release --example tower_fuzz_feasibility
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::join_all;
use tower::{Service, ServiceExt};

use zebra_batch_equivalence::fuzz_input::redjubjub_items;
use zebra_batch_equivalence::redjubjub::{RedJubjub, RedJubjubItem};
use zebra_batch_equivalence::tower::{batched_with, Weighted};
use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::Transaction;

/// The timer the existing suite uses. Kept deliberately: the point is to show
/// that with the truncation trick it is never reached, not to hide it behind a
/// small value.
const SLOW_TIMER: Duration = Duration::from_secs(30);
const SEED: u64 = 0x5eed;

fn load_items() -> Vec<Arc<RedJubjubItem>> {
    let mut items = Vec::new();
    for dir in ["orchard_v5_pre_nu6_2", "orchard_v5_nu6_2", "nu6_3_activation"] {
        let path = format!("{}/seeds-real/{dir}", env!("CARGO_MANIFEST_DIR"));
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        let mut files: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_none_or(|x| x != "md"))
            .collect();
        files.sort();
        for f in files {
            let Ok(bytes) = std::fs::read(&f) else { continue };
            let Ok(tx) = Transaction::zcash_deserialize(&bytes[..]) else {
                continue;
            };
            items.extend(redjubjub_items(&tx).into_iter().map(Arc::new));
        }
    }
    items
}

/// One fuzz input's worth of work: submit `items` through the middleware with
/// the given `max_weight`, collect a verdict each.
async fn submit_all(items: &[Arc<RedJubjubItem>], max_weight: usize) -> Vec<bool> {
    let (svc, _log) = batched_with::<RedJubjub>(&(), SEED, max_weight, SLOW_TIMER);
    let mut pending = Vec::with_capacity(items.len());
    for item in items {
        let mut svc = svc.clone();
        pending.push(
            svc.ready()
                .await
                .expect("batch service accepts items")
                .call(Weighted::<RedJubjub>::new(Arc::clone(item))),
        );
    }
    join_all(pending)
        .await
        .into_iter()
        .map(|r| r.expect("every item receives a verdict"))
        .collect()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let all = load_items();
    println!("corpus: {} RedJubjub items\n", all.len());
    assert!(
        all.len() >= 32,
        "not enough items to measure anything meaningful"
    );

    // Batch sizes a fuzzer's control byte would land on. For each, the item
    // count is truncated to a multiple of it — the whole point of the exercise.
    println!(
        "{:>10} {:>8} {:>10} {:>12} {:>10}",
        "max_weight", "items", "batches", "elapsed", "est ex/s"
    );
    println!("{}", "-".repeat(54));

    for max_weight in [1usize, 2, 4, 7, 16, 64] {
        // A: truncate so the final batch is full and the timer is never reached.
        let n = (all.len().min(64) / max_weight) * max_weight;
        if n == 0 {
            continue;
        }
        let items = &all[..n];

        // Warm any lazy state before timing, so the first row does not carry
        // everyone else's setup — the mistake that produced a `timeout-<hash>`
        // reproducer for an innocent input earlier today.
        let _ = submit_all(&items[..max_weight], max_weight).await;

        const REPS: usize = 5;
        let start = Instant::now();
        for _ in 0..REPS {
            let verdicts = submit_all(items, max_weight).await;
            assert_eq!(verdicts.len(), items.len());
        }
        let per_input = start.elapsed() / REPS as u32;

        println!(
            "{:>10} {:>8} {:>10} {:>12?} {:>10.1}",
            max_weight,
            n,
            n / max_weight,
            per_input,
            1.0 / per_input.as_secs_f64(),
        );
    }

    println!(
        "\nEvery row above avoided the {SLOW_TIMER:?} timer: the item count is a multiple of\n\
         max_weight, so the last batch fills and flushes on weight. A row anywhere near\n\
         {SLOW_TIMER:?} would mean the truncation is not working and the timer is on the path."
    );
}
