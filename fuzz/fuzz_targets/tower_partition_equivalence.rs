//! Who shares a batch must not change anyone's verdict — under evolved input.
//!
//! The fourth of the four surfaces M2 added, and the only one where the batch
//! boundary is not ours. Everywhere else in this crate we choose the groups; here
//! `tower-batch-control`'s worker draws them from a `select!` between "another
//! item arrived" and "the timer fired". That matters beyond coverage: batch
//! membership is partly a function of what the network delivered, so it is not
//! entirely under the node's control — and the property that has to hold is that
//! **it does not matter**.
//!
//! **Input model**: concatenated transaction wire bytes, plus one trailing
//! control byte choosing `max_weight` — the batch capacity, which is what decides
//! the partition.
//!
//! **The truncation is load-bearing, not tidiness.** `tower-batch-control`
//! flushes on exactly two events: the batch reaching `max_weight`, or the latency
//! timer firing. Closing the channel does *not* flush — the worker returns and
//! the items still in hand never get a verdict (`worker.rs:285` at the pinned
//! revision). So a partly-full final batch can only be released by the timer, and
//! every fuzz input would pay it: 0.03 executions per second at the 30-second
//! timer the deterministic suite uses. Truncating the item list to a multiple of
//! `max_weight` makes every batch full, takes the timer off the path entirely,
//! and measures at 13–72 exec/s (`examples/tower_fuzz_feasibility.rs`).
//!
//! **A short timer would also be fast, and is rejected.** It buys the speed by
//! letting the clock decide who shares a batch — and a crash whose reproducer
//! needs the same scheduling accident is not a reproducer. The truncation keeps
//! the partition a pure function of the input.
//!
//! **What is asserted**, over two different partitions of the same items. The
//! shape of these two matters more than it looks:
//!
//!   * **No false-accept, under either partition.** The middleware must never
//!     hand an item an accept it does not earn on its own. Asked through
//!     [`classify`] rather than a comparison written here, because the direction
//!     *is* the judgement: this target's first draft asserted `batched != alone`,
//!     which also fires when a batch **rejects** an individually-valid item — and
//!     that is what one shared verdict over an aggregate means, not a finding. It
//!     turned every mutated signature in the corpus into a false alarm within 94
//!     executions.
//!   * **Partition-independence, but only where that is a real claim.** When
//!     every item verifies alone, no batch can hold a reason to reject, so both
//!     partitions must accept everything. With an invalid item present the two
//!     partitions poison *different* neighbours by construction; comparing them
//!     there would report the definition of batch verification as a bug.

#![no_main]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures::future::join_all;
use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;
use tower::{Service, ServiceExt};

use zebra_batch_equivalence::fuzz_input::redjubjub_items;
use zebra_batch_equivalence::redjubjub::{RedJubjub, RedJubjubItem};
use zebra_batch_equivalence::tower::{batched_with, Weighted};
use zebra_batch_equivalence::verifier::{classify, BatchVerifier};
use zebra_batch_equivalence::{derive_seed, items_from_tx_stream_with, EquivReport};

/// Long enough that it is never reached: with the truncation below, every batch
/// flushes on weight. Kept at the deterministic suite's value rather than shrunk,
/// so that a run drifting into timer-driven flushes shows up as a target that
/// suddenly crawls instead of one that quietly changed what it tests.
const NEVER: Duration = Duration::from_secs(30);

/// One runtime for the whole fuzzing session. Built in `init`, before libFuzzer's
/// per-input clock starts, and reused — building one per input would charge every
/// execution for thread-pool setup and put a fixed cost between the fuzzer and
/// the code under test.
static RT: OnceLock<Runtime> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RT.get().expect("runtime built in init")
}

async fn verdicts_under(items: &[Arc<RedJubjubItem>], max_weight: usize, seed: u64) -> Vec<bool> {
    let (svc, _log) = batched_with::<RedJubjub>(&(), seed, max_weight, NEVER);
    let mut pending = Vec::with_capacity(items.len());
    for item in items {
        let mut svc = svc.clone();
        // Submitted without awaiting the verdict: awaiting each one before
        // sending the next would serialise everything into batches of one, which
        // is precisely the thing this target must not accidentally do.
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
        .map(|r| r.expect("every submitted item receives a verdict"))
        .collect()
}

fuzz_target!(init: {
    let _ = RT.set(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime"),
    );
}, |data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (stream, control) = data.split_at(data.len() - 1);
    let control = control[0] as usize;

    let items: Vec<Arc<RedJubjubItem>> = items_from_tx_stream_with(stream, redjubjub_items)
        .into_iter()
        .map(Arc::new)
        .collect();
    if items.len() < 2 {
        return;
    }
    let seed = derive_seed(data);

    // Two capacities, so the same items are partitioned two different ways. The
    // second is derived rather than taken from a second control byte: it must
    // differ from the first, and a fuzzer handed two free bytes spends most of
    // its inputs on pairs that happen to be equal — which assert nothing.
    let wide = 1 + (control % items.len());
    let narrow = if wide == 1 { 2.min(items.len()) } else { 1 + (wide - 1) / 2 };
    if wide == narrow {
        return;
    }

    // Truncate to a length divisible by both, so neither run's final batch is
    // partial. See the module docs: a partial final batch waits for a 30-second
    // timer, and that is the difference between a target that fuzzes and one that
    // merely runs.
    let step = lcm(wide, narrow);
    let n = (items.len() / step) * step;
    if n == 0 {
        return;
    }
    let items = &items[..n];

    let (wide_verdicts, narrow_verdicts, alone) = runtime().block_on(async {
        let w = verdicts_under(items, wide, seed).await;
        let n = verdicts_under(items, narrow, seed).await;
        let a: Vec<bool> = items
            .iter()
            .map(|item| RedJubjub::validate_one(item, &(), seed))
            .collect();
        (w, n, a)
    });

    // The soundness question, asked of each partition independently: did the
    // middleware hand an item an accept that the item does not earn on its own?
    //
    // `classify` rather than a comparison written here: the direction is the
    // whole content of the judgement, and `w != a` — which is what this target
    // asserted in its first draft — fires on the *opposite* case too. A batch
    // rejecting an individually-valid item is what one shared verdict over an
    // aggregate means, not a finding; escalating it turns every mutated
    // signature in the corpus into a false alarm.
    for (label, verdicts, weight) in [
        ("wide", &wide_verdicts, wide),
        ("narrow", &narrow_verdicts, narrow),
    ] {
        for (i, (&batched, &solo)) in verdicts.iter().zip(alone.iter()).enumerate() {
            if classify(batched, solo) == EquivReport::FalseAccept {
                panic!(
                    "TOWER FALSE-ACCEPT at item {i} ({label}, max_weight={weight}): the middleware \
                     accepted an item that fails on its own. items={}, seed={seed:#x}",
                    items.len(),
                );
            }
        }
    }

    // Partition-independence, and only where it is a real claim: when every item
    // is individually valid, no batch can contain a reason to reject, so both
    // partitions must accept everything. With an invalid item present the two
    // partitions poison *different* neighbours by construction — comparing them
    // there would report the definition of batch verification as a bug.
    if alone.iter().all(|&ok| ok) {
        for (i, (&w, &n)) in wide_verdicts.iter().zip(narrow_verdicts.iter()).enumerate() {
            if !(w && n) {
                panic!(
                    "TOWER PARTITION DEPENDENCE at item {i}: every item verifies alone, yet \
                     {wide}-wide says {w} and {narrow}-wide says {n}. Who an item shares a batch \
                     with changed its verdict. items={}, seed={seed:#x}",
                    items.len(),
                );
            }
        }
    }
});

fn lcm(a: usize, b: usize) -> usize {
    a / gcd(a, b) * b
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}
