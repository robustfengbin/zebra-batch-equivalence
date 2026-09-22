//! Sprout JoinSplit Groth16 `batch ⟺ single` equivalence under evolved input.
//!
//! **Read `src/sprout.rs`'s module docs before citing anything from this
//! target.** Zebra does not batch-verify JoinSplits: `JOINSPLIT_VERIFIER` calls
//! `Item::verify_single` on each one, and the upstream issue proposing batch
//! support was closed `not planned`. So the disagreement this target hunts for
//! cannot occur in Zebra today — there is no batch to disagree with. What it
//! covers is `bellman::groth16::batch` under Sprout's parameters and real Sprout
//! proofs: the code JoinSplit verification would run on if batching were ever
//! switched on, and one of the four verifiers the grant names.
//!
//! **Input model**: concatenated transaction wire bytes. Every Groth16 JoinSplit
//! in every transaction becomes an item — several per transaction is normal,
//! unlike the other pools.
//!
//! Note what is *not* filtered here, and why it differs from every other pool in
//! this crate: there is no shielded-only rule. A Sprout Groth16 proof is not
//! bound to a sighash, so a transparent input cannot invalidate it. (The Ed25519
//! signature over the same JoinSplit *is* bound to one — a different item
//! stream, with a different usability rule.)
//!
//! A false-accept panics; a false-reject is logged. Batch verification is
//! entitled to reject a set of valid proofs — that is what one shared verdict
//! over an aggregate equation means — and escalating it would bury the
//! soundness signal in liveness noise.

#![no_main]

use libfuzzer_sys::fuzz_target;

use zebra_batch_equivalence::fuzz_input::sprout_items;
use zebra_batch_equivalence::sprout::{Sprout, SproutItem, SproutKeys};
use zebra_batch_equivalence::verifier::{check_equivalence_per_item, check_equivalence_refs};
use zebra_batch_equivalence::{derive_seed, items_from_tx_stream_with, EquivReport};

fuzz_target!(init: {
    // Before libFuzzer's per-input clock starts: `SproutKeys::bundled` loads and
    // hash-checks the JoinSplit proving parameters, a multi-second cold start.
    // Left lazy it is charged to whichever input happens to run first, and
    // reported as a `-timeout=25` crash naming an input that is fine.
    let _ = SproutKeys::bundled();
}, |data: &[u8]| {
    // No sighash rule for this pool — see `fuzz_input`'s module docs.
    let items = items_from_tx_stream_with(data, sprout_items);
    if items.is_empty() {
        return;
    }
    let refs: Vec<&SproutItem> = items.iter().collect();
    let seed = derive_seed(data);
    let keys = SproutKeys::bundled();

    // 1. Whole-batch equivalence.
    match check_equivalence_refs::<Sprout>(&refs, keys, seed) {
        EquivReport::FalseAccept => panic!(
            "SPROUT BATCH FALSE-ACCEPT: the bellman batch verifier accepted a set single \
             verification rejects. items={}, seed={seed:#x}",
            refs.len(),
        ),
        EquivReport::FalseReject => {
            eprintln!(
                "sprout batch FALSE-REJECT (liveness): items={}, seed={seed:#x}",
                refs.len(),
            );
        }
        EquivReport::Agree(_) => {}
    }

    // 2. Per-item equivalence. In this pool every item shares one verdict by
    //    construction — `queue` cannot fail and batch verification is a single
    //    equation over the whole set — so a per-item false-accept here means the
    //    aggregate equation accepted where an individual proof does not, which
    //    is the aggregation-glue failure the whole-batch boolean cannot localise.
    let per_item = check_equivalence_per_item::<Sprout>(&refs, keys, seed);
    let false_accepts = per_item.false_accepts();
    if !false_accepts.is_empty() {
        panic!(
            "SPROUT PER-ITEM FALSE-ACCEPT at indices {false_accepts:?}: the batch accepted a \
             JoinSplit single verification rejects. items={}, seed={seed:#x}",
            refs.len(),
        );
    }
});
