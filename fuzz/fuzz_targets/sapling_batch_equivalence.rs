//! Sapling `batch ⟺ single` equivalence under evolved input.
//!
//! M2 put the Sapling verifier under the equivalence oracle and exercised it
//! with a designed corpus — real mainnet bundles and four enumerable tamper
//! classes. That answers "does it agree on the inputs we thought of". This
//! target answers the other half: a coverage-guided fuzzer picks the inputs, so
//! agreement is asserted over transaction shapes nobody enumerated.
//!
//! **Input model**: concatenated transaction wire bytes, the same shape the
//! Orchard targets take, parsed by [`items_from_tx_stream_with`]. One Sapling
//! bundle per transaction, so items map one-to-one onto transactions here —
//! unlike Orchard, where a v6 transaction can contribute two.
//!
//! **What is asserted**, both at once because they are not the same claim:
//!
//!   * **whole-batch equivalence** — `batch(N)` must equal `AND(single_i)`. The
//!     batch accepting a set that single verification rejects is a false-accept:
//!     the counterfeiting-class break.
//!   * **per-item equivalence** — every item must be judged identically by both
//!     paths. Strictly stronger, and it is the question a whole-batch boolean
//!     cannot ask: *did one item's presence change a different item's verdict?*
//!     A batch that is already "not clean" at whole-batch granularity masks
//!     exactly that.
//!
//! A false-accept panics, so libFuzzer captures the reproducer. A false-reject
//! is logged: batch verification is allowed to reject a set of valid proofs
//! (that is what a shared verdict means), and treating it as a crash would bury
//! the soundness signal under liveness noise.

#![no_main]

use libfuzzer_sys::fuzz_target;

use zebra_batch_equivalence::fuzz_input::sapling_items;
use zebra_batch_equivalence::sapling::{Sapling, SaplingItem, SaplingKeys};
use zebra_batch_equivalence::verifier::{check_equivalence_per_item, check_equivalence_refs};
use zebra_batch_equivalence::{derive_seed, items_from_tx_stream_with, EquivReport};

fuzz_target!(init: {
    // Before libFuzzer's per-input clock starts. `SaplingKeys::bundled` parses
    // the bundled Groth16 parameters, which is a multi-second cold start; left
    // lazy it lands inside whichever input runs first and is reported as a
    // `-timeout=25` crash naming an input that is fine. See
    // `era::warm_verifying_keys` for the same problem on the Orchard side.
    let _ = SaplingKeys::bundled();
}, |data: &[u8]| {
    // `fuzz_input::sapling_items` carries the transparent-input rule and why it
    // is per-verifier. Shared with `examples/survey_fuzz_seeds.rs`, so what that
    // survey measures is what this target actually consumes.
    let items = items_from_tx_stream_with(data, sapling_items);
    if items.is_empty() {
        return;
    }
    let refs: Vec<&SaplingItem> = items.iter().collect();
    let seed = derive_seed(data);
    let keys = SaplingKeys::bundled();

    // 1. Whole-batch equivalence.
    match check_equivalence_refs::<Sapling>(&refs, keys, seed) {
        EquivReport::FalseAccept => panic!(
            "SAPLING BATCH FALSE-ACCEPT: batch accepted a set single verification rejects — \
             counterfeiting-class soundness failure. items={}, seed={seed:#x}",
            refs.len(),
        ),
        EquivReport::FalseReject => {
            eprintln!(
                "sapling batch FALSE-REJECT (liveness): items={}, seed={seed:#x}",
                refs.len(),
            );
        }
        EquivReport::Agree(_) => {}
    }

    // 2. Per-item equivalence. Reported separately from the whole-batch check
    //    above: a per-item false-accept can hide inside a batch whose overall
    //    verdict already disagreed, and that is precisely the cross-item
    //    influence this milestone exists to rule out.
    let per_item = check_equivalence_per_item::<Sapling>(&refs, keys, seed);
    let false_accepts = per_item.false_accepts();
    if !false_accepts.is_empty() {
        panic!(
            "SAPLING PER-ITEM FALSE-ACCEPT at indices {false_accepts:?}: the batch accepted an \
             item single verification rejects. items={}, seed={seed:#x}",
            refs.len(),
        );
    }
});
