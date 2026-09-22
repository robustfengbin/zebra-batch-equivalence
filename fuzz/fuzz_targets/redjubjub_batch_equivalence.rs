//! Sapling RedJubjub `batch ⟺ single` equivalence under evolved input.
//!
//! The fourth verifier the grant names, and the one with no production caller:
//! `sapling-crypto` bundles the RedJubjub signatures into the same validator as
//! the Groth16 proofs, so Zebra's standalone `redjubjub` verifier service is
//! never reached. This target drives the signature batch directly, which is what
//! makes it a distinct surface from `sapling_batch_equivalence` rather than a
//! subset of it: there, a signature failure and a proof failure are the same
//! verdict; here, only the signatures are in play.
//!
//! **Input model**: concatenated transaction wire bytes. Items come out of each
//! transaction's Sapling bundle — the spend-auth signature per spend plus the
//! binding signature — so one transaction usually yields several items.
//!
//! **What is asserted**: whole-batch equivalence and per-item equivalence, the
//! second being the stronger claim (it is the only one that can see one item's
//! presence changing another item's verdict). A false-accept panics so libFuzzer
//! keeps the reproducer; a false-reject is logged, because a batch rejecting a
//! set of individually-valid signatures is what a shared verdict means, not a
//! finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

use zebra_batch_equivalence::fuzz_input::redjubjub_items;
use zebra_batch_equivalence::redjubjub::{RedJubjub, RedJubjubItem};
use zebra_batch_equivalence::verifier::{check_equivalence_per_item, check_equivalence_refs};
use zebra_batch_equivalence::{derive_seed, items_from_tx_stream_with, EquivReport};

fuzz_target!(|data: &[u8]| {
    // No init warm-up here, and that is not an oversight: RedJubjub verifies
    // against the key each item carries, so this verifier has no key material to
    // build (`type Context = ()`). Extraction goes through the Sapling item,
    // which needs no parameters either — only the batch/single verification does,
    // and there is none for signatures.
    // Same transparent-input rule as the Sapling target; both take it from
    // `fuzz_input` rather than restating it.
    let items = items_from_tx_stream_with(data, redjubjub_items);
    if items.is_empty() {
        return;
    }
    let refs: Vec<&RedJubjubItem> = items.iter().collect();
    let seed = derive_seed(data);

    // 1. Whole-batch equivalence.
    match check_equivalence_refs::<RedJubjub>(&refs, &(), seed) {
        EquivReport::FalseAccept => panic!(
            "REDJUBJUB BATCH FALSE-ACCEPT: batch accepted signatures single verification \
             rejects. items={}, seed={seed:#x}",
            refs.len(),
        ),
        EquivReport::FalseReject => {
            eprintln!(
                "redjubjub batch FALSE-REJECT (liveness): items={}, seed={seed:#x}",
                refs.len(),
            );
        }
        EquivReport::Agree(_) => {}
    }

    // 2. Per-item equivalence.
    let per_item = check_equivalence_per_item::<RedJubjub>(&refs, &(), seed);
    let false_accepts = per_item.false_accepts();
    if !false_accepts.is_empty() {
        panic!(
            "REDJUBJUB PER-ITEM FALSE-ACCEPT at indices {false_accepts:?}: the batch accepted a \
             signature single verification rejects. items={}, seed={seed:#x}",
            refs.len(),
        );
    }
});
