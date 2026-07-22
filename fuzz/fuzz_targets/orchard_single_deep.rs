//! Orchard **single-bundle deep** verification harness (M1).
//!
//! A sister to the batch targets at *single-bundle* granularity — the depth
//! equivalent of ZCG#234's `orchard_bundle_verify` (which only asserted
//! panic-freedom), but adding the soundness assertions this grant exists for.
//!
//! Each Orchard bundle is extracted through the layered path
//! (`Transaction::zcash_deserialize` → V5+/Orchard filter → `sighasher` → native
//! `orchard::bundle::Bundle`), then verified on its own — a *batch of one*, which
//! is exactly `halo2::Item::verify_single`'s code path (halo2 proof +
//! RedPallas binding-signature verification). Every bundle is checked under
//! **each** circuit-era key:
//!
//!   * **no era may false-accept** the single bundle (batch-of-one vs single
//!     agree; a divergence is the harness/soundness break).
//!   * **at most one era accepts** a given bundle — single-bundle era routing.
//!
//! Throughput here is intentionally low: each accepted bundle triggers real
//! SNARK verification. Coverage of the single-item verify path — not exec/s — is
//! the signal.
//!
//! No pool control byte: this target is single-bundle-granular, so extraction
//! (which yields Orchard- and Ironwood-pool items alike from v6 wire) already
//! walks every pool's items through the full era matrix one by one.

#![no_main]

use libfuzzer_sys::fuzz_target;

use zebra_batch_equivalence::{
    check_equivalence_refs, derive_seed, items_from_tx_stream, CircuitEra, EquivReport, OrchardItem,
};

fuzz_target!(|data: &[u8]| {
    // `items_from_tx_stream` performs the layered extraction (deserialize →
    // V5+/Orchard filter → sighash → bundle) under catch_unwind per tx.
    let items = items_from_tx_stream(data);
    if items.is_empty() {
        return;
    }
    let seed = derive_seed(data);

    // Each bundle on its own (single granularity), under every era key.
    for (i, item) in items.iter().enumerate() {
        let one: [&OrchardItem; 1] = [item];
        let mut accepting = 0usize;

        for era in CircuitEra::ALL {
            match check_equivalence_refs(&one, era.key(), seed) {
                EquivReport::FalseAccept => panic!(
                    "ORCHARD SINGLE FALSE-ACCEPT: bundle #{i} accepted-as-batch-of-one but \
                     rejected-as-single under {era:?} — soundness break. seed={seed:#x}",
                ),
                EquivReport::Agree(true) => accepting += 1,
                EquivReport::Agree(false) | EquivReport::FalseReject => {}
            }
        }

        if accepting > 1 {
            panic!(
                "ORCHARD SINGLE ERA-ROUTING: bundle #{i} verified under {accepting} circuit \
                 eras — key confusion. seed={seed:#x}",
            );
        }
    }
});
