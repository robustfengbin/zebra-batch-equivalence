//! Orchard **era-routing** equivalence harness (M1).
//!
//! The Orchard verifying key changes across three circuit eras (pre-NU6.2 /
//! NU6.2 / NU6.3-onward), and production routes each bundle to a key by the
//! block's network upgrade. Routing is one of the few Orchard bugs that is *not*
//! a negligible-probability cryptographic event but plain glue logic: a wrong
//! key, a fail-open, a key that verifies a proof it should not. This target
//! stresses the key matrix at **batch** granularity.
//!
//! For one set of real bundles, verified under **every** circuit-era key:
//!
//!   * **no key may false-accept** — batch and single must agree under each key;
//!     a batch that accepts what single rejects, under any key, is the break.
//!   * **at most one era accepts** — a proof commits to exactly one circuit, so a
//!     valid same-era set verifies under at most one era key. Two accepting keys
//!     would mean one proof verified under two circuits — key confusion / a
//!     fail-open. (Invalid or mixed-era sets accept under none.)
//!
//! Fed the real multi-era corpus (pre-NU6.2 + NU6.2), the accepting era is the
//! bundles' true era and every other key must reject both paths.
//!
//! The pool dimension needs no control byte here: extraction yields Orchard-
//! and Ironwood-pool items alike (a v6 tx can carry both), and the at-most-one-
//! era matrix quantifies over whatever set arrives — including cross-pool sets,
//! which share the PostNu6_3 circuit and must still accept under at most the
//! NU6.3 key.

#![no_main]

use libfuzzer_sys::fuzz_target;

use zebra_batch_equivalence::{
    check_equivalence_refs, derive_seed, items_from_tx_stream, CircuitEra, EquivReport, OrchardItem,
};

fuzz_target!(|data: &[u8]| {
    let items = items_from_tx_stream(data);
    if items.is_empty() {
        return;
    }
    let refs: Vec<&OrchardItem> = items.iter().collect();
    let seed = derive_seed(data);

    let mut accepting = 0usize;
    for era in CircuitEra::ALL {
        let report = check_equivalence_refs(&refs, era.key(), seed);
        match report {
            EquivReport::FalseAccept => panic!(
                "ORCHARD ERA-ROUTING FALSE-ACCEPT: batch accepted under {era:?} what single \
                 rejects — fail-open key confusion. items={}, seed={seed:#x}",
                refs.len(),
            ),
            EquivReport::Agree(true) => accepting += 1,
            EquivReport::Agree(false) | EquivReport::FalseReject => {}
        }
    }

    // A valid same-era set verifies under at most one circuit-era key.
    if accepting > 1 {
        panic!(
            "ORCHARD ERA-ROUTING: {accepting} era keys accepted the same set — a proof verified \
             under multiple circuits (key confusion / fail-open). items={}, seed={seed:#x}",
            refs.len(),
        );
    }
});
