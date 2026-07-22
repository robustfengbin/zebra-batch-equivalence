//! Add-time rejection equivalence over the NU6.3 cross-address restriction (ZCG #332 · W4e).
//!
//! orchard 0.15.0's `BatchValidator::add_bundle` returns `Err(RestrictionUnsupportedByKey)`
//! for a bundle that *disables* cross-address transfers when the verifying key's circuit
//! cannot constrain that restriction (pre-NU6.2 / NU6.2). That introduces a rejection site
//! *before* proof verification — **add time** — alongside verify-time rejection. These tests
//! pin the equivalence contract across it:
//!
//! * under an unsupported key (pre-NU6.2, NU6.2) the bundle must be rejected fail-closed on
//!   BOTH paths — `Agree(false)`, never a one-sided FalseAccept/FalseReject;
//! * under the supporting key (NU6.3-onward) it is accepted at add time and, being genuinely
//!   proven, verifies end to end — `Agree(true)`. This doubles as the suite's first
//!   **synthetic NU6.3-era accept-true vector** (W4f leg 1): a real PostNu6_3 proof, not a stub;
//! * folded into an otherwise-valid batch, an un-queueable bundle must poison the whole batch
//!   identically on both paths — batch aggregation cannot mask an item that never entered it.
//!
//! Why synthesized: a cross-address-*disabled* bundle is unrepresentable in any pre-NU6.3 wire
//! encoding (the flag bit does not exist there), so no extracted mainnet corpus or fuzzed
//! byte stream can ever reach this arm. Until real NU6.3 traffic exists (mainnet activation
//! ~2026-07-28), orchard's builder is the only source.

mod common;

use common::synth;
use zebra_batch_equivalence::{check_equivalence_refs, CircuitEra, EquivReport, OrchardItem};

/// Unsupported keys (pre-NU6.2, NU6.2): rejected at add time on BOTH paths, across seeds.
/// A one-sided outcome here would mean the add-time gate diverges between batch and single —
/// exactly the class of asymmetry this grant exists to catch.
#[test]
fn add_time_rejection_agrees_under_unsupported_keys() {
    let item = synth::disabled_orchard_item();
    for era in [CircuitEra::PreNu6_2, CircuitEra::Nu6_2] {
        assert!(
            !era.supports_cross_address_restriction(),
            "test premise: {era:?} cannot constrain the cross-address restriction"
        );
        for seed in [0u64, 1, 0xDEAD_BEEF] {
            let report = check_equivalence_refs(&[item], era.key(), seed);
            assert_eq!(
                report,
                EquivReport::Agree(false),
                "disabled-cross-address bundle under {era:?} (seed {seed}) must be \
                 rejected fail-closed by BOTH paths; got {report:?}"
            );
        }
    }
}

/// The supporting key (NU6.3-onward): accepted at add time and the real proof verifies —
/// end-to-end `Agree(true)`. First synthetic NU6.3-era accept-true vector in the suite.
#[test]
fn supporting_key_accepts_and_verifies_end_to_end() {
    let item = synth::disabled_orchard_item();
    let era = CircuitEra::Nu6_3Onward;
    assert!(era.supports_cross_address_restriction());

    let report = check_equivalence_refs(&[item], era.key(), 7);
    assert_eq!(
        report,
        EquivReport::Agree(true),
        "a genuinely-proven disabled-cross-address bundle under the NU6.3 key must be \
         accepted by BOTH paths; got {report:?}"
    );
}

/// era-routing corollary over the synthetic vector: exactly one era accepts it. Mirrors the
/// `orchard_era_routing` fuzz target's "at most one era accepts" soundness matrix, now with a
/// third-era-native member.
#[test]
fn exactly_one_era_accepts_the_synthetic_vector() {
    let item = synth::disabled_orchard_item();
    let accepting: Vec<CircuitEra> = CircuitEra::ALL
        .into_iter()
        .filter(|era| check_equivalence_refs(&[item], era.key(), 3) == EquivReport::Agree(true))
        .collect();
    assert_eq!(
        accepting,
        vec![CircuitEra::Nu6_3Onward],
        "the synthetic NU6.3 vector must verify under exactly its own era"
    );
}

/// The synthetic Ironwood vector verifies under the third era and only it: the legacy
/// keys reject at *verify* time (the proof commits to the wrong circuit; cross-address
/// stays enabled so the add gate does not fire), the NU6.3 key accepts end to end.
#[test]
fn synthetic_ironwood_vector_verifies_under_third_era_only() {
    let item = synth::ironwood_item();
    for era in CircuitEra::ALL {
        let expected = if era == CircuitEra::Nu6_3Onward {
            EquivReport::Agree(true)
        } else {
            EquivReport::Agree(false)
        };
        let report = check_equivalence_refs(&[item], era.key(), 12);
        assert_eq!(
            report, expected,
            "synthetic Ironwood bundle under {era:?}: expected {expected:?}, got {report:?}"
        );
    }
}

/// An un-queueable bundle folded into an otherwise-valid batch poisons the whole batch
/// identically on both paths, wherever it sits: batch fails closed at add time, and the
/// single conjunction contains the same reject. No aggregation masking.
#[test]
fn unqueueable_item_poisons_batch_consistently() {
    let corpus = common::pre_nu6_2_corpus();
    assert!(
        !corpus.is_empty(),
        "in-tree mainnet vectors must yield at least one pre-NU6.2 Orchard item"
    );
    let vk = CircuitEra::PreNu6_2.key();

    // The valid corpus alone agrees on accept (baseline premise, not the point of this test).
    let valid_refs: Vec<&OrchardItem> = corpus.iter().collect();
    assert_eq!(
        check_equivalence_refs(&valid_refs, vk, 0xF00D),
        EquivReport::Agree(true)
    );

    // Splice the disabled bundle at the front, middle, and back of the valid batch: the
    // group must flip to fail-closed agreement in every position.
    for position in [0, corpus.len() / 2, corpus.len()] {
        let mut refs = valid_refs.clone();
        refs.insert(position, synth::disabled_orchard_item());
        let report = check_equivalence_refs(&refs, vk, 0xF00D);
        assert_eq!(
            report,
            EquivReport::Agree(false),
            "valid pre-NU6.2 batch with an un-queueable bundle spliced at index {position} \
             must fail closed on BOTH paths; got {report:?}"
        );
    }
}
