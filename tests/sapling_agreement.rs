//! Sapling `batch ⟺ single` equivalence over real mainnet bundles (ZCG #332 · M2).
//!
//! The first assertion of the grant's property outside Orchard. Sapling is a
//! different shape in every respect that matters: a bundle carries many Groth16
//! proofs rather than one halo2 proof, the signatures ride inside the same
//! validator as the proofs, and — the part that changes the test design —
//! `BatchValidator::check_bundle` may leave part of a rejected bundle in the
//! shared batch, which `orchard`'s `add_bundle` never does.
//!
//! Corpus is the in-tree mainnet block vectors, which carry Sapling activity from
//! its activation height onward. No node and no extraction run is needed to reach
//! it: these bundles have been sitting in the repository since M1, unused, because
//! M1's extraction layer only ever asked for Orchard.
//!
//! Each transaction is verified under the network upgrade in force at its own
//! height. A v5 transaction states its consensus branch id and can answer for
//! itself; a v4 one cannot, and Sapling long predates v5, so most of this corpus
//! needs the height-derived answer.

mod common;

use common::in_tree_sapling_corpus;
use zebra_batch_equivalence::sapling::{Sapling, SaplingItem, SaplingKeys};
use zebra_batch_equivalence::verifier::{
    check_equivalence_per_item, check_equivalence_refs, check_strategy_equivalence, StrategyReport,
};
// `validate_one` / `validate_batch` are trait methods; the trait has to be in
// scope to call them on `Sapling`.
use zebra_batch_equivalence::{BatchVerifier, EquivReport};

/// Largest group fed to one equivalence call. Sapling bundles are cheaper per
/// proof than halo2 but a single bundle can carry many, so cap by bundle count
/// and let the suite stay in the tens of seconds.
const MAX_GROUP: usize = 8;

/// The premise every other test here rests on: the corpus is non-empty and every
/// bundle in it verifies. A corpus that silently yielded nothing would make the
/// agreement assertions vacuously true.
#[test]
fn real_sapling_bundles_verify_and_the_corpus_is_not_empty() {
    let corpus = in_tree_sapling_corpus();
    assert!(
        !corpus.is_empty(),
        "in-tree mainnet vectors must yield at least one shielded-only Sapling bundle"
    );

    let keys = SaplingKeys::bundled();
    for (index, item) in corpus.iter().enumerate() {
        assert!(
            Sapling::validate_one(item, keys, 0xF00D),
            "real mainnet Sapling bundle #{index} ({} proofs) failed to verify alone",
            item.proof_count()
        );
    }
}

/// The core assertion, at both granularities, over real mainnet bundles.
///
/// Deliberately asserts equivalence rather than a specific verdict. Every bundle
/// here is valid, so agreement-on-accept is what should happen — but the property
/// under test is that the two paths *agree*, not that they accept.
#[test]
fn batch_and_single_agree_on_real_sapling_bundles() {
    let corpus = in_tree_sapling_corpus();
    assert!(!corpus.is_empty(), "corpus must not be empty");
    let keys = SaplingKeys::bundled();

    for (group_index, group) in corpus.chunks(MAX_GROUP).enumerate() {
        let refs: Vec<&SaplingItem> = group.iter().collect();

        // Whole-batch granularity (M1's question).
        let report = check_equivalence_refs::<Sapling>(&refs, keys, 0xF00D);
        assert_eq!(
            report,
            EquivReport::Agree(true),
            "Sapling group {group_index} ({} bundles): batch and single disagreed; got {report:?}",
            refs.len()
        );

        // Per-item granularity (M2's question): no bundle's verdict may depend on
        // which other bundles shared its batch.
        let per_item = check_equivalence_per_item::<Sapling>(&refs, keys, 0xF00D);
        assert!(
            per_item.is_agreement(),
            "Sapling group {group_index}: some bundle was judged differently inside the batch \
             than alone: {:?}",
            per_item.disagreements().collect::<Vec<_>>()
        );
    }
}

/// Layer 2: the batch-derived verdict against a genuinely independent
/// implementation — `SaplingVerificationContext`, which verifies each proof and
/// signature directly instead of folding them into a randomized linear
/// combination, and which Zebra never runs.
///
/// This is the layer with power over a bug the two layer-1 paths would share,
/// since both of those ultimately drive `BatchValidator`.
#[test]
fn batch_strategy_agrees_with_direct_verification() {
    let corpus = in_tree_sapling_corpus();
    assert!(!corpus.is_empty(), "corpus must not be empty");
    let keys = SaplingKeys::bundled();

    for (index, item) in corpus.iter().enumerate() {
        let report = check_strategy_equivalence::<Sapling>(item, keys, 0xF00D);
        assert_eq!(
            report,
            StrategyReport::Agree(true),
            "Sapling bundle #{index}: the batch strategy and direct verification disagreed; \
             got {report:?}"
        );
        assert_ne!(
            report,
            StrategyReport::NotApplicable,
            "Sapling must expose an independent implementation; if this fires, layer 2 has \
             silently stopped running rather than failing"
        );
    }
}

/// Batch composition must not change any verdict: the same bundles, verified one
/// at a time, in one batch, and in two halves, must reach identical per-bundle
/// results.
///
/// The Orchard equivalent of this is an M1 invariant. It is worth restating for
/// Sapling specifically because Sapling is where a residue left by one bundle
/// could reach another — this asserts that no such influence exists for valid
/// input, which is the baseline the adversarial corpus will later push against.
#[test]
fn splitting_a_batch_does_not_change_any_verdict() {
    let corpus = in_tree_sapling_corpus();
    // Spread rather than `take`: this corpus is small enough that a prefix would
    // do, but `historical_sapling_corpus` now sits in the same module and its
    // composition drifts monotonically with height — swapping the source here
    // would be a one-line change that silently turned this into a biased sample.
    // Reproducible, not an error, and invisible.
    let group = common::spread(&corpus, MAX_GROUP);
    assert!(
        group.len() >= 2,
        "need at least two Sapling bundles to split a batch"
    );
    let keys = SaplingKeys::bundled();

    let whole = Sapling::validate_batch(&group, keys, 0xF00D);

    let mid = group.len() / 2;
    let mut split = Sapling::validate_batch(&group[..mid], keys, 0xF00D);
    split.extend(Sapling::validate_batch(&group[mid..], keys, 0xF00D));

    assert_eq!(
        whole, split,
        "splitting the batch at {mid} changed at least one bundle's verdict"
    );

    let alone: Vec<bool> = group
        .iter()
        .map(|item| Sapling::validate_one(item, keys, 0xF00D))
        .collect();
    assert_eq!(
        whole, alone,
        "at least one bundle's verdict inside the batch differs from its verdict alone"
    );
}
