//! Sprout JoinSplit Groth16 equivalence over real mainnet proofs
//! (ZCG #332 · M2).
//!
//! The fourth of the grant's verifiers, and the one whose relationship to
//! production is different from the other three: **Zebra does not batch-verify
//! JoinSplits today**. `JOINSPLIT_VERIFIER` is a plain `service_fn` calling
//! `verify_single` on each one, and upstream issue #3127, which proposed adding
//! batch support, was **closed as not planned in 2022**. So what is asserted here
//! is the equivalence of `bellman::groth16::batch` under Sprout's parameters —
//! the path JoinSplit verification would take if batching were ever switched on,
//! gated in advance rather than afterwards.
//!
//! Two consequences for how to read a green run here:
//!
//! * A `batch ⟺ single` disagreement in this pool would not be a live Zebra
//!   bug. It would be a bug in what Zebra is planning to switch on.
//! * The layer-2 path — `Item::verify_single` — **is** what Zebra runs today, so
//!   a layer-2 disagreement would be live.
//!
//! ## Why `real_joinsplits_verify_under_the_vendored_key` is the load-bearing test
//!
//! The public-input encoding is reproduced from `zebra-consensus`, which cannot
//! be a dependency here. If that encoding were wrong, both paths would receive
//! the same wrong inputs, agree on rejecting everything, and every equivalence
//! assertion below would pass — the exact failure mode this project keeps
//! cataloguing. Real mainnet proofs verify only under the correct encoding and
//! the correct key, so that test is what makes the rest mean anything.

mod common;

use common::{historical_sprout_corpus, historical_transactions, spread};
use zebra_batch_equivalence::sprout::{
    item_from_joinsplit, items_from_tx, Sprout, SproutItem, SproutKeys,
};
use zebra_batch_equivalence::verifier::{
    check_equivalence_refs, check_strategy_equivalence, StrategyReport,
};
use zebra_batch_equivalence::{BatchVerifier, EquivReport};

/// Zebra's batch size limit. For Sprout, as for RedJubjub, this counts items:
/// `groth16::Item` takes the default `RequestWeight` of 1.
const MAX_BATCH_SIZE: usize = 64;

const SEED: u64 = 0xF00D;

/// Groth16 proofs are expensive enough that the full corpus in every test would
/// dominate the suite. Sampled with a stride, never a prefix — Sprout density
/// falls monotonically across this window, so a prefix would be the densest part
/// of it and nothing else.
const SAMPLE: usize = 96;

/// The premise everything else rests on: real mainnet JoinSplits verify under
/// the vendored key and the reproduced public-input encoding.
///
/// If either were wrong every proof would reject, and every equivalence
/// assertion in this file would still pass — batch and single would agree
/// perfectly on rejecting all of it. This test is what separates "the two paths
/// agree" from "the two paths agree about nothing".
#[test]
fn real_joinsplits_verify_under_the_vendored_key() {
    let corpus = historical_sprout_corpus();
    assert!(
        corpus.len() >= 500,
        "historical corpus yielded only {} Groth16 JoinSplits; the delivery material cites a \
         figure in the high hundreds, so this is corpus loss or a loader regression",
        corpus.len()
    );

    let keys = SproutKeys::bundled();
    let sample = spread(&corpus, SAMPLE);
    for (index, item) in sample.iter().enumerate() {
        assert!(
            Sprout::validate_one(item, keys, SEED),
            "real mainnet JoinSplit #{index} failed to verify: the public-input encoding or the \
             vendored verifying key is wrong, and every equivalence assertion here is vacuous"
        );
    }

    eprintln!(
        "sprout corpus: {} Groth16 JoinSplits ({} sampled per test)",
        corpus.len(),
        sample.len()
    );
}

/// The core assertion: the batch accepts exactly when every proof accepts alone.
#[test]
fn batch_and_single_agree_on_real_joinsplits() {
    let corpus = historical_sprout_corpus();
    assert!(!corpus.is_empty(), "corpus must not be empty");
    let keys = SproutKeys::bundled();
    let sample = spread(&corpus, SAMPLE);

    for (group_index, group) in sample.chunks(MAX_BATCH_SIZE).enumerate() {
        let report = check_equivalence_refs::<Sprout>(group, keys, SEED);
        assert_eq!(
            report,
            EquivReport::Agree(true),
            "Sprout group {group_index} ({} proofs): batch and single disagreed; got {report:?}",
            group.len()
        );
    }
}

/// Layer 2: the batch machinery at N=1 against `bellman`'s non-batched
/// verification, which the crate documents as the fallback path — and which
/// Zebra runs for every JoinSplit today.
///
/// So unlike the other pools, a disagreement here would be about code currently
/// in production, not about code being prepared.
#[test]
fn batch_strategy_agrees_with_direct_verification() {
    let corpus = historical_sprout_corpus();
    assert!(!corpus.is_empty(), "corpus must not be empty");
    let keys = SproutKeys::bundled();

    for (index, item) in spread(&corpus, SAMPLE).iter().enumerate() {
        let report = check_strategy_equivalence::<Sprout>(item, keys, SEED);
        assert_ne!(
            report,
            StrategyReport::NotApplicable,
            "Sprout must expose an independent implementation; if this fires, layer 2 has \
             silently stopped running rather than failing"
        );
        assert_eq!(
            report,
            StrategyReport::Agree(true),
            "JoinSplit #{index}: the batch strategy and direct verification disagreed; \
             got {report:?}"
        );
    }
}

/// A JoinSplit whose proof no longer matches its public inputs, built by pairing
/// it with another transaction's JoinSplit validating key.
///
/// That key feeds `h_sig`, which is one of the proof's primary inputs, so the
/// proof stops satisfying the statement. Nothing is forged and no bytes are
/// flipped — the proof and the key are both real, they simply did not come from
/// the same transaction.
fn joinsplit_under_the_wrong_key() -> SproutItem {
    let txs = historical_transactions();

    // Two transactions that each carry Groth16 JoinSplits and have different
    // validating keys.
    let mut with_joinsplits = txs
        .iter()
        .filter(|(_, tx)| tx.sprout_joinsplit_pub_key().is_some() && !items_from_tx(tx).is_empty());
    let (_, first) = with_joinsplits.next().expect("a JoinSplit-bearing tx");
    let first_key = first.sprout_joinsplit_pub_key().expect("validating key");
    let (_, second) = with_joinsplits
        .find(|(_, tx)| tx.sprout_joinsplit_pub_key() != Some(first_key))
        .expect("a second tx with a different validating key");
    let other_key = second.sprout_joinsplit_pub_key().expect("validating key");

    let joinsplit = first
        .sprout_groth16_joinsplits()
        .next()
        .expect("first tx has a Groth16 JoinSplit");

    item_from_joinsplit(joinsplit, &other_key).expect("proof bytes still decode")
}

/// An invalid item must be rejected by all three paths, and they must agree that
/// it is invalid.
///
/// Without this, every assertion above could be satisfied by a verifier that
/// accepts everything.
#[test]
fn a_joinsplit_under_the_wrong_key_is_rejected_by_every_path() {
    let keys = SproutKeys::bundled();
    let wrong = joinsplit_under_the_wrong_key();

    assert!(
        !Sprout::validate_one(&wrong, keys, SEED),
        "a JoinSplit paired with another transaction's validating key was accepted by the \
         batch path at N=1"
    );
    assert_eq!(
        check_strategy_equivalence::<Sprout>(&wrong, keys, SEED),
        StrategyReport::Agree(false),
        "the two algorithms disagreed on an invalid proof"
    );
    assert_eq!(
        check_equivalence_refs::<Sprout>(&[&wrong], keys, SEED),
        EquivReport::Agree(false)
    );
}

/// One invalid proof among valid ones: the batch rejects, and individual
/// verification then recovers exactly the valid proofs.
///
/// The same fallback condition asserted for RedJubjub, and it matters more here:
/// individual verification is not a fallback for Sprout, it is the *only* path
/// Zebra runs. If batching were ever switched on and a bad proof could make good
/// ones fail individually, the fallback such a change would need would not work.
#[test]
fn a_failed_batch_falls_back_to_exactly_the_valid_proofs() {
    let corpus = historical_sprout_corpus();
    let keys = SproutKeys::bundled();

    let valid: Vec<&SproutItem> = spread(&corpus, 8);
    assert!(valid.len() >= 4, "need several valid proofs");
    let poison = joinsplit_under_the_wrong_key();

    let mut mixed = valid.clone();
    mixed.push(&poison);

    let batch = Sprout::validate_batch(&mixed, keys, SEED);
    assert!(
        batch.iter().all(|&ok| !ok),
        "a batch containing an invalid proof must reject as a whole"
    );

    let recovered: Vec<bool> = mixed
        .iter()
        .map(|item| {
            Sprout::validate_one_independent(item, keys).expect("Sprout has an independent path")
        })
        .collect();
    let expected: Vec<bool> = std::iter::repeat_n(true, valid.len())
        .chain(std::iter::once(false))
        .collect();
    assert_eq!(
        recovered, expected,
        "individual re-verification after a failed batch did not recover exactly the valid proofs"
    );
}
