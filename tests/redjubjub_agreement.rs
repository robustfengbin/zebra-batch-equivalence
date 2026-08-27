//! RedJubjub `batch ⟺ single` equivalence over real mainnet signatures
//! (ZCG #332 · M2).
//!
//! The third of the grant's four verifiers, and the one whose shape differs most
//! from the others. Two differences drive every test here:
//!
//! * **A batch of signatures has one verdict, not one per signature.** `queue`
//!   cannot fail and batch verification is a single equation over the whole set,
//!   so one invalid signature rejects the batch it is in — by design, and stated
//!   as such in `redjubjub::batch`'s own documentation. Reading that as a
//!   false-reject finding would be a category error, so the assertions below are
//!   about *equivalence between paths*, never about a specific verdict. The
//!   per-item question is still asked, in the form it takes here: after a batch
//!   rejects, does individual verification recover exactly the valid signatures?
//!   See [`a_failed_batch_falls_back_to_exactly_the_valid_signatures`].
//! * **Zebra's `verify_single` for this pool is a genuinely separate algorithm**
//!   (`primitives/redjubjub.rs:51`), not the batch verifier fed one item, and the
//!   batch service is wrapped in `Fallback<Batch<..>, verify_single>`. So the
//!   layer-2 check here is not a hypothetical second opinion: it is the code
//!   production runs when a batch fails.
//!
//! Batch size is 64 throughout, matching `MAX_BATCH_SIZE`. For RedJubjub that
//! constant really does mean 64 signatures: `RequestWeight` is left at its default
//! of 1 per item, and an item here *is* one signature (unlike halo2, which
//! overrides the weight to count actions, or Sapling, where one weighted item is a
//! whole bundle of unbounded proof count).

mod common;

use common::{historical_sapling_corpus, in_tree_sapling_corpus};
use zebra_batch_equivalence::redjubjub::{
    items_from_bundle, items_from_sapling_item, RedJubjub, RedJubjubItem, SigRole,
};
use zebra_batch_equivalence::sapling::SaplingItem;
use zebra_batch_equivalence::verifier::{
    check_equivalence_refs, check_strategy_equivalence, StrategyReport,
};
use zebra_batch_equivalence::{BatchVerifier, EquivReport};

/// Production's batch size, and here it is literally 64 signatures. See the
/// module docs.
const MAX_BATCH_SIZE: usize = 64;

/// A fixed seed, so any disagreement reproduces. Soundness must hold for every
/// RNG; the seed only fixes reproducibility.
const SEED: u64 = 0xF00D;

/// Every RedJubjub signature reachable from the in-tree mainnet vectors.
fn in_tree_signatures() -> Vec<RedJubjubItem> {
    in_tree_sapling_corpus()
        .iter()
        .flat_map(items_from_sapling_item)
        .collect()
}

/// The premise the rest of this file rests on: the corpus yields signatures of
/// both roles, and each one verifies on its own. A corpus that silently yielded
/// nothing — or only binding signatures, which every Sapling bundle has even with
/// no spends — would make the agreement assertions vacuously true.
#[test]
fn real_signatures_verify_and_the_corpus_carries_both_roles() {
    let items = in_tree_signatures();
    assert!(
        !items.is_empty(),
        "in-tree mainnet vectors must yield at least one RedJubjub signature"
    );

    let spend_auth = items
        .iter()
        .filter(|i| matches!(i.role, SigRole::SpendAuth { .. }))
        .count();
    let binding = items
        .iter()
        .filter(|i| matches!(i.role, SigRole::Binding))
        .count();
    assert!(
        spend_auth > 0 && binding > 0,
        "corpus must exercise both signature roles (spend-auth {spend_auth}, binding {binding}): \
         RedJubjub accumulates a separate group element per role, so a corpus of one role only \
         leaves half the batch equation untouched"
    );

    for (index, item) in items.iter().enumerate() {
        assert!(
            RedJubjub::validate_one(item, &(), SEED),
            "real mainnet signature #{index} ({:?}) failed to verify alone",
            item.role
        );
    }
}

/// The core assertion over real mainnet signatures: the batch accepts exactly
/// when every signature accepts alone.
///
/// Asserts equivalence, not a verdict. Every signature here is valid, so
/// agreement-on-accept is what should happen — but the property under test is that
/// the two paths *agree*.
#[test]
fn batch_and_single_agree_on_real_signatures() {
    let items = in_tree_signatures();
    assert!(!items.is_empty(), "corpus must not be empty");

    for (group_index, group) in items.chunks(MAX_BATCH_SIZE).enumerate() {
        let refs: Vec<&RedJubjubItem> = group.iter().collect();
        let report = check_equivalence_refs::<RedJubjub>(&refs, &(), SEED);
        assert_eq!(
            report,
            EquivReport::Agree(true),
            "RedJubjub group {group_index} ({} signatures): batch and single disagreed; \
             got {report:?}",
            refs.len()
        );
    }
}

/// Layer 2: the batch machinery at N=1 against `Item::verify_single`, which
/// verifies the signature directly with no randomised linear combination and no
/// RNG.
///
/// For every other verifier in this crate the independent path is one Zebra never
/// runs. Here it is the fallback path Zebra runs whenever a batch fails.
#[test]
fn batch_strategy_agrees_with_direct_verification() {
    let items = in_tree_signatures();
    assert!(!items.is_empty(), "corpus must not be empty");

    for (index, item) in items.iter().enumerate() {
        let report = check_strategy_equivalence::<RedJubjub>(item, &(), SEED);
        assert_ne!(
            report,
            StrategyReport::NotApplicable,
            "RedJubjub must expose an independent implementation; if this fires, layer 2 has \
             silently stopped running rather than failing"
        );
        assert_eq!(
            report,
            StrategyReport::Agree(true),
            "signature #{index} ({:?}): the batch strategy and direct verification disagreed; \
             got {report:?}",
            item.role
        );
    }
}

/// Two bundles whose signatures can be recombined into an invalid set: the
/// signatures of the first, bound to the sighash of the second.
///
/// No forgery and no bit-flipping — the signatures are real, the keys are real,
/// and the binding key is still derived from the first bundle's own commitments.
/// Only the message is wrong, which is precisely the condition RedJubjub
/// verification exists to detect.
fn signatures_bound_to_the_wrong_sighash(corpus: &[SaplingItem]) -> Vec<RedJubjubItem> {
    let (first, second) = (&corpus[0], &corpus[1]);
    assert_ne!(
        first.sighash.0, second.sighash.0,
        "the two bundles must have different sighashes for this to be a wrong-message test"
    );
    items_from_bundle(&first.bundle, &second.sighash)
}

/// An invalid signature must be rejected by all three paths — batch, batch-of-one,
/// and direct verification — and they must agree that it is invalid.
///
/// Without this, every other assertion in the file could be satisfied by a
/// verifier that accepts everything.
#[test]
fn a_signature_bound_to_the_wrong_sighash_is_rejected_by_every_path() {
    let corpus = in_tree_sapling_corpus();
    assert!(
        corpus.len() >= 2,
        "need two bundles to cross their sighashes"
    );
    let wrong = signatures_bound_to_the_wrong_sighash(&corpus);
    assert!(!wrong.is_empty(), "recombination must yield signatures");

    for (index, item) in wrong.iter().enumerate() {
        assert!(
            !RedJubjub::validate_one(item, &(), SEED),
            "signature #{index} ({:?}) bound to another transaction's sighash was accepted \
             by the batch path at N=1",
            item.role
        );
        assert_eq!(
            check_strategy_equivalence::<RedJubjub>(item, &(), SEED),
            StrategyReport::Agree(false),
            "signature #{index}: the two algorithms disagreed on an invalid signature"
        );
    }

    let refs: Vec<&RedJubjubItem> = wrong.iter().collect();
    assert_eq!(
        check_equivalence_refs::<RedJubjub>(&refs, &(), SEED),
        EquivReport::Agree(false),
        "batch and single disagreed on a batch of invalid signatures"
    );
}

/// The correctness condition behind Zebra's `Fallback<Batch<..>, verify_single>`,
/// which nothing upstream asserts.
///
/// One invalid signature rejects the whole batch — that is what batch verification
/// means, and it is why the fallback exists. What must then hold is that the
/// fallback recovers exactly the valid signatures: every signature that was valid
/// still verifies individually, and every invalid one still fails. If a batch
/// failure could make a valid signature fail individually too, the fallback would
/// turn one bad signature into a transaction-level denial of service.
///
/// Note what is *not* asserted: that the batch accepts the valid signatures. It
/// must not, and a per-item reading of this batch would report a false reject for
/// every valid signature in it. That is the category error the module docs warn
/// about — at signature granularity the batch has one verdict, and production
/// never asks it for more.
#[test]
fn a_failed_batch_falls_back_to_exactly_the_valid_signatures() {
    let corpus = in_tree_sapling_corpus();
    assert!(corpus.len() >= 2, "need two bundles");

    let valid = items_from_sapling_item(&corpus[0]);
    let invalid = signatures_bound_to_the_wrong_sighash(&corpus);
    assert!(!valid.is_empty() && !invalid.is_empty());

    // One invalid signature among many valid ones.
    let mut mixed: Vec<&RedJubjubItem> = valid.iter().collect();
    let poison = &invalid[0];
    mixed.push(poison);

    let batch = RedJubjub::validate_batch(&mixed, &(), SEED);
    assert!(
        batch.iter().all(|&ok| !ok),
        "a batch containing an invalid signature must reject as a whole"
    );

    // The fallback: each signature re-verified on its own by the independent
    // algorithm. Exactly the valid ones come back.
    let recovered: Vec<bool> = mixed
        .iter()
        .map(|item| {
            RedJubjub::validate_one_independent(item, &())
                .expect("RedJubjub exposes an independent path")
        })
        .collect();

    let expected: Vec<bool> = std::iter::repeat_n(true, valid.len())
        .chain(std::iter::once(false))
        .collect();
    assert_eq!(
        recovered, expected,
        "individual re-verification after a failed batch did not recover exactly the valid \
         signatures"
    );
}

/// However a mixed batch is divided, every sub-batch's verdict must still be the
/// conjunction of its members' individual verdicts.
///
/// This is the batch-composition invariant in the form that has content for a
/// signature batch. The whole-batch verdict *does* depend on composition — split a
/// mixed batch and one half comes back clean — so pinning "the verdict does not
/// change" would be false. What must hold is that the verdict remains *derivable*
/// from the members: no division may produce a sub-batch that accepts despite
/// containing the invalid signature, or rejects without it.
///
/// Driven over every split point rather than the midpoint, so the invalid
/// signature lands on both sides of the cut and alone in a sub-batch of one.
#[test]
fn every_division_of_a_mixed_batch_stays_consistent_with_its_members() {
    let corpus = in_tree_sapling_corpus();
    assert!(corpus.len() >= 2, "need two bundles");

    let mut items = items_from_sapling_item(&corpus[0]);
    // Items `[..valid_count)` are the real signatures of a real bundle; the rest
    // are that same bundle's signatures bound to a different transaction's sighash.
    let valid_count = items.len();
    items.extend(signatures_bound_to_the_wrong_sighash(&corpus));
    assert!(items.len() >= 4, "need enough signatures to split");

    for mid in 1..items.len() {
        for (side, range) in [("left", 0..mid), ("right", mid..items.len())] {
            let part: Vec<&RedJubjubItem> = range.clone().map(|i| &items[i]).collect();
            // `check_equivalence_refs` compares the sub-batch's verdict against
            // the conjunction of its members verified alone, so agreement *is*
            // the invariant; the expected value additionally pins which way it
            // should come out.
            let all_valid = range.clone().all(|i| i < valid_count);
            let report = check_equivalence_refs::<RedJubjub>(&part, &(), SEED);
            assert_eq!(
                report,
                EquivReport::Agree(all_valid),
                "split at {mid}, {side} sub-batch ({} signatures): expected \
                 Agree({all_valid}), got {report:?}",
                part.len()
            );
        }
    }
}

/// An empty batch accepts, matching the vacuous-agreement convention the oracle
/// uses everywhere else (an empty conjunction of singles is true).
///
/// Asserted rather than assumed: `reddsa`'s batch equation over an empty set is
/// not obviously either way from the API, and the oracle's empty-group handling
/// depends on the answer.
#[test]
fn an_empty_batch_accepts() {
    let empty: Vec<&RedJubjubItem> = Vec::new();
    assert!(RedJubjub::validate_batch(&empty, &(), SEED).is_empty());
    assert_eq!(
        check_equivalence_refs::<RedJubjub>(&empty, &(), SEED),
        EquivReport::Agree(true)
    );
}

/// The same assertions over the full committed historical corpus — Sapling
/// activation to Canopy, four network upgrades, every transaction in the window
/// rather than a prefix.
///
/// Affordable at this scale precisely because RedJubjub is the cheap verifier: no
/// SNARK is involved, so the whole corpus runs in seconds where the Sapling proof
/// suite has to work in groups of eight.
#[test]
fn batch_and_single_agree_across_the_historical_corpus() {
    let corpus = historical_sapling_corpus();
    let items: Vec<RedJubjubItem> = corpus.iter().flat_map(items_from_sapling_item).collect();

    // The corpus size is a number the delivery report cites, so it has to be
    // something the code asserts rather than something it happens to satisfy.
    // Without this, the corpus could shrink to two bundles and every assertion
    // in this file would still pass — while the report went on claiming a
    // thousand. A decode failure already panics in the loader, so these bounds
    // are the second half of the same guard.
    //
    // Bounds rather than today's exact 965 / 2,208, because the corpus is
    // slated to grow and a test that failed on *more* material would punish the
    // thing it exists to encourage.
    assert!(
        corpus.len() >= 500,
        "historical corpus collapsed to {} shielded-only Sapling bundles; the delivery report \
         cites a figure in the high hundreds, so this is either corpus loss or a loader \
         regression, not a passing test",
        corpus.len()
    );
    assert!(
        items.len() >= 1_500,
        "historical corpus yielded only {} signatures from {} bundles",
        items.len(),
        corpus.len()
    );

    // Scale is part of what this milestone delivers, so state it rather than
    // leaving it to be inferred from a passing test. Visible under `--nocapture`.
    eprintln!(
        "redjubjub historical corpus: {} bundles -> {} signatures ({} spend-auth, {} binding)",
        corpus.len(),
        items.len(),
        items
            .iter()
            .filter(|i| matches!(i.role, SigRole::SpendAuth { .. }))
            .count(),
        items
            .iter()
            .filter(|i| matches!(i.role, SigRole::Binding))
            .count(),
    );

    for (group_index, group) in items.chunks(MAX_BATCH_SIZE).enumerate() {
        let refs: Vec<&RedJubjubItem> = group.iter().collect();
        let report = check_equivalence_refs::<RedJubjub>(&refs, &(), SEED);
        assert_eq!(
            report,
            EquivReport::Agree(true),
            "historical group {group_index} ({} signatures): batch and single disagreed; \
             got {report:?}",
            refs.len()
        );
    }

    // Layer 2 over the same corpus: the fallback algorithm must reach the same
    // verdict as the batch machinery on every signature.
    for (index, item) in items.iter().enumerate() {
        let report = check_strategy_equivalence::<RedJubjub>(item, &(), SEED);
        assert_eq!(
            report,
            StrategyReport::Agree(true),
            "historical signature #{index} ({:?}): batch strategy and direct verification \
             disagreed; got {report:?}",
            item.role
        );
    }
}
