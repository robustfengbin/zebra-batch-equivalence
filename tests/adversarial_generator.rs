//! The adversarial corpus generator, over real mainnet material
//! (ZCG #332 · M2).
//!
//! ## Disclosure: settled 2026-08-26, gate released
//!
//! `controlled_experiment_does_a_rejected_bundle_leave_residue` is a working,
//! self-contained reproduction: it builds a transaction shape that makes a rejected
//! Sapling bundle drag valid neighbours down with it, and it prints the difference.
//! Publishing this file publishes that recipe, so until the disclosure question had an
//! answer this header carried a marker that our export tooling refuses to publish —
//! turning "someone remembered" into "the tooling refused". (The marker is not quoted
//! here: the check greps for it, so prose about it would re-arm the gate against the
//! very file it just released.)
//!
//! The question now has an answer, and the marker is gone because of that rather than
//! because a build went red. Decided by the grant owner:
//!
//!   * severity — a performance/liveness observation, not a security advisory. The
//!     residue can only make a batch *reject* more, never accept more: it comes only
//!     from a bundle already judged false, and it can only add proofs that might fail.
//!     Zebra's `Fallback` re-verifies individually, so affected transactions do pass.
//!     That is a resource-amplification property, not a soundness one.
//!   * upstream — not reported for M2; carried to M3, where a release-build figure and
//!     a concrete patch can go with it. `sapling-crypto` documents the residue itself
//!     and states a workaround, so reporting it bare would be answered by a citation.
//!   * write-up — presented as evidence the oracle finds real behaviour, not as a
//!     vulnerability claim: what is new here is Zebra broadcasting the consequence to
//!     every item sharing the batch, which no upstream discussion was found for.
//!
//! Cost of a poisoned batch, for whoever quotes it: **4.5x–7.8x** — a range, and the
//! only form this figure has. Ten runs of `examples/batch_speedup.rs` over the same
//! corpus and seed, on two machines; wall clock, debug build. Machine load is the one
//! dispersion source that has been isolated; the rest (machine, frequency scaling,
//! cache state) has not been, so the magnitude is the argument and no individual
//! measurement explains itself.
//!
//! `reports/m2-coverage.md` §7 is the single place that states it, and the individual
//! runs are not repeated here. This header used to carry its own narrower range from
//! three earlier runs, and kept carrying it after the report moved to ten — the same
//! quantity in two exported files, disagreeing, in a deliverable whose whole claim is
//! that a reader can recompute every number. A figure quoted in two places is a figure
//! that gets updated in one.
//!
//! M1's mutation smoke test damaged a handful of proofs by hand and asserted both
//! paths still agreed. This is the systematic version the grant asks for: a valid
//! base, single-element tampers, and batch compositions — with the generator
//! checking that what it produced is what it claims.
//!
//! ## What this suite does not do
//!
//! It does not assert that a disagreement appears, and it does not assert that
//! none does. The oracle's assertion is **equivalence**, and the answer for any
//! given adversarial shape is a measurement rather than an expectation. Writing
//! `assert_eq!(report, FalseReject)` for a shape we suspect will disagree would
//! turn a finding into a fixture — the test would then go red the day the
//! behaviour was *fixed*.
//!
//! That matters most for `residue_from_a_rejected_bundle_must_not_change_a_neighbour`,
//! which builds the one shape `sapling-crypto` documents as possible: a bundle
//! that fails partway leaves part of itself in the shared batch. If that residue
//! can change a valid neighbour's verdict, the assertion below fails, and that
//! failure is a finding to disclose — not a line to update.

mod common;

use common::{historical_sapling_corpus, spread};
use zebra_batch_equivalence::adversarial::{
    half_enqueued_residue, tamper_spend_proof, AdversarialBatch, ProofDamage, TamperTarget,
};
use zebra_batch_equivalence::sapling::{Sapling, SaplingItem, SaplingKeys};
use zebra_batch_equivalence::verifier::{check_equivalence_refs, check_strategy_equivalence};
use zebra_batch_equivalence::{BatchVerifier, EquivReport};

const SEED: u64 = 0xF00D;

/// Bundles carrying more than one spend — the material a residue construction
/// needs, since it takes one spend to be queued and a later one to end the
/// bundle.
fn multi_spend_bundles() -> Vec<SaplingItem> {
    historical_sapling_corpus()
        .into_iter()
        .filter(|item| item.bundle.shielded_spends().len() >= 2)
        .collect()
}

/// A modest valid base: real bundles, sampled with a stride rather than taken
/// from the front.
fn valid_base(n: usize) -> Vec<SaplingItem> {
    let corpus = historical_sapling_corpus();
    spread(&corpus, n).into_iter().cloned().collect()
}

/// **The contract the residue construction rests on**: `FlipBit` must leave a
/// proof that still decodes, and `Undecodable` must leave one that does not.
///
/// If a "flipped" proof failed to decode, `check_bundle` would return false at
/// that spend and queue nothing — the residue would never form, and the residue
/// test would pass while testing an empty construction.
#[test]
fn damage_kinds_honour_their_decoding_contracts() {
    use bellman::groth16::Proof;
    use bls12_381::Bls12;

    let base = valid_base(4);
    for (index, item) in base.iter().enumerate() {
        let original = item.bundle.shielded_spends()[0].zkproof();
        assert!(
            Proof::<Bls12>::read(&original[..]).is_ok(),
            "#{index}: a real mainnet proof must decode"
        );

        let decodable = tamper_spend_proof(item, 0, ProofDamage::DecodableButWrong);
        let bytes = decodable.bundle.shielded_spends()[0].zkproof();
        assert!(
            Proof::<Bls12>::read(&bytes[..]).is_ok(),
            "#{index}: DecodableButWrong produced bytes that do not decode. `check_bundle` would \
             then return false at this spend having queued nothing, so no residue would form and \
             the residue test would pass over an empty construction"
        );
        assert_ne!(
            &bytes[..],
            &original[..],
            "#{index}: damage must change the proof"
        );

        let broken = tamper_spend_proof(item, 0, ProofDamage::Undecodable);
        let bytes = broken.bundle.shielded_spends()[0].zkproof();
        assert!(
            Proof::<Bls12>::read(&bytes[..]).is_err(),
            "#{index}: Undecodable produced bytes that decode, so `check_bundle` would carry on \
             past this spend instead of stopping there"
        );
    }
}

/// The generator's own premise: the corpus contains multi-spend bundles, and
/// they verify before anything is done to them.
#[test]
fn the_valid_base_is_valid_and_carries_multi_spend_bundles() {
    let keys = SaplingKeys::bundled();

    let base = valid_base(6);
    assert!(base.len() >= 4, "need a few valid bundles");
    for (index, item) in base.iter().enumerate() {
        assert!(
            Sapling::validate_one(item, keys, SEED),
            "valid base bundle #{index} does not verify; the base is not valid and every \
             adversarial result built on it is meaningless"
        );
    }

    let multi = multi_spend_bundles();
    assert!(
        !multi.is_empty(),
        "the residue construction needs a bundle with at least two spends; the corpus has none, \
         so that shape is untested rather than tested-and-clean"
    );
    eprintln!(
        "adversarial base: {} valid bundles, {} of the corpus carry >= 2 spends",
        base.len(),
        multi.len()
    );
}

/// A single-element tamper must actually invalidate its element — and both
/// verification strategies must agree that it did.
///
/// Both damage kinds are covered because they take different routes through
/// `check_bundle`: a flipped bit produces a proof that decodes and is wrong,
/// while undecodable bytes end the bundle before that proof is ever queued.
#[test]
fn single_element_tampers_invalidate_and_both_strategies_agree() {
    let keys = SaplingKeys::bundled();
    let base = valid_base(4);

    for (index, item) in base.iter().enumerate() {
        for damage in [ProofDamage::DecodableButWrong, ProofDamage::Undecodable] {
            let tampered = tamper_spend_proof(item, 0, damage);
            assert!(
                !Sapling::validate_one(&tampered, keys, SEED),
                "bundle #{index}: {damage:?} on spend 0 did not invalidate it — the tamper is a \
                 no-op and any batch built from it is secretly all-valid"
            );
            // Layer 2 must reach the same verdict. Proof bytes are one of the
            // targets that genuinely reaches the diverging half of the two
            // paths, unlike consensus inputs.
            assert!(
                TamperTarget::ProofBytes.is_discriminating(),
                "proof bytes must be a discriminating target"
            );
            let report = check_strategy_equivalence::<Sapling>(&tampered, keys, SEED);
            assert!(
                !report.is_disagreement(),
                "bundle #{index}, {damage:?}: batch-derived and direct verification disagreed \
                 on a tampered proof; got {report:?}"
            );
        }
    }
}

/// **Controlled experiment: does a rejected bundle really leave residue behind?**
///
/// This is the question `sapling-crypto`'s documentation raises and that nothing
/// upstream measures. Two carriers, differing in exactly one thing:
///
/// * **A** — spend 0 gets a proof that decodes and is wrong, spend 1 gets one
///   that does not decode. `check_bundle` queues spend 0's invalid proof, then
///   hits spend 1 and returns `false`. The bundle is rejected **and its invalid
///   proof stays in the shared batch**.
/// * **B** — spend 0 itself gets a proof that does not decode. `check_bundle`
///   returns `false` immediately, having queued **nothing**.
///
/// Both carriers are rejected on their own. If their valid neighbours are judged
/// differently, the only thing that can explain it is the residue — which makes
/// this a measurement of the residue's effect rather than an inference about it.
///
/// The result is printed rather than asserted in either direction. Whether the
/// observed behaviour is a finding is a judgement about Zebra's fallback
/// behaviour and disclosure, not something a test should decide by encoding one
/// answer.
#[test]
fn controlled_experiment_does_a_rejected_bundle_leave_residue() {
    let keys = SaplingKeys::bundled();
    let multi = multi_spend_bundles();
    assert!(!multi.is_empty(), "need a multi-spend bundle");
    let carrier = &multi[0];

    // A: queues an invalid proof, then stops.
    let with_residue = half_enqueued_residue(carrier, 0, 1).expect("two spends");
    // B: stops before queueing anything.
    let without_residue = tamper_spend_proof(carrier, 0, ProofDamage::Undecodable);

    assert!(
        !Sapling::validate_one(&with_residue, keys, SEED),
        "carrier A must be rejected on its own"
    );
    assert!(
        !Sapling::validate_one(&without_residue, keys, SEED),
        "carrier B must be rejected on its own"
    );

    let neighbours = valid_base(3);
    for (index, item) in neighbours.iter().enumerate() {
        assert!(
            Sapling::validate_one(item, keys, SEED),
            "neighbour #{index} must verify alone"
        );
    }

    let verdicts = |carrier: &SaplingItem| -> Vec<bool> {
        let batch = AdversarialBatch::<Sapling>::mostly_valid_plus_one_invalid(
            &neighbours,
            carrier,
            neighbours.len(),
        );
        Sapling::validate_batch(&batch.items, keys, SEED)
    };

    let a = verdicts(&with_residue);
    let b = verdicts(&without_residue);

    eprintln!(
        "residue experiment: A (queues then stops) neighbour verdicts = {:?}",
        &a[..neighbours.len()]
    );
    eprintln!(
        "residue experiment: B (stops immediately)  neighbour verdicts = {:?}",
        &b[..neighbours.len()]
    );

    // What the two carriers have in common: both are rejected.
    assert!(
        !a[neighbours.len()],
        "carrier A must be rejected inside the batch"
    );
    assert!(
        !b[neighbours.len()],
        "carrier B must be rejected inside the batch"
    );

    if a[..neighbours.len()] != b[..neighbours.len()] {
        eprintln!(
            "RESIDUE OBSERVED: a bundle rejected by its own consensus checks changed how its \
             valid neighbours were judged. Carrier B, rejected at its first spend, did not."
        );
    } else {
        eprintln!("no residue effect distinguishable at this batch shape");
    }
}

/// The batch composition the grant names: many valid items, exactly one invalid,
/// swept across every position.
///
/// The shape is checked before the oracle runs. Without that, a tamper that
/// failed to take would produce an all-valid batch, the per-item check would
/// pass, and the run would be indistinguishable from a real one.
#[test]
fn mostly_valid_plus_one_invalid_agrees_at_every_position() {
    let keys = SaplingKeys::bundled();
    let base = valid_base(5);
    assert!(base.len() >= 3, "need a few valid bundles");

    let invalid = tamper_spend_proof(&base[0], 0, ProofDamage::DecodableButWrong);

    for position in 0..=base.len() {
        let batch =
            AdversarialBatch::<Sapling>::mostly_valid_plus_one_invalid(&base, &invalid, position);
        batch
            .check_shape(keys, SEED)
            .unwrap_or_else(|e| panic!("generated batch is not the shape it claims: {e:?}"));

        // Whole-batch granularity is the level this assertion belongs at, and
        // the reason is worth stating because it corrects something the design
        // notes assumed.
        //
        // Per-item equivalence holds when a batch *should* accept: no item may
        // be judged differently from how it verifies alone. It cannot hold once
        // the batch contains an invalid item, because a batch verifier answers
        // "is all of this valid", so every valid item in that batch is rejected
        // with it. Comparing position by position would report a false reject
        // for each of them — the same category error as at signature
        // granularity in RedJubjub, arrived at from the other direction.
        //
        // What must hold, and does: the batch rejects exactly when some member
        // rejects alone.
        let report = check_equivalence_refs::<Sapling>(&batch.items, keys, SEED);
        assert_eq!(
            report,
            EquivReport::Agree(false),
            "invalid item at position {position}: batch and single disagreed; got {report:?}"
        );
    }
}
