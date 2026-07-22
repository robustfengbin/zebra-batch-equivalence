//! Strategy-level differential + BatchValidator edge pins (ZCG #332 · W2 coverage closure).
//!
//! M1's core assertion — batch and single verification agree — is checked at the
//! `BatchValidator` level by the corpus/invariant suites. But "single" there is a
//! batch-of-one: Zebra's `Item::verify_single` constructs a fresh `BatchValidator`
//! (zebra-consensus `halo2.rs`), so BOTH production paths ultimately drive halo2's
//! *batch* strategy (`plonk/verifier/batch.rs`) and reddsa's *batch* verifier. Each
//! backend also ships a genuinely distinct single-verification strategy that Zebra
//! never calls:
//!
//! - halo2 `SingleVerifier` (per-proof MSM eval, `plonk/verifier.rs`), reachable
//!   through `Bundle::verify_proof`;
//! - reddsa per-item `Item::verify_single` (`reddsa/src/batch.rs`), the per-item
//!   fallback shape of Zebra's redpallas service.
//!
//! If a batch strategy and its own backend's single strategy ever disagreed on the
//! same input, one layer would be wrong — the counterfeiting-class signal the
//! top-level oracle hunts, one layer down. This suite pins pairwise agreement on
//! real mainnet proofs (accept) and damaged inputs (reject), and closes two
//! `BatchValidator` edges the replay corpus cannot reach (the empty batch and the
//! `BatchError` Display contract).
//!
//! Smoke-scale by design, same as `mutation_smoke`: systematic strategy-differential
//! generators are M2 machinery — do not grow a generator API here.

mod common;

use halo2_proofs::plonk::Error as PlonkError;
use orchard::bundle::{Authorized, BatchError};
use orchard::circuit::Proof;
use orchard::primitives::redpallas::{batch, Binding, Signature, SpendAuth};
use rand::rngs::StdRng;
use rand::SeedableRng;
use zebra_batch_equivalence::{
    check_equivalence_refs, pre_nu6_2_key, EquivReport, OrchardItem, SigHash,
};

/// Clone `item` with its proof bytes passed through `mutate` (signatures untouched).
/// Same helper as `mutation_smoke.rs` — cargo integration tests cannot share code
/// outside `tests/common`, and this stays byte-for-byte with its sibling.
fn with_mutated_proof(item: &OrchardItem, mutate: impl FnOnce(&mut Vec<u8>)) -> OrchardItem {
    let bundle = item.bundle.clone().map_authorization(
        &mut (),
        |_, _, spend_auth| spend_auth,
        |_, auth: Authorized| {
            let mut bytes = auth.proof().as_ref().to_vec();
            mutate(&mut bytes);
            Authorized::from_parts(Proof::new(bytes), auth.binding_signature().clone())
        },
    );
    OrchardItem {
        bundle,
        sighash: SigHash(item.sighash.0),
        pool: item.pool,
    }
}

/// Every RedPallas item of one bundle — each spend-auth signature plus the binding
/// signature — exactly the set `BatchValidator::add_bundle` queues for it.
fn redpallas_items(item: &OrchardItem) -> Vec<batch::Item<SpendAuth, Binding>> {
    let sighash = item.sighash.0;
    let mut items: Vec<batch::Item<SpendAuth, Binding>> = item
        .bundle
        .actions()
        .iter()
        .map(|action| {
            action
                .rk()
                .create_batch_item(action.authorization().clone(), &sighash)
        })
        .collect();
    items.push(
        item.bundle.binding_validating_key().create_batch_item(
            item.bundle.authorization().binding_signature().clone(),
            &sighash,
        ),
    );
    items
}

/// The binding-signature item of one bundle, with the raw 64 signature bytes passed
/// through `mutate` before the item is built.
fn mutated_binding_item(
    item: &OrchardItem,
    mutate: impl FnOnce(&mut [u8; 64]),
) -> batch::Item<SpendAuth, Binding> {
    let mut bytes: [u8; 64] = item.bundle.authorization().binding_signature().into();
    mutate(&mut bytes);
    item.bundle
        .binding_validating_key()
        .create_batch_item(Signature::<Binding>::from(bytes), &item.sighash.0)
}

/// halo2's own single strategy agrees with both production (batch-strategy) paths on
/// every real in-tree mainnet proof: `SingleVerifier` accepts exactly what the
/// `BatchValidator` batch and batch-of-one accept.
#[test]
fn halo2_single_strategy_agrees_on_real_proofs() {
    let corpus = common::pre_nu6_2_corpus();
    assert!(!corpus.is_empty());
    let vk = pre_nu6_2_key();

    for (i, item) in corpus.iter().enumerate() {
        assert!(
            item.bundle.verify_proof(vk).is_ok(),
            "halo2 SingleVerifier rejected real proof #{i} that the batch strategy accepts"
        );
        assert_eq!(
            check_equivalence_refs(&[item], vk, 0x51D0 + i as u64),
            EquivReport::Agree(true),
            "premise: both BatchValidator paths accept real proof #{i}"
        );
    }
}

/// A tampered proof is rejected by all three routes — and at least one tamper
/// position must fail *inside the constraint system* (`ConstraintSystemFailure`:
/// the proof still parses as curve points and scalars, every transcript read
/// succeeds, and the final MSM evaluation is what says no). Tail bytes land in the
/// multiopen evaluation-scalar region, where a low-bit flip stays a canonical
/// scalar with overwhelming probability, so the deep arm is deterministically
/// reachable from real proofs.
#[test]
fn halo2_single_strategy_rejects_tampered_proofs_in_agreement() {
    let corpus = common::pre_nu6_2_corpus();
    assert!(!corpus.is_empty());
    let vk = pre_nu6_2_key();
    let item = &corpus[0];
    let proof_len = item.bundle.authorization().proof().as_ref().len();

    let positions = [
        0,                  // head: first transcript point read
        proof_len / 2,      // middle: commitment region
        proof_len * 3 / 4,  // late commitments / early evaluations
        proof_len - 33,     // evaluation-scalar region
        proof_len - 17,     // evaluation-scalar region
        proof_len - 1,      // last evaluation scalar
    ];

    let mut saw_constraint_failure = false;
    for (i, &pos) in positions.iter().enumerate() {
        let mutant = with_mutated_proof(item, |bytes| bytes[pos] ^= 0x01);
        let err = mutant
            .bundle
            .verify_proof(vk)
            .expect_err("halo2 SingleVerifier must reject a bit-flipped real proof");
        if matches!(err, PlonkError::ConstraintSystemFailure) {
            saw_constraint_failure = true;
        }
        assert_eq!(
            check_equivalence_refs(&[&mutant], vk, 0x7A3B + i as u64),
            EquivReport::Agree(false),
            "both BatchValidator paths must reject the byte-{pos} mutant the \
             SingleVerifier rejects (disagreement = counterfeiting-class signal)"
        );
    }
    assert!(
        saw_constraint_failure,
        "no tamper position reached the constraint-system check: every mutant died \
         at transcript decode, which leaves the deep reject arm untested"
    );
}

/// reddsa's per-item single strategy agrees with its batch strategy on every real
/// mainnet signature (each spend-auth and binding signature of the corpus).
#[test]
fn redpallas_single_strategy_agrees_on_real_signatures() {
    let corpus = common::pre_nu6_2_corpus();
    assert!(!corpus.is_empty());

    let mut verifier = batch::Verifier::new();
    let mut n = 0usize;
    for item in &corpus {
        for sig_item in redpallas_items(item) {
            verifier.queue(sig_item.clone());
            assert!(
                sig_item.verify_single().is_ok(),
                "reddsa verify_single rejected a real mainnet signature the batch accepts"
            );
            n += 1;
        }
    }
    assert!(n > 0);
    assert!(
        verifier.verify(StdRng::seed_from_u64(0x9E1)).is_ok(),
        "reddsa batch strategy rejected {n} real mainnet signatures the singles accept"
    );
}

/// Damaged signature encodings are rejected by batch and single in agreement, for
/// each damage class: a non-canonical scalar half (`s` = 0xFF…), a non-decodable
/// point half (`R` = 0xFF…), and a decodable-but-wrong single bit flip. The first
/// two die in the batch verifier's own decode arms; the third survives decoding and
/// fails the aggregate check — three distinct reject paths, one contract.
#[test]
fn redpallas_single_strategy_rejects_damaged_signatures_in_agreement() {
    let corpus = common::pre_nu6_2_corpus();
    assert!(!corpus.is_empty());
    let item = &corpus[0];

    let damages: [(&str, fn(&mut [u8; 64])); 3] = [
        ("s-half all-0xFF (non-canonical scalar)", |b| {
            b[32..64].fill(0xFF);
        }),
        ("R-half all-0xFF (invalid point encoding)", |b| {
            b[0..32].fill(0xFF);
        }),
        ("single bit flip (decodes, fails verification)", |b| {
            b[0] ^= 0x01;
        }),
    ];

    for (name, damage) in damages {
        let bad = mutated_binding_item(item, damage);

        assert!(
            bad.clone().verify_single().is_err(),
            "reddsa verify_single accepted a damaged binding signature ({name})"
        );

        // A batch of all-valid items plus the one damaged item must fail closed,
        // matching the single-side conjunction (valid ∧ … ∧ invalid = false).
        let mut verifier = batch::Verifier::new();
        for good in redpallas_items(item) {
            verifier.queue(good);
        }
        verifier.queue(bad);
        assert!(
            verifier.verify(StdRng::seed_from_u64(0xD4E)).is_err(),
            "reddsa batch strategy accepted a batch containing a damaged binding \
             signature ({name}) — aggregation masked the damage"
        );
    }
}

/// The empty batch is vacuously valid on both paths, in agreement: orchard's
/// `BatchValidator::validate` short-circuits `true` for a batch with no signatures,
/// and the single-side conjunction over zero items is `true`. Pinned here because
/// no replay corpus can express "no items at all".
#[test]
fn empty_batch_is_vacuously_valid_on_both_paths() {
    assert_eq!(
        check_equivalence_refs(&[], pre_nu6_2_key(), 0xE3),
        EquivReport::Agree(true),
        "empty group must be a vacuous accept on both paths"
    );
}

/// The `BatchError` Display contract: the add-time rejection (the not-fail-open arm
/// `add_reject_equivalence` pins) renders an operator-actionable message naming the
/// cross-address restriction.
#[test]
fn batch_error_display_names_the_restriction() {
    let msg = BatchError::RestrictionUnsupportedByKey.to_string();
    assert!(
        msg.contains("cross-address"),
        "BatchError Display contract drifted: {msg:?}"
    );
}
