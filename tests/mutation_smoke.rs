//! Mutation smoke vectors (ZCG #332 · W11): both paths must reject a *tampered* real proof.
//!
//! The valid corpus proves batch⟺single agreement on accept; the era-routing tests prove it
//! on structurally-mismatched inputs. This suite closes the remaining not-fail-open gap at
//! smoke scale: take a REAL mainnet proof, damage it mechanically, and pin that both paths
//! agree on **reject** — batch aggregation must not mask a corrupted proof body, truncated
//! proof, mismatched sighash, or damaged binding signature (`Agree(false)`; a `FalseAccept`
//! here is the counterfeiting-class signal this grant exists to catch).
//!
//! Deliberately smoke-scale (a handful of hand-rolled mutants, tests-only): the systematic
//! adversarial-corpus *generators* (single-element tamper: corrupt proof / swap nullifier /
//! perturb signature scalar / replace public input; mostly-valid-plus-one-invalid batches)
//! are M2's deliverable. This file is that machinery's skeleton preview, not its
//! implementation — do not grow a generator API here.

mod common;

use zebra_batch_equivalence::{check_equivalence_refs, pre_nu6_2_key, EquivReport, OrchardItem};

use common::{with_mutated_binding_sig, with_mutated_proof, with_mutated_sighash};

/// Every mutant of every real in-tree proof is rejected by BOTH paths — proof-body bit
/// flip (SNARK aggregate must fail), proof truncation (proof must not even parse),
/// sighash mismatch (signature batch must fail before proofs are reached), and
/// binding-signature bit flip (the signature itself must fail to verify).
#[test]
fn mutated_real_proofs_are_rejected_consistently() {
    let corpus = common::pre_nu6_2_corpus();
    assert!(!corpus.is_empty());
    let vk = pre_nu6_2_key();

    let mutations: [(&str, fn(&OrchardItem) -> OrchardItem); 4] = [
        ("proof bit-flip", |item| {
            with_mutated_proof(item, |bytes| bytes[0] ^= 0x01)
        }),
        ("proof truncation", |item| {
            with_mutated_proof(item, |bytes| {
                bytes.truncate(bytes.len() - 1);
            })
        }),
        ("sighash mismatch", with_mutated_sighash),
        ("binding-sig bit-flip", with_mutated_binding_sig),
    ];

    for (name, mutate) in mutations {
        for (i, item) in corpus.iter().enumerate() {
            let mutant = mutate(item);
            let report = check_equivalence_refs(&[&mutant], vk, 0xBAD0 + i as u64);
            assert_eq!(
                report,
                EquivReport::Agree(false),
                "{name} of real proof #{i} must be rejected fail-closed by BOTH paths; \
                 got {report:?} (FalseAccept = counterfeiting-class finding)"
            );
        }
    }
}

/// One tampered proof inside an otherwise-valid batch flips the whole group to
/// fail-closed agreement: the batch aggregate rejects, and the single conjunction
/// contains the same reject. Aggregation must not mask the mutant.
#[test]
fn mutant_poisons_valid_batch_consistently() {
    let corpus = common::pre_nu6_2_corpus();
    assert!(!corpus.is_empty());
    let vk = pre_nu6_2_key();

    let valid_refs: Vec<&OrchardItem> = corpus.iter().collect();
    assert_eq!(
        check_equivalence_refs(&valid_refs, vk, 0xF00D),
        EquivReport::Agree(true),
        "premise: the untouched corpus agrees on accept"
    );

    let mutant = with_mutated_proof(&corpus[0], |bytes| bytes[0] ^= 0x01);
    for position in [0, valid_refs.len() / 2, valid_refs.len()] {
        let mut refs = valid_refs.clone();
        refs.insert(position, &mutant);
        let report = check_equivalence_refs(&refs, vk, 0xF00D);
        assert_eq!(
            report,
            EquivReport::Agree(false),
            "a valid batch with a bit-flipped proof spliced at index {position} must fail \
             closed on BOTH paths; got {report:?}"
        );
    }
}
