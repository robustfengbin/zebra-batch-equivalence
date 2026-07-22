//! Baseline agreement over the real pre-NU6.2 mainnet Orchard corpus (ZCG #332 · M1).
//!
//! Grant M1 acceptance criterion AC2: the oracle must assert `batch ⟺ single` agreement over the
//! valid corpus with **zero spurious disagreements**. This test drives [`check_equivalence`] over
//! every real pre-NU6.2 Orchard bundle in Zebra's in-tree mainnet vectors
//! (`zebra_test::vectors::MAINNET_BLOCKS`, blocks 1,687,107 / 118 / 121) and asserts
//! [`EquivReport::Agree`]`(true)` — both paths accept, no disagreement.
//!
//! These are the only real Orchard proofs shipped in-tree, and they are all pre-NU6.2 (NU5-era),
//! so they verify under [`pre_nu6_2_key`]. NU6.2/NU6.3-era corpus (mined after the June-5 fix) is
//! extracted from a node snapshot and added under M1's corpus pipeline / M2.

use zebra_batch_equivalence::{
    check_equivalence, item_from_tx_with_nu, pre_nu6_2_key, EquivReport, OrchardItem,
};
use zebra_chain::{
    block::Block, parameters::NetworkUpgrade, serialization::ZcashDeserializeInto,
};

/// Every transparent-input-free pre-NU6.2 Orchard item from the in-tree mainnet vectors.
///
/// Transparent-input transactions are excluded: their ZIP-244 sighash folds in the prevouts they
/// spend, which the block vectors do not carry, so an empty-prevout sighash would not match and
/// the bundle would (correctly) fail to verify — that belongs to the adversarial/mixed path, not
/// the valid baseline.
fn pre_nu6_2_corpus() -> Vec<OrchardItem> {
    let mut items = Vec::new();
    for bytes in zebra_test::vectors::MAINNET_BLOCKS.values() {
        let block: Block = bytes
            .zcash_deserialize_into()
            .expect("hard-coded mainnet test vector must deserialize");
        for tx in &block.transactions {
            if tx.orchard_shielded_data().is_none() || !tx.inputs().is_empty() {
                continue;
            }
            if let Some(item) = item_from_tx_with_nu(tx, NetworkUpgrade::Nu5) {
                items.push(item);
            }
        }
    }
    items
}

/// AC2: batch and single agree — and both accept — over the real valid corpus.
#[test]
fn baseline_agreement_over_real_pre_nu6_2_corpus() {
    let items = pre_nu6_2_corpus();
    assert!(
        !items.is_empty(),
        "in-tree mainnet vectors must yield at least one pre-NU6.2 Orchard item"
    );

    let vk = pre_nu6_2_key();
    let report = check_equivalence(&items, &vk, 0xF00D);

    assert_eq!(
        report,
        EquivReport::Agree(true),
        "baseline: {} real pre-NU6.2 Orchard bundles must agree with both paths accepting; \
         got {report:?} (FalseAccept here would be a counterfeiting-class finding)",
        items.len(),
    );
}

/// Reproducibility: the seeded oracle is deterministic across runs, and — because the corpus is
/// valid — outcome-invariant across seeds. This is the M1 discipline that lets an M2 adversarial
/// disagreement be cited (it reproduces).
#[test]
fn agreement_is_reproducible_across_seeds() {
    let items = pre_nu6_2_corpus();
    let vk = pre_nu6_2_key();
    let a = check_equivalence(&items, &vk, 1);
    let b = check_equivalence(&items, &vk, 1);
    let c = check_equivalence(&items, &vk, 0xDEAD_BEEF);
    assert_eq!(a, b, "same seed must give the same report");
    assert_eq!(a, c, "a valid corpus agrees regardless of rng seed");
    assert_eq!(a, EquivReport::Agree(true));
}

/// Not-fail-open guard: under the wrong (NU6.2) era key the pre-NU6.2 proofs are rejected by both
/// paths — the oracle still reports agreement, on `false`. A batch that accepted here regardless of
/// era would be a fail-open false-accept.
#[test]
fn wrong_era_key_still_agrees_on_rejection() {
    use orchard::circuit::OrchardCircuitVersion;
    use zebra_batch_equivalence::verifying_key;

    let items = pre_nu6_2_corpus();
    let wrong_key = verifying_key(OrchardCircuitVersion::FixedPostNu6_2);
    let report = check_equivalence(&items, &wrong_key, 0xF00D);

    assert_eq!(
        report,
        EquivReport::Agree(false),
        "pre-NU6.2 proofs under the NU6.2 key must be rejected by BOTH paths (agree on false); \
         got {report:?}",
    );
}
