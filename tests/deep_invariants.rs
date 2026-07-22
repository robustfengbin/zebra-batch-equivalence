//! Deep batching-invariant integration tests over the real pre-NU6.2 corpus.
//!
//! Where `baseline_agreement.rs` asserts the *base* `batch ⟺ single` property,
//! this drives the *deeper* invariants ([`invariants`]) over the same real
//! in-tree Orchard proofs: order-independence, duplicate-consistency, sub-batch
//! compositionality, and era-routing / not-fail-open. These exercise the
//! batching, key-selection and composition glue where a real regression would
//! hide — the base check alone passes trivially on a valid corpus.
//!
//! The in-tree tests below run the sweep over the (three-proof) in-tree corpus.
//! W6 widens the real-data surface with two tiers over the full committed
//! node-extracted corpus (`seeds-real/`, 162 pre-NU6.2 + 250 NU6.2 items):
//!
//! * **PR tier** (`deep_check_sampled_*`): a deterministic 16-item window per
//!   real era, always-green in `cargo test`.
//! * **Full tier** (`deep_check_full_real_corpus_folded`, `#[ignore]`): every
//!   item, in [`FOLD`]-sized windows. Folding keeps the sweep linear: the
//!   sub-batch invariant walks every prefix of its input, so one unfolded
//!   415-item window would be ~86k SNARK verifications (hours), for no more
//!   assurance than the same invariant over bounded windows. Nightly/manual:
//!   `cargo test --test deep_invariants -- --ignored` (measured runtime lives
//!   in the coverage/W6 log).

mod common;

use zebra_batch_equivalence::era::CircuitEra;
use zebra_batch_equivalence::invariants::{
    check_duplicate_consistency, check_era_routing, check_order_invariance, deep_check,
};
use zebra_batch_equivalence::{item_from_tx_with_nu, OrchardItem};
use zebra_chain::{block::Block, parameters::NetworkUpgrade, serialization::ZcashDeserializeInto};

/// Full-tier window size: the sub-batch prefix walk stays ≤16 deep, mirroring
/// the production flush scale (`MAX_BATCH_ITEMS`' spirit).
const FOLD: usize = 16;

/// PR-tier sample width per era. Structurally the same sweep as a full-tier
/// window, narrowed: measured 2026-07-17, a 16-item window costs ~2.5 min per
/// era on a warm 8-core box (~6 min under load) — too heavy for an always-green
/// job on 2-core CI runners. Width 8 keeps the prefix walk meaningful at ~¼ the
/// SNARK count; the 16-deep walk still runs nightly in the full tier.
const SAMPLE: usize = 8;

/// Every transparent-input-free pre-NU6.2 Orchard item from the in-tree mainnet
/// vectors. (Transparent-input txs are excluded: their ZIP-244 sighash folds in
/// prevouts the block vectors do not carry, so an empty-prevout sighash would
/// not match — that is the adversarial/mixed path, not the valid baseline.)
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

/// The full deep sweep must find zero violations on the real valid corpus.
#[test]
fn deep_check_is_clean_over_real_pre_nu6_2_corpus() {
    let items = pre_nu6_2_corpus();
    assert!(!items.is_empty(), "must have at least one real Orchard item");
    let refs: Vec<&OrchardItem> = items.iter().collect();

    let violations = deep_check(&refs, CircuitEra::PreNu6_2, 0xF00D);
    assert!(
        violations.is_empty(),
        "deep batching invariants must hold on {} real pre-NU6.2 proofs; got {violations:?}",
        items.len(),
    );
}

/// Batch validation is order-independent: permuting real valid bundles never
/// flips the batch outcome.
#[test]
fn order_independent_on_real_corpus() {
    let items = pre_nu6_2_corpus();
    let refs: Vec<&OrchardItem> = items.iter().collect();
    let vk = CircuitEra::PreNu6_2.key();
    assert_eq!(
        check_order_invariance(&refs, vk, 0xABCD),
        None,
        "real valid batch must be order-independent",
    );
}

/// Duplicating real valid bundles keeps batch and single in agreement.
#[test]
fn duplicate_consistent_on_real_corpus() {
    let items = pre_nu6_2_corpus();
    let refs: Vec<&OrchardItem> = items.iter().collect();
    let vk = CircuitEra::PreNu6_2.key();
    assert_eq!(check_duplicate_consistency(&refs, vk, 0xABCD), None);
}

/// Not fail-open: pre-NU6.2 proofs are rejected by BOTH paths under every other
/// era key (NU6.2 and NU6.3), never accepted under the wrong key. This is the
/// generalisation of the baseline's single wrong-era check to all wrong eras.
#[test]
fn era_routing_never_fails_open_on_real_corpus() {
    let items = pre_nu6_2_corpus();
    let refs: Vec<&OrchardItem> = items.iter().collect();
    let violations = check_era_routing(&refs, CircuitEra::PreNu6_2, 0xF00D);
    assert!(
        violations.is_empty(),
        "pre-NU6.2 proofs must reject-both under NU6.2 and NU6.3 keys; got {violations:?}",
    );
}

/// The two real node-extracted eras, each as `(seeds-real dir, era)`.
const REAL_ERAS: [(&str, CircuitEra); 2] = [
    ("orchard_v5_pre_nu6_2", CircuitEra::PreNu6_2),
    ("orchard_v5_nu6_2", CircuitEra::Nu6_2),
];

/// W6 PR tier: the full deep sweep over a deterministic [`SAMPLE`]-item window
/// of each real node-extracted era. Always-green scale (~one narrow window per
/// era); the full corpus at [`FOLD`] width runs in the `#[ignore]` tier below.
#[test]
fn deep_check_sampled_window_per_real_era() {
    for (dir, era) in REAL_ERAS {
        let items = common::seeds_real_corpus(dir);
        assert!(
            items.len() >= SAMPLE,
            "expected ≥{SAMPLE} usable items under seeds-real/{dir}, got {}",
            items.len()
        );
        let window: Vec<&OrchardItem> = items.iter().take(SAMPLE).collect();
        let violations = deep_check(&window, era, 0x516D);
        assert!(
            violations.is_empty(),
            "deep invariants must hold on the first {SAMPLE} real {era:?} proofs; got {violations:?}",
        );
    }
}

/// W6 full tier: the deep sweep over EVERY committed real proof, folded into
/// [`FOLD`]-sized windows per era (see the module docs for why folding, not one
/// giant window, is the honest full-corpus shape). Nightly/manual:
/// `cargo test --test deep_invariants -- --ignored`.
#[test]
#[ignore = "full-corpus tier (minutes of real SNARK verification): cargo test --test deep_invariants -- --ignored"]
fn deep_check_full_real_corpus_folded() {
    let started = std::time::Instant::now();
    let mut windows = 0usize;
    let mut proofs = 0usize;
    for (dir, era) in REAL_ERAS {
        let items = common::seeds_real_corpus(dir);
        assert!(!items.is_empty(), "empty corpus under seeds-real/{dir}");
        for chunk in items.chunks(FOLD) {
            let window: Vec<&OrchardItem> = chunk.iter().collect();
            let violations = deep_check(&window, era, 0xF01D ^ windows as u64);
            assert!(
                violations.is_empty(),
                "deep invariants must hold on real {era:?} window #{windows}; got {violations:?}",
            );
            windows += 1;
            proofs += window.len();
        }
    }
    eprintln!(
        "deep_check_full_real_corpus_folded: {proofs} proofs / {windows} windows (fold {FOLD}) in {:?}",
        started.elapsed()
    );
}
