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
    check_duplicate_consistency, check_era_routing, check_era_routing_for_claimed,
    check_order_invariance, deep_check,
};
use zebra_batch_equivalence::{
    check_equivalence_refs, derive_seed, item_from_tx_with_nu, items_from_tx_stream, EquivReport,
    OrchardItem, Pool,
};
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

/// Every real node-extracted era, each as `(seeds-real dir, era)`.
///
/// This list must cover [`CircuitEra::ALL`]; `real_eras_cover_every_circuit_era`
/// below fails if it stops doing so. It was short by one era until M3 — the
/// NU6.3-onward corpus existed and the deep sweep never ran over it, which is
/// invisible from a green suite because the two-era sweep passes on its own
/// terms.
const REAL_ERAS: [(&str, CircuitEra); 3] = [
    ("orchard_v5_pre_nu6_2", CircuitEra::PreNu6_2),
    ("orchard_v5_nu6_2", CircuitEra::Nu6_2),
    ("nu6_3_activation", CircuitEra::Nu6_3Onward),
];

/// The deep sweep must reach every era the crate knows about.
///
/// A missing era does not fail anything: the sweep runs over the eras it was
/// given and reports success for them. The only way it shows up is a check that
/// compares the two lists.
#[test]
fn real_eras_cover_every_circuit_era() {
    for era in CircuitEra::ALL {
        assert!(
            REAL_ERAS.iter().any(|(_, e)| *e == era),
            "{era:?} has no entry in REAL_ERAS, so the deep invariant sweep never \
             runs over it. Add its corpus directory, or state here why it has none."
        );
    }
}

/// The NU6.3 corpus must load Ironwood-pool items, not just its Orchard half.
///
/// `REAL_ERAS` feeds a loader, and the single-item loader keeps one bundle per
/// transaction, the Orchard one whenever there are two. On this corpus that
/// drops the Ironwood half of all 77 dual-pool transactions: 172 of its 249
/// items reach the sweep, and 29 of them, not 106, are Ironwood.
#[test]
fn nu6_3_entry_loads_both_pools() {
    let items = common::seeds_real_corpus_all_pools("nu6_3_activation");
    let ironwood = items
        .iter()
        .filter(|i| i.pool == zebra_batch_equivalence::Pool::Ironwood)
        .count();
    let orchard = items.len() - ironwood;
    assert!(
        ironwood > 0 && orchard > 0,
        "NU6.3 entry loaded {orchard} Orchard / {ironwood} Ironwood items; the deep \
         sweep over this era is only covering Ironwood if both are non-zero"
    );
}

/// W6 PR tier: the full deep sweep over a deterministic [`SAMPLE`]-item window
/// of each real node-extracted era. Always-green scale (~one narrow window per
/// era); the full corpus at [`FOLD`] width runs in the `#[ignore]` tier below.
#[test]
fn deep_check_sampled_window_per_real_era() {
    for (dir, era) in REAL_ERAS {
        let items = common::seeds_real_corpus_all_pools(dir);
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
        let items = common::seeds_real_corpus_all_pools(dir);
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

/// The first continuous run's only crash, kept as a regression: a claimed era is
/// not the correct one.
///
/// ClusterFuzzLite's first daily run (2026-09-22) stopped `orchard_batch_equivalence`
/// with a critical `EraFailOpen { correct: Nu6_2, used: Nu6_3Onward }`. The input
/// is a real NU6.3 Orchard bundle whose trailing control byte a mutation had
/// turned from `0x02` into `0x4f` — which the target reads as era `Nu6_2`. The
/// bundle verifies under its own era and no other, which is exactly right; the
/// harness had taken the byte's claim as fact and reported the bundle's own key
/// accepting it as a fail-open. The file is that input, unmodified.
#[test]
fn a_claimed_era_is_not_trusted_as_the_correct_one() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/regressions/orchard_batch_equivalence/crash-a31a4495c0bf01973bfbefa9526911360a442f36"
    ))
    .expect("regression input");
    let (stream, control) = data.split_at(data.len() - 1);
    let control = control[0];
    // Decoded the way the fuzz target decodes it.
    let claimed = CircuitEra::ALL[control as usize % CircuitEra::ALL.len()];
    assert_eq!(claimed, CircuitEra::Nu6_2);
    assert_eq!(control >> 6, 0b01, "the pool bits select Orchard-only");
    let items = items_from_tx_stream(stream);
    let refs: Vec<&OrchardItem> = items.iter().filter(|i| i.pool == Pool::Orchard).collect();
    assert_eq!(refs.len(), 1);
    let seed = derive_seed(&data);

    // What the cryptography does: exactly one era accepts, and it is the bundle's own.
    let accepting: Vec<CircuitEra> = CircuitEra::ALL
        .into_iter()
        .filter(|e| check_equivalence_refs(&refs, e.key(), seed) == EquivReport::Agree(true))
        .collect();
    assert_eq!(accepting, vec![CircuitEra::Nu6_3Onward]);

    // What the ungated check says when handed the claim as fact: a fail-open. This
    // is the false positive, kept visible so the precondition stays documented by
    // a failing example rather than by a comment alone.
    assert!(!check_era_routing(&refs, claimed, seed).is_empty());

    // The gated check does not report the claim, and still holds the true era to
    // the property: every other key rejects.
    let claimed_report = check_equivalence_refs(&refs, claimed.key(), seed);
    assert!(check_era_routing_for_claimed(&refs, claimed, claimed_report, seed).is_empty());
    let true_report = check_equivalence_refs(&refs, CircuitEra::Nu6_3Onward.key(), seed);
    assert_eq!(true_report, EquivReport::Agree(true));
    assert!(check_era_routing_for_claimed(&refs, CircuitEra::Nu6_3Onward, true_report, seed).is_empty());
}
