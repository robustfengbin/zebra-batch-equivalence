//! Adversarial batches that straddle the Orchard/Ironwood boundary.
//!
//! M2's adversarial generators run on Sapling. Every fixture in
//! `tests/adversarial_generator.rs` is a `SaplingItem`, which was right for M2 —
//! its acceptance criterion names the generators, not a pool. M3's names a pool:
//!
//! > "Ironwood verifier covered by the oracle"
//!
//! and `covered` for every other verifier in this crate has meant five surfaces,
//! of which the adversarial one was at zero for Ironwood.
//!
//! ## What is actually new here
//!
//! Not the damage: `mutation_smoke.rs` has damaged Orchard proofs since M1, and
//! those three mutations now live in `common` so there is one definition of
//! each. Not the composition either: `AdversarialBatch` is generic over
//! `BatchVerifier` and `Orchard` implements it.
//!
//! What is new is the **mixed batch**. A v6 transaction can carry an
//! Orchard-pool and an Ironwood-pool bundle, and both verify under the same
//! NU6.3 key by the same code — `Pool` is an annotation, not a branch
//! (`src/lib.rs`). That is a claim, and the batch layer is where it would stop
//! being true: if aggregation ever grew a per-pool path, damaging a member of
//! one pool could leave the other pool's members judged on their own.
//!
//! `tests/v6_pool_dimensions.rs::cross_pool_batch_agrees_under_every_era_in_every_order`
//! already pins the valid direction — a mixed batch of good bundles accepts on
//! both paths, in either order. This is its other side: a mixed batch with one
//! damaged member must **reject as a whole**, and it must do so whichever pool
//! the damaged member came from. Both directions are tested because a one-sided
//! test passes just as well when the pools are not symmetric.

mod common;

use zebra_batch_equivalence::adversarial::AdversarialBatch;
use zebra_batch_equivalence::era::CircuitEra;
use zebra_batch_equivalence::verifier::check_equivalence_refs;
use zebra_batch_equivalence::{items_from_tx, EquivReport, Orchard, OrchardItem, Pool};
use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::Transaction;

use common::{with_mutated_binding_sig, with_mutated_proof};

const SEED: u64 = 0xF00D;
const CORPUS: &str = "nu6_3_activation";

/// Every item in the committed NU6.3 corpus, both pools, in file-name order.
///
/// Uses the plural loader deliberately: `item_from_tx` returns at most one item
/// per transaction and would keep the Orchard half of every dual-pool
/// transaction, leaving a suite that reads as cross-pool while never seeing an
/// Ironwood bundle.
fn nu6_3_items() -> Vec<OrchardItem> {
    let dir = format!("{}/seeds-real/{CORPUS}", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("NU6.3 seed corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    let mut items = Vec::new();
    for path in &files {
        let bytes = std::fs::read(path).expect("read corpus file");
        let tx = Transaction::zcash_deserialize(&bytes[..]).unwrap_or_else(|e| {
            panic!("corpus file {} failed to deserialize: {e}", path.display())
        });
        items.extend(items_from_tx(&tx));
    }
    items
}

/// `n` items from each pool, interleaved, so a mixed batch is the ordinary case
/// rather than a boundary one.
///
/// Takes the corpus by value and re-orders it: `OrchardItem` is deliberately not
/// `Clone` (a bundle plus its proof is not something to duplicate by accident),
/// so a mixed base is built by moving items out of the loaded corpus rather than
/// by copying references into a batch that needs owned items.
fn mixed_base(items: Vec<OrchardItem>, n: usize) -> Vec<OrchardItem> {
    let (orchard, ironwood): (Vec<OrchardItem>, Vec<OrchardItem>) =
        items.into_iter().partition(|i| i.pool == Pool::Orchard);
    assert!(
        orchard.len() >= n && ironwood.len() >= n,
        "need {n} items per pool; corpus has {} Orchard / {} Ironwood",
        orchard.len(),
        ironwood.len()
    );

    let mut base = Vec::with_capacity(n * 2);
    for (o, i) in orchard.into_iter().take(n).zip(ironwood.into_iter().take(n)) {
        base.push(o);
        base.push(i);
    }
    base
}

/// The corpus reaches both pools through this file's loader.
///
/// Runs first: every assertion below is about a mixed batch, and a corpus that
/// silently loaded one pool would let all of them pass while testing nothing
/// cross-pool.
#[test]
fn the_base_is_actually_mixed() {
    let items = nu6_3_items();
    let orchard = items.iter().filter(|i| i.pool == Pool::Orchard).count();
    let ironwood = items.iter().filter(|i| i.pool == Pool::Ironwood).count();
    eprintln!("NU6.3 corpus: {orchard} Orchard-pool, {ironwood} Ironwood-pool");
    assert!(orchard > 0 && ironwood > 0);

    let base = mixed_base(items, 3);
    assert_eq!(base.len(), 6);
    assert_eq!(base.iter().filter(|i| i.pool == Pool::Orchard).count(), 3);
    assert_eq!(base.iter().filter(|i| i.pool == Pool::Ironwood).count(), 3);
}

/// A mixed batch with one damaged member rejects as a whole, from either pool,
/// at every position.
///
/// The expected report is `Agree(false)` rather than per-item agreement, for the
/// reason `adversarial_generator.rs` states: a batch verifier answers "is all of
/// this valid", so every valid member is rejected along with the invalid one.
/// Comparing position by position would report a false reject for each of them.
///
/// What this pins is that the whole batch is the granularity **across pools
/// too** — that an Ironwood member is not judged separately from the Orchard
/// members it shares a batch with, and vice versa.
#[test]
fn a_damaged_member_rejects_the_whole_mixed_batch_from_either_pool() {
    let vk = CircuitEra::Nu6_3Onward.key();
    let base = mixed_base(nu6_3_items(), 3);

    for damaged_pool in [Pool::Orchard, Pool::Ironwood] {
        let source = base
            .iter()
            .find(|i| i.pool == damaged_pool)
            .expect("mixed_base guarantees both pools");
        let invalid = with_mutated_proof(source, |bytes| bytes[0] ^= 0x01);

        for position in 0..=base.len() {
            let batch =
                AdversarialBatch::<Orchard>::mostly_valid_plus_one_invalid(&base, &invalid, position);
            batch.check_shape(vk, SEED).unwrap_or_else(|e| {
                panic!("generated batch is not the shape it claims ({damaged_pool:?}): {e:?}")
            });

            let report = check_equivalence_refs::<Orchard>(&batch.items, vk, SEED);
            assert_eq!(
                report,
                EquivReport::Agree(false),
                "damaged {damaged_pool:?} member at position {position}: got {report:?}"
            );
        }
    }
}

/// The same, with the binding signature damaged instead of the proof.
///
/// Two mutations rather than one because they fail in different layers:
/// `BatchValidator` queues the RedPallas signatures *and* the halo2 proof and
/// accepts only if both batches verify. A test that only ever damaged proofs
/// would leave the signature layer of a mixed batch unexercised, and the two
/// layers are exactly where a per-pool path could hide.
#[test]
fn a_damaged_binding_signature_also_rejects_the_whole_mixed_batch() {
    let vk = CircuitEra::Nu6_3Onward.key();
    let base = mixed_base(nu6_3_items(), 3);

    for damaged_pool in [Pool::Orchard, Pool::Ironwood] {
        let source = base
            .iter()
            .find(|i| i.pool == damaged_pool)
            .expect("mixed_base guarantees both pools");
        let invalid = with_mutated_binding_sig(source);

        for position in [0, base.len() / 2, base.len()] {
            let batch =
                AdversarialBatch::<Orchard>::mostly_valid_plus_one_invalid(&base, &invalid, position);
            batch.check_shape(vk, SEED).unwrap_or_else(|e| {
                panic!("generated batch is not the shape it claims ({damaged_pool:?}): {e:?}")
            });

            let report = check_equivalence_refs::<Orchard>(&batch.items, vk, SEED);
            assert_eq!(
                report,
                EquivReport::Agree(false),
                "damaged {damaged_pool:?} signature at position {position}: got {report:?}"
            );
        }
    }
}

/// An all-Ironwood adversarial batch.
///
/// Ironwood has never had one: M1's mutation smoke and M2's generators both
/// predate the pool. A mixed batch does not cover this, because in a mixed batch
/// the Orchard members alone would be enough to make the batch reject — an
/// Ironwood-only batch is the only shape where the damaged Ironwood member is
/// the sole reason for the verdict.
#[test]
fn an_ironwood_only_batch_rejects_its_damaged_member() {
    let vk = CircuitEra::Nu6_3Onward.key();
    let mut ironwood: Vec<OrchardItem> = nu6_3_items()
        .into_iter()
        .filter(|i| i.pool == Pool::Ironwood)
        .collect();
    ironwood.truncate(4);
    assert!(
        ironwood.len() >= 3,
        "need a few Ironwood bundles; got {}",
        ironwood.len()
    );

    let invalid = with_mutated_proof(&ironwood[0], |bytes| bytes[0] ^= 0x01);

    for position in 0..=ironwood.len() {
        let batch =
            AdversarialBatch::<Orchard>::mostly_valid_plus_one_invalid(&ironwood, &invalid, position);
        batch
            .check_shape(vk, SEED)
            .unwrap_or_else(|e| panic!("generated batch is not the shape it claims: {e:?}"));

        let report = check_equivalence_refs::<Orchard>(&batch.items, vk, SEED);
        assert_eq!(
            report,
            EquivReport::Agree(false),
            "damaged Ironwood member at position {position}: got {report:?}"
        );
    }
}
