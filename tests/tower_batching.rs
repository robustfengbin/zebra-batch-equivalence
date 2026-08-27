//! The batching middleware under a real scheduler (ZCG #332 · M2).
//!
//! Everywhere else in this crate the batch boundaries are ours: we pick the
//! groups, the permutations, the sub-batches, synchronously. Here they are drawn
//! by `tower-batch-control`'s worker from arrival timing — a `tokio::select!`
//! between "another item arrived" and "the batch timer expired". This is the only
//! suite that reaches those 754 lines, and the only one where the grouping is not
//! something we decided.
//!
//! That is also why it is worth asserting rather than merely covering. Batch
//! membership depends partly on arrival order, and arrival order depends partly
//! on what the network delivered. So a node does not fully control who shares a
//! batch with whom — and the property that has to hold is that **it does not
//! matter**.
//!
//! Driven with RedJubjub throughout: signature verification is cheap enough to
//! run many partitions of a real corpus, where a suite built on halo2 could
//! afford one. The middleware is verifier-agnostic — [`Weighted`] is generic over
//! [`BatchVerifier`] — so what is exercised here is the scheduler, not the pool.
//!
//! **Every invariance test reads [`BatchLog`] and asserts the partitions actually
//! differed before comparing verdicts.** Two submission patterns that both
//! happened to land in one batch would satisfy every assertion below while
//! testing nothing, and would look exactly like a pass.

mod common;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures::future::join_all;
use tower::{Service, ServiceExt};

use common::{historical_sapling_corpus, in_tree_sapling_corpus};
use zebra_batch_equivalence::redjubjub::{
    items_from_bundle, items_from_sapling_item, RedJubjub, RedJubjubItem,
};
use zebra_batch_equivalence::sapling::{Sapling, SaplingItem};
use zebra_batch_equivalence::tower::{batched_with, BatchLog, Weighted, MAX_BATCH_SIZE};
use zebra_batch_equivalence::{BatchVerifier, Orchard};

const SEED: u64 = 0xF00D;

/// Long enough that the timer never fires while a test is still submitting, so
/// tests that mean to exercise weight-driven flushes are not silently exercising
/// latency-driven ones instead.
const SLOW_TIMER: Duration = Duration::from_secs(30);

/// How many bundles to draw from the historical corpus. Enough that a
/// production-sized batch of 64 signatures cannot hold them all — otherwise this
/// suite would exercise one batch and call it scheduling.
const SAMPLE_BUNDLES: usize = 120;

/// Real signatures for submission, cached across the tests in this binary.
///
/// Drawn from the historical corpus rather than the in-tree vectors, which yield
/// 63 signatures — one short of a single production batch, so nothing would ever
/// be partitioned. Sampled with a stride rather than a prefix because this
/// corpus's composition drifts monotonically with height.
fn corpus() -> &'static [Arc<RedJubjubItem>] {
    static CORPUS: OnceLock<Vec<Arc<RedJubjubItem>>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let bundles = historical_sapling_corpus();
        common::spread(&bundles, SAMPLE_BUNDLES)
            .into_iter()
            .flat_map(items_from_sapling_item)
            .map(Arc::new)
            .collect()
    })
}

/// Submit every item and collect one verdict each, in submission order.
///
/// Items are handed to the service in order without awaiting their verdicts, so
/// the arrival sequence is fixed while the batching remains the scheduler's
/// decision. Awaiting each verdict before submitting the next would serialise
/// everything into batches of one — which is exactly the thing this suite must
/// not accidentally do.
async fn submit_all(
    items: &[Arc<RedJubjubItem>],
    max_weight: usize,
    max_latency: Duration,
) -> (Vec<bool>, BatchLog) {
    let (svc, log) = batched_with::<RedJubjub>(&(), SEED, max_weight, max_latency);

    let mut pending = Vec::with_capacity(items.len());
    for item in items {
        let mut svc = svc.clone();
        let ready = svc
            .ready()
            .await
            .expect("batch service accepts items")
            .call(Weighted::<RedJubjub>::new(Arc::clone(item)));
        pending.push(ready);
    }

    let verdicts = join_all(pending)
        .await
        .into_iter()
        .map(|r| r.expect("every item receives a verdict"))
        .collect();

    (verdicts, log)
}

/// Each item's verdict when verified entirely outside the middleware.
fn verdicts_alone(items: &[Arc<RedJubjubItem>]) -> Vec<bool> {
    items
        .iter()
        .map(|item| RedJubjub::validate_one(item, &(), SEED))
        .collect()
}

/// The baseline: real signatures through the real scheduler reach the same
/// verdicts they reach on their own — and the scheduler really did cut more than
/// one batch getting there.
#[tokio::test(flavor = "multi_thread")]
async fn every_item_gets_its_own_verdict_through_the_real_scheduler() {
    let items = corpus();
    assert!(
        items.len() > MAX_BATCH_SIZE,
        "corpus of {} signatures cannot fill more than one batch of {MAX_BATCH_SIZE}; this suite \
         would then be testing a single batch and calling it scheduling",
        items.len()
    );

    let (verdicts, log) = submit_all(items, MAX_BATCH_SIZE, SLOW_TIMER).await;

    assert_eq!(
        log.sizes().iter().sum::<usize>(),
        items.len(),
        "every submitted item must appear in exactly one flushed batch; batches were {:?}",
        log.sizes()
    );
    assert!(
        log.count() >= 2,
        "expected the corpus to be split across batches, got a single batch of {:?}",
        log.sizes()
    );
    assert_eq!(
        verdicts,
        verdicts_alone(items),
        "at least one signature was judged differently inside the scheduler than on its own"
    );

    // How the scheduler actually cut the work is a result, not a detail: it is
    // what says this suite exercised batching rather than describing it.
    // Visible under `--nocapture`.
    eprintln!(
        "tower: {} signatures -> {} batches, sizes {:?}",
        items.len(),
        log.count(),
        log.sizes()
    );
}

/// The core tower-layer property: a different partition of the same items yields
/// the same verdicts.
///
/// Both runs are asserted to have partitioned differently, so a pass cannot come
/// from the two runs having batched identically.
#[tokio::test(flavor = "multi_thread")]
async fn verdicts_survive_a_different_partition() {
    let items = corpus();

    let (wide, wide_log) = submit_all(items, MAX_BATCH_SIZE, SLOW_TIMER).await;
    let (narrow, narrow_log) = submit_all(items, 7, SLOW_TIMER).await;

    assert_ne!(
        wide_log.sizes(),
        narrow_log.sizes(),
        "the two runs partitioned the work identically, so this proves nothing about batching"
    );
    assert_eq!(
        wide, narrow,
        "changing how the scheduler divided the work changed at least one verdict"
    );
    assert_eq!(wide, verdicts_alone(items));
}

/// An invalid signature and the blast radius it actually has.
///
/// One bad signature rejects its own batch — that is what batch verification
/// means, and Zebra's `Fallback` exists because of it. What must not happen is
/// that it reaches items the scheduler put in a *different* batch. That is the
/// difference between a bounded failure and one whose size an attacker sets by
/// choosing when to send.
///
/// The partition is read from the log rather than assumed: which batch each item
/// landed in is the scheduler's decision, and predicting it would be asserting
/// our model of the scheduler instead of the scheduler.
#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_signature_cannot_reach_another_batch() {
    let sapling = in_tree_sapling_corpus();
    assert!(sapling.len() >= 2, "need two bundles to cross sighashes");

    // Real signatures, real keys, bound to another transaction's sighash.
    let poison = items_from_bundle(&sapling[0].bundle, &sapling[1].sighash)
        .into_iter()
        .next()
        .expect("bundle yields at least a binding signature");

    let mut items = corpus().to_vec();
    let poison_index = items.len() / 2;
    items.insert(poison_index, Arc::new(poison));

    let max_weight = 7;
    let (verdicts, log) = submit_all(&items, max_weight, SLOW_TIMER).await;

    // Walk the flushed batches in order, in step with submission order, and find
    // the one holding the invalid signature.
    let mut start = 0;
    let mut poisoned_range = None;
    for size in log.sizes() {
        let end = start + size;
        if (start..end).contains(&poison_index) {
            poisoned_range = Some(start..end);
        }
        start = end;
    }
    let poisoned_range = poisoned_range.expect("the invalid signature landed in some batch");
    assert_eq!(
        start,
        items.len(),
        "batches must cover every item exactly once"
    );
    assert!(
        log.count() >= 2,
        "need more than one batch for 'another batch' to mean anything: {:?}",
        log.sizes()
    );

    for (index, verdict) in verdicts.iter().enumerate() {
        if poisoned_range.contains(&index) {
            assert!(
                !verdict,
                "item {index} shared a batch with the invalid signature, so the batch must \
                 reject it; the fallback is what recovers it afterwards"
            );
        } else {
            assert!(
                verdict,
                "item {index} was in a different batch from the invalid signature ({:?}) and \
                 must be unaffected by it",
                poisoned_range
            );
        }
    }
}

/// A batch that never fills up is still flushed, by the latency timer, and its
/// verdicts are the same ones a full batch would have produced.
///
/// The timer path is the other half of `worker.rs`'s `select!`, and the only one
/// that runs when traffic is thin — which is most of the time on a quiet node.
#[tokio::test(flavor = "multi_thread")]
async fn the_latency_timer_flushes_a_batch_that_never_filled() {
    let items: Vec<Arc<RedJubjubItem>> = corpus().iter().take(3).cloned().collect();
    assert!(items.len() == 3, "need a few items to under-fill a batch");

    // A batch size far larger than what is submitted, so only the timer can
    // flush it.
    let (verdicts, log) = submit_all(&items, 4096, Duration::from_millis(50)).await;

    assert_eq!(
        log.sizes(),
        vec![items.len()],
        "the timer should have flushed exactly one under-filled batch"
    );
    assert_eq!(verdicts, verdicts_alone(&items));
}

/// `MAX_BATCH_SIZE = 64` is one constant, and it does not measure one thing.
///
/// Zebra applies the same limit to every batch verifier through `RequestWeight`,
/// whose default is 1 per item; only halo2 overrides it, to count actions. So the
/// same 64 bounds Orchard's *actions* and Sapling's *bundles* — and a Sapling
/// bundle carries an unbounded number of proofs.
///
/// This is a property of the verifiers rather than of the scheduler, so it needs
/// no runtime. It is asserted rather than described because it is the load-bearing
/// fact behind what an adversarial corpus can do to a batch's size: few bundles,
/// each stuffed with spends and outputs, is a shape Sapling permits and Orchard
/// cannot express.
#[test]
fn one_batch_size_limit_measures_two_different_things() {
    let sapling = in_tree_sapling_corpus();
    assert!(!sapling.is_empty(), "corpus must not be empty");

    // Sapling: one bundle weighs 1 no matter how many proofs it carries.
    let widest: &SaplingItem = sapling
        .iter()
        .max_by_key(|item| item.proof_count())
        .expect("corpus is non-empty");
    assert_eq!(
        Sapling::item_weight(widest),
        1,
        "Sapling must take the default weight, as Zebra's sapling::Item does"
    );
    assert!(
        widest.proof_count() > 1,
        "corpus should contain a bundle carrying several proofs, or this asserts nothing; \
         widest carries {}",
        widest.proof_count()
    );

    // So a full Sapling batch of 64 bundles carries at least this many proofs —
    // already more than the 64 the same constant allows Orchard in actions.
    let proofs_in_a_full_batch = widest.proof_count() * MAX_BATCH_SIZE;
    assert!(
        proofs_in_a_full_batch > MAX_BATCH_SIZE,
        "a full Sapling batch ({proofs_in_a_full_batch} proofs) should already exceed what the \
         same limit allows Orchard (64 actions)"
    );

    // RedJubjub: one signature weighs 1, which is the one pool where the
    // constant really does count what it appears to count.
    let signature = items_from_sapling_item(&sapling[0])
        .into_iter()
        .next()
        .expect("bundle yields signatures");
    assert_eq!(RedJubjub::item_weight(&signature), 1);

    // Orchard: weight is the action count, the sole override Zebra ships
    // (`halo2.rs:126`).
    let orchard = common::pre_nu6_2_corpus();
    assert!(!orchard.is_empty(), "Orchard corpus must not be empty");
    for item in &orchard {
        assert_eq!(
            Orchard::item_weight(item),
            item.action_count(),
            "Orchard's weight must be its action count, not 1"
        );
    }
    assert!(
        orchard.iter().any(|item| item.action_count() > 1),
        "corpus should contain a multi-action bundle, or the override is indistinguishable \
         from the default"
    );
}
