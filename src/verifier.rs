//! The pool-independent core of the equivalence oracle.
//!
//! M1 asserted `batch ⟺ single` for one verifier (Orchard halo2 + RedPallas,
//! via `orchard::BatchValidator`). M2 must assert the same property for every
//! batch verifier Zebra runs — Sapling Groth16 + RedJubjub, Sprout Groth16,
//! and the Ed25519 JoinSplit signatures — without duplicating the oracle four
//! times.
//!
//! Everything M1 wrote is separable into two halves:
//!
//! * **Pool-specific** — what an item is, what key material verifies it, and how
//!   the two paths are actually driven. Three things, and only these three.
//! * **Pool-independent** — running both paths under one seed, classifying the
//!   result pair, and the deeper invariants (order-independence, duplicate
//!   consistency, sub-batch compositionality, empty/singleton boundaries). None
//!   of that mentions Orchard.
//!
//! [`BatchVerifier`] is exactly that seam. Each pool implements the first half;
//! the second half is written once, here, and every pool inherits it.
//!
//! ## Two layers of differential, and why the second one is the load-bearing one
//!
//! [`BatchVerifier::validate_one`] mirrors what Zebra's production `verify_single`
//! does — and in every pool Zebra ships, that turns out to be *the batch verifier
//! fed one item*, not a separate implementation (`halo2.rs:441`,
//! `sapling.rs:182`). So `batch ⟺ single` alone compares an aggregation against
//! itself-at-N=1: necessary, but it cannot see a bug living in code both paths
//! share.
//!
//! [`BatchVerifier::validate_one_independent`] is the answer to that: a *different
//! algorithm* for the same question — per-item direct verification instead of a
//! randomized linear combination — which Zebra never runs in production but which
//! the underlying crates do expose. That is where a shared-math bug becomes
//! visible. A verifier that has no such second implementation returns `None`, and
//! the layer-2 assertions skip it rather than silently degrading into layer-1.
//!
//! **Layer 2's power stops where the two paths stop differing**, and how far that
//! is varies by pool. Orchard's independent path bypasses `add_bundle` entirely;
//! Sapling's shares a whole consensus-check context with the batch path and
//! diverges only in the verification algebra. Each implementation documents its
//! own divergence point, because that is what says which tampered inputs can
//! distinguish the two paths and which merely run shared code twice — a
//! distinction the adversarial corpus depends on and a reviewer reading the
//! upstream source will check.
//!
//! No modifications to Zebra consensus/verification source: every path here is
//! driven through public APIs.

use crate::EquivReport;

/// One of Zebra's production batch verifiers, expressed as the three things
/// that differ between pools.
///
/// Implementors drive **real** verification on both sides. Neither path may be
/// a re-implementation of the proof system: the whole oracle rests on both
/// sides being code that actually ships.
pub trait BatchVerifier {
    /// One verification item — whatever the batch API consumes. For a proof
    /// system this carries the proof and its public inputs; for a signature
    /// scheme, the key, signature, and signed message.
    type Item;

    /// Key material and parameters the two paths need. `()` for schemes that
    /// verify against the item alone (signatures carry their own key).
    ///
    /// This is an associated type rather than a parameter because the *shape*
    /// differs per pool: Orchard takes one `VerifyingKey`, Sapling needs the
    /// spend **and** output keys, Sprout a prepared JoinSplit key.
    ///
    /// `'static` because that is what key material is in every pool — Zebra
    /// holds each verifier's keys in a `Lazy`/`OnceLock` for the process
    /// lifetime, and [`crate::tower`] needs a service that outlives the caller
    /// that spawned it.
    type Context: 'static;

    /// Verifier name as it appears in reports and coverage tables.
    const NAME: &'static str;

    /// **BATCH path** — all items aggregated into one validator and validated
    /// once, returning **one verdict per item, in input order**.
    ///
    /// Per-item rather than a single boolean because that is what production
    /// actually does. Zebra's halo2 service says so in its own comment at the
    /// enqueue-failure branch (`halo2.rs:471`): *"Reject the item on its own
    /// without poisoning the rest of the batch."* An item that fails to enqueue
    /// gets `false`; every item that did enqueue receives the one shared verdict
    /// from the batch's single `validate` call. Sapling is structurally the same
    /// (`sapling.rs:107-114`).
    ///
    /// Collapsing this to one boolean — as a whole-batch fail-closed model does —
    /// is safe in the false-accept direction but erases the question M2 exists to
    /// ask: **can one bad item change the verdict of a different, valid item in
    /// the same batch?** That effect is only visible per item.
    ///
    /// Implementations must return exactly `items.len()` verdicts.
    fn validate_batch(items: &[&Self::Item], ctx: &Self::Context, seed: u64) -> Vec<bool>;

    /// **SINGLE path** — one item verified alone, mirroring the pool's
    /// production `verify_single`. In every pool Zebra ships this is a
    /// batch-of-one, not an independent implementation; see the module docs for
    /// why that makes [`Self::validate_one_independent`] necessary.
    fn validate_one(item: &Self::Item, ctx: &Self::Context, seed: u64) -> bool;

    /// **INDEPENDENT single path** (layer 2) — the same verdict reached by a
    /// genuinely different algorithm: direct per-item verification rather than
    /// a randomized linear combination.
    ///
    /// Returns `None` when the pool's crate exposes no such path, so callers
    /// can skip layer-2 explicitly instead of quietly re-running layer 1.
    ///
    /// Deterministic by construction — direct verification consumes no
    /// randomness, which is precisely what distinguishes it from the batch path.
    fn validate_one_independent(_item: &Self::Item, _ctx: &Self::Context) -> Option<bool> {
        None
    }

    /// What this item counts as against a batch's size limit, mirroring the
    /// pool's `tower_batch_control::RequestWeight` implementation.
    ///
    /// Zebra applies **one** constant to every batch verifier —
    /// `MAX_BATCH_SIZE = 64`, whose comment says it is "for any of the batch
    /// verifiers" — through this weight. But the weight is not the same unit in
    /// each pool. The trait's default is 1, and only halo2 overrides it, to
    /// count a bundle's actions (`halo2.rs:126`). So a full Orchard batch holds
    /// at most 64 actions, while a full Sapling batch holds 64 *bundles*, each
    /// carrying as many spend and output proofs as it likes — the same number
    /// bounding two quantities that differ by an unbounded factor.
    ///
    /// Mirrored here rather than hard-coded at the tower layer so the asymmetry
    /// is a property of each verifier, and so a test can assert it rather than
    /// restate it.
    fn item_weight(_item: &Self::Item) -> usize {
        1
    }
}

/// The four-way classification of a `(batch, single)` result pair. Pool-independent.
///
/// Public because the tower-layer fuzz target reaches the same question from
/// outside this module — it drives the batch through the real middleware rather
/// than through [`BatchVerifier::validate_batch`], so it cannot use the checks
/// below, but the *meaning* of a `(batch, single)` pair must not be restated
/// there. The direction is the whole content of the judgement and it is easy to
/// write backwards: batch-accepts-what-single-rejects is the soundness failure,
/// while batch-rejects-what-single-accepts is what a shared verdict means and is
/// not a finding. A second copy of this match is a second chance to swap them.
pub fn classify(batch_ok: bool, single_all: bool) -> EquivReport {
    match (batch_ok, single_all) {
        (true, true) => EquivReport::Agree(true),
        (false, false) => EquivReport::Agree(false),
        (true, false) => EquivReport::FalseAccept,
        (false, true) => EquivReport::FalseReject,
    }
}

/// **Layer 1** — the core `batch ⟺ single` assertion, for any verifier.
///
/// Both paths run under the same context and the same seed, so a disagreement
/// reproduces. Soundness must hold for *every* RNG; the seed only fixes
/// reproducibility.
///
/// An empty group is vacuously in agreement: a batch of nothing accepts, and an
/// empty conjunction of singles is true.
pub fn check_equivalence_refs<V: BatchVerifier>(
    items: &[&V::Item],
    ctx: &V::Context,
    seed: u64,
) -> EquivReport {
    // `all` short-circuits on the first reject, mirroring the production
    // fallback's early exit.
    let single_all = items.iter().all(|item| V::validate_one(item, ctx, seed));
    // Whole-batch acceptance is the conjunction of the per-item verdicts: the
    // batch accepted everything only if no item was rejected, whether by a
    // failed enqueue or by the shared verdict.
    let batch_ok = V::validate_batch(items, ctx, seed).iter().all(|&ok| ok);
    classify(batch_ok, single_all)
}

/// Owned-slice convenience form of [`check_equivalence_refs`].
pub fn check_equivalence<V: BatchVerifier>(
    items: &[V::Item],
    ctx: &V::Context,
    seed: u64,
) -> EquivReport {
    let refs: Vec<&V::Item> = items.iter().collect();
    check_equivalence_refs::<V>(&refs, ctx, seed)
}

/// Per-item outcome of the layer-1b check: one [`EquivReport`] per input item,
/// in input order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerItemReport {
    /// How batch and single each judged item `i`.
    pub items: Vec<EquivReport>,
}

impl PerItemReport {
    /// Whether every item was judged identically by both paths.
    pub fn is_agreement(&self) -> bool {
        self.items.iter().all(|r| !r.is_disagreement())
    }

    /// The index and kind of every disagreement.
    pub fn disagreements(&self) -> impl Iterator<Item = (usize, EquivReport)> + '_ {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, r)| r.is_disagreement())
            .map(|(i, r)| (i, *r))
    }

    /// Indices of items the batch accepted but single verification rejects —
    /// the soundness-class finding.
    pub fn false_accepts(&self) -> Vec<usize> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, r)| r.is_false_accept())
            .map(|(i, _)| i)
            .collect()
    }
}

/// **Layer 1b** — assert batch and single agree **on every item individually**,
/// not merely on whether the batch as a whole was clean.
///
/// Strictly stronger than [`check_equivalence_refs`]: per-item agreement implies
/// whole-batch agreement, but not the reverse. The gap is exactly the question a
/// whole-batch boolean cannot express — whether one item's presence changed
/// another item's verdict. A batch containing one item that fails to enqueue is
/// already "not clean" at whole-batch granularity, which masks whatever that
/// item's residue did to the rest of the batch.
///
/// The single path is run per item by construction, so its verdicts are
/// independent by definition; any cross-item influence can only come from the
/// batch side.
pub fn check_equivalence_per_item<V: BatchVerifier>(
    items: &[&V::Item],
    ctx: &V::Context,
    seed: u64,
) -> PerItemReport {
    let batch = V::validate_batch(items, ctx, seed);
    debug_assert_eq!(
        batch.len(),
        items.len(),
        "{}: validate_batch must return one verdict per item",
        V::NAME
    );

    let reports = items
        .iter()
        .zip(batch)
        .map(|(item, batch_ok)| classify(batch_ok, V::validate_one(item, ctx, seed)))
        .collect();

    PerItemReport { items: reports }
}

/// Outcome of a layer-2 (strategy-differential) check on one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyReport {
    /// Both strategies reached the same verdict.
    Agree(bool),
    /// The batch-derived path accepted what direct verification rejects — the
    /// same soundness class as [`EquivReport::FalseAccept`], but reached by two
    /// different algorithms rather than two batch sizes. Strictly stronger
    /// evidence: it cannot be explained by shared aggregation code.
    BatchAcceptsDirectRejects,
    /// Direct verification accepted what the batch-derived path rejects —
    /// liveness, not soundness.
    DirectAcceptsBatchRejects,
    /// This verifier exposes no independent implementation; layer 2 does not
    /// apply. Never silently treated as agreement.
    NotApplicable,
}

impl StrategyReport {
    /// Whether the two strategies disagreed (either direction). `NotApplicable`
    /// is not a disagreement.
    pub fn is_disagreement(self) -> bool {
        matches!(
            self,
            StrategyReport::BatchAcceptsDirectRejects | StrategyReport::DirectAcceptsBatchRejects
        )
    }

    /// Whether this is the soundness-class disagreement.
    pub fn is_false_accept(self) -> bool {
        matches!(self, StrategyReport::BatchAcceptsDirectRejects)
    }
}

/// **Layer 2** — assert the pool's production single path and an *independent*
/// implementation reach the same verdict on one item.
///
/// This is the check with power over bugs that live in code both layer-1 paths
/// share. Zebra never runs the independent side in production, which is exactly
/// why nothing else in the ecosystem asserts this.
pub fn check_strategy_equivalence<V: BatchVerifier>(
    item: &V::Item,
    ctx: &V::Context,
    seed: u64,
) -> StrategyReport {
    let Some(direct) = V::validate_one_independent(item, ctx) else {
        return StrategyReport::NotApplicable;
    };
    let via_batch = V::validate_one(item, ctx, seed);

    match (via_batch, direct) {
        (true, true) => StrategyReport::Agree(true),
        (false, false) => StrategyReport::Agree(false),
        (true, false) => StrategyReport::BatchAcceptsDirectRejects,
        (false, true) => StrategyReport::DirectAcceptsBatchRejects,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verifier whose verdicts are dictated by the test, so the pool-independent
    /// logic can be exercised without paying for real proof verification.
    ///
    /// Deliberately shaped like the production services rather than as a free
    /// choice of per-item results: each item either enqueues or does not, and
    /// every item that enqueued receives one shared verdict. That is the structure
    /// (`halo2.rs:467-510`, `sapling.rs:107-114`) whose consequences these tests
    /// are meant to pin.
    struct Mock;

    struct MockItem {
        /// Whether this item makes it into the batch at all.
        queues_ok: bool,
        /// Verdict of the single path on this item.
        single: bool,
        /// Verdict of an independent implementation, if the pool has one.
        independent: Option<bool>,
    }

    impl BatchVerifier for Mock {
        type Item = MockItem;
        /// The one shared verdict the batch's `validate` call produces.
        type Context = bool;
        const NAME: &'static str = "mock";

        fn validate_batch(items: &[&Self::Item], ctx: &Self::Context, _seed: u64) -> Vec<bool> {
            items.iter().map(|item| item.queues_ok && *ctx).collect()
        }

        fn validate_one(item: &Self::Item, _ctx: &Self::Context, _seed: u64) -> bool {
            item.single
        }

        fn validate_one_independent(item: &Self::Item, _ctx: &Self::Context) -> Option<bool> {
            item.independent
        }
    }

    fn item(single: bool, independent: Option<bool>) -> MockItem {
        MockItem {
            queues_ok: true,
            single,
            independent,
        }
    }

    /// An item that cannot be enqueued — rejected on its own, per `halo2.rs:471`.
    fn unqueueable(single: bool) -> MockItem {
        MockItem {
            queues_ok: false,
            single,
            independent: None,
        }
    }

    #[test]
    fn classify_covers_all_four_quadrants() {
        assert_eq!(classify(true, true), EquivReport::Agree(true));
        assert_eq!(classify(false, false), EquivReport::Agree(false));
        assert_eq!(classify(true, false), EquivReport::FalseAccept);
        assert_eq!(classify(false, true), EquivReport::FalseReject);
    }

    #[test]
    fn layer1_flags_false_accept_through_the_trait() {
        // Batch accepts; one single rejects => the soundness finding.
        let items = vec![item(true, None), item(false, None)];
        assert_eq!(
            check_equivalence::<Mock>(&items, &true, 0),
            EquivReport::FalseAccept
        );
    }

    #[test]
    fn layer1_flags_false_reject_through_the_trait() {
        let items = vec![item(true, None), item(true, None)];
        assert_eq!(
            check_equivalence::<Mock>(&items, &false, 0),
            EquivReport::FalseReject
        );
    }

    #[test]
    fn empty_group_is_vacuously_in_agreement() {
        let items: Vec<MockItem> = Vec::new();
        assert_eq!(
            check_equivalence::<Mock>(&items, &true, 0),
            EquivReport::Agree(true)
        );
    }

    #[test]
    fn per_item_agreement_implies_whole_batch_agreement() {
        // Every item enqueues and the shared verdict matches every single verdict.
        let items = vec![item(true, None), item(true, None)];
        let refs: Vec<&MockItem> = items.iter().collect();

        let per_item = check_equivalence_per_item::<Mock>(&refs, &true, 0);
        assert!(per_item.is_agreement());
        assert_eq!(per_item.disagreements().count(), 0);
        assert_eq!(
            check_equivalence_refs::<Mock>(&refs, &true, 0),
            EquivReport::Agree(true)
        );
    }

    #[test]
    fn per_item_localises_which_item_disagreed() {
        // Shared verdict accepts; item 1's single path rejects. Whole-batch
        // granularity says only "FalseAccept happened"; per-item names the item.
        let items = vec![item(true, None), item(false, None), item(true, None)];
        let refs: Vec<&MockItem> = items.iter().collect();

        let per_item = check_equivalence_per_item::<Mock>(&refs, &true, 0);
        assert_eq!(per_item.false_accepts(), vec![1]);
        assert_eq!(
            per_item.items,
            vec![
                EquivReport::Agree(true),
                EquivReport::FalseAccept,
                EquivReport::Agree(true)
            ]
        );
    }

    /// The gap between the two granularities, and the reason M2 needs the finer
    /// one: an item that fails to enqueue makes the whole batch "not clean", so
    /// whole-batch granularity reports a plain `Agree(false)` and cannot show that
    /// a *different*, valid item was dragged down with it.
    #[test]
    fn whole_batch_granularity_masks_a_dragged_down_item() {
        // Item 0 is valid and verifies alone. Item 1 cannot enqueue, and its
        // presence flips the shared verdict to reject.
        let items = vec![item(true, None), unqueueable(false)];
        let refs: Vec<&MockItem> = items.iter().collect();

        // Whole-batch: batch rejected, singles disagree among themselves, so the
        // conjunction matches — nothing looks wrong.
        assert_eq!(
            check_equivalence_refs::<Mock>(&refs, &false, 0),
            EquivReport::Agree(false)
        );

        // Per-item: item 0 verifies alone but is rejected inside the batch. The
        // finding whole-batch granularity could not express.
        let per_item = check_equivalence_per_item::<Mock>(&refs, &false, 0);
        assert!(!per_item.is_agreement());
        assert_eq!(
            per_item.items,
            vec![EquivReport::FalseReject, EquivReport::Agree(false)]
        );
        assert_eq!(per_item.disagreements().collect::<Vec<_>>(), vec![(0, EquivReport::FalseReject)]);
    }

    #[test]
    fn unqueueable_item_is_rejected_alone_not_by_poisoning_the_batch() {
        // `halo2.rs:471` — "Reject the item on its own without poisoning the rest
        // of the batch." The item that failed to enqueue is false; its neighbour,
        // which enqueued fine, still receives the shared verdict.
        let items = vec![unqueueable(false), item(true, None)];
        let refs: Vec<&MockItem> = items.iter().collect();

        assert_eq!(Mock::validate_batch(&refs, &true, 0), vec![false, true]);
    }

    #[test]
    fn layer2_reports_not_applicable_rather_than_agreement() {
        // A verifier with no independent implementation must be visibly skipped,
        // never counted as a passing layer-2 check.
        let report = check_strategy_equivalence::<Mock>(&item(true, None), &true, 0);
        assert_eq!(report, StrategyReport::NotApplicable);
        assert!(!report.is_disagreement());
    }

    #[test]
    fn layer2_flags_the_soundness_direction() {
        // Production single path accepts, independent algorithm rejects.
        let report = check_strategy_equivalence::<Mock>(&item(true, Some(false)), &true, 0);
        assert_eq!(report, StrategyReport::BatchAcceptsDirectRejects);
        assert!(report.is_disagreement());
        assert!(report.is_false_accept());
    }

    #[test]
    fn layer2_flags_the_liveness_direction() {
        let report = check_strategy_equivalence::<Mock>(&item(false, Some(true)), &true, 0);
        assert_eq!(report, StrategyReport::DirectAcceptsBatchRejects);
        assert!(report.is_disagreement());
        assert!(!report.is_false_accept());
    }

    #[test]
    fn layer2_agreement_carries_the_verdict() {
        assert_eq!(
            check_strategy_equivalence::<Mock>(&item(true, Some(true)), &true, 0),
            StrategyReport::Agree(true)
        );
        assert_eq!(
            check_strategy_equivalence::<Mock>(&item(false, Some(false)), &true, 0),
            StrategyReport::Agree(false)
        );
    }
}
