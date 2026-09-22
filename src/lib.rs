//! # Orchard `batch ⟺ single` verification-equivalence oracle
//!
//! ZCG #332 Milestone 1. Drives Zebra's Orchard proof verification down two
//! paths and asserts they agree on every input:
//!
//! * **BATCH** — one [`orchard::bundle::BatchValidator`] fed `N` bundles and
//!   validated once (the aggregate, randomised-linear-combination path Zebra's
//!   `zebra-consensus::primitives::halo2` runs in production). Internally the
//!   validator batches RedPallas spend-auth + binding signatures *and* the halo2
//!   proofs, verifying signatures first and the proof batch second.
//! * **SINGLE** — each bundle validated on its own (a *batch of one*). This is
//!   exactly the semantics of `halo2::Item::verify_single`, whose body is
//!   `BatchValidator::new(vk).queue(item).validate(rng)`.
//!
//! A disagreement is a finding:
//!
//! * batch **Ok**, some single **reject** → [`EquivReport::FalseAccept`] —
//!   the batch accepted a set single-verification rejects. This is the
//!   counterfeiting-class soundness failure M1 exists to guard.
//! * batch **reject**, all singles **Ok** → [`EquivReport::FalseReject`] —
//!   a liveness / DoS problem, not a soundness one.
//!
//! The existing coverage-guided harness only asserts *panic-freedom* ("we do
//! not assert verify=Ok"); this oracle adds the missing soundness assertion.
//!
//! ## Depth beyond the base check
//!
//! The base [`check_equivalence`] is the core assertion, but batch verification
//! has more structure to guard, all reachable through public APIs:
//!
//! * [`mod@era`] — the three Orchard circuit eras (pre-NU6.2 / NU6.2 /
//!   NU6.3-onward), their verifying keys, and the block-era routing that decides
//!   which key a bundle is checked under. Using the wrong era key must fail
//!   *closed*, never open.
//! * [`mod@invariants`] — deeper properties a sound batch verifier must have:
//!   order-independence, duplicate-consistency, empty/singleton boundaries,
//!   sub-batch compositionality, and era-routing (right key accepts, wrong key
//!   rejects both paths). Each is expressed as a differential the fuzz target
//!   drives over the real corpus.
//! * [`Pool`] — from NU6.3 (Ironwood) the pool is a dimension too: a v6
//!   transaction may carry an Orchard-pool *and* an Ironwood-pool bundle
//!   (same bundle type, same PostNu6_3 circuit, same batch stack), so
//!   extraction yields one item per bundle and batches may mix pools. The
//!   pool-dimension differentials live in `tests/v6_pool_dimensions.rs`.
//!
//! ## Why `orchard` directly and not Zebra's Tower service
//!
//! Zebra's `halo2::Item` lives in a private `primitives` module and its `queue`
//! is private, and every production `validate` hard-codes `thread_rng()` with no
//! seam to inject a seed. To build a *deterministic, real N-element batch* we
//! drop to the `orchard` crate's public `BatchValidator` — which is also the
//! batch API the grant names. Determinism matters: a disagreement must
//! reproduce, or it cannot be cited. The Tower `Batch<Verifier, Item>` glue
//! layer is covered separately by mirroring it over the public
//! `tower-batch-control` crate (planned).
//!
//! No modifications to Zebra consensus/verification source: everything here
//! drives existing verifiers through public APIs.
//!
//! ## How upstream is cited throughout this crate
//!
//! Doc comments here cite Zebra by short path and line number
//! (`sapling.rs:107-114`, `worker.rs:204`). **Every such reference is relative to
//! the pinned base revision `f5c5277` (Zebra v6.3.0)** — the revision
//! `Cargo.toml` builds against — and not to upstream `main`, which moves daily.
//!
//! This is stated once here rather than repeated at each site because the
//! failure mode is silent: a line number that has drifted still points at a real
//! line of a real file, and a reader following it to `main` gets plausible
//! wrong code with no indication anything is off. Upstream `#10461` (merged
//! 2026-08-22, not in any release as of 2026-08-28) rewrote
//! `zebra-consensus/src/primitives/groth16.rs` in exactly this way; the citations
//! in [`mod@sprout`] carry the revision inline for that reason.
//!
//! Citations that already name a vendored crate version
//! (`sapling-crypto-0.7.0/src/verifier/batch.rs:22`) are pinned by that version
//! and are unaffected.

use std::io::Cursor;
use std::panic;
use std::sync::Arc;

use orchard::bundle::{Authorized, BatchValidator, Bundle};
use orchard::circuit::OrchardCircuitVersion;
use orchard::primitives::redpallas::{batch as redpallas_batch, Binding, SpendAuth};
use rand::rngs::StdRng;
use rand::SeedableRng;

use zebra_chain::parameters::NetworkUpgrade;
use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::{HashType, Transaction};
use zebra_chain::transparent;

pub mod adversarial;
pub mod era;
pub mod fuzz_input;
pub mod invariants;
pub mod redjubjub;
pub mod sapling;
pub mod sprout;
pub mod tower;
pub mod turnstile;
pub mod verifier;

// Re-exports so downstream crates depend only on this crate and cannot
// accidentally pull a *different* `orchard` version whose `Bundle` would be an
// incompatible type.
pub use era::CircuitEra;
pub use orchard::circuit::VerifyingKey;
pub use verifier::{
    check_strategy_equivalence, BatchVerifier, PerItemReport, StrategyReport,
};
pub use zcash_protocol::value::ZatBalance;
pub use zebra_chain::transaction::SigHash;

/// The concrete Orchard bundle type Zebra hands us (authorized, `ZatBalance`).
pub type OrchardBundle = Bundle<Authorized, ZatBalance>;

/// Which shielded pool a bundle spends from. NU6.3 (Ironwood) introduces a
/// second pool whose bundles share the Orchard bundle *type*, the PostNu6_3
/// circuit, and Zebra's batch stack (`VERIFIER_NU6_3_ONWARD`) — one v6
/// transaction may carry one bundle of **each** pool. The pool does not change
/// how an item is verified (same key, same paths); it is carried so corpora,
/// reports, and pool-dimension differentials can tell the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pool {
    /// The original Orchard pool (v5 wire onward; cross-address-restricted
    /// under NU6.3 rules).
    Orchard,
    /// The Ironwood pool (v6 wire, NU6.3 onward; cross-address permitted).
    Ironwood,
}

/// One Orchard verification item: a bundle plus the ZIP-244 sighash it is bound
/// to. The exact pair carried inside `halo2::Item`.
pub struct OrchardItem {
    /// The authorized Orchard bundle (proof + binding signature).
    pub bundle: OrchardBundle,
    /// The ZIP-244 sighash the bundle's binding signature is over.
    pub sighash: SigHash,
    /// The shielded pool the bundle spends from (annotation only — both pools
    /// verify identically under the same era key).
    pub pool: Pool,
}

impl OrchardItem {
    /// Whether this bundle disables cross-address transfers. A cross-address
    /// *disabled* bundle can only be verified under a key whose circuit
    /// constrains the restriction (NU6.3-onward); earlier eras reject it at
    /// `add_bundle`. See [`era::CircuitEra::supports_cross_address_restriction`].
    pub fn cross_address_enabled(&self) -> bool {
        self.bundle.flags().cross_address_enabled()
    }

    /// Number of Orchard actions in the bundle (its per-item verification cost).
    pub fn action_count(&self) -> usize {
        self.bundle.actions().len()
    }
}

/// Cap on how many items are folded into one batch. Each halo2 proof takes
/// hundreds of ms, so unbounded batches would starve the fuzzer; a batch of a
/// few dozen already exercises the aggregation path.
pub const MAX_BATCH_ITEMS: usize = 32;

/// Outcome of one equivalence check over a group of same-era items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquivReport {
    /// batch and single agreed on this boolean (the expected outcome).
    Agree(bool),
    /// Batch accepted but at least one single rejected — counterfeiting-class
    /// soundness failure. The critical finding this milestone guards.
    FalseAccept,
    /// Batch rejected but every single accepted — liveness / DoS.
    FalseReject,
}

impl EquivReport {
    /// Whether this outcome is a batch/single disagreement (either direction).
    pub fn is_disagreement(self) -> bool {
        !matches!(self, EquivReport::Agree(_))
    }

    /// Whether this is the critical (soundness) disagreement.
    pub fn is_false_accept(self) -> bool {
        matches!(self, EquivReport::FalseAccept)
    }
}

/// Build the Orchard verifying key for a circuit version. Mirrors
/// `zebra-consensus::primitives::halo2`'s per-era keys. `build` is a
/// multi-second cold start — prefer the cached [`era::CircuitEra::key`].
pub fn verifying_key(version: OrchardCircuitVersion) -> VerifyingKey {
    VerifyingKey::build(version)
}

/// The **pre-NU6.2** (historical, pre-fix) Orchard circuit key — M1's baseline
/// era, and the key Zebra retains to re-verify pre-soft-fork Orchard history.
/// Cached; cheap to call repeatedly.
pub fn pre_nu6_2_key() -> &'static VerifyingKey {
    CircuitEra::PreNu6_2.key()
}

/// Core differential check over borrowed items (the flexible entry point the
/// invariants build on: it can be handed any permutation / sub-selection /
/// duplication of items without cloning bundles).
///
/// Runs `items` through the single path and the batch path under the **same**
/// verifying key and **same** seeded RNG, then classifies. All `items` must
/// belong to the same circuit era as `vk`; a batch may never mix eras.
///
/// An empty group is vacuously in agreement (`Agree(true)`): orchard's
/// `BatchValidator::validate` returns `true` for an empty batch, and an empty
/// conjunction of singles is true.
pub fn check_equivalence_refs(items: &[&OrchardItem], vk: &VerifyingKey, seed: u64) -> EquivReport {
    verifier::check_equivalence_refs::<Orchard>(items, vk, seed)
}

/// Core differential check over a slice of owned items. See
/// [`check_equivalence_refs`]; this is the convenience entry point for the
/// baseline corpus.
pub fn check_equivalence(items: &[OrchardItem], vk: &VerifyingKey, seed: u64) -> EquivReport {
    verifier::check_equivalence::<Orchard>(items, vk, seed)
}

/// Per-item differential check (layer 1b) over Orchard items: asserts batch and
/// single agree on **each item individually**, not merely on whether the batch as
/// a whole was clean.
///
/// Strictly stronger than [`check_equivalence_refs`]. See
/// [`verifier::check_equivalence_per_item`] for why the finer granularity is the
/// one that can see cross-item influence.
pub fn check_equivalence_per_item(
    items: &[&OrchardItem],
    vk: &VerifyingKey,
    seed: u64,
) -> PerItemReport {
    verifier::check_equivalence_per_item::<Orchard>(items, vk, seed)
}

/// Zebra's Orchard verifier — halo2 proofs and RedPallas signatures, driven
/// through `orchard::BatchValidator`: the batch API the grant names and the one
/// `zebra-consensus::primitives::halo2` runs in production.
///
/// The first implementation of [`verifier::BatchVerifier`], and the reference
/// the other pools are modelled on.
pub struct Orchard;

impl BatchVerifier for Orchard {
    type Item = OrchardItem;
    type Context = VerifyingKey;
    const NAME: &'static str = "orchard (halo2 + RedPallas)";

    fn validate_batch(items: &[&Self::Item], vk: &Self::Context, seed: u64) -> Vec<bool> {
        validate_batch_per_item(items, vk, seed)
    }

    fn validate_one(item: &Self::Item, vk: &Self::Context, seed: u64) -> bool {
        validate_one(item, vk, seed)
    }

    /// halo2's `SingleVerifier` — per-proof MSM evaluation, reached through
    /// `Bundle::verify_proof` — together with reddsa's per-item `verify_single`.
    /// Each backend ships this second strategy; Zebra calls neither.
    ///
    /// Both must accept, because that is what `BatchValidator` asserts over the
    /// same bundle: it queues the RedPallas signatures *and* the halo2 proof, and
    /// accepts only if both batches verify. Comparing a proof-only independent
    /// check against a proof-and-signature batch would not be the same question.
    fn validate_one_independent(item: &Self::Item, vk: &Self::Context) -> Option<bool> {
        let proof_ok = item.bundle.verify_proof(vk).is_ok();
        let sigs_ok = redpallas_items(item)
            .into_iter()
            .all(|sig_item| sig_item.verify_single().is_ok());
        Some(proof_ok && sigs_ok)
    }

    /// A bundle weighs its action count, mirroring `halo2.rs:126` — the **only**
    /// `RequestWeight` override Zebra ships.
    ///
    /// Which is what makes `MAX_BATCH_SIZE = 64` mean something different here
    /// than anywhere else: a full Orchard batch is bounded at 64 actions, while
    /// a full batch of any other pool is 64 *items*, each carrying an unbounded
    /// number of proofs or signatures.
    fn item_weight(item: &Self::Item) -> usize {
        item.action_count()
    }
}

/// Every RedPallas item of one bundle — each action's spend-auth signature plus
/// the bundle's binding signature — exactly the set `BatchValidator::add_bundle`
/// queues for it.
///
/// Lives here rather than in a test file because reaching the independent
/// signature path needs it, and that is oracle machinery rather than a test
/// fixture.
///
/// **RedPallas only.** Each pool needs its own decomposition and they do not
/// share a type: this returns `reddsa::batch::Item<orchard::SpendAuth,
/// orchard::Binding>`, while Sapling's signatures are RedJubjub — the same
/// `reddsa` batch machinery instantiated at different curve parameters. The
/// shape of the step generalises; the function does not.
pub fn redpallas_items(item: &OrchardItem) -> Vec<redpallas_batch::Item<SpendAuth, Binding>> {
    let sighash = item.sighash.0;
    let mut items: Vec<redpallas_batch::Item<SpendAuth, Binding>> = item
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

/// Validate a single item as a batch-of-one. Equivalent to
/// `halo2::Item::verify_single`, but with a seeded RNG for reproducibility. A
/// bundle that cannot even be queued (era/restriction mismatch) counts as
/// rejected — the same fail-closed contract `verify_single` upholds.
pub(crate) fn validate_one(item: &OrchardItem, vk: &VerifyingKey, seed: u64) -> bool {
    let mut bv = BatchValidator::new(vk);
    if bv.add_bundle(&item.bundle, item.sighash.0).is_err() {
        return false;
    }
    bv.validate(seeded_rng(seed))
}

/// Validate all items as one aggregate batch, returning **one verdict per item**
/// in input order — the shape Zebra's halo2 service actually produces.
///
/// Mirrors `zebra-consensus::primitives::halo2`'s `Service::call`
/// (`halo2.rs:467-510`): a bundle that fails to enqueue is rejected *on its own*
/// (upstream's own words: *"Reject the item on its own without poisoning the rest
/// of the batch"*), while every bundle that did enqueue receives the one shared
/// verdict from the batch's single `validate` call.
///
/// Note this does **not** short-circuit on a failed enqueue. Production keeps
/// accepting subsequent items after one is rejected, so stopping early would
/// batch a different set of bundles than production would.
pub(crate) fn validate_batch_per_item(
    items: &[&OrchardItem],
    vk: &VerifyingKey,
    seed: u64,
) -> Vec<bool> {
    let mut bv = BatchValidator::new(vk);
    let queued: Vec<bool> = items
        .iter()
        .map(|item| bv.add_bundle(&item.bundle, item.sighash.0).is_ok())
        .collect();
    let shared = bv.validate(seeded_rng(seed));
    queued.into_iter().map(|ok| ok && shared).collect()
}

/// Whether the batch accepted **every** item — the whole-batch view, and the
/// conjunction of [`validate_batch_per_item`].
///
/// Retained for the invariants that compare whole-batch outcomes across
/// permutations and sub-batches, where the question genuinely is about the batch
/// rather than about an individual item.
pub(crate) fn validate_batch(items: &[&OrchardItem], vk: &VerifyingKey, seed: u64) -> bool {
    validate_batch_per_item(items, vk, seed).into_iter().all(|ok| ok)
}

/// A deterministic, seedable RNG (ChaCha-based `StdRng`, which is `CryptoRng` as
/// orchard's `validate` requires) so any disagreement reproduces. Batch and
/// single are handed the same seed so the comparison is fair. Soundness must
/// hold for *any* RNG; the seed only fixes reproducibility.
pub(crate) fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Extract **all** Orchard-protocol `(bundle, sighash)` items from a parsed
/// transaction, using the transaction's own network upgrade for the sighash.
/// Returns an empty vec for non-V5+, pre-NU5, or bundle-less transactions.
///
/// A v5 transaction yields at most one item (Orchard pool). A v6 transaction
/// may yield **two** — one Orchard-pool and one Ironwood-pool bundle — sharing
/// the same ZIP-244 sighash (both binding signatures commit to it).
pub fn items_from_tx(tx: &Transaction) -> Vec<OrchardItem> {
    let Some(nu) = tx.network_upgrade() else {
        return Vec::new();
    };
    if nu < NetworkUpgrade::Nu5 {
        return Vec::new();
    }
    items_from_tx_with_nu(tx, nu)
}

/// Extract all Orchard-protocol items using an explicit network upgrade for the
/// sighash (e.g. a fixed `Nu5` for a known pre-NU6.2 corpus). See
/// [`items_from_tx`] for the 0/1/2-item contract.
pub fn items_from_tx_with_nu(tx: &Transaction, nu: NetworkUpgrade) -> Vec<OrchardItem> {
    if tx.orchard_shielded_data().is_none() && tx.ironwood_shielded_data().is_none() {
        return Vec::new();
    }
    // The Orchard sighash does not fold in transparent prevouts for
    // shielded-only flavors; an empty prevout set drives the verify path. For a
    // mixed transparent+Orchard tx the sighash may differ (verify=false) but the
    // verifier internals still execute — which is what we exercise.
    let empty_prevouts: Arc<Vec<transparent::Output>> = Arc::new(Vec::new());
    let Ok(sighasher) = tx.sighasher(nu, empty_prevouts) else {
        return Vec::new();
    };
    let sighash = sighasher.sighash(HashType::ALL, None);

    let mut items = Vec::with_capacity(2);
    if let Some(bundle) = sighasher.orchard_bundle() {
        items.push(OrchardItem {
            bundle,
            sighash: SigHash(sighash.0),
            pool: Pool::Orchard,
        });
    }
    if let Some(bundle) = sighasher.ironwood_bundle() {
        items.push(OrchardItem {
            bundle,
            sighash: SigHash(sighash.0),
            pool: Pool::Ironwood,
        });
    }
    items
}

/// Extract the first Orchard-protocol item from a transaction (Orchard pool
/// first). Single-bundle convenience entry point — exact v5 semantics are
/// unchanged; for the v6 two-bundle case use [`items_from_tx`].
pub fn item_from_tx(tx: &Transaction) -> Option<OrchardItem> {
    items_from_tx(tx).into_iter().next()
}

/// Single-bundle counterpart of [`items_from_tx_with_nu`]. See [`item_from_tx`].
pub fn item_from_tx_with_nu(tx: &Transaction, nu: NetworkUpgrade) -> Option<OrchardItem> {
    items_from_tx_with_nu(tx, nu).into_iter().next()
}

/// Parse a stream of concatenated transaction wire bytes (a fuzz input model)
/// into Orchard items, capped at [`MAX_BATCH_ITEMS`]. Each transaction is
/// extracted under `catch_unwind`, because sighasher construction can panic on
/// malformed-but-deserialized inputs; a panic there just drops that item.
///
/// Items are counted per **bundle**, not per transaction: one v6 transaction
/// can contribute an Orchard-pool and an Ironwood-pool item. The cap's meaning
/// is unchanged (it bounds batch size); a two-bundle transaction straddling the
/// cap is truncated to its first bundle.
pub fn items_from_tx_stream(data: &[u8]) -> Vec<OrchardItem> {
    items_from_tx_stream_with(data, items_from_tx)
}

/// The transaction-stream input model itself, with the per-pool extraction left
/// to the caller.
///
/// Every pool's fuzz target consumes the same shape — concatenated transaction
/// wire bytes — and differs only in what it pulls out of each transaction. That
/// makes the *parsing* rules shared, and they are the part with teeth: stop at
/// the first undeserializable transaction rather than trying to resynchronise
/// (a fuzzer would otherwise spend its budget on offsets, not on verifiers);
/// extract under `catch_unwind`, because sighasher construction can panic on
/// input that deserialized but is not a coherent transaction, and one such
/// transaction should cost its own item rather than the whole batch; and stop
/// at [`MAX_BATCH_ITEMS`] so batch size stays bounded whatever the input says.
///
/// Written once here rather than per target: four copies of these rules is how
/// three of them keep a subtlety the fourth quietly loses.
pub fn items_from_tx_stream_with<T>(
    data: &[u8],
    extract: impl Fn(&Transaction) -> Vec<T>,
) -> Vec<T> {
    let mut cursor = Cursor::new(data);
    let mut items = Vec::new();

    while (cursor.position() as usize) < data.len() && items.len() < MAX_BATCH_ITEMS {
        let tx = match Transaction::zcash_deserialize(&mut cursor) {
            Ok(tx) => tx,
            Err(_) => break,
        };
        let extracted = panic::catch_unwind(panic::AssertUnwindSafe(|| extract(&tx)));
        if let Ok(tx_items) = extracted {
            for item in tx_items {
                if items.len() == MAX_BATCH_ITEMS {
                    break;
                }
                items.push(item);
            }
        }
    }

    items
}

/// Filename of the per-corpus seed-reach manifest.
///
/// Named in one place because three things must agree on it: the generator
/// (`examples/seed_reach_manifest.rs`), the seeding script
/// (`scripts/prep-fuzz-corpus.sh`), and the test that re-measures it
/// (`tests/fuzz_input_reach.rs`). A string literal in three files is how two of
/// them keep pointing at a file the third stopped writing.
pub const MANIFEST_NAME: &str = "REACHES.txt";

/// The comment block every manifest opens with.
pub const MANIFEST_HEADER: &str = "\
# Which files in this corpus reach which extractor, and with how many items.
#
# Generated: cargo run --release --example seed_reach_manifest
# Consumed:  scripts/prep-fuzz-corpus.sh, to pick seeds by whether they reach a
#            verifier rather than by filename order.
# Checked:   tests/fuzz_input_reach.rs re-measures this and fails if it is stale.
#
# Files reaching no extractor are omitted, so `files scanned` and `files listed`
# differ; both are stated because their difference is the thing worth seeing.
";

/// Derive a deterministic RNG seed from the fuzz input, so mutating the input
/// also explores the RNG space while keeping each input reproducible. FNV-1a.
pub fn derive_seed(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_disagreements_report_disagreement() {
        assert!(!EquivReport::Agree(true).is_disagreement());
        assert!(!EquivReport::Agree(false).is_disagreement());
        assert!(EquivReport::FalseAccept.is_disagreement());
        assert!(EquivReport::FalseAccept.is_false_accept());
        assert!(EquivReport::FalseReject.is_disagreement());
        assert!(!EquivReport::FalseReject.is_false_accept());
    }

    #[test]
    fn seed_is_deterministic() {
        assert_eq!(derive_seed(b"hello"), derive_seed(b"hello"));
        assert_ne!(derive_seed(b"hello"), derive_seed(b"world"));
    }
}
