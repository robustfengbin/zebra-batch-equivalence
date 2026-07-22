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

use std::io::Cursor;
use std::panic;
use std::sync::Arc;

use orchard::bundle::{Authorized, BatchValidator, Bundle};
use orchard::circuit::OrchardCircuitVersion;
use rand::rngs::StdRng;
use rand::SeedableRng;

use zebra_chain::parameters::NetworkUpgrade;
use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::{HashType, Transaction};
use zebra_chain::transparent;

pub mod era;
pub mod invariants;

// Re-exports so downstream crates depend only on this crate and cannot
// accidentally pull a *different* `orchard` version whose `Bundle` would be an
// incompatible type.
pub use era::CircuitEra;
pub use orchard::circuit::VerifyingKey;
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
    // SINGLE path: each bundle validated alone (batch-of-one), matching
    // `Item::verify_single`. `all` short-circuits on the first reject.
    let single_all = items.iter().all(|item| validate_one(item, vk, seed));

    // BATCH path: one validator fed all N bundles, validated once.
    let batch_ok = validate_batch(items, vk, seed);

    classify(batch_ok, single_all)
}

/// Core differential check over a slice of owned items. See
/// [`check_equivalence_refs`]; this is the convenience entry point for the
/// baseline corpus.
pub fn check_equivalence(items: &[OrchardItem], vk: &VerifyingKey, seed: u64) -> EquivReport {
    let refs: Vec<&OrchardItem> = items.iter().collect();
    check_equivalence_refs(&refs, vk, seed)
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

/// Validate all items as one aggregate batch. A single un-queueable bundle fails
/// the whole batch closed (matching how a rejected queue poisons that item).
pub(crate) fn validate_batch(items: &[&OrchardItem], vk: &VerifyingKey, seed: u64) -> bool {
    let mut bv = BatchValidator::new(vk);
    for item in items {
        if bv.add_bundle(&item.bundle, item.sighash.0).is_err() {
            return false;
        }
    }
    bv.validate(seeded_rng(seed))
}

/// The four-way classification of a (batch, single) result pair.
fn classify(batch_ok: bool, single_all: bool) -> EquivReport {
    match (batch_ok, single_all) {
        (true, true) => EquivReport::Agree(true),
        (false, false) => EquivReport::Agree(false),
        (true, false) => EquivReport::FalseAccept,
        (false, true) => EquivReport::FalseReject,
    }
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
    let mut cursor = Cursor::new(data);
    let mut items = Vec::new();

    while (cursor.position() as usize) < data.len() && items.len() < MAX_BATCH_ITEMS {
        let tx = match Transaction::zcash_deserialize(&mut cursor) {
            Ok(tx) => tx,
            Err(_) => break,
        };
        let extracted = panic::catch_unwind(panic::AssertUnwindSafe(|| items_from_tx(&tx)));
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
    fn classify_covers_all_four_quadrants() {
        assert_eq!(classify(true, true), EquivReport::Agree(true));
        assert_eq!(classify(false, false), EquivReport::Agree(false));
        assert_eq!(classify(true, false), EquivReport::FalseAccept);
        assert_eq!(classify(false, true), EquivReport::FalseReject);
    }

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
