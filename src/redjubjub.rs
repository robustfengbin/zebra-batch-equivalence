//! RedJubjub `batch ⟺ single` verification equivalence — the signature half of
//! Sapling, isolated.
//!
//! Sapling's signatures are already exercised by [`crate::sapling`]: a Sapling
//! bundle carries them, and `sapling_crypto::BatchValidator` verifies them inside
//! the same validator as the Groth16 proofs. So why a second verifier?
//!
//! Because that validator answers one question for two subsystems. Its `validate`
//! runs the signature batch **first** and returns `false` immediately if it fails,
//! never reaching the proof batches — so a Sapling `false` cannot be attributed to
//! a side, and a signature-side disagreement cannot be told apart from a
//! proof-side one. The grant names four verifiers; reporting RedJubjub as "covered
//! by Sapling" would leave that attribution unmade, in the report and in the
//! coverage table alike.
//!
//! This module drives the signature sub-batch directly, at signature granularity.
//!
//! ## What is being driven is production's own type, not a stand-in
//!
//! `sapling_crypto::BatchValidator`'s `signatures` field is a
//! `redjubjub::batch::Verifier` (`sapling-crypto-0.7.0/src/verifier/batch.rs:22`),
//! and that is exactly the type below. Zebra's own standalone service uses the
//! same one (`zebra-consensus/src/primitives/redjubjub.rs:29`). The extraction in
//! [`items_from_bundle`] reproduces, statement for statement, the sequence of
//! `signatures.queue(..)` calls `check_bundle` makes for a bundle — including
//! where it stops early.
//!
//! ## Two shapes worth stating, because they differ from every other verifier here
//!
//! **1. There is no enqueue-rejection step, so the per-item question changes
//! form.** `Verifier::queue` returns nothing and cannot fail; every queued
//! signature shares the batch's one verdict. So [`RedJubjub::validate_batch`]
//! returns the same boolean for every item. **A batch containing one invalid
//! signature rejects every signature in it, by design** — `redjubjub::batch`'s own
//! documentation says batch verification "asks whether *all* signatures in some set
//! are valid, rather than asking whether *each* of them is valid". Comparing
//! `batch_per_item[i]` against `single[i]` position by position would therefore
//! report a false reject for every valid signature sharing a batch with a bad one,
//! which is a category error: production never issues a verdict for an individual
//! signature, only for a bundle.
//!
//! The per-item question does not disappear, though — it moves. Here it reads
//! *"once the batch has rejected, does individual verification recover exactly the
//! signatures that were valid?"*, which is the fallback condition below and is
//! asserted in `tests/redjubjub_agreement.rs`. Same property, stated at the level
//! where production actually acts on it.
//!
//! **2. This is the one verifier whose production `verify_single` really is a
//! separate algorithm.** For halo2 and Sapling, Zebra's `verify_single` is the
//! batch verifier fed one item (`halo2.rs:441`, `sapling.rs:175`). Zebra's
//! RedJubjub service instead calls `batch::Item::verify_single()` directly
//! (`redjubjub.rs:51`) — per-signature verification, no randomised linear
//! combination — and wraps the batch service in
//! `Fallback<Batch<Verifier, Item>, verify_single>`, so a failed batch is retried
//! signature by signature.
//!
//! That fallback has a correctness condition nothing upstream asserts: **after a
//! batch fails, the signatures that were valid must still verify individually.**
//! Layer-1a plus layer-2 is exactly that condition — layer-1a says the batch
//! accepts iff every signature accepts alone, layer-2 says the individual verdict
//! is the same under both algorithms.
//!
//! No modifications to Zebra or to `redjubjub`: every path here is a public API.

use bellman::groth16::Proof;
use bls12_381::Bls12;
// `ExtendedPoint::from_bytes` is a `GroupEncoding` method, not an inherent one.
use group::GroupEncoding;
use sapling_crypto::value::CommitmentSum;
// The `redjubjub` crate as Zebra re-exports it, so the types here are the same
// instance Zebra and `sapling-crypto` use rather than a second copy that merely
// looks alike.
use zebra_chain::primitives::redjubjub as rj;

use crate::sapling::{SaplingBundle, SaplingItem};
use crate::verifier::BatchVerifier;
use crate::{seeded_rng, SigHash};

/// Which of a Sapling bundle's two signature kinds an item carries.
///
/// Both end up in the same `redjubjub::batch::Verifier` — RedJubjub batches
/// spend-auth and binding signatures together, accumulating a separate group
/// element for each — but they are produced at different points of
/// `check_bundle` and reject for different reasons, so a failing item is worth
/// naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigRole {
    /// The spend-authorization signature of the spend at this index, verified
    /// under the spend's randomized validating key `rk`.
    SpendAuth {
        /// Position of the spend within its bundle.
        spend_index: usize,
    },
    /// The bundle's binding signature, verified under the binding validating key
    /// derived from the value commitments and the value balance.
    Binding,
}

/// One RedJubjub verification item: a single signature, in the exact form
/// `sapling_crypto::BatchValidator` queues it into its signature sub-batch.
///
/// The item carries no message reference — `redjubjub::batch::Item` hashes the
/// message at construction, which is why the batch API can outlive the sighash
/// it was built from.
#[derive(Clone)]
pub struct RedJubjubItem {
    item: rj::batch::Item,
    /// Which signature of its bundle this is. Annotation only: both roles verify
    /// through the same batch.
    pub role: SigRole,
}

impl RedJubjubItem {
    /// The underlying batch item, cloned.
    ///
    /// Both verification paths consume the item, so every use is a clone; this
    /// exposes the same handle to callers that need to build their own batches
    /// (batch-composition differentials, adversarial groupings).
    pub fn batch_item(&self) -> rj::batch::Item {
        self.item.clone()
    }
}

/// Every RedJubjub signature a Sapling bundle contributes to the shared
/// signature sub-batch, in queue order.
///
/// Mirrors `BatchValidator::check_bundle` statement for statement, **including
/// its early returns**: `check_bundle` walks the spends queueing each
/// signature as it goes and returns `false` the moment a consensus check fails,
/// leaving everything queued so far in the shared batch. A bundle that fails
/// partway therefore contributes a *prefix* of its spend-auth signatures and no
/// binding signature — the signature-side face of the half-enqueued residue
/// documented in [`crate::sapling`]. This function returns exactly that prefix,
/// so the set it yields is the set production would have queued.
///
/// The consensus checks reproduced here are the ones that gate a `queue` call:
/// proof decoding, `rk` small-order rejection, ephemeral-key decoding and
/// small-order rejection. They are reproduced rather than skipped because
/// skipping them would build batches production could never build.
pub fn items_from_bundle(bundle: &SaplingBundle, sighash: &SigHash) -> Vec<RedJubjubItem> {
    let sighash = sighash.0;
    let mut cv_sum = CommitmentSum::zero();
    let mut items = Vec::new();

    for (spend_index, spend) in bundle.shielded_spends().iter().enumerate() {
        // `check_bundle` decodes the proof before it looks at the spend at all.
        if Proof::<Bls12>::read(&spend.zkproof()[..]).is_err() {
            return items;
        }

        // `check_spend` rejects a small-order `rk` before queueing its signature.
        // Upstream unwraps the decoding because a `VerificationKey` cannot hold
        // bytes that fail to decode; we stop instead of panicking, which reaches
        // the same set of queued items by a route that cannot abort the process.
        let rk_bytes: [u8; 32] = (*spend.rk()).into();
        let rk_affine: Option<jubjub::AffinePoint> =
            jubjub::AffinePoint::from_bytes(rk_bytes).into();
        let Some(rk_affine) = rk_affine else {
            return items;
        };
        if bool::from(rk_affine.is_small_order()) {
            return items;
        }

        // Accumulated before the signature is queued, exactly as upstream does —
        // the order matters for a bundle that stops partway, since the binding
        // key is derived from whatever was accumulated.
        cv_sum += spend.cv();

        items.push(RedJubjubItem {
            item: (
                rj::VerificationKeyBytes::<rj::SpendAuth>::from(*spend.rk()),
                *spend.spend_auth_sig(),
                &sighash,
            )
                .into(),
            role: SigRole::SpendAuth { spend_index },
        });
    }

    for output in bundle.shielded_outputs() {
        // Outputs queue no signature, but they can end the bundle early and they
        // move the binding key, so they are walked with the same checks.
        let epk: Option<jubjub::ExtendedPoint> =
            jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key().0).into();
        let Some(epk) = epk else {
            return items;
        };
        if Proof::<Bls12>::read(&output.zkproof()[..]).is_err() {
            return items;
        }
        if bool::from(epk.is_small_order()) {
            return items;
        }
        cv_sum -= output.cv();
    }

    // `final_check`: the binding key comes out of the accumulated commitments and
    // the value balance, and is queued last. `into_bvk` is the same function
    // production derives it with, not a re-derivation.
    let bvk = cv_sum.into_bvk(*bundle.value_balance());
    items.push(RedJubjubItem {
        item: (
            rj::VerificationKeyBytes::<rj::Binding>::from(bvk),
            bundle.authorization().binding_sig,
            &sighash,
        )
            .into(),
        role: SigRole::Binding,
    });

    items
}

/// Every RedJubjub signature of a [`SaplingItem`], bundle and sighash already
/// paired. See [`items_from_bundle`].
pub fn items_from_sapling_item(item: &SaplingItem) -> Vec<RedJubjubItem> {
    items_from_bundle(&item.bundle, &item.sighash)
}

/// Zebra's RedJubjub verifier — the signature sub-batch of Sapling, driven at
/// signature granularity through `redjubjub::batch::Verifier`.
pub struct RedJubjub;

impl BatchVerifier for RedJubjub {
    type Item = RedJubjubItem;
    /// RedJubjub needs no external key material: every item carries its own
    /// validating key.
    type Context = ();
    const NAME: &'static str = "redjubjub (Sapling signatures)";

    /// All signatures in one batch, one verdict per item.
    ///
    /// Every item receives the *same* verdict, because `queue` cannot fail and
    /// batch verification is a single equation over the whole set. See the module
    /// docs: at signature granularity that is the faithful shape, not a loss of
    /// resolution.
    fn validate_batch(items: &[&Self::Item], _ctx: &Self::Context, seed: u64) -> Vec<bool> {
        let mut verifier = rj::batch::Verifier::new();
        for item in items {
            verifier.queue(item.item.clone());
        }
        let shared = verifier.verify(seeded_rng(seed)).is_ok();
        vec![shared; items.len()]
    }

    /// One signature through the batch machinery alone — the aggregation path at
    /// N=1, which is what makes layer-1 a comparison of batch sizes rather than
    /// of algorithms.
    fn validate_one(item: &Self::Item, _ctx: &Self::Context, seed: u64) -> bool {
        let mut verifier = rj::batch::Verifier::new();
        verifier.queue(item.item.clone());
        verifier.verify(seeded_rng(seed)).is_ok()
    }

    /// The independent path: `batch::Item::verify_single`, which verifies this
    /// one signature directly (`verify_prehashed`) with no randomised linear
    /// combination and no RNG.
    ///
    /// Unlike every other verifier in this crate, this path *is* production code
    /// for its pool — Zebra's RedJubjub service calls it as the fallback when a
    /// batch fails (`redjubjub.rs:51`, `:166-169`).
    ///
    /// ## Where the two paths diverge
    ///
    /// Stated for the same reason [`crate::sapling`] states it: layer 2 is only
    /// as strong as the distance between the paths, and here they share a real
    /// prefix. The challenge scalar `c` is computed once, when the
    /// [`RedJubjubItem`] is built (`Item::from_spendauth` / `from_binding`), and
    /// both paths consume that one value — a wrong `c` is invisible to this
    /// check. Both also decode the validating key through the same
    /// `VerificationKey::try_from`, so a non-canonical key fails both alike.
    ///
    /// The verification equations then genuinely differ. Direct verification
    /// evaluates `h · (sB − cA − R) = 0` once per signature against the
    /// type's own basepoint; the batch path randomises each signature by a fresh
    /// 128-bit `z`, keeps separate spend-auth and binding basepoint accumulators,
    /// and settles the whole set in a single multiscalar multiplication. The
    /// signature-component decoding is written out separately on each side
    /// (`batch.rs` and `verification_key.rs`), so the two are independent code
    /// even where they are meant to agree.
    ///
    /// For the adversarial corpus that means the distinguishing inputs are the
    /// signature bytes themselves — `R` and `s` — not the key or the message,
    /// which the shared prefix consumes before the paths part.
    fn validate_one_independent(item: &Self::Item, _ctx: &Self::Context) -> Option<bool> {
        Some(item.item.clone().verify_single().is_ok())
    }
}
