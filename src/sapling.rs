//! Sapling `batch ⟺ single` verification equivalence.
//!
//! Zebra verifies Sapling through one `sapling_crypto::BatchValidator`
//! (`zebra-consensus::primitives::sapling`, v6.3.0 — byte-identical to v6.2.3),
//! which internally keeps
//! three sub-batches: the spend Groth16 proofs, the output Groth16 proofs, and
//! the RedJubjub signatures. That is why Zebra's standalone `redjubjub` verifier
//! service has no production caller — Sapling's signatures are verified here,
//! inside the proof verifier, not beside it.
//!
//! ## The one place this must not copy Orchard
//!
//! Orchard's `add_bundle` returns a `Result` and leaves nothing behind when it
//! rejects, so M1 could treat a failed enqueue as failing the whole batch. Sapling's
//! [`BatchValidator::check_bundle`] returns a plain `bool`, and its own documentation
//! says what happens on the way to `false`:
//!
//! > *"some or all of the proofs and signatures from this bundle **may have already
//! > been added to the batch** even if it fails other consensus rules."*
//!
//! Following the implementation (`sapling-crypto-0.7.0/src/verifier/batch.rs`): it
//! walks the spends, queueing each one that passes its consensus checks, and returns
//! `false` the moment one does not — leaving everything queued so far in the shared
//! batch. Signatures are queued only at the very end, so a bundle that fails partway
//! contributes *some* of its proofs and *none* of its signatures.
//!
//! Zebra does not contain that residue; it broadcasts it. The failing item errors
//! immediately, the batch keeps going, and `BatchControl::Flush` validates the
//! polluted batch and sends the one result to every other item still waiting
//! (`sapling.rs:104-118`).
//!
//! So [`Sapling::validate_batch`] deliberately does **not** stop at the first
//! `check_bundle` returning false. Stopping would skip the polluted `validate` call
//! entirely — which is exactly the code path worth testing, and the only place the
//! question "can one bad bundle change a different, valid bundle's verdict?" can
//! even be asked.
//!
//! No modifications to Zebra or to `sapling-crypto`: both paths here are public APIs.

use std::sync::{Arc, OnceLock};

use bellman::groth16::Proof;
// `ExtendedPoint::from_bytes` is a `GroupEncoding` method, not an inherent one.
use group::GroupEncoding;
use sapling_crypto::bundle::Authorized;
use sapling_crypto::circuit::{
    OutputVerifyingKey, PreparedOutputVerifyingKey, PreparedSpendVerifyingKey, SpendVerifyingKey,
};
use sapling_crypto::{BatchValidator, Bundle, SaplingVerificationContext};
use zcash_proofs::prover::LocalTxProver;

use zebra_chain::parameters::NetworkUpgrade;
use zebra_chain::transaction::{HashType, Transaction};
use zebra_chain::transparent;

use crate::verifier::BatchVerifier;
use crate::{seeded_rng, SigHash, ZatBalance};

/// The authorized Sapling bundle type Zebra hands us.
pub type SaplingBundle = Bundle<Authorized, ZatBalance>;

/// One Sapling verification item: the bundle plus the sighash its signatures are
/// bound to. The exact pair carried inside `zebra-consensus`'s `sapling::Item`.
///
/// `Clone` because the adversarial generator builds tampered variants from valid
/// items and needs the original intact to compare against.
#[derive(Clone)]
pub struct SaplingItem {
    /// The authorized Sapling bundle (spend/output proofs, spend-auth and binding
    /// signatures).
    pub bundle: SaplingBundle,
    /// The sighash the bundle's signatures are over.
    pub sighash: SigHash,
}

impl SaplingItem {
    /// Number of Groth16 proofs this bundle contributes to a batch: one per spend
    /// plus one per output.
    ///
    /// Worth stating explicitly because Zebra's batch size limit does *not* count
    /// them. `MAX_BATCH_SIZE = 64` is applied through `RequestWeight`, which Sapling
    /// leaves at the default weight of 1 per **bundle** (only halo2 overrides it, to
    /// count actions). A batch of 64 Sapling bundles therefore carries an unbounded
    /// number of proofs, while a batch of Orchard bundles is capped at 64 actions.
    pub fn proof_count(&self) -> usize {
        self.bundle.shielded_spends().len() + self.bundle.shielded_outputs().len()
    }
}

/// The Sapling verifying keys, in both forms the two paths need.
///
/// The batch path takes the plain keys; the independent path takes the prepared
/// ones (precomputations for verifying proofs individually). Both derive from the
/// same parameters, so a disagreement between the paths can never be blamed on the
/// keys differing.
pub struct SaplingKeys {
    spend_vk: SpendVerifyingKey,
    output_vk: OutputVerifyingKey,
    prepared_spend_vk: PreparedSpendVerifyingKey,
    prepared_output_vk: PreparedOutputVerifyingKey,
}

impl SaplingKeys {
    /// The bundled Sapling parameters, obtained exactly as Zebra obtains them
    /// (`LocalTxProver::bundled`, `sapling.rs:32`).
    ///
    /// Despite the name, this downloads nothing: the `bundled-prover` feature pulls
    /// the parameters in as the `wagyu-zcash-parameters` crate. Cached, because
    /// parsing them is slow and every call would otherwise redo it.
    pub fn bundled() -> &'static Self {
        static KEYS: OnceLock<SaplingKeys> = OnceLock::new();
        KEYS.get_or_init(|| {
            let prover = LocalTxProver::bundled();
            let (spend_vk, output_vk) = prover.verifying_keys();
            let prepared_spend_vk = spend_vk.prepare();
            let prepared_output_vk = output_vk.prepare();
            SaplingKeys {
                spend_vk,
                output_vk,
                prepared_spend_vk,
                prepared_output_vk,
            }
        })
    }
}

/// Extract the Sapling item from a transaction, using the transaction's own
/// network upgrade for the sighash. `None` for transactions with no Sapling
/// bundle.
///
/// A transaction yields at most one Sapling item, unlike Orchard under NU6.3,
/// where a v6 transaction can carry both an Orchard-pool and an Ironwood-pool
/// bundle.
pub fn item_from_tx(tx: &Transaction) -> Option<SaplingItem> {
    item_from_tx_with_nu(tx, tx.network_upgrade()?)
}

/// Extract the Sapling item using an explicit network upgrade for the sighash
/// (a fixed upgrade for a corpus of known era). See [`item_from_tx`].
///
/// Transparent inputs are the caller's problem, not this function's: the sighash
/// is computed against an empty prevout set, which is correct for a
/// shielded-only transaction and wrong for one spending transparent inputs,
/// whose ZIP-243/244 sighash folds in prevouts a bare transaction does not
/// carry. Corpus loaders filter those out for the signature-bearing paths.
/// (Sprout's Groth16 proofs are the exception — they are not bound to a sighash
/// at all, so that filter would only discard usable material there.)
pub fn item_from_tx_with_nu(tx: &Transaction, nu: NetworkUpgrade) -> Option<SaplingItem> {
    if !tx.has_sapling_shielded_data() {
        return None;
    }
    let empty_prevouts: Arc<Vec<transparent::Output>> = Arc::new(Vec::new());
    let sighasher = tx.sighasher(nu, empty_prevouts).ok()?;
    let bundle = sighasher.sapling_bundle()?;
    let sighash = sighasher.sighash(HashType::ALL, None);

    Some(SaplingItem {
        bundle,
        sighash: SigHash(sighash.0),
    })
}

/// Zebra's Sapling verifier — Groth16 spend/output proofs and RedJubjub
/// signatures, driven through `sapling_crypto::BatchValidator`.
///
/// Leaves [`BatchVerifier::item_weight`] at the default of 1 per **bundle**,
/// because that is what Zebra does: `sapling::Item` takes the blanket
/// `RequestWeight` impl and never overrides it. Worth naming rather than leaving
/// as a silent default, since the consequence is the asymmetry the tower-layer
/// tests exist to pin — a full Sapling batch is 64 bundles, each carrying an
/// unbounded [`SaplingItem::proof_count`], so the number of Groth16 proofs in
/// one batch is not bounded at all. The Orchard batch beside it, under the same
/// constant, is capped at 64 actions.
pub struct Sapling;

impl BatchVerifier for Sapling {
    type Item = SaplingItem;
    type Context = SaplingKeys;
    const NAME: &'static str = "sapling (Groth16 + RedJubjub)";

    /// All bundles through one validator, one verdict per bundle.
    ///
    /// **Does not stop at the first rejected bundle** — see the module docs. A
    /// bundle that fails `check_bundle` has already contributed part of itself to
    /// the shared batch, and production runs `validate` over that polluted batch
    /// anyway; short-circuiting would silently skip the path being tested.
    fn validate_batch(items: &[&Self::Item], ctx: &Self::Context, seed: u64) -> Vec<bool> {
        let mut bv = BatchValidator::new();
        let checked: Vec<bool> = items
            .iter()
            .map(|item| bv.check_bundle(item.bundle.clone(), item.sighash.0))
            .collect();

        let shared = bv.validate(&ctx.spend_vk, &ctx.output_vk, seeded_rng(seed));

        // Mirrors `sapling.rs:104-118`: a bundle rejected at check time fails on its
        // own; every bundle that passed receives the batch's single verdict.
        checked.into_iter().map(|ok| ok && shared).collect()
    }

    /// One bundle alone, mirroring `zebra-consensus`'s `sapling::verify_single`
    /// (`sapling.rs:175`) — which is itself a batch of one, not a separate
    /// implementation. That is why [`Self::validate_one_independent`] exists.
    fn validate_one(item: &Self::Item, ctx: &Self::Context, seed: u64) -> bool {
        let mut bv = BatchValidator::new();
        if !bv.check_bundle(item.bundle.clone(), item.sighash.0) {
            return false;
        }
        bv.validate(&ctx.spend_vk, &ctx.output_vk, seeded_rng(seed))
    }

    /// The independent path: `SaplingVerificationContext` checks each spend and
    /// output on its own, calling `bellman`'s `verify_proof` per proof and
    /// `rk.verify` per signature, then reconciles the value balance and binding
    /// signature in `final_check`. Zebra never runs it.
    ///
    /// ## Exactly where the two paths diverge, and where they do not
    ///
    /// Worth stating precisely, because the divergence is narrower than "a
    /// different implementation" suggests and the report has to survive a reviewer
    /// reading `sapling-crypto`'s source. Both paths are thin shells over the
    /// **same** `SaplingVerificationContextInner`, differing only in the closures
    /// they hand it — queue-into-a-batch versus verify-here. Everything that
    /// happens outside those closures is one body of code shared by both:
    ///
    /// * the small-order rejections of `rk` and of an output's ephemeral key,
    /// * the `cv_sum` accumulation and the `into_bvk` derivation of the binding key,
    /// * the construction of each proof's public inputs.
    ///
    /// What genuinely differs is the verification algebra the closures reach:
    /// `groth16::batch::Verifier`'s randomized linear combination against
    /// `bellman::verify_proof` per proof, and `redjubjub::batch::Verifier` against
    /// `rk.verify` per signature.
    ///
    /// So layer 2 has power over the verification equations and **not** over the
    /// consensus checks or the public-input construction — a bug there would fail
    /// both paths identically and this check would report a clean `Agree(false)`.
    /// The consequence for the adversarial corpus is direct: tampering with a
    /// value balance, an ephemeral key, or an `rk` into small order exercises only
    /// shared code, and the two paths agreeing proves nothing. Proof bytes and
    /// signature bytes are the two inputs that reach the diverging half.
    ///
    /// Consumes no randomness, which is what makes it deterministic where the
    /// batch path is seeded.
    ///
    /// Field extraction deliberately mirrors `check_bundle` (`verifier/batch.rs`),
    /// so the two paths are fed byte-identical inputs and any disagreement is about
    /// the verification, not about how the bundle was read.
    fn validate_one_independent(item: &Self::Item, ctx: &Self::Context) -> Option<bool> {
        let mut vctx = SaplingVerificationContext::new();
        let sighash = item.sighash.0;

        for spend in item.bundle.shielded_spends() {
            let Ok(zkproof) = Proof::read(&spend.zkproof()[..]) else {
                // Undecodable proof: the batch path returns false here too.
                return Some(false);
            };
            let passed = vctx.check_spend(
                spend.cv(),
                *spend.anchor(),
                &spend.nullifier().0,
                *spend.rk(),
                &sighash,
                *spend.spend_auth_sig(),
                zkproof,
                &ctx.prepared_spend_vk,
            );
            if !passed {
                return Some(false);
            }
        }

        for output in item.bundle.shielded_outputs() {
            let epk = jubjub::ExtendedPoint::from_bytes(&output.ephemeral_key().0);
            let epk: Option<jubjub::ExtendedPoint> = epk.into();
            let Some(epk) = epk else {
                return Some(false);
            };
            let Ok(zkproof) = Proof::read(&output.zkproof()[..]) else {
                return Some(false);
            };
            let passed = vctx.check_output(
                output.cv(),
                *output.cmu(),
                epk,
                zkproof,
                &ctx.prepared_output_vk,
            );
            if !passed {
                return Some(false);
            }
        }

        Some(vctx.final_check(
            *item.bundle.value_balance(),
            &sighash,
            item.bundle.authorization().binding_sig,
        ))
    }
}
