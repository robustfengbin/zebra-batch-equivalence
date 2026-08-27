//! Sprout JoinSplit Groth16 `batch ⟺ single` verification equivalence.
//!
//! ## Read this before citing anything from this module
//!
//! **Zebra does not batch-verify Sprout JoinSplits.** `JOINSPLIT_VERIFIER` is a
//! bare `tower::service_fn` that calls `Item::verify_single` on each JoinSplit
//! (`groth16.rs:83-102`), with the comment *"We just need a Service to use: there
//! is no batch verification for JoinSplits"* and a pointer to the upstream issue
//! that proposed adding it, [ZcashFoundation/zebra#3127].
//!
//! **That issue is closed — `not planned`, 2022-03-15** — so this module does not
//! describe it as pending. The reasons given were that most JoinSplits sit below
//! the checkpoint verifier and never reach proof verification, so the gain would
//! be small; the closing comment redirects to the general performance tracker
//! [ZcashFoundation/zebra#3153] with *"can be done if we detect it's a
//! bottleneck"*. Upstream's source comment still links #3127 as though open.
//!
//! So the `batch ⟺ single` disagreement this module looks for **cannot occur in
//! Zebra today** — there is no batch to disagree with. What it covers is the
//! `bellman::groth16::batch` verifier under Sprout's parameters and real Sprout
//! proofs: the code JoinSplit verification would run on if batching were ever
//! switched on, and which the grant names as one of its four verifiers.
//!
//! That makes this the one pool where the oracle runs ahead of the deployment
//! rather than beside it — and, since the deployment is not scheduled, ahead of
//! a decision rather than of a release. Worth having either way: the gate is
//! cheaper to build now than to retrofit if batching is ever revisited. But
//! any report sentence that lets a reader think Zebra batches JoinSplits today
//! would be false, so this module states it here rather than leaving it to be
//! inferred.
//!
//! ## Two things are reproduced rather than called, and why that is safe
//!
//! `zebra-consensus` cannot enter this crate's dependency graph — it pulls in
//! `zebra-state` and therefore rocksdb — so two pieces of it are reproduced here
//! from `groth16.rs`:
//!
//! * the JoinSplit public-input encoding (`Item::from_joinsplit`, `:132-190`),
//! * the `h_sig` hash (`:112-131`), computed with the same crate and version.
//!
//! Reproduction is exactly the hazard this project keeps warning about: if the
//! encoding were wrong, **both** paths would receive the same wrong public inputs
//! and agree on rejecting everything — a green suite proving nothing. The guard
//! is that the corpus is real mainnet JoinSplits, which verify only if the
//! encoding is right. `real_joinsplits_verify` in `tests/sprout_agreement.rs` is
//! therefore not a smoke test; it is what makes every other assertion here mean
//! something.
//!
//! The verifying key is Zebra's own file, vendored byte-for-byte and checked
//! against its hash at load time — see [`SproutKeys::bundled`].
//!
//! [ZcashFoundation/zebra#3127]: https://github.com/ZcashFoundation/zebra/issues/3127
//! [ZcashFoundation/zebra#3153]: https://github.com/ZcashFoundation/zebra/issues/3153

use bellman::gadgets::multipack;
use bellman::groth16::{batch, prepare_verifying_key, PreparedVerifyingKey, Proof, VerifyingKey};
use bls12_381::Bls12;

use zebra_chain::primitives::ed25519;
use zebra_chain::primitives::Groth16Proof;
use zebra_chain::sprout::{JoinSplit, Nullifier, RandomSeed};
use zebra_chain::transaction::Transaction;

use crate::seeded_rng;
use crate::verifier::BatchVerifier;

/// One Sprout verification item: a JoinSplit's Groth16 proof and its primary
/// inputs, in the form both `bellman` paths consume.
pub struct SproutItem {
    item: batch::Item<Bls12>,
}

impl SproutItem {
    /// The underlying batch item, cloned. Both paths consume the item, so every
    /// use is a clone.
    pub fn batch_item(&self) -> batch::Item<Bls12> {
        self.item.clone()
    }
}

/// The Sprout JoinSplit verifying key, in both forms the two paths need.
///
/// The batch path takes the raw key; the independent path takes the prepared
/// one. Both are derived from the same bytes, so a disagreement between the
/// paths can never be blamed on the keys differing.
pub struct SproutKeys {
    vk: VerifyingKey<Bls12>,
    pvk: PreparedVerifyingKey<Bls12>,
}

/// Zebra's Sprout verifying key, vendored from
/// `zebra-consensus/src/primitives/groth16/sprout-groth16.vk` at the pinned
/// revision (`f5c5277f`). Re-hashed at the v6.2.3 -> v6.3.0 bump and found
/// byte-identical upstream, so this copy carries over unmodified.
///
/// Vendored rather than read from the dependency: `zebra-consensus` is not in
/// this crate's graph, and reaching into a cargo git checkout by path would not
/// survive a clean clone. 1,828 bytes, unmodified.
const SPROUT_VK_BYTES: &[u8] = include_bytes!("../vendor/sprout-groth16.vk");

/// Keyed BLAKE2b-256 digest of [`SPROUT_VK_BYTES`] as vendored, filled in from a
/// measured value (see the test below).
///
/// Checked at load time so the file cannot be swapped or corrupted silently.
/// A verifying key that changed without anyone noticing would not make this
/// suite fail — it would make every proof reject, and assertions about
/// *equivalence* rather than acceptance stay perfectly green while verifying
/// against the wrong key.
///
/// BLAKE2b rather than SHA-256 because `blake2b_simd` is already in the graph
/// for `h_sig`; a hand-written hash would be one more implementation that can
/// be wrong, in a crate whose entire argument is that it does not reimplement
/// the things it checks.
pub const SPROUT_VK_DIGEST: [u8; 32] = [
    0x36, 0x82, 0x89, 0xf0, 0xee, 0x6f, 0xa0, 0x18, 0xa5, 0xc2, 0x8b, 0xa8, 0x4b, 0x30, 0xb3, 0x58,
    0xc8, 0x5a, 0x2e, 0xe9, 0x89, 0x0d, 0xa9, 0x4b, 0xcd, 0xf6, 0xe6, 0xdb, 0xfa, 0xf5, 0x37, 0x9a,
];

impl SproutKeys {
    /// Zebra's Sprout verifying key, parsed exactly as `SproutParams::default`
    /// parses it (`groth16/params.rs:28`), after checking the vendored bytes
    /// against [`SPROUT_VK_DIGEST`].
    pub fn bundled() -> &'static Self {
        use std::sync::OnceLock;
        static KEYS: OnceLock<SproutKeys> = OnceLock::new();
        KEYS.get_or_init(|| {
            assert_eq!(
                vk_digest(SPROUT_VK_BYTES),
                SPROUT_VK_DIGEST,
                "vendored Sprout verifying key does not match its recorded hash: the file has \
                 been modified or replaced"
            );
            let vk = VerifyingKey::<Bls12>::read(SPROUT_VK_BYTES)
                .expect("vendored Sprout verifying key must parse");
            let pvk = prepare_verifying_key(&vk);
            SproutKeys { vk, pvk }
        })
    }
}

/// Digest of the vendored key bytes, for the integrity check in
/// [`SproutKeys::bundled`]. Personalised so the value cannot be confused with
/// any other digest of the same bytes.
fn vk_digest(data: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"zbe-sprout-vk-v1")
        .hash(data)
        .as_bytes()
        .try_into()
        .expect("32 byte digest")
}

/// The `h_sig` hash function a JoinSplit's proof commits to
/// ([protocol spec §5.4.1.5][hsig]).
///
/// Reproduced from `groth16.rs:112-131`, using the same crate at the same
/// version, because `zebra-consensus` cannot be a dependency here.
///
/// [hsig]: https://zips.z.cash/protocol/protocol.pdf#hsigcrh
pub fn h_sig(
    random_seed: &RandomSeed,
    nf1: &Nullifier,
    nf2: &Nullifier,
    joinsplit_pub_key: &ed25519::VerificationKeyBytes,
) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZcashComputehSig")
        .to_state()
        .update(&(<[u8; 32]>::from(random_seed))[..])
        .update(&(<[u8; 32]>::from(nf1))[..])
        .update(&(<[u8; 32]>::from(nf2))[..])
        .update(joinsplit_pub_key.as_ref())
        .finalize()
        .as_bytes()
        .try_into()
        .expect("32 byte array")
}

/// Build the verification item for one JoinSplit, encoding its primary inputs
/// exactly as `Item::from_joinsplit` does (`groth16.rs:150-190`).
///
/// `None` if the proof bytes do not decode — the same fail-closed outcome
/// production reaches there, by way of `TransactionError::MalformedGroth16`.
///
/// All JoinSplits in a transaction share one validating key, which is why it is
/// a separate argument rather than something the JoinSplit carries.
pub fn item_from_joinsplit(
    joinsplit: &JoinSplit<Groth16Proof>,
    joinsplit_pub_key: &ed25519::VerificationKeyBytes,
) -> Option<SproutItem> {
    let rt: [u8; 32] = joinsplit.anchor.into();
    let mac1: [u8; 32] = (&joinsplit.vmacs[0]).into();
    let mac2: [u8; 32] = (&joinsplit.vmacs[1]).into();
    let nf1: [u8; 32] = (&joinsplit.nullifiers[0]).into();
    let nf2: [u8; 32] = (&joinsplit.nullifiers[1]).into();
    let cm1: [u8; 32] = (&joinsplit.commitments[0]).into();
    let cm2: [u8; 32] = (&joinsplit.commitments[1]).into();
    let vpub_old = joinsplit.vpub_old.to_bytes();
    let vpub_new = joinsplit.vpub_new.to_bytes();

    let h_sig = h_sig(
        &joinsplit.random_seed,
        &joinsplit.nullifiers[0],
        &joinsplit.nullifiers[1],
        joinsplit_pub_key,
    );

    // Field order is consensus-critical and matches the reference implementation
    // (librustzcash `zcash_proofs/src/sprout.rs`), which is what `groth16.rs`
    // follows.
    let mut public_input = Vec::with_capacity((32 * 8) + (8 * 2));
    public_input.extend(rt);
    public_input.extend(h_sig);
    public_input.extend(nf1);
    public_input.extend(mac1);
    public_input.extend(nf2);
    public_input.extend(mac2);
    public_input.extend(cm1);
    public_input.extend(cm2);
    public_input.extend(vpub_old);
    public_input.extend(vpub_new);

    let public_input = multipack::bytes_to_bits(&public_input);
    let primary_inputs = multipack::compute_multipacking(&public_input);

    let proof = Proof::read(&joinsplit.zkproof.0[..]).ok()?;

    Some(SproutItem {
        item: batch::Item::from((proof, primary_inputs)),
    })
}

/// Every Groth16 JoinSplit item in a transaction.
///
/// Empty for transactions with no JoinSplits, and for those whose JoinSplits
/// carry BCTV14 proofs — pre-Sapling history that no shipping verifier accepts.
/// `sprout_groth16_joinsplits` makes that distinction; `joinsplit_count` does
/// not, which is how a corpus survey can overstate Sprout material several-fold.
///
/// **No shielded-only filter here**, unlike every other pool in this crate: a
/// Sprout Groth16 proof is not bound to a sighash, so a transparent input cannot
/// invalidate it. (The Ed25519 signature over the same JoinSplit *is* bound to
/// one — a different item stream, with a different usability rule.)
pub fn items_from_tx(tx: &Transaction) -> Vec<SproutItem> {
    let Some(pub_key) = tx.sprout_joinsplit_pub_key() else {
        return Vec::new();
    };
    tx.sprout_groth16_joinsplits()
        .filter_map(|joinsplit| item_from_joinsplit(joinsplit, &pub_key))
        .collect()
}

/// Sprout JoinSplit Groth16 proofs, driven through `bellman::groth16::batch`.
///
/// See the module docs: Zebra verifies these one at a time today, and the issue
/// proposing batch support (#3127) was closed as not planned, so the batch side
/// of this verifier is a path Zebra's dependency can reach but Zebra does not
/// run.
pub struct Sprout;

impl BatchVerifier for Sprout {
    type Item = SproutItem;
    type Context = SproutKeys;
    const NAME: &'static str = "sprout (JoinSplit Groth16)";

    /// All proofs in one batch, one verdict per item.
    ///
    /// Every item receives the same verdict: `queue` cannot fail, and batch
    /// verification is one equation over the whole set. Structurally identical to
    /// [`crate::redjubjub`], and for the same reason — comparing this against the
    /// singles position by position would report a false reject for every valid
    /// proof sharing a batch with a bad one, which is what batch verification
    /// means rather than a finding.
    fn validate_batch(items: &[&Self::Item], ctx: &Self::Context, seed: u64) -> Vec<bool> {
        let mut verifier = batch::Verifier::new();
        for item in items {
            verifier.queue(item.item.clone());
        }
        let shared = verifier.verify(seeded_rng(seed), &ctx.vk).is_ok();
        vec![shared; items.len()]
    }

    /// One proof through the batch machinery alone — the aggregation path at
    /// N=1, which is what makes layer 1 a comparison of batch sizes rather than
    /// of algorithms.
    fn validate_one(item: &Self::Item, ctx: &Self::Context, seed: u64) -> bool {
        let mut verifier = batch::Verifier::new();
        verifier.queue(item.item.clone());
        verifier.verify(seeded_rng(seed), &ctx.vk).is_ok()
    }

    /// The independent path: `batch::Item::verify_single`, which runs
    /// `bellman::verify_proof` against the prepared key — no randomised linear
    /// combination, no RNG.
    ///
    /// bellman documents it as *"non-batched verification ... useful for
    /// implementing fallback logic"*, and it is what Zebra calls for every
    /// JoinSplit today. So, as with RedJubjub, layer 2 here is production code
    /// rather than a second opinion nobody runs.
    ///
    /// The two paths share the primary-input encoding built in
    /// [`item_from_joinsplit`] and diverge at the verification equation: a
    /// randomised linear combination checked with one multi-Miller loop, against
    /// a per-proof pairing check. An error in the encoding is invisible to this
    /// check, which is why the corpus has to be real proofs that must verify.
    fn validate_one_independent(item: &Self::Item, ctx: &Self::Context) -> Option<bool> {
        Some(item.item.clone().verify_single(&ctx.pvk).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vendored key parses and still matches its recorded digest.
    ///
    /// This is the assertion that makes every other Sprout result meaningful: a
    /// swapped key would reject every proof, and equivalence assertions would
    /// stay green throughout.
    #[test]
    fn vendored_verifying_key_is_intact() {
        assert_eq!(
            vk_digest(SPROUT_VK_BYTES),
            SPROUT_VK_DIGEST,
            "vendored Sprout verifying key digest changed"
        );
        assert_eq!(SPROUT_VK_BYTES.len(), 1828);
        // Forces the parse and the assertion inside `bundled`.
        let _ = SproutKeys::bundled();
    }
}
