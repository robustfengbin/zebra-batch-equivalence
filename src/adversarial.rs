//! The adversarial corpus generator.
//!
//! M1's `tests/mutation_smoke.rs` damaged a few real proofs by hand and pinned
//! that both paths still agreed. Its header says what this module is for: *"the
//! systematic adversarial-corpus generators ... are M2's deliverable. This file
//! is that machinery's skeleton preview, not its implementation."*
//!
//! Three things the generator produces, matching the grant's deliverable:
//! a valid base (real mainnet items), single-element tampers, and
//! batch compositions — chiefly **mostly-valid-plus-one-invalid**.
//!
//! ## Not every tamper is worth generating
//!
//! The obvious way to build an adversarial corpus is to damage whatever the item
//! exposes. For this oracle that would be a mistake, and a quiet one.
//!
//! Layer 2's power extends only as far as the two verification paths actually
//! differ, and how far that is varies by pool (see [`crate::verifier`]). In
//! Sapling, both paths are shells over one `SaplingVerificationContextInner`:
//! the small-order rejections, the `cv_sum` accumulation, the binding-key
//! derivation and the public-input construction are **one body of code used by
//! both**. So a tamper that damages a value balance, an ephemeral key, or forces
//! a key to small order makes both paths run the same code and reject
//! identically. The check reports a clean `Agree(false)`, the suite goes green,
//! and nothing has been tested.
//!
//! [`TamperTarget`] exists to make that distinction a named property rather than
//! a comment someone might not read: a generator can then exclude the useless
//! class deliberately instead of by omission.
//!
//! ## A generator has to prove it generated what it claims
//!
//! The same hazard as everywhere else in this crate. If a tamper silently failed
//! to invalidate its item, a "mostly-valid-plus-one-invalid" batch would be an
//! all-valid batch, every equivalence assertion over it would pass, and the run
//! would be indistinguishable from a real one. [`AdversarialBatch::check_shape`]
//! is therefore not a convenience: it is what makes the batches mean what their
//! name says.

use bellman::groth16::Proof;
use bls12_381::Bls12;

use crate::sapling::{SaplingBundle, SaplingItem};
use crate::verifier::BatchVerifier;
use crate::SigHash;

use sapling_crypto::bundle::{Authorized, GrothProofBytes};

/// What part of an item a tamper damages, and whether the verification paths can
/// tell the damage apart.
///
/// The distinction is the point. Two of these reach the code where the batch and
/// independent paths genuinely differ; one does not, in at least one pool, and a
/// corpus built from it would be decorative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperTarget {
    /// Proof bytes. Reaches the verification algebra in every pool — the batch
    /// path folds the proof into a randomised linear combination, the
    /// independent path checks it on its own.
    ProofBytes,
    /// Signature bytes (`R`, `s`). Likewise reaches the diverging half: a batched
    /// multiscalar equation against a per-signature check.
    SignatureBytes,
    /// The message a signature is bound to — a well-formed signature checked
    /// against the wrong sighash.
    BoundMessage,
    /// Consensus-rule inputs: value balance, ephemeral keys, small-order
    /// validating keys.
    ///
    /// **Not discriminating in Sapling**, where both paths share
    /// `SaplingVerificationContextInner` and therefore reject identically. Named
    /// rather than omitted so that leaving it out of a corpus is a decision on
    /// the record instead of an oversight.
    ///
    /// ## The specific branches, and why coverage will tempt someone to hit them
    ///
    /// Three of `check_bundle`'s five rejection points fall in this class:
    ///
    /// * `rk` forced to small order,
    /// * an output's ephemeral key failing to decode,
    /// * an output's ephemeral key in the small-order subgroup.
    ///
    /// They are **reachable**, and they are the difference between the measured
    /// line coverage of `sapling-crypto`'s `BatchValidator` and a round number.
    /// So sooner or later someone will look at the gap and write tampers to
    /// close it.
    ///
    /// **Doing that raises the number and verifies nothing further.** Any input
    /// that reaches these branches makes both the batch path and the independent
    /// path run the same consensus code and reject together, so
    /// `check_strategy_equivalence` returns `Agree(false)` by construction.
    ///
    /// This crate exists to keep gaps from looking like full coverage. Closing
    /// these is the mirror of that failure — making full coverage look like
    /// something was verified — and it is the worse direction, because
    /// afterwards there is no gap left to notice.
    ConsensusInput,
}

impl TamperTarget {
    /// Whether damage here can distinguish the batch path from the independent
    /// one, for pools whose two paths share their consensus-check context.
    ///
    /// Conservative: `false` means "cannot be relied on to discriminate
    /// anywhere", not "never discriminates in any pool".
    pub fn is_discriminating(self) -> bool {
        !matches!(self, TamperTarget::ConsensusInput)
    }
}

/// How to damage a Groth16 proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofDamage {
    /// A proof that still **decodes** and does not satisfy the statement.
    ///
    /// The distinction from [`Self::Undecodable`] is what makes Sapling's
    /// half-enqueued residue reachable: `check_bundle` decodes each spend's proof
    /// before queueing it, so a decodable-but-wrong proof *enters the shared
    /// batch*, while an undecodable one ends the bundle before anything is
    /// queued.
    ///
    /// 🔴 Which is why this cannot be "flip a bit and hope". A compressed
    /// BLS12-381 point is roughly half the encodings in its byte range, so an
    /// arbitrary bit flip decodes only about half the time — and when it does
    /// not, `check_bundle` returns false at *that* spend, queues nothing, and
    /// the residue never forms. A test built on it would pass while exercising
    /// an empty construction. Measured, not assumed: flipping the low bit of the
    /// last byte failed to decode on every corpus bundle tried.
    ///
    /// So this searches for a single-bit flip that does decode.
    DecodableButWrong,
    /// Make the bytes fail to decode as a group element at all, so
    /// `groth16::Proof::read` returns `Err` and `check_bundle` returns `false`
    /// on the spot.
    Undecodable,
}

impl ProofDamage {
    /// Apply the damage. See each variant for the contract it guarantees;
    /// `tests/adversarial_generator.rs` asserts both against real proofs.
    pub fn apply(self, mut proof: GrothProofBytes) -> GrothProofBytes {
        match self {
            // Search for a flip whose result is still a valid encoding. Walking
            // from the end keeps the change inside coordinate data rather than
            // the leading flag bits, where a "successful decode" could mean the
            // point at infinity rather than a wrong point.
            ProofDamage::DecodableButWrong => {
                for byte in (0..proof.len()).rev() {
                    for bit in 0..8u8 {
                        let mut candidate = proof;
                        candidate[byte] ^= 1 << bit;
                        if Proof::<Bls12>::read(&candidate[..]).is_ok() {
                            return candidate;
                        }
                    }
                }
                panic!(
                    "no single-bit flip of this proof decodes as a group element; the residue \
                     construction cannot be built from it"
                )
            }
            // All-ones is not a valid compressed BLS12-381 point encoding.
            ProofDamage::Undecodable => {
                proof[0] = 0xff;
                proof[1] = 0xff;
                proof
            }
        }
    }
}

/// A Sapling item with the proof of one spend damaged, everything else
/// untouched.
///
/// `spend_index` is a position in `bundle.shielded_spends()`; out-of-range
/// indices leave the bundle unchanged, which
/// [`AdversarialBatch::check_shape`] would then catch as a tamper that failed to
/// invalidate.
pub fn tamper_spend_proof(
    item: &SaplingItem,
    spend_index: usize,
    damage: ProofDamage,
) -> SaplingItem {
    // The counter is threaded through `map_authorization`'s context, which is
    // the only way to address a single spend: the callback sees proofs, not
    // positions. Outputs and signatures use their own callbacks and never touch
    // it, so the count is over spends alone.
    let bundle: SaplingBundle = item.bundle.clone().map_authorization(
        0usize,
        |seen: &mut usize, proof: GrothProofBytes| {
            let index = *seen;
            *seen += 1;
            if index == spend_index {
                damage.apply(proof)
            } else {
                proof
            }
        },
        |_, proof| proof,
        |_, sig| sig,
        |_, auth: Authorized| auth,
    );

    SaplingItem {
        bundle,
        sighash: SigHash(item.sighash.0),
    }
}

/// A Sapling item carrying the half-enqueued residue its batch validator's
/// documentation warns about.
///
/// `sapling_crypto`'s `check_bundle` says *"some or all of the proofs and
/// signatures from this bundle may have already been added to the batch even if
/// it fails other consensus rules"*, and the implementation is why: it walks the
/// spends, queueing each one that passes its checks, and returns `false` the
/// moment one does not — leaving everything queued so far in the **shared**
/// batch.
///
/// This builds an item that exercises exactly that. The spend at
/// `queued_but_invalid` gets a proof that decodes and is wrong, so it is queued;
/// the spend at `stops_the_bundle` gets a proof that does not decode, so
/// `check_bundle` returns `false` there. The bundle is rejected — and its first,
/// invalid proof stays behind in the batch every other bundle is sharing.
///
/// Requires a bundle with at least two spends, and
/// `queued_but_invalid < stops_the_bundle`, or the residue never forms. Returns
/// `None` rather than silently producing an item that does not do what its name
/// says.
///
/// ## The residue cannot cause a false accept
///
/// Worth stating where the construction lives, because it bounds what any
/// measurement here can mean. Production accepts item `i` when
/// `checked[i] && shared`. Residue can only come from a bundle whose
/// `check_bundle` returned `false` — a bundle that succeeded contributed all of
/// itself, not a remnant — so that bundle's own `checked` is already `false` and
/// it is rejected on both paths regardless. And what the residue adds to the
/// shared batch is *more* proofs that can fail, which can only push `shared`
/// toward `false`, never from `false` to `true`.
///
/// So this construction can subtract acceptances and cannot add any: a
/// false-accept is structurally impossible here, not merely unobserved. The
/// only disagreement it can produce is a false reject.
pub fn half_enqueued_residue(
    item: &SaplingItem,
    queued_but_invalid: usize,
    stops_the_bundle: usize,
) -> Option<SaplingItem> {
    if queued_but_invalid >= stops_the_bundle
        || stops_the_bundle >= item.bundle.shielded_spends().len()
    {
        return None;
    }
    let staged = tamper_spend_proof(item, queued_but_invalid, ProofDamage::DecodableButWrong);
    Some(tamper_spend_proof(
        &staged,
        stops_the_bundle,
        ProofDamage::Undecodable,
    ))
}

/// A batch of mostly-valid items with exactly one invalid one — the composition
/// the grant names, and the one where a batch verifier's failure mode matters
/// most.
pub struct AdversarialBatch<'a, V: BatchVerifier> {
    /// The batch, in submission order.
    pub items: Vec<&'a V::Item>,
    /// Where the invalid item sits.
    pub invalid_index: usize,
}

/// Why a generated batch was not the shape it claimed to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedBatch {
    /// An item placed as valid does not verify on its own.
    ValidItemDoesNotVerify(usize),
    /// The item placed as invalid verifies on its own — the tamper did not take,
    /// so this is an all-valid batch wearing an adversarial name.
    InvalidItemVerifies,
}

impl<'a, V: BatchVerifier> AdversarialBatch<'a, V> {
    /// Splice `invalid` into `valid` at `position`.
    ///
    /// Position matters: an item's place in the batch is exactly what a
    /// composition-sensitive bug would care about, so callers sweep it rather
    /// than fixing it.
    pub fn mostly_valid_plus_one_invalid(
        valid: &'a [V::Item],
        invalid: &'a V::Item,
        position: usize,
    ) -> Self {
        let position = position.min(valid.len());
        let mut items: Vec<&V::Item> = valid.iter().collect();
        items.insert(position, invalid);
        Self {
            items,
            invalid_index: position,
        }
    }

    /// Verify that this batch is what it claims: every item placed as valid
    /// verifies alone, and the one placed as invalid does not.
    ///
    /// **Call this before drawing any conclusion from a batch.** A tamper that
    /// failed to invalidate its item yields an all-valid batch on which every
    /// equivalence assertion passes — a green run that tested nothing and looks
    /// exactly like a green run that tested everything.
    pub fn check_shape(&self, ctx: &V::Context, seed: u64) -> Result<(), MalformedBatch> {
        for (index, item) in self.items.iter().enumerate() {
            let verifies = V::validate_one(item, ctx, seed);
            if index == self.invalid_index {
                if verifies {
                    return Err(MalformedBatch::InvalidItemVerifies);
                }
            } else if !verifies {
                return Err(MalformedBatch::ValidItemDoesNotVerify(index));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_input_tampers_are_marked_non_discriminating() {
        assert!(TamperTarget::ProofBytes.is_discriminating());
        assert!(TamperTarget::SignatureBytes.is_discriminating());
        assert!(TamperTarget::BoundMessage.is_discriminating());
        // The one whose omission from a corpus has to be a decision, not an
        // accident.
        assert!(!TamperTarget::ConsensusInput.is_discriminating());
    }

    #[test]
    fn undecodable_damage_does_not_decode() {
        let proof: GrothProofBytes = [0x42; 192];
        let broken = ProofDamage::Undecodable.apply(proof);
        assert_ne!(broken, proof);
        // The undecodable damage rewrites the leading bytes of the first point
        // and nothing else.
        assert_eq!(broken[2..], proof[2..]);
        assert!(
            Proof::<Bls12>::read(&broken[..]).is_err(),
            "Undecodable must not decode — the whole point of the variant"
        );
    }
}
