//! What each pool's fuzz target takes out of a transaction.
//!
//! The parsing half of the fuzz input model lives in
//! [`crate::items_from_tx_stream_with`] — where a transaction ends, what a
//! panic costs, how large a batch may get. This module is the other half: given
//! one parsed transaction, which items does *this* verifier get?
//!
//! It exists because that answer is not the same as "call `item_from_tx`". Two
//! of the three pools drop transactions with transparent inputs, and one does
//! not, and the difference is a property of the verifier rather than of the
//! transaction:
//!
//! * Sapling's binding signature and RedJubjub's spend-auth signatures are
//!   bound to a sighash that folds in transparent prevouts. A bare transaction
//!   does not carry them, so the sighash we can reconstruct is the wrong one,
//!   both paths reject, and the input scores `Agree(false)`. That input is
//!   *reachable and has no discriminating power* — the worst thing a fuzz input
//!   can be, because it costs a real pairing check and can never separate the
//!   two paths.
//! * Sprout's Groth16 proof is not bound to a sighash at all, so the same
//!   transactions are perfectly good material there. 850 of the 2,032 seeds in
//!   the historical corpus have transparent inputs; filtering them at the corpus
//!   would throw away 40% of the Sprout material to serve the other two pools.
//!
//! `seeds-real/historical_419200_1046400/README.md` states the same rule from
//! the corpus side and asks the loader to enforce it. This module is that
//! loader, and it is shared by the fuzz targets and by
//! `examples/survey_fuzz_seeds.rs`, so the question "does this seed give this
//! target anything to check?" is answered by the same code that runs during
//! fuzzing rather than by a second copy of the rule.

use zebra_chain::transaction::Transaction;

use crate::redjubjub::{items_from_sapling_item, RedJubjubItem};
use crate::sapling::{item_from_tx as sapling_item_from_tx, SaplingItem};
use crate::sprout::{items_from_tx as sprout_items_from_tx, SproutItem};

/// Whether this transaction's sighash can be reconstructed from its own bytes.
///
/// False when it spends transparent inputs, whose prevouts a bare transaction
/// does not carry. Only the signature-bearing paths care.
fn sighash_is_reconstructable(tx: &Transaction) -> bool {
    tx.inputs().is_empty()
}

/// Sapling items for a fuzz input: at most one per transaction, and none at all
/// for transactions whose sighash cannot be reconstructed.
pub fn sapling_items(tx: &Transaction) -> Vec<SaplingItem> {
    if !sighash_is_reconstructable(tx) {
        return Vec::new();
    }
    sapling_item_from_tx(tx).into_iter().collect()
}

/// RedJubjub items for a fuzz input: the spend-auth and binding signatures of
/// the transaction's Sapling bundle, under the same sighash rule as
/// [`sapling_items`].
pub fn redjubjub_items(tx: &Transaction) -> Vec<RedJubjubItem> {
    if !sighash_is_reconstructable(tx) {
        return Vec::new();
    }
    sapling_item_from_tx(tx)
        .map(|item| items_from_sapling_item(&item))
        .unwrap_or_default()
}

/// Sprout items for a fuzz input: every Groth16 JoinSplit in the transaction.
///
/// No sighash rule here — see the module docs. A transaction with transparent
/// inputs is ordinary Sprout material.
pub fn sprout_items(tx: &Transaction) -> Vec<SproutItem> {
    sprout_items_from_tx(tx)
}
