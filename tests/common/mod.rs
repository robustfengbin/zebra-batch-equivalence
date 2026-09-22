//! Shared helpers for the integration-test suite.
//!
//! (`tests/common/` is the cargo-blessed pattern for cross-test-file helpers: it is
//! compiled into each test crate that declares `mod common;`, not run as its own suite.)

// Compiled into every test binary that declares `mod common;`; most use only a
// subset, so unused items are expected, not a smell.
#[allow(dead_code)]
pub mod synth;

use zebra_batch_equivalence::sapling::SaplingItem;
use zebra_batch_equivalence::sprout::SproutItem;
use zebra_batch_equivalence::{item_from_tx, item_from_tx_with_nu, OrchardItem};
use zebra_chain::{
    block::{Block, Height},
    parameters::{Network, NetworkUpgrade},
    serialization::{ZcashDeserialize, ZcashDeserializeInto},
    transaction::Transaction,
};

/// Every transparent-input-free pre-NU6.2 Orchard item from the in-tree mainnet vectors
/// (`zebra_test::vectors::MAINNET_BLOCKS`, blocks 1,687,107 / 118 / 121).
///
/// Transparent-input transactions are excluded: their ZIP-244 sighash folds in prevouts the
/// block vectors do not carry, so an empty-prevout sighash would not match and the bundle
/// would (correctly) fail to verify — that belongs to the adversarial path, not a valid
/// baseline.
#[allow(dead_code)] // not every test binary that declares `mod common;` reads the corpus
pub fn pre_nu6_2_corpus() -> Vec<OrchardItem> {
    let mut items = Vec::new();
    for bytes in zebra_test::vectors::MAINNET_BLOCKS.values() {
        let block: Block = bytes
            .zcash_deserialize_into()
            .expect("hard-coded mainnet test vector must deserialize");
        for tx in &block.transactions {
            if tx.orchard_shielded_data().is_none() || !tx.inputs().is_empty() {
                continue;
            }
            if let Some(item) = item_from_tx_with_nu(tx, NetworkUpgrade::Nu5) {
                items.push(item);
            }
        }
    }
    items
}

/// A sample of `n` items spread evenly across `items` — never a prefix.
///
/// Exists because `take(n)` is correct for exactly one corpus and silently wrong
/// for the next. The committed corpora are ordered by height and their
/// composition drifts along that axis, so a prefix is a biased sample that is
/// also perfectly reproducible and raises no error. A stride keeps whatever
/// range the corpus covers, so swapping the corpus underneath a test changes
/// how much it sees, not what kind of thing it sees.
///
/// Returns everything when `items.len() <= n`.
#[allow(dead_code)] // not every test binary that compiles `common` samples a corpus
pub fn spread<T>(items: &[T], n: usize) -> Vec<&T> {
    if n == 0 {
        return Vec::new();
    }
    if items.len() <= n {
        return items.iter().collect();
    }
    // Round rather than truncate, so the sample reaches the end of the corpus
    // instead of clustering toward its start.
    (0..n)
        .map(|k| &items[k * (items.len() - 1) / (n - 1).max(1)])
        .collect()
}

/// Every Sapling item reachable from the in-tree mainnet vectors, in height order.
///
/// These bundles sat in the repository unused throughout M1, whose extraction layer
/// only ever asked for Orchard. Each transaction is verified under the network
/// upgrade in force at its own height: a v5 transaction states its consensus branch
/// id and could answer for itself, but Sapling long predates v5, so the height is
/// the general answer.
///
/// Transparent-input transactions are excluded for the same reason M1 excludes them
/// from the Orchard corpus: their sighash folds in prevouts the block vectors do not
/// carry, so the sighash reconstructible here is not the one the bundle was signed
/// under, and it would fail for a reason that has nothing to do with batching.
#[allow(dead_code)] // not every test binary that compiles `common` uses this loader
pub fn in_tree_sapling_corpus() -> Vec<SaplingItem> {
    let mut items = Vec::new();

    for (height, bytes) in zebra_test::vectors::MAINNET_BLOCKS.iter() {
        let block: Block = bytes
            .zcash_deserialize_into()
            .expect("hard-coded mainnet test vector must deserialize");
        let nu = NetworkUpgrade::current(&Network::Mainnet, Height(*height));

        for tx in &block.transactions {
            if !tx.has_sapling_shielded_data() || !tx.inputs().is_empty() {
                continue;
            }
            if let Some(item) = zebra_batch_equivalence::sapling::item_from_tx_with_nu(tx, nu) {
                items.push(item);
            }
        }
    }
    items
}

/// Every Sapling item in the committed historical corpus
/// (`seeds-real/historical_419200_1046400/`, Sapling activation → Canopy), loaded
/// **in full**.
///
/// In full deliberately: the corpus README documents that pool composition drifts
/// monotonically across this window — Sprout is progressively displaced by Sapling —
/// so a prefix is not a sample. Signature verification is cheap enough per item that
/// the whole window is affordable, which removes the question.
///
/// The height comes from the filename because it cannot come from anywhere else: this
/// window spans Sapling → Blossom → Heartwood → Canopy, the sighash depends on which,
/// and a v4 transaction does not state its own consensus branch id.
///
/// Transparent-input transactions (850 of the 2,032 seeds) are excluded here for the
/// sighash reason above. They are kept in the corpus on purpose — Sprout's Groth16
/// proofs are not bound to a sighash at all, so that filter would only throw away
/// usable material on the proof side.
#[allow(dead_code)] // not every test binary that compiles `common` uses this loader
pub fn historical_sapling_corpus() -> Vec<SaplingItem> {
    historical_transactions()
        .iter()
        .filter(|(_, tx)| {
            // Both *are* filters: a transaction with no Sapling bundle has
            // nothing for this loader, and one with transparent inputs has a
            // sighash that cannot be reconstructed from the transaction alone.
            tx.has_sapling_shielded_data() && tx.inputs().is_empty()
        })
        .filter_map(|(nu, tx)| zebra_batch_equivalence::sapling::item_from_tx_with_nu(tx, *nu))
        .collect()
}

/// Every Sprout JoinSplit item in the committed historical corpus.
///
/// **No transparent-input filter**, unlike every other loader here. A Sprout
/// Groth16 proof is not bound to a sighash, so a transparent input cannot make
/// it fail — filtering on one would throw away usable material for no reason.
/// (The Ed25519 signature over the same JoinSplit *is* bound to a sighash. Same
/// pool, different item stream, different usability rule — which is why the
/// extraction layer splits per verifier rather than per pool.)
///
/// Only Groth16 JoinSplits: pre-Sapling history carries BCTV14 proofs that no
/// shipping verifier accepts, and counting those would overstate the corpus
/// several-fold.
#[allow(dead_code)] // not every test binary that compiles `common` uses this loader
pub fn historical_sprout_corpus() -> Vec<SproutItem> {
    historical_transactions()
        .iter()
        .flat_map(|(_, tx)| zebra_batch_equivalence::sprout::items_from_tx(tx))
        .collect()
}

/// Every transaction in the committed historical corpus
/// (`seeds-real/historical_419200_1046400/`, Sapling activation → Canopy), in
/// height order, each paired with the network upgrade in force at its height.
///
/// Loaded in full deliberately: the corpus README documents that pool
/// composition drifts monotonically across this window, so a prefix is not a
/// sample. Use [`spread`] to sample it.
///
/// The height comes from the filename because it cannot come from anywhere else:
/// this window spans Sapling → Blossom → Heartwood → Canopy, the sighash depends
/// on which, and a v4 transaction does not state its own consensus branch id.
#[allow(dead_code)] // not every test binary that compiles `common` uses this loader
pub fn historical_transactions() -> Vec<(NetworkUpgrade, Transaction)> {
    let dir = format!(
        "{}/seeds-real/historical_419200_1046400",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("historical corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    let mut out = Vec::with_capacity(files.len());
    for path in &files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("corpus filename is utf-8");
        // `v<version>_<zero-padded height>_<txid prefix>.bin`
        let height: u32 = name
            .split('_')
            .nth(1)
            .and_then(|h| h.parse().ok())
            .unwrap_or_else(|| panic!("corpus filename {name} carries no height"));
        let nu = NetworkUpgrade::current(&Network::Mainnet, Height(height));

        let bytes = std::fs::read(path).expect("read corpus file");
        // Not `continue`. These are bytes we committed ourselves, so a decode
        // failure is corrupt corpus or a wire-format drift, not a transaction
        // that fails to meet a condition. Skipping it would let the corpus
        // shrink silently while every assertion downstream still passed — and
        // the reported corpus size would then be a claim the code does not
        // make.
        let tx = Transaction::zcash_deserialize(&bytes[..])
            .unwrap_or_else(|e| panic!("corpus file {name} failed to deserialize: {e}"));
        out.push((nu, tx));
    }
    out
}

/// Every oracle-usable item from one committed `seeds-real/<dir>` era directory:
/// shielded-only transactions (the corpus tool's filter), loaded in file-name
/// order so sampled prefixes and folded windows are reproducible run-to-run.
/// The network upgrade (and so the sighash) comes from each transaction's own
/// consensus branch id.
#[allow(dead_code)] // not every test binary that compiles `common` uses this loader
pub fn seeds_real_corpus(dir_name: &str) -> Vec<OrchardItem> {
    let dir = format!("{}/seeds-real/{dir_name}", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    let mut items = Vec::new();
    for path in &files {
        let bytes = std::fs::read(path).expect("read corpus file");
        // Committed bytes: a decode failure is a broken corpus, not a seed that
        // fails a filter. See `historical_sapling_corpus` for why the two must
        // not share a `continue`.
        let tx = Transaction::zcash_deserialize(&bytes[..]).unwrap_or_else(|e| {
            panic!("corpus file {} failed to deserialize: {e}", path.display())
        });
        if !tx.inputs().is_empty() {
            continue;
        }
        if let Some(item) = item_from_tx(&tx) {
            items.push(item);
        }
    }
    items
}

/// Every item from every transaction under `seeds-real/<dir_name>`, **both
/// pools**.
///
/// The difference from [`seeds_real_corpus`] is the loader: that one calls
/// `item_from_tx`, which returns at most one item per transaction, so on a
/// corpus of v6 dual-pool transactions it keeps the Orchard bundle and silently
/// drops the Ironwood one. Every equivalence assertion downstream still passes —
/// on half the material, with nothing to indicate it.
///
/// `tests/nu6_3_agreement.rs` carries a test named for this exact trap. Use this
/// loader for any corpus that can carry Ironwood, and assert the pool counts
/// afterwards rather than trusting the choice of loader.
#[allow(dead_code)]
pub fn seeds_real_corpus_all_pools(dir_name: &str) -> Vec<OrchardItem> {
    let dir = format!("{}/seeds-real/{dir_name}", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed corpus dir {dir}: {e}"))
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
        if !tx.inputs().is_empty() {
            continue;
        }
        items.extend(zebra_batch_equivalence::items_from_tx(&tx));
    }
    items
}


// ---------------------------------------------------------------------------
// Item damage, shared rather than duplicated.
//
// These moved out of `tests/mutation_smoke.rs` when the cross-pool adversarial
// suite needed the same three mutations. Two copies of "how to damage a bundle"
// is how one of them keeps a subtlety the other loses -- the sighash mutant in
// particular is deliberately *not* the same thing as the binding-signature
// mutant (one damages the message, the other the signature over it), and that
// distinction survives only while there is one definition of each.
// ---------------------------------------------------------------------------

use orchard::bundle::Authorized;
use orchard::circuit::Proof;
use orchard::primitives::redpallas::{Binding, Signature};
use zebra_batch_equivalence::SigHash;

#[allow(dead_code)] // not every test binary that compiles `common` damages items
/// Clone `item` with its proof bytes passed through `mutate` (signatures untouched).
pub fn with_mutated_proof(item: &OrchardItem, mutate: impl FnOnce(&mut Vec<u8>)) -> OrchardItem {
    let bundle = item.bundle.clone().map_authorization(
        &mut (),
        |_, _, spend_auth| spend_auth,
        |_, auth: Authorized| {
            let mut bytes = auth.proof().as_ref().to_vec();
            mutate(&mut bytes);
            Authorized::from_parts(Proof::new(bytes), auth.binding_signature().clone())
        },
    );
    OrchardItem {
        bundle,
        sighash: SigHash(item.sighash.0),
        pool: item.pool,
    }
}

#[allow(dead_code)] // not every test binary that compiles `common` damages items
/// Clone `item` with one bit of its binding signature flipped (proof and sighash
/// untouched: the signature *body* is damaged, unlike the sighash mutant where a
/// well-formed signature is checked against the wrong message). Byte-level damage
/// only — systematic scalar/point perturbation generators are M2's deliverable.
pub fn with_mutated_binding_sig(item: &OrchardItem) -> OrchardItem {
    let bundle = item.bundle.clone().map_authorization(
        &mut (),
        |_, _, spend_auth| spend_auth,
        |_, auth: Authorized| {
            let mut bytes: [u8; 64] = auth.binding_signature().into();
            bytes[0] ^= 0x01;
            Authorized::from_parts(
                Proof::new(auth.proof().as_ref().to_vec()),
                Signature::<Binding>::from(bytes),
            )
        },
    );
    OrchardItem {
        bundle,
        sighash: SigHash(item.sighash.0),
        pool: item.pool,
    }
}

#[allow(dead_code)] // not every test binary that compiles `common` damages items
/// Clone `item` with one bit of its sighash flipped (bundle untouched: the binding
/// signature no longer matches the sighash handed to the validator).
pub fn with_mutated_sighash(item: &OrchardItem) -> OrchardItem {
    let mut sighash = item.sighash.0;
    sighash[0] ^= 0x01;
    OrchardItem {
        bundle: item.bundle.clone(),
        sighash: SigHash(sighash),
        pool: item.pool,
    }
}

