//! Batch⟺single agreement + era-routing over real **NU6.2 fixed-key** Orchard corpus
//! (ZCG #332 · M1).
//!
//! These are real mainnet Orchard transactions mined **after the June-5 NU6.2 hard-fork fix**
//! (heights ≥ 3,364,600), extracted from a synced Zebra node — the fixed-key era at the centre of
//! the incident this grant targets. Nothing in-tree carries NU6.2 proofs, so this is the only
//! real-data check of the post-fix verifier.
//!
//! Two assertions, both on real data:
//!   1. under the correct **NU6.2** key: batch and single agree, and both **accept**;
//!   2. under the wrong **pre-NU6.2** key: batch and single agree on **rejection** — real
//!      era-routing evidence that the verifier is not fail-open across the incident boundary.

use std::fs;

use orchard::circuit::OrchardCircuitVersion;
use zebra_batch_equivalence::{
    check_equivalence, item_from_tx, pre_nu6_2_key, verifying_key, EquivReport, OrchardItem,
};
use zebra_chain::{serialization::ZcashDeserialize, transaction::Transaction};

const BATCH_SIZE: usize = 16;

fn nu6_2_corpus() -> Vec<OrchardItem> {
    let dir = format!(
        "{}/seeds-real/orchard_v5_nu6_2",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("NU6.2 seed corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    let mut items = Vec::new();
    for path in &files {
        let bytes = fs::read(path).expect("read corpus file");
        let Ok(tx) = Transaction::zcash_deserialize(&bytes[..]) else {
            continue;
        };
        if let Some(item) = item_from_tx(&tx) {
            items.push(item);
        }
    }
    items
}

/// Real NU6.2 proofs verify under the fixed NU6.2 key, and batch agrees with single.
#[test]
fn nu6_2_real_proofs_agree_and_accept_under_fixed_key() {
    let items = nu6_2_corpus();
    assert!(!items.is_empty(), "must have real NU6.2 Orchard bundles under seeds-real/");

    let vk = verifying_key(OrchardCircuitVersion::FixedPostNu6_2);
    let mut batches = 0usize;
    let mut non_accept = 0usize;
    let mut disagreements = 0usize;

    for group in items.chunks(BATCH_SIZE) {
        batches += 1;
        match check_equivalence(group, &vk, 0xF00D) {
            EquivReport::Agree(true) => {}
            EquivReport::Agree(false) => non_accept += 1,
            other => {
                disagreements += 1;
                eprintln!("EQUIVALENCE VIOLATION (NU6.2 key) batch {batches}: {other:?}");
            }
        }
    }

    eprintln!(
        "NU6.2 fixed-key: {} bundles, {batches} batches, {non_accept} non-accept, {disagreements} disagreements",
        items.len()
    );
    assert_eq!(disagreements, 0, "batch/single must agree on the real NU6.2 corpus");
    assert_eq!(
        non_accept, 0,
        "real NU6.2 mainnet proofs must be ACCEPTED under the fixed NU6.2 key"
    );
}

/// Era-routing on real data: NU6.2 proofs are rejected under the pre-NU6.2 key, and batch/single
/// agree on that rejection (not fail-open across the incident boundary).
#[test]
fn nu6_2_proofs_agree_reject_under_pre_nu6_2_key() {
    let items = nu6_2_corpus();
    let wrong_key = pre_nu6_2_key();

    for (i, group) in items.chunks(BATCH_SIZE).enumerate() {
        let report = check_equivalence(group, &wrong_key, 0xF00D);
        assert_eq!(
            report,
            EquivReport::Agree(false),
            "NU6.2 proofs under the pre-NU6.2 key must agree-reject (batch {i}); got {report:?} \
             — a batch accepting here would be a fail-open false-accept across the NU6.2 fix"
        );
    }
}
