//! The three M3 turnstile properties, against the real post-NU6.3 corpus.
//!
//! Grant wording, which is the specification:
//!
//! > "turnstile/migration soundness target (conservation, no double-migration,
//! > no forged residual value crossing)"
//!
//! The first test here is not a soundness assertion at all — it fixes the
//! *ruler*. The obvious reading of conservation is rejected by every legitimate
//! migration on mainnet, so it is written down as a test rather than left as a
//! remark: anyone who later "simplifies" the check to that form gets told why
//! it does not work, by the corpus, instead of getting a red suite and going
//! looking for a bug in Zebra.

use std::fs;

use zebra_batch_equivalence::turnstile::{
    check_conservation, Conservation, Indeterminacy, Pool, TurnstileState, TurnstileViolation,
};
use zebra_chain::amount::{Amount, NegativeAllowed};
use zebra_chain::ironwood;
use zebra_chain::orchard::{Flags, ShieldedDataV6};
use zebra_chain::parameters::NetworkUpgrade;
use zebra_chain::serialization::{ZcashDeserialize, ZcashDeserializeInto};
use zebra_chain::transaction::arbitrary::{fake_v6_orchard_shielded_data, fake_v6_transaction};
use zebra_chain::{block::Block, transaction::Transaction};

const CORPUS: &str = "nu6_3_activation";

/// Every transaction in the committed NU6.3 corpus, with its file name, in
/// file-name order so a run is reproducible.
fn corpus() -> Vec<(String, Transaction)> {
    let dir = format!("{}/seeds-real/{CORPUS}", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("NU6.3 seed corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    files
        .iter()
        .map(|path| {
            let bytes = fs::read(path).expect("read corpus file");
            // A decode failure is a broken corpus, not a filtered seed: a
            // silently shrinking corpus is how a run stays green while covering
            // less than it claims.
            let tx = Transaction::zcash_deserialize(&bytes[..]).unwrap_or_else(|e| {
                panic!("corpus file {} failed to deserialize: {e}", path.display())
            });
            let label = path.file_name().unwrap().to_string_lossy().into_owned();
            (label, tx)
        })
        .collect()
}

/// **The ruler, not the property.**
///
/// "A migration conserves value" read as "the two pool balances cancel" is
/// rejected by every dual-pool transaction on mainnet. This asserts that, so
/// the reason the real check is shaped the way it is stays attached to the
/// evidence: the fee is what the two balances do not account for.
#[test]
fn the_obvious_conservation_rule_rejects_every_real_migration() {
    let txs = corpus();
    let mut dual = 0;
    let mut cancelling = 0;

    for (_, tx) in &txs {
        if !(tx.has_orchard_shielded_data() && tx.has_ironwood_shielded_data()) {
            continue;
        }
        dual += 1;
        let o: i64 = tx.orchard_value_balance().orchard_amount().into();
        let i: i64 = tx.ironwood_value_balance().ironwood_amount().into();
        if o + i == 0 {
            cancelling += 1;
        }
    }

    assert!(
        dual >= 70,
        "corpus must carry the dual-pool population this reasoning rests on; got {dual}"
    );
    assert_eq!(
        cancelling, 0,
        "{cancelling} of {dual} dual-pool transactions have cancelling pool balances. \
         If this ever stops being zero the corpus has changed shape, and the note in \
         `turnstile`'s module docs about why conservation is stated over all pools \
         needs re-checking against the new corpus rather than trusted."
    );
}

/// Conservation, as actually specified: every shielded pool, less what leaves
/// transparently, is the fee — and the fee is not negative.
#[test]
fn conservation_holds_over_the_real_corpus() {
    let txs = corpus();
    let mut fees = Vec::new();
    let mut indeterminate = 0;

    for (label, tx) in &txs {
        match check_conservation(tx) {
            Conservation::Holds { fee } => fees.push(fee),
            Conservation::Violated { implied_fee } => {
                panic!("{label}: value not conserved, implied fee {implied_fee}")
            }
            Conservation::Indeterminate(_) => indeterminate += 1,
        }
    }

    // The corpus filter drops transparent-input transactions, so every one of
    // these is decidable. Asserting that keeps "all passed" distinguishable
    // from "most were skipped" — the two are the same green otherwise.
    assert_eq!(
        indeterminate,
        0,
        "{indeterminate} of {} transactions could not be evaluated; conservation was \
         asserted over the rest and the pass means less than it appears to",
        txs.len()
    );
    assert_eq!(fees.len(), txs.len());
    assert!(
        fees.iter().all(|f| *f > 0),
        "a zero or negative fee means value left without being accounted for"
    );
    // ZIP-317's conventional fee is `marginal_fee * max(grace_actions,
    // logical_actions)` with marginal_fee = 5000 zatoshi and grace_actions = 2,
    // so it is always a multiple of 5000. Consensus does not *require* that —
    // a transaction may pay any fee — so this is not a rule being enforced
    // here. It is a cross-check that the arithmetic above is measuring a fee
    // and not an artefact: an off-by-one in the value-balance signs, or a
    // transparent output missed, would land on an arbitrary number rather than
    // on the grid real wallets pay on.
    assert!(
        fees.iter().all(|f| f % 5000 == 0),
        "implied fees should be multiples of 5000 zatoshi; got {:?}",
        fees.iter().filter(|f| *f % 5000 != 0).collect::<Vec<_>>()
    );
}

/// A transaction that spends transparently cannot have its fee computed here,
/// and must be reported as such rather than passed.
#[test]
fn transparent_inputs_are_indeterminate_not_a_pass() {
    let mut seen_any = false;
    for bytes in zebra_test::vectors::MAINNET_BLOCKS.values() {
        let block: Block = bytes
            .zcash_deserialize_into()
            .expect("hard-coded mainnet test vector must deserialize");
        for tx in &block.transactions {
            if tx.inputs().is_empty() {
                continue;
            }
            seen_any = true;
            assert!(
                matches!(
                    check_conservation(tx),
                    Conservation::Indeterminate(Indeterminacy::TransparentInputs(n)) if n > 0
                ),
                "a transaction with transparent inputs must not be reported as conserving: \
                 its inputs' values are in outputs this crate never sees"
            );
        }
    }
    assert!(
        seen_any,
        "in-tree mainnet vectors carry no transparent-input transaction, so this test \
         asserted nothing"
    );
}

/// The real corpus passes the turnstile: no double spends, no cross-pool
/// nullifier reuse, no pool driven negative.
#[test]
fn real_corpus_passes_the_turnstile() {
    let mut state = TurnstileState::mid_chain();
    for (label, tx) in &corpus() {
        let violations = state.admit(tx, label);
        assert!(
            violations.is_empty(),
            "{label}: real mainnet transaction violated the turnstile: {violations:?}"
        );
    }
    let (checked, seen) = state.coverage();
    assert_eq!(checked, seen, "every transaction should be decidable here");
    assert!(state.total_fees() > 0);
}

/// Replaying the corpus through one turnstile must report every nullifier as
/// already spent. This is what the accumulated state exists for: no single
/// transaction can see the repeat, so a per-transaction check would call the
/// replay clean.
#[test]
fn replaying_the_corpus_is_caught_as_double_spending() {
    let txs = corpus();
    let mut state = TurnstileState::mid_chain();
    for (label, tx) in &txs {
        assert!(state.admit(tx, label).is_empty());
    }

    let mut double_spends = 0;
    for (label, tx) in &txs {
        for v in state.admit(tx, &format!("{label}#replay")) {
            if matches!(v, TurnstileViolation::DoubleSpend { .. }) {
                double_spends += 1;
            }
        }
    }

    // Every nullifier in the corpus, seen a second time.
    let expected: usize = txs
        .iter()
        .map(|(_, tx)| tx.orchard_nullifiers().count() + tx.ironwood_nullifiers().count())
        .sum();
    assert_eq!(
        double_spends, expected,
        "a replay must be caught nullifier-for-nullifier"
    );
}

/// Cross-pool nullifier reuse: the real corpus contains no instance.
///
/// This is the corpus having no carrier, **not** the property holding — the two
/// produce the same green. Recorded as its own test so the distinction is
/// written down where someone reading a passing suite will see it, and so the
/// day a corpus does carry one, this is the test that changes.
#[test]
fn real_corpus_carries_no_cross_pool_nullifier_carrier() {
    let mut state = TurnstileState::mid_chain();
    let mut reuse = 0;
    for (label, tx) in &corpus() {
        for v in state.admit(tx, label) {
            if matches!(v, TurnstileViolation::CrossPoolNullifierReuse { .. }) {
                reuse += 1;
            }
        }
    }
    assert_eq!(
        reuse, 0,
        "found cross-pool nullifier reuse in real mainnet data. Upstream's per-pool \
         duplicate checks do not catch this shape (zebra-chain/src/ironwood.rs:20-23 \
         allows the bit patterns to coincide), so this would need reporting, not fixing here."
    );
}

/// The same corpus, told it starts at genesis, is reported as taking value out
/// of an empty pool.
///
/// This is the mistake that shaped [`Origin`], kept as a test: the corpus is
/// 172 valid mainnet transactions, and under the wrong starting assumption the
/// turnstile reports a violation on the first file. Without this test `Origin`
/// is just a flag nobody can show does anything; with it, the failure mode it
/// prevents is on the record and stays reachable.
#[test]
fn a_mid_chain_corpus_told_it_starts_at_genesis_reports_a_floor_violation() {
    let mut state = TurnstileState::from_genesis();
    let mut floor_violations = 0;
    for (label, tx) in &corpus() {
        for v in state.admit(tx, label) {
            if matches!(v, TurnstileViolation::PoolBalanceNegative { .. }) {
                floor_violations += 1;
            }
        }
    }
    assert!(
        floor_violations > 0,
        "the NU6.3 corpus opens millions of blocks into the chain, so under a \
         genesis assumption it must report pool balances going negative. If this \
         is ever zero, either the corpus changed or the floor check stopped \
         running -- and the mid-chain tests above would not notice either."
    );
}

/// One v6 transaction with only an Ironwood bundle, moving `value_balance` out
/// of the pool (positive) or into it (negative).
fn ironwood_only_tx(value_balance: i64) -> Transaction {
    let vb: Amount<NegativeAllowed> =
        Amount::try_from(value_balance).expect("in-range amount");
    let ironwood = ironwood::ShieldedData::new(ShieldedDataV6::new(
        fake_v6_orchard_shielded_data(Flags::ENABLE_SPENDS | Flags::ENABLE_OUTPUTS, vb, 1),
    ));
    fake_v6_transaction(NetworkUpgrade::Nu6_3, None, Some(ironwood))
}

fn floor_violations(violations: &[TurnstileViolation]) -> Vec<&TurnstileViolation> {
    violations
        .iter()
        .filter(|v| matches!(v, TurnstileViolation::PoolBalanceNegative { .. }))
        .collect()
}

/// The floor check stays quiet while a pool holds what leaves it, and fires on
/// the first zatoshi that leaves beyond that.
///
/// The test above only shows the check firing, and a check that always fires
/// passes it too: with the floor condition replaced by `true`, every other
/// test in this file stays green. "No forged residual value crossing" is one of
/// the three properties the grant names, so it needs the passing direction as
/// well, and on the same run as the failing one.
///
/// The fixtures are upstream's structural helpers, so conservation reports on
/// them are beside the point here (value entering from nowhere is
/// `ValueCreated`, tested separately); only the floor is under test.
#[test]
fn the_floor_holds_while_a_pool_covers_its_outflow_and_fires_beyond_it() {
    let mut state = TurnstileState::from_genesis();

    let into = state.admit(&ironwood_only_tx(-100_000), "constructed:into-ironwood");
    assert!(floor_violations(&into).is_empty(), "value entering an empty pool: {into:?}");

    let covered = state.admit(&ironwood_only_tx(60_000), "constructed:out-60k");
    assert!(
        floor_violations(&covered).is_empty(),
        "60,000 out of a pool holding 100,000 must not breach the floor: {covered:?}"
    );
    assert_eq!(state.pool_balances(), (0, 40_000));

    let beyond = state.admit(&ironwood_only_tx(60_000), "constructed:out-another-60k");
    let floor = floor_violations(&beyond);
    assert_eq!(
        floor.len(),
        1,
        "60,000 out of a pool holding 40,000 must breach the floor once: {beyond:?}"
    );
    assert!(
        matches!(
            floor[0],
            TurnstileViolation::PoolBalanceNegative { pool: Pool::Ironwood, balance: -20_000 }
        ),
        "wrong pool or balance: {floor:?}"
    );
}

/// A constructed carrier for cross-pool nullifier reuse: one v6 transaction
/// whose Ironwood bundle repeats a nullifier from its Orchard bundle.
///
/// The two bundles are upstream's `fake_v6_*` structural helpers — canonical
/// wire layout, cryptographically invalid, which is exactly right here: this
/// asks whether the turnstile *notices* the shape, and a real proof would only
/// make the fixture expensive without making the question different.
fn tx_with_shared_nullifier_across_pools() -> Transaction {
    let zero: Amount<NegativeAllowed> = Amount::try_from(0).expect("zero is a valid amount");
    let orchard = ShieldedDataV6::new(fake_v6_orchard_shielded_data(
        Flags::ENABLE_SPENDS | Flags::ENABLE_OUTPUTS,
        zero,
        1,
    ));
    let mut ironwood_inner = ShieldedDataV6::new(fake_v6_orchard_shielded_data(
        Flags::ENABLE_SPENDS,
        zero,
        1,
    ));

    // Copy the Orchard bundle's nullifier into the Ironwood bundle. The two
    // pools reuse the same nullifier construction (`ironwood::Nullifier` is a
    // newtype over `orchard::Nullifier`), so this is a bit pattern that could
    // in principle appear in both -- which is the case upstream's comment
    // leaves open.
    let shared = orchard
        .data()
        .actions()
        .next()
        .expect("fake bundle has at least one action")
        .nullifier;
    for authorized in ironwood_inner.data_mut().actions.iter_mut() {
        authorized.action.nullifier = shared;
    }

    fake_v6_transaction(
        NetworkUpgrade::Nu6_3,
        Some(orchard),
        Some(ironwood::ShieldedData::new(ironwood_inner)),
    )
}

/// The turnstile catches cross-pool nullifier reuse that upstream's own
/// duplicate checks do not.
///
/// `spend_conflicts` runs `check_for_duplicates` over the Orchard and Ironwood
/// nullifier sets independently, so a value in both is not a duplicate to it.
/// This is the carrier the real corpus does not contain -- and without it,
/// `real_corpus_carries_no_cross_pool_nullifier_carrier` passing would be
/// equally consistent with the detector not working at all.
#[test]
fn a_constructed_cross_pool_carrier_is_caught() {
    let tx = tx_with_shared_nullifier_across_pools();
    let mut state = TurnstileState::mid_chain();
    let violations = state.admit(&tx, "constructed:cross-pool-nullifier");

    assert!(
        violations
            .iter()
            .any(|v| matches!(v, TurnstileViolation::CrossPoolNullifierReuse { .. })),
        "constructed carrier was not caught; got {violations:?}"
    );
}

/// The same construction *without* the shared nullifier is clean, so the test
/// above is detecting the reuse rather than the fixture.
#[test]
fn the_same_fixture_without_reuse_is_clean() {
    let zero: Amount<NegativeAllowed> = Amount::try_from(0).expect("zero is a valid amount");
    let orchard = ShieldedDataV6::new(fake_v6_orchard_shielded_data(
        Flags::ENABLE_SPENDS | Flags::ENABLE_OUTPUTS,
        zero,
        1,
    ));
    let ironwood = ironwood::ShieldedData::new(ShieldedDataV6::new(
        fake_v6_orchard_shielded_data(Flags::ENABLE_SPENDS, zero, 1),
    ));
    let tx = fake_v6_transaction(NetworkUpgrade::Nu6_3, Some(orchard), Some(ironwood));

    let mut state = TurnstileState::mid_chain();
    let violations = state.admit(&tx, "constructed:no-reuse");
    assert!(
        !violations
            .iter()
            .any(|v| matches!(v, TurnstileViolation::CrossPoolNullifierReuse { .. })),
        "an unmodified two-bundle fixture must not report cross-pool reuse: {violations:?}"
    );
}

/// Value created out of nothing is caught.
///
/// Every other violation variant reaches a test through either the real corpus
/// or a construction; this one has no natural carrier, because a transaction
/// that creates value does not exist on mainnet. Without a constructed one,
/// `ValueCreated` would be a branch nothing has ever taken — and a detector
/// that has never fired is indistinguishable from one that cannot.
#[test]
fn a_transaction_that_creates_value_is_caught() {
    // A negative Orchard value balance moves value *into* the pool. With no
    // transparent output and nothing paying for it, the implied fee is
    // negative: more value ends up inside than went in.
    let minus: Amount<NegativeAllowed> =
        Amount::try_from(-100_000).expect("in-range negative amount");
    let orchard = ShieldedDataV6::new(fake_v6_orchard_shielded_data(
        Flags::ENABLE_SPENDS | Flags::ENABLE_OUTPUTS,
        minus,
        1,
    ));
    let tx = fake_v6_transaction(NetworkUpgrade::Nu6_3, Some(orchard), None);

    assert_eq!(
        check_conservation(&tx),
        Conservation::Violated {
            implied_fee: -100_000
        },
        "a transaction whose pools gain more than anything pays for must not conserve"
    );

    let mut state = TurnstileState::mid_chain();
    let violations = state.admit(&tx, "constructed:value-created");
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, TurnstileViolation::ValueCreated { .. })),
        "got {violations:?}"
    );
}

/// Every `TurnstileViolation` variant is reachable by some test in this file.
///
/// Not a property of the code under test — a property of this suite. A variant
/// no test constructs is a branch that has never run, and the suite reports the
/// same green whether that branch works or not. Written as a list rather than
/// derived, so adding a variant without a test is a compile error here.
#[test]
fn every_violation_variant_has_a_test() {
    fn exhaustive(v: &TurnstileViolation) -> &'static str {
        match v {
            // a_transaction_that_creates_value_is_caught
            TurnstileViolation::ValueCreated { .. } => "ValueCreated",
            // replaying_the_corpus_is_caught_as_double_spending
            TurnstileViolation::DoubleSpend { .. } => "DoubleSpend",
            // a_constructed_cross_pool_carrier_is_caught
            TurnstileViolation::CrossPoolNullifierReuse { .. } => "CrossPoolNullifierReuse",
            // the_floor_holds_while_a_pool_covers_its_outflow_and_fires_beyond_it
            // (both directions), and
            // a_mid_chain_corpus_told_it_starts_at_genesis_reports_a_floor_violation
            TurnstileViolation::PoolBalanceNegative { .. } => "PoolBalanceNegative",
        }
    }
    // The match above is exhaustive, so this compiles only while every variant
    // is named with the test that reaches it.
    let _ = exhaustive;
}

/// A third sighting still names the *first* transaction.
///
/// `HashMap::insert` returns the old value and replaces it, so the obvious
/// implementation makes `first_seen` name the previous sighting rather than the
/// first one — wrong exactly when the history being reported is longest. A
/// replay test that feeds the corpus twice cannot tell the difference; this one
/// feeds it three times.
#[test]
fn first_seen_names_the_first_sighting_not_the_previous_one() {
    let txs = corpus();
    let (label, tx) = txs.first().expect("corpus is not empty");
    let mut state = TurnstileState::mid_chain();

    assert!(state.admit(tx, "pass-1").is_empty());
    let second = state.admit(tx, "pass-2");
    let third = state.admit(tx, "pass-3");

    for (round, violations) in [("second", &second), ("third", &third)] {
        let firsts: Vec<&String> = violations
            .iter()
            .filter_map(|v| match v {
                TurnstileViolation::DoubleSpend { first_seen, .. } => Some(first_seen),
                _ => None,
            })
            .collect();
        assert!(
            !firsts.is_empty(),
            "{round} sighting of {label} reported no double spend"
        );
        assert!(
            firsts.iter().all(|f| *f == "pass-1"),
            "{round} sighting should name pass-1 as first_seen; got {firsts:?}"
        );
    }
}

/// Which nullifiers the turnstile flags as double-spent must not depend on the
/// order transactions arrive in.
///
/// This is the turnstile's version of the property the rest of this crate is
/// built on. `invariants::order_independence` asks it of a batch verifier's
/// verdict; here it is asked of accumulated state, where the mechanism that
/// could break it is different: a `HashMap` whose insertion order decides what
/// gets reported.
///
/// **What must not change is the set of (pool, nullifier) pairs reported.**
/// `first_seen` and `again_in` *must* change with the order -- they name
/// transactions, and which one came first is exactly what the order decides.
/// Asserting on the whole violation would fail for the right reason and teach
/// the wrong lesson, so the comparison is on the part that is order-invariant
/// and the part that is not is named here rather than silently dropped.
///
/// The corpus is fed twice so there is something to find: on its own it is
/// clean, and a property about which violations are reported is untestable
/// against zero violations.
///
/// Three fixed permutations rather than a seeded shuffle: the orders are then
/// part of the test rather than of a random-number generator's behaviour, and a
/// failure names an order someone can reconstruct by reading.
#[test]
fn the_reported_double_spends_do_not_depend_on_arrival_order() {
    use std::collections::BTreeSet;

    let corpus = corpus();
    let sample: Vec<&(String, Transaction)> = corpus.iter().take(20).collect();
    assert!(sample.len() >= 10, "need a few transactions");

    // Every transaction twice, so every nullifier in the sample is a double
    // spend regardless of how the halves are interleaved.
    let doubled: Vec<&(String, Transaction)> =
        sample.iter().chain(sample.iter()).copied().collect();

    let orders: [(&str, Vec<usize>); 3] = [
        ("forward", (0..doubled.len()).collect()),
        ("reverse", (0..doubled.len()).rev().collect()),
        (
            "evens-then-odds",
            (0..doubled.len())
                .filter(|k| k % 2 == 0)
                .chain((0..doubled.len()).filter(|k| k % 2 == 1))
                .collect(),
        ),
    ];

    let mut results = Vec::new();
    for (name, order) in &orders {
        let mut state = TurnstileState::mid_chain();
        let mut flagged: BTreeSet<(String, [u8; 32])> = BTreeSet::new();
        for (position, &k) in order.iter().enumerate() {
            let (label, tx) = doubled[k];
            for v in state.admit(tx, &format!("{label}@{position}")) {
                if let TurnstileViolation::DoubleSpend {
                    pool, nullifier, ..
                } = v
                {
                    flagged.insert((format!("{pool:?}"), nullifier));
                }
            }
        }
        assert!(
            !flagged.is_empty(),
            "order {name} reported no double spend over a corpus fed twice; the \
             property below would then hold vacuously"
        );
        results.push((*name, flagged));
    }

    let (first_name, first) = &results[0];
    for (name, flagged) in &results[1..] {
        assert_eq!(
            flagged, first,
            "order {name} flagged a different set of nullifiers than {first_name}"
        );
    }
}
