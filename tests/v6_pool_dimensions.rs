//! v6 / NU6.3 **pool-dimension** differentials (ZCG #332 · W4a/b).
//!
//! NU6.3 (Ironwood) makes the pool a real dimension of the verification
//! surface: a v6 transaction may carry an Orchard-pool *and* an Ironwood-pool
//! bundle (same bundle type, same PostNu6_3 circuit, same batch stack), and the
//! `enableCrossAddress` flag becomes legal — but only on the Ironwood side.
//! Three new differential dimensions, each asserted rather than assumed:
//!
//! * **cross-pool mixed batches** — Orchard-pool and Ironwood-pool items in one
//!   batch must preserve `batch ⟺ single` under every era key, in every order;
//! * **two bundles of one transaction** — the pools of a single v6 tx share one
//!   ZIP-244 sighash; extraction must yield one item per bundle, and the items
//!   must agree whether they are verified in separate batches or the same one;
//! * **cross-address parse differential** — a *wire* encoding that puts the
//!   cross-address bit on the Orchard pool must be rejected at parse, on real
//!   v5 mainnet bytes and on the v6 codec alike, so no such bundle can ever
//!   reach either verification path (fail-closed at the parse layer).
//!
//! Provably-valid vectors come from `common::synth` (real PostNu6_3 proofs);
//! structural v6 wire shapes come from zebra-chain's `fake_v6_*` helpers
//! (canonical layout, cryptographically invalid — upstream's tooling for
//! structural consensus-rule tests).

mod common;

use common::synth;
use zebra_batch_equivalence::{
    check_equivalence_refs, items_from_tx_stream, items_from_tx_with_nu, CircuitEra, EquivReport,
    OrchardItem, Pool, MAX_BATCH_ITEMS,
};
use zebra_chain::amount::{Amount, NegativeAllowed};
use zebra_chain::block::Block;
use zebra_chain::ironwood;
use zebra_chain::orchard::{Flags, ShieldedDataV6};
use zebra_chain::parameters::NetworkUpgrade;
use zebra_chain::serialization::{ZcashDeserializeInto, ZcashSerialize};
use zebra_chain::transaction::arbitrary::{fake_v6_orchard_shielded_data, fake_v6_transaction};
use zebra_chain::transaction::Transaction;

/// A structural v6 transaction with one bundle in **each** pool (upstream's
/// `fake_v6_*` helpers; canonical wire layout, cryptographically invalid).
fn fake_two_bundle_tx() -> Transaction {
    let zero: Amount<NegativeAllowed> = Amount::try_from(0).expect("zero is a valid amount");
    let orchard = ShieldedDataV6::new(fake_v6_orchard_shielded_data(
        Flags::ENABLE_SPENDS | Flags::ENABLE_OUTPUTS,
        zero,
        1,
    ));
    let ironwood = ironwood::ShieldedData::new(ShieldedDataV6::new(
        fake_v6_orchard_shielded_data(Flags::ENABLE_SPENDS, zero, 2),
    ));
    fake_v6_transaction(NetworkUpgrade::Nu6_3, Some(orchard), Some(ironwood))
}

/// Cross-pool mixed batch: one provably-valid bundle from each pool in a single
/// batch. Under the shared NU6.3 key both are genuinely proven, so the batch
/// must accept on both paths — in either pool order. Under each legacy key the
/// mixed batch must fail *closed* on both paths (the Orchard-pool member is
/// rejected at add time, the Ironwood member at verify time — aggregation must
/// not let either layer mask the other).
#[test]
fn cross_pool_batch_agrees_under_every_era_in_every_order() {
    let orchard_item = synth::disabled_orchard_item();
    let ironwood_item = synth::ironwood_item();
    assert_eq!(orchard_item.pool, Pool::Orchard);
    assert_eq!(ironwood_item.pool, Pool::Ironwood);

    for (name, batch) in [
        ("orchard-first", [orchard_item, ironwood_item]),
        ("ironwood-first", [ironwood_item, orchard_item]),
    ] {
        for era in CircuitEra::ALL {
            let expected = if era == CircuitEra::Nu6_3Onward {
                EquivReport::Agree(true)
            } else {
                EquivReport::Agree(false)
            };
            let report = check_equivalence_refs(&batch, era.key(), 0x9001);
            assert_eq!(
                report, expected,
                "cross-pool batch ({name}) under {era:?}: expected {expected:?}, got {report:?}"
            );
        }
    }
}

/// The two synthetic vectors share one sighash — they model the two bundles of
/// a single v6 transaction. Verified in separate batches and in one shared
/// batch, the outcomes must agree: batching the two bundles of one tx together
/// (as `items_from_tx_stream` naturally does) must be indistinguishable from
/// verifying them apart.
#[test]
fn two_bundles_of_one_tx_agree_separately_and_together() {
    let orchard_item = synth::disabled_orchard_item();
    let ironwood_item = synth::ironwood_item();
    assert_eq!(
        orchard_item.sighash.0, ironwood_item.sighash.0,
        "test premise: one transaction = one shared ZIP-244 sighash for both bundles"
    );

    let vk = CircuitEra::Nu6_3Onward.key();
    let seed = 0x9002;
    assert_eq!(
        check_equivalence_refs(&[orchard_item], vk, seed),
        EquivReport::Agree(true),
        "the tx's Orchard-pool bundle must verify in its own batch"
    );
    assert_eq!(
        check_equivalence_refs(&[ironwood_item], vk, seed),
        EquivReport::Agree(true),
        "the tx's Ironwood-pool bundle must verify in its own batch"
    );
    assert_eq!(
        check_equivalence_refs(&[orchard_item, ironwood_item], vk, seed),
        EquivReport::Agree(true),
        "both bundles of the tx in ONE batch must agree with the separate-batch outcomes"
    );
}

/// Extraction yields one item per bundle with the right pool annotation, for
/// all three v6 bundle arrangements, and both items of a two-bundle tx carry
/// the same ZIP-244 sighash.
#[test]
fn v6_extraction_yields_one_item_per_bundle_with_pool_annotation() {
    let zero: Amount<NegativeAllowed> = Amount::try_from(0).expect("zero is a valid amount");

    // Orchard-only v6 tx → exactly one Orchard-pool item.
    let orchard_only = fake_v6_transaction(
        NetworkUpgrade::Nu6_3,
        Some(ShieldedDataV6::new(fake_v6_orchard_shielded_data(
            Flags::ENABLE_SPENDS | Flags::ENABLE_OUTPUTS,
            zero,
            1,
        ))),
        None,
    );
    let items = items_from_tx_with_nu(&orchard_only, NetworkUpgrade::Nu6_3);
    assert_eq!(items.len(), 1, "orchard-only v6 tx yields one item");
    assert_eq!(items[0].pool, Pool::Orchard);

    // Ironwood-only v6 tx → exactly one Ironwood-pool item.
    let ironwood_only = fake_v6_transaction(
        NetworkUpgrade::Nu6_3,
        None,
        Some(ironwood::ShieldedData::new(ShieldedDataV6::new(
            fake_v6_orchard_shielded_data(Flags::ENABLE_SPENDS, zero, 1),
        ))),
    );
    let items = items_from_tx_with_nu(&ironwood_only, NetworkUpgrade::Nu6_3);
    assert_eq!(items.len(), 1, "ironwood-only v6 tx yields one item");
    assert_eq!(items[0].pool, Pool::Ironwood);

    // Two-bundle v6 tx → two items, Orchard first, one shared sighash.
    let both = fake_two_bundle_tx();
    let items = items_from_tx_with_nu(&both, NetworkUpgrade::Nu6_3);
    assert_eq!(items.len(), 2, "two-bundle v6 tx yields one item per bundle");
    assert_eq!(items[0].pool, Pool::Orchard);
    assert_eq!(items[1].pool, Pool::Ironwood);
    assert_eq!(
        items[0].sighash.0, items[1].sighash.0,
        "both bundles of one tx share its ZIP-244 sighash"
    );
    assert_eq!(
        items[1].action_count(),
        2,
        "the Ironwood item is the two-action bundle, not a re-read of the Orchard one"
    );
}

/// The fuzz input model counts items per **bundle**, not per transaction: a
/// stream of two-bundle v6 transactions yields two items each, alternating
/// pools, and the batch cap truncates mid-transaction rather than overshooting.
#[test]
fn stream_counts_items_per_bundle_and_truncates_at_the_cap() {
    let tx_bytes = fake_two_bundle_tx()
        .zcash_serialize_to_vec()
        .expect("two-bundle v6 tx serializes");

    // One tx: two items, Orchard first (wire order).
    let items = items_from_tx_stream(&tx_bytes);
    assert_eq!(items.len(), 2, "one v6 tx contributes one item per bundle");
    assert_eq!(items[0].pool, Pool::Orchard);
    assert_eq!(items[1].pool, Pool::Ironwood);

    // A one-bundle tx followed by 16 two-bundle txs = 33 bundles. The final tx
    // is entered with 31 items on board (< cap), so its Orchard bundle lands as
    // item #32 and its Ironwood twin is truncated mid-transaction — the cap
    // bounds bundles, not transactions, without overshooting.
    let zero: Amount<NegativeAllowed> = Amount::try_from(0).expect("zero is a valid amount");
    let single_tx_bytes = fake_v6_transaction(
        NetworkUpgrade::Nu6_3,
        Some(ShieldedDataV6::new(fake_v6_orchard_shielded_data(
            Flags::ENABLE_SPENDS | Flags::ENABLE_OUTPUTS,
            zero,
            1,
        ))),
        None,
    )
    .zcash_serialize_to_vec()
    .expect("orchard-only v6 tx serializes");

    let mut stream = single_tx_bytes;
    stream.extend_from_slice(&tx_bytes.repeat(16));
    let items = items_from_tx_stream(&stream);
    assert_eq!(
        items.len(),
        MAX_BATCH_ITEMS,
        "the cap bounds items (bundles), not transactions"
    );
    assert_eq!(
        items[MAX_BATCH_ITEMS - 1].pool,
        Pool::Orchard,
        "the last item is the final tx's Orchard bundle — its Ironwood twin fell past the cap"
    );
    assert_eq!(
        items[MAX_BATCH_ITEMS - 2].pool,
        Pool::Ironwood,
        "the item before it is the previous tx's Ironwood bundle (alternation intact)"
    );
}

/// The structurally-fake two-bundle tx is cryptographically invalid, so under
/// every era key BOTH paths must reject every arrangement of its items — each
/// bundle alone and the cross-pool pair. A one-sided outcome (either direction)
/// on garbage-proof v6 items would be a real harness finding: the paths must
/// stay in lock-step on reject as well as accept.
#[test]
fn fake_v6_two_bundle_tx_rejects_consistently_under_every_era() {
    let tx = fake_two_bundle_tx();
    let items = items_from_tx_with_nu(&tx, NetworkUpgrade::Nu6_3);
    assert_eq!(items.len(), 2, "test premise: one item per pool");

    let arrangements: [Vec<&OrchardItem>; 3] = [
        vec![&items[0]],
        vec![&items[1]],
        vec![&items[0], &items[1]],
    ];
    for (i, refs) in arrangements.iter().enumerate() {
        for era in CircuitEra::ALL {
            let report = check_equivalence_refs(refs, era.key(), 0x9003 + i as u64);
            assert_eq!(
                report,
                EquivReport::Agree(false),
                "fake-proof v6 items (arrangement #{i}) under {era:?} must be rejected \
                 in lock-step by BOTH paths; got {report:?}"
            );
        }
    }
}

/// v6 codec: the cross-address bit on the **Orchard** pool is rejected at
/// parse — the wire layer is the guard that keeps such a bundle from ever
/// reaching either verification path (`items_from_tx_stream` yields nothing:
/// vacuous, fail-closed agreement). The same bit on the **Ironwood** pool is
/// legal: it round-trips and extraction hands the verifier a cross-address
/// item. This anchors upstream's wire guard into the oracle's contract — if
/// the guard ever regresses, the Orchard arm here goes red.
#[test]
fn cross_address_bit_rejects_on_orchard_pool_and_round_trips_on_ironwood() {
    let zero: Amount<NegativeAllowed> = Amount::try_from(0).expect("zero is a valid amount");

    // Orchard pool + cross-address bit: serializes (the struct is constructible
    // in memory) but must NOT deserialize.
    let bad = fake_v6_transaction(
        NetworkUpgrade::Nu6_3,
        Some(ShieldedDataV6::new(fake_v6_orchard_shielded_data(
            Flags::ENABLE_SPENDS | Flags::ENABLE_OUTPUTS | Flags::ENABLE_CROSS_ADDRESS,
            zero,
            1,
        ))),
        None,
    );
    let bytes = bad
        .zcash_serialize_to_vec()
        .expect("in-memory struct serializes");
    assert!(
        bytes
            .zcash_deserialize_into::<Transaction>()
            .is_err(),
        "cross-address bit on the Orchard pool must be rejected by the v6 wire parser"
    );
    assert!(
        items_from_tx_stream(&bytes).is_empty(),
        "the extraction pipeline must yield no verifiable item from such bytes \
         (fail-closed at parse, before either verification path exists)"
    );

    // Ironwood pool + cross-address bit: legal — round-trips and extracts.
    let good = fake_v6_transaction(
        NetworkUpgrade::Nu6_3,
        None,
        Some(ironwood::ShieldedData::new(ShieldedDataV6::new(
            fake_v6_orchard_shielded_data(
                Flags::ENABLE_SPENDS | Flags::ENABLE_OUTPUTS | Flags::ENABLE_CROSS_ADDRESS,
                zero,
                1,
            ),
        ))),
    );
    let bytes = good
        .zcash_serialize_to_vec()
        .expect("ironwood cross-address tx serializes");
    let reparsed: Transaction = bytes
        .zcash_deserialize_into()
        .expect("the same bit on the Ironwood pool is wire-legal");
    let items = items_from_tx_with_nu(&reparsed, NetworkUpgrade::Nu6_3);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].pool, Pool::Ironwood);
    assert!(
        items[0].cross_address_enabled(),
        "extraction must hand the verifier the cross-address flag it will constrain"
    );
}

/// Real-corpus arm of the parse differential: take genuine v5 mainnet wire
/// bytes and set the (v5-reserved) cross-address bit in the Orchard `flagsOrchard`
/// field — deserialization must fail, so the mutated bytes can never produce a
/// verification item. The flag byte's offset is derived from ZIP-225's layout
/// (the Orchard section ends the v5 transaction) and self-checked against the
/// parsed flags before mutation, so a layout drift fails loudly rather than
/// flipping the wrong byte.
#[test]
fn real_v5_wire_with_cross_address_bit_rejects_at_parse() {
    let mut checked = 0usize;
    for block_bytes in zebra_test::vectors::MAINNET_BLOCKS.values() {
        let block: Block = block_bytes
            .zcash_deserialize_into()
            .expect("hard-coded mainnet test vector must deserialize");
        for tx in &block.transactions {
            let Some(shielded) = tx.orchard_shielded_data() else {
                continue;
            };
            let wire = tx
                .zcash_serialize_to_vec()
                .expect("parsed mainnet tx re-serializes");

            // ZIP-225 v5 layout, tail of the transaction (the Orchard section):
            //   flagsOrchard(1) ‖ valueBalanceOrchard(8) ‖ anchorOrchard(32) ‖
            //   sizeProofsOrchard(compactSize) ‖ proofsOrchard ‖
            //   vSpendAuthSigsOrchard(64·nActions) ‖ bindingSigOrchard(64)
            let n_actions = shielded.actions.len();
            let proof_len = shielded.proof.0.len();
            let compact_size_len = match proof_len {
                0..=0xFC => 1,
                0xFD..=0xFFFF => 3,
                _ => 5,
            };
            let tail_after_flags = 8 + 32 + compact_size_len + proof_len + 64 * n_actions + 64;
            let flags_pos = wire.len() - tail_after_flags - 1;

            // Self-check the derived offset before trusting it.
            assert_eq!(
                wire[flags_pos],
                shielded.flags.bits(),
                "derived flagsOrchard offset must land on the parsed flags byte \
                 (ZIP-225 layout drift?)"
            );

            let mut mutated = wire;
            mutated[flags_pos] |= Flags::ENABLE_CROSS_ADDRESS.bits();
            assert!(
                mutated.zcash_deserialize_into::<Transaction>().is_err(),
                "the cross-address bit is unrepresentable in v5 wire: parsing must reject"
            );
            assert!(
                items_from_tx_stream(&mutated).is_empty(),
                "no verification item may be extracted from the mutated bytes"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "the in-tree mainnet vectors must contain at least one Orchard transaction"
    );
}
