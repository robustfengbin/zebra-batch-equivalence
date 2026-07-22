//! Synthetic NU6.3-era vectors, shared across test files (ZCG #332 · W4e/f).
//!
//! Until real NU6.3 traffic exists (mainnet activation ~2026-07-28), orchard's
//! builder is the only source of NU6.3-era bundles: a cross-address-*disabled*
//! Orchard-pool bundle is unrepresentable in any pre-NU6.3 wire encoding, and
//! Ironwood-pool bundles only exist in v6 wire. Both vectors here are *real*
//! proofs under the PostNu6_3 circuit — synthetic provenance, not stubs.
//!
//! The two vectors share [`SYNTH_SIGHASH`], so together they model the two
//! bundles of one v6 transaction (one per pool, binding-signed over the same
//! ZIP-244 sighash) — which is exactly the shape the pool-dimension
//! differentials exercise.
//!
//! Each test binary that touches a vector pays one `ProvingKey::build` (tens of
//! seconds, `LazyLock`-cached per binary); binaries that never touch them pay
//! nothing.

use std::sync::LazyLock;

use orchard::builder::{Builder, BundleType};
use orchard::bundle::{BundleVersion, Flags};
use orchard::circuit::{OrchardCircuitVersion, ProvingKey};
use orchard::keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::tree::Anchor;
use orchard::value::NoteValue;
use rand::rngs::StdRng;
use rand::SeedableRng;

use zebra_batch_equivalence::{OrchardItem, Pool, SigHash, ZatBalance};

/// One PostNu6_3 proving key for every synthetic vector (build is the dominant
/// cost and all vectors prove under the same circuit).
static PROVING_KEY: LazyLock<ProvingKey> =
    LazyLock::new(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3));

/// The fixed sighash every synthesized binding signature commits to. Any 32
/// bytes work: the equivalence contract only needs `add_bundle` to receive the
/// same sighash the signature was produced over, mirroring how a real item
/// carries its ZIP-244 sighash. Shared by both vectors, so they model the two
/// bundles of a single v6 transaction.
pub const SYNTH_SIGHASH: [u8; 32] = [7u8; 32];

/// A real, provably-valid **Orchard-pool** bundle that *disables* cross-address
/// transfers: NU6.3-era Orchard pool semantics (`BundleVersion::orchard_v3`),
/// proven under the PostNu6_3 circuit, binding-signed over [`SYNTH_SIGHASH`].
pub fn disabled_orchard_item() -> &'static OrchardItem {
    static ITEM: LazyLock<OrchardItem> = LazyLock::new(|| {
        // Deterministic construction so any failure reproduces; proof randomness
        // does not affect the equivalence contract.
        let mut rng = StdRng::seed_from_u64(0x332_4e55_3633);

        let sk = SpendingKey::from_bytes([42; 32]).expect("fixed spending-key bytes are valid");
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        let anchor = Anchor::empty_tree();
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::orchard_v3(),
            Flags::CROSS_ADDRESS_DISABLED,
            anchor,
        )
        .expect("cross-address-disabled flags are valid for an NU6.3-era Orchard bundle");
        // A cross-address-disabled bundle admits no ordinary outputs (there is no
        // spender for them to "self"-transfer to); the legal shape is a
        // wallet-controlled change output, which the builder pairs with a
        // fabricated spend — ZIP 2006's self-transfer-only semantics for the
        // restricted pool.
        builder
            .add_change_output(fvk, None, recipient, NoteValue::from_raw(5000), [0u8; 512])
            .expect("wallet-controlled change output is accepted");

        let (unauthorized, _meta) = builder
            .build::<i64>(&mut rng)
            .expect("bundle builds")
            .expect("bundle is non-empty");
        assert_eq!(
            unauthorized.circuit_version(),
            OrchardCircuitVersion::PostNu6_3,
            "an NU6.3-era Orchard bundle must commit to the third circuit"
        );
        let proven = unauthorized
            .create_proof(&PROVING_KEY, &mut rng)
            .expect("proof creation succeeds");
        // The change output's fabricated spend is wallet-controlled: unlike a
        // dummy spend (self-signed inside the builder), it must be authorized by
        // the wallet's own key.
        let bundle = proven
            .apply_signatures(rng, SYNTH_SIGHASH, &[SpendAuthorizingKey::from(&sk)])
            .expect("signatures apply")
            .try_map_value_balance(ZatBalance::try_from)
            .expect("value balance is in range");

        assert!(
            !bundle.flags().cross_address_enabled(),
            "the synthesized bundle must carry the disabled cross-address flag"
        );
        OrchardItem {
            bundle,
            sighash: SigHash(SYNTH_SIGHASH),
            pool: Pool::Orchard,
        }
    });
    &ITEM
}

/// A real, provably-valid **Ironwood-pool** bundle: `BundleVersion::ironwood_v3`
/// shares the PostNu6_3 circuit (asserted at build), so the oracle's third era —
/// and only it — must accept this bundle. Unlike [`disabled_orchard_item`] it
/// keeps cross-address transfers enabled (the Ironwood pool permits them), so
/// under the two legacy keys it exercises the *verify-time* rejection path
/// rather than the add-time gate — the two synthetic vectors cover one
/// rejection layer each.
pub fn ironwood_item() -> &'static OrchardItem {
    static ITEM: LazyLock<OrchardItem> = LazyLock::new(|| {
        let mut rng = StdRng::seed_from_u64(0x1207_4e55_3633);

        let sk = SpendingKey::from_bytes([43; 32]).expect("fixed spending-key bytes are valid");
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        // Output-only shielding shape: spends disabled, so no spend-auth keys
        // are needed.
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::ironwood_v3(),
            Flags::SPENDS_DISABLED,
            Anchor::empty_tree(),
        )
        .expect("output-only flags are valid for an Ironwood bundle");
        builder
            .add_output(None, recipient, NoteValue::from_raw(5000), [0u8; 512])
            .expect("ordinary output is accepted: the Ironwood pool permits cross-address");

        let (unauthorized, _meta) = builder
            .build::<i64>(&mut rng)
            .expect("bundle builds")
            .expect("bundle is non-empty");
        assert_eq!(
            unauthorized.circuit_version(),
            OrchardCircuitVersion::PostNu6_3,
            "an Ironwood bundle must commit to the shared third circuit (the grant's \
             near-free premise for M3)"
        );
        let proven = unauthorized
            .create_proof(&PROVING_KEY, &mut rng)
            .expect("proof creation succeeds");
        let bundle = proven
            .apply_signatures(rng, SYNTH_SIGHASH, &[])
            .expect("signatures apply")
            .try_map_value_balance(ZatBalance::try_from)
            .expect("value balance is in range");

        OrchardItem {
            bundle,
            sighash: SigHash(SYNTH_SIGHASH),
            pool: Pool::Ironwood,
        }
    });
    &ITEM
}
