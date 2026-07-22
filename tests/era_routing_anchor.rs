//! Era-routing faithfulness anchor (ZCG #332 · W5).
//!
//! [`CircuitEra::from_network_upgrade`] mirrors Zebra's
//! `zebra_consensus::primitives::halo2::orchard_v5_verifier_for` (and the
//! NU6.3-onward constant routing of `orchard_v6_verifier`) **by hand** — this
//! crate deliberately does not depend on `zebra-consensus`, which would drag half
//! a node into the build. A hand mirror can silently rot: route an upgrade to the
//! wrong verifying key and nothing else here fails, while the oracle quietly
//! verifies under the wrong era (wrong key / fail-open / mixed-era batch — a plain
//! glue-logic mistake, not a negligible-probability cryptographic one).
//!
//! This anchor is the *correctness* check. It pins the **expected** mapping —
//! upstream's routing at the grant base revision (Zebra v6.2.0,
//! `135c1361914cf1759d63953e5175b36b195f0873`) — as an independent ground-truth
//! table transcribed by hand from the upstream source, and asserts the mirror
//! reproduces it over **every** [`NetworkUpgrade`]. The table is deliberately a
//! *separate copy*, not derived from `src/era.rs`, so a wrong edit to the mirror
//! makes the two disagree and turns this red.
//!
//! Self-contained by design: it reads no external source, so `cargo test` needs
//! no local Zebra checkout (Zebra is a pinned git dependency). Whether *upstream
//! itself* changes its routing is a distinct concern that only matters when the
//! pinned revision is bumped; it is re-verified by hand at that time (see the note
//! below), not on every build.
//!
//! **When bumping the grant base revision:** re-read upstream's two routing
//! functions at the new revision and update `src/era.rs` and the [`expected_era`]
//! table below to match, in the same commit that bumps the pin — an auditable
//! acknowledgement trail.

use zebra_batch_equivalence::CircuitEra;
use zebra_chain::parameters::NetworkUpgrade;

/// The Orchard circuit era each network upgrade routes to at the pinned base
/// revision, transcribed by hand from upstream `orchard_v5_verifier_for` and the
/// constant routing of `orchard_v6_verifier` (which binds v6 Orchard and Ironwood
/// to the NU6.3-onward key). This is **independent ground truth** — it is not
/// `src/era.rs`, so the two can be compared for divergence.
///
/// Upstream arms at the pin:
/// * `Genesis ..= Nu5 | Nu6 | Nu6_1 => VERIFIER_PRE_NU6_2` — Orchard exists from
///   NU5; every pre-NU6.2 upgrade re-verifies under the original (insecure) key.
/// * `Nu6_2 => VERIFIER_NU6_2` — the fixed circuit, active NU6.2 until NU6.3.
/// * `Nu6_3 | Nu7 => VERIFIER_NU6_3_ONWARD` — the fixed circuit plus the
///   `disableCrossAddress` constraint; every Orchard Action from NU6.3 onward.
/// * `ZFuture => VERIFIER_NU6_3_ONWARD` — post-NU6.3, inherits the NU6.3 circuit.
fn expected_era(nu: NetworkUpgrade) -> CircuitEra {
    use NetworkUpgrade::*;
    match nu {
        Genesis | BeforeOverwinter | Overwinter | Sapling | Blossom | Heartwood | Canopy | Nu5
        | Nu6 | Nu6_1 => CircuitEra::PreNu6_2,
        Nu6_2 => CircuitEra::Nu6_2,
        Nu6_3 | Nu7 => CircuitEra::Nu6_3Onward,
        #[cfg(zcash_unstable = "zfuture")]
        ZFuture => CircuitEra::Nu6_3Onward,
    }
}

/// Every `NetworkUpgrade` this build knows. A new upgrade added upstream is a
/// compile error in both [`expected_era`] and `CircuitEra::from_network_upgrade`
/// (both are exhaustive `match`es with no wildcard) until it is bound to an era
/// deliberately — so this list cannot silently fall behind the enum.
fn all_network_upgrades() -> Vec<NetworkUpgrade> {
    use NetworkUpgrade::*;
    #[allow(unused_mut)]
    let mut upgrades = vec![
        Genesis,
        BeforeOverwinter,
        Overwinter,
        Sapling,
        Blossom,
        Heartwood,
        Canopy,
        Nu5,
        Nu6,
        Nu6_1,
        Nu6_2,
        Nu6_3,
        Nu7,
    ];
    #[cfg(zcash_unstable = "zfuture")]
    upgrades.push(ZFuture);
    upgrades
}

/// The mirror reproduces the pinned upstream routing for every network upgrade.
/// A wrong edit to `src/era.rs::from_network_upgrade` diverges from the
/// independently-transcribed [`expected_era`] table here and fails this test.
#[test]
fn mirror_matches_pinned_upstream_routing_for_every_upgrade() {
    for nu in all_network_upgrades() {
        let mirror = CircuitEra::from_network_upgrade(nu);
        let expected = expected_era(nu);
        assert_eq!(
            mirror, expected,
            "era-routing mirror diverged from pinned upstream for {nu:?}: \
             src/era.rs routes it to {mirror:?}, but upstream \
             orchard_v5_verifier_for/orchard_v6_verifier pins it to {expected:?}. \
             Re-audit src/era.rs against upstream at the grant base revision."
        );
    }
}

/// The boundaries that actually shift verifying keys, asserted explicitly for
/// first-glance diagnostics: the June-5 pre-NU6.2 key, the NU6.2 fix, and the
/// NU6.3-onward cross-address era that v5-at-NU6.3, v6 Orchard, and Ironwood share.
#[test]
fn load_bearing_era_boundaries() {
    use NetworkUpgrade::*;
    assert_eq!(CircuitEra::from_network_upgrade(Nu5), CircuitEra::PreNu6_2);
    assert_eq!(CircuitEra::from_network_upgrade(Nu6_1), CircuitEra::PreNu6_2);
    assert_eq!(CircuitEra::from_network_upgrade(Nu6_2), CircuitEra::Nu6_2);
    assert_eq!(CircuitEra::from_network_upgrade(Nu6_3), CircuitEra::Nu6_3Onward);
    assert_eq!(CircuitEra::from_network_upgrade(Nu7), CircuitEra::Nu6_3Onward);
}
