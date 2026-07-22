//! Orchard circuit eras: the three verifying keys, their cross-address
//! capability, and the block-era routing that picks a key.
//!
//! The Orchard Action circuit — and therefore its verifying key — changed across
//! network upgrades, and a proof produced under one circuit does not verify
//! under another. There are three eras:
//!
//! * **pre-NU6.2** (`InsecurePreNu6_2`) — the original, under-constrained circuit
//!   the June-5 2026 incident lived in. Retained so pre-soft-fork Orchard history
//!   still re-verifies on resync.
//! * **NU6.2** (`FixedPostNu6_2`) — the fixed circuit shipped in the NU6.2 hard
//!   fork.
//! * **NU6.3-onward** (`PostNu6_3`) — the fixed circuit plus the
//!   `disableCrossAddress` constraint (ZIP 229). v5 Orchard at NU6.3, v6 Orchard,
//!   and Ironwood bundles all share this key.
//!
//! Routing depends on the **block's** network upgrade, not the transaction
//! version. Getting it wrong is one of the few Orchard bugs that is *not* a
//! negligible-probability cryptographic event but a plain glue-logic mistake
//! (wrong key, fail-open, mixed-era batch) — exactly what the equivalence oracle
//! should catch. This module mirrors the production routing in
//! `zebra_consensus::primitives::halo2::orchard_v5_verifier_for` so the oracle
//! checks against the same mapping.

use std::sync::OnceLock;

use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
use zebra_chain::parameters::NetworkUpgrade;

/// The three Orchard circuit eras a bundle can belong to. A batch must never mix
/// eras: each era commits to a different circuit and verifying key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitEra {
    /// NU5..NU6.2 — the original, under-constrained circuit (the June-5 bug
    /// lived here). Retained so pre-soft-fork Orchard history re-verifies.
    PreNu6_2,
    /// NU6.2..NU6.3 — the fixed circuit.
    Nu6_2,
    /// NU6.3 onward — the fixed circuit plus the `disableCrossAddress`
    /// constraint. v5 Orchard at NU6.3, v6 Orchard, and Ironwood share this.
    Nu6_3Onward,
}

impl CircuitEra {
    /// All three eras, for exhaustive coverage.
    pub const ALL: [CircuitEra; 3] = [Self::PreNu6_2, Self::Nu6_2, Self::Nu6_3Onward];

    /// The orchard circuit version this era commits to.
    pub fn circuit_version(self) -> OrchardCircuitVersion {
        match self {
            Self::PreNu6_2 => OrchardCircuitVersion::InsecurePreNu6_2,
            Self::Nu6_2 => OrchardCircuitVersion::FixedPostNu6_2,
            Self::Nu6_3Onward => OrchardCircuitVersion::PostNu6_3,
        }
    }

    /// Whether this era's circuit constrains the cross-address restriction. Only
    /// NU6.3-onward does; adding a cross-address-*disabled* bundle under an
    /// earlier era's key is rejected at `add_bundle` (fail-closed) — a property
    /// the era-routing invariant checks.
    pub fn supports_cross_address_restriction(self) -> bool {
        self.circuit_version().supports_cross_address_restriction()
    }

    /// Route a block's network upgrade to its Orchard circuit era, mirroring
    /// `zebra_consensus::primitives::halo2::orchard_v5_verifier_for`. This is the
    /// exact production routing the oracle must agree with. The match is
    /// exhaustive on purpose: a future upgrade is a compile error here until it
    /// is bound to an era deliberately.
    pub fn from_network_upgrade(nu: NetworkUpgrade) -> CircuitEra {
        use NetworkUpgrade::*;
        match nu {
            // Orchard did not exist before NU5; these never carry Orchard bundles
            // and route to the only key any pre-NU6.2 Orchard history verifies
            // under.
            Genesis | BeforeOverwinter | Overwinter | Sapling | Blossom | Heartwood | Canopy
            | Nu5 | Nu6 | Nu6_1 => Self::PreNu6_2,
            Nu6_2 => Self::Nu6_2,
            Nu6_3 | Nu7 => Self::Nu6_3Onward,
            #[cfg(zcash_unstable = "zfuture")]
            ZFuture => Self::Nu6_3Onward,
        }
    }

    /// The cached verifying key for this era. `VerifyingKey::build` is a
    /// multi-second cold start, so each era's key is built once and reused for
    /// the life of the process.
    pub fn key(self) -> &'static VerifyingKey {
        match self {
            Self::PreNu6_2 => {
                static K: OnceLock<VerifyingKey> = OnceLock::new();
                K.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::InsecurePreNu6_2))
            }
            Self::Nu6_2 => {
                static K: OnceLock<VerifyingKey> = OnceLock::new();
                K.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2))
            }
            Self::Nu6_3Onward => {
                static K: OnceLock<VerifyingKey> = OnceLock::new();
                K.get_or_init(|| VerifyingKey::build(OrchardCircuitVersion::PostNu6_3))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_matches_production_boundaries() {
        assert_eq!(CircuitEra::from_network_upgrade(NetworkUpgrade::Nu5), CircuitEra::PreNu6_2);
        assert_eq!(CircuitEra::from_network_upgrade(NetworkUpgrade::Nu6_1), CircuitEra::PreNu6_2);
        assert_eq!(CircuitEra::from_network_upgrade(NetworkUpgrade::Nu6_2), CircuitEra::Nu6_2);
        assert_eq!(
            CircuitEra::from_network_upgrade(NetworkUpgrade::Nu6_3),
            CircuitEra::Nu6_3Onward
        );
    }

    #[test]
    fn only_nu6_3_constrains_cross_address() {
        assert!(!CircuitEra::PreNu6_2.supports_cross_address_restriction());
        assert!(!CircuitEra::Nu6_2.supports_cross_address_restriction());
        assert!(CircuitEra::Nu6_3Onward.supports_cross_address_restriction());
    }
}
