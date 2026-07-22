//! Drift anchor for the hand-mirrored era routing (ZCG #332 · W5).
//!
//! `era::CircuitEra::from_network_upgrade` mirrors Zebra's
//! `zebra_consensus::primitives::halo2::orchard_v5_verifier_for` (and the NU6.3-onward
//! constant routing of `orchard_v6_verifier`) **by hand** — this crate deliberately does
//! not depend on `zebra-consensus` (it would drag half a node into the build). A hand
//! mirror can silently rot: if upstream rebinds an upgrade to a different verifying key,
//! nothing here would fail while the oracle quietly verifies under the wrong era.
//!
//! This test pins the mirrored source. It reads the pinned Zebra checkout (the same
//! `../zebra` path dependency the whole crate builds against), extracts both routing
//! functions, normalizes away comments/whitespace, and asserts:
//!
//! 1. an FNV-1a fingerprint of each normalized function body matches the recorded
//!    baseline — ANY upstream change to the routing text turns this red, forcing a human
//!    to re-check `src/era.rs` and then update the baseline in the same commit (an
//!    auditable acknowledgement trail);
//! 2. the load-bearing arms are literally present (readable first-line diagnostics, and
//!    a guard against a pathological same-fingerprint rewrite).
//!
//! This is the *correctness anchor*: is our hand-mirrored copy still faithful to the
//! pinned upstream?

use std::fs;
use std::path::PathBuf;

/// FNV-1a over the normalized function text. Stable, dependency-free, and independent of
/// the oracle's own seed derivation (this is an anchor, not an RNG seed).
fn fnv1a(data: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The pinned Zebra checkout this crate builds against (the `../zebra` path dependency).
fn upstream_halo2_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../zebra/zebra-consensus/src/primitives/halo2.rs");
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read the pinned Zebra checkout at {}: {e}. The anchor (and the whole \
             crate) requires the `../zebra` path dependency to be checked out at the \
             pinned revision (see README / ci.yml ZEBRA_REV).",
            path.display()
        )
    })
}

/// Extracts a top-level `fn` item: from its signature to the brace that closes its body.
/// (Neither anchored function contains braces inside string literals, so plain brace
/// counting is exact; if upstream ever adds one, the fingerprint changes anyway and the
/// human re-baselining will notice.)
fn extract_fn(source: &str, signature: &str) -> String {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` not found in upstream halo2.rs — the routing \
                                   function was renamed or removed; re-audit src/era.rs"));
    let body = &source[start..];
    let mut depth = 0usize;
    let mut opened = false;
    for (i, c) in body.char_indices() {
        match c {
            '{' => {
                depth += 1;
                opened = true;
            }
            '}' => {
                depth -= 1;
                if opened && depth == 0 {
                    return body[..=i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces extracting `{signature}`");
}

/// Comment- and whitespace-insensitive view of the function: doc/format churn does not
/// trip the anchor, code changes do. `#[cfg(...)]` lines are semantic and are kept.
fn normalize(src: &str) -> String {
    src.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Baseline fingerprints of the normalized routing functions at the pinned base
/// (`57ddc3132`, Zebra v6.0.0). When upstream changes the routing:
/// 1. this test goes red and prints the new fingerprint;
/// 2. diff the upstream function, decide whether `src/era.rs` must follow;
/// 3. update `src/era.rs` (if needed) and this baseline **in the same commit**.
const V5_ROUTING_FINGERPRINT: u64 = 0xb1f2_b778_7517_d002;
const V6_ROUTING_FINGERPRINT: u64 = 0x92a2_7692_a412_7cfd;

#[test]
fn upstream_v5_era_routing_is_unchanged() {
    let source = upstream_halo2_source();
    let normalized = normalize(&extract_fn(
        &source,
        "pub fn orchard_v5_verifier_for(network_upgrade: NetworkUpgrade)",
    ));

    // Load-bearing arms, asserted literally for first-glance diagnostics.
    for arm in [
        "| Nu6 | Nu6_1 => &VERIFIER_PRE_NU6_2",
        "Nu6_2 => &VERIFIER_NU6_2",
        "Nu6_3 | Nu7 => &VERIFIER_NU6_3_ONWARD",
        "ZFuture => &VERIFIER_NU6_3_ONWARD",
    ] {
        assert!(
            normalized.contains(arm),
            "expected routing arm `{arm}` is gone from upstream orchard_v5_verifier_for — \
             re-audit src/era.rs::from_network_upgrade before touching this test"
        );
    }

    let fingerprint = fnv1a(&normalized);
    assert_eq!(
        fingerprint, V5_ROUTING_FINGERPRINT,
        "upstream orchard_v5_verifier_for changed (normalized FNV-1a fingerprint \
         {fingerprint:#018x}). Diff the function, re-check src/era.rs mirrors it, then \
         update V5_ROUTING_FINGERPRINT in the same commit.\n--- normalized ---\n{normalized}"
    );
}

#[test]
fn upstream_v6_era_routing_is_unchanged() {
    let source = upstream_halo2_source();
    let normalized = normalize(&extract_fn(
        &source,
        "pub fn orchard_v6_verifier()",
    ));

    assert!(
        normalized.contains("&VERIFIER_NU6_3_ONWARD"),
        "orchard_v6_verifier no longer routes to the NU6.3-onward verifier — v6/Ironwood \
         bundles moved off the shared key; re-audit src/era.rs and the W4 pool handling"
    );

    let fingerprint = fnv1a(&normalized);
    assert_eq!(
        fingerprint, V6_ROUTING_FINGERPRINT,
        "upstream orchard_v6_verifier changed (normalized FNV-1a fingerprint \
         {fingerprint:#018x}). Diff the function, re-check src/era.rs, then update \
         V6_ROUTING_FINGERPRINT in the same commit.\n--- normalized ---\n{normalized}"
    );
}
