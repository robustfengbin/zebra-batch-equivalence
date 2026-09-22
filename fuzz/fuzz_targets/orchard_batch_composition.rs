//! Orchard **batch-composition** equivalence harness (M1).
//!
//! Where the primary target checks the batch as-is, this one deliberately
//! *re-shapes* the batch and asserts `batch ⟺ single` survives every shape. The
//! batching glue is where composition bugs hide — an off-by-one in the queue, a
//! mishandled empty/singleton, an aggregation that is not permutation-invariant.
//! All bundles are real and valid; only their arrangement changes, so any
//! disagreement is a composition bug, not an input artifact.
//!
//! Shapes exercised, each asserted `batch(shape) == AND(single over shape)`:
//!
//!   * **empty** — an empty batch validates (`true`); the empty single-AND is
//!     also `true`. A verifier that rejected the empty batch would diverge.
//!   * **singleton** — a one-element batch equals that single.
//!   * **every prefix sub-batch** — soundness is compositional: an agreeing whole
//!     cannot contain a disagreeing part.
//!   * **reversed / rotated order** — permutation-invariance of the boolean.
//!   * **duplicated** — `[a,b]` vs `[a,b,a,b]`.
//!
//! The trailing control byte picks the circuit-era key (low bits) and the pool
//! composition being re-shaped (bits 6-7: mixed / Orchard-only / Ironwood-only).
//!
//! A false-accept in any shape panics.

#![no_main]

use libfuzzer_sys::fuzz_target;

use zebra_batch_equivalence::invariants::{
    check_duplicate_consistency, check_order_invariance, check_subbatch_consistency,
    InvariantViolation,
};
use zebra_batch_equivalence::{
    check_equivalence_refs, derive_seed, items_from_tx_stream, CircuitEra, EquivReport, OrchardItem,
    Pool,
};

fuzz_target!(init: {
    // Before libFuzzer's per-input clock starts. See
    // `zebra_batch_equivalence::era::warm_verifying_keys` for why: without it the
    // first unit of every run pays three multi-second circuit key builds and is
    // reported as a `-timeout=25` crash, blaming an input that is fine.
    zebra_batch_equivalence::era::warm_verifying_keys();
}, |data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (stream, control) = data.split_at(data.len() - 1);
    let era = CircuitEra::ALL[control[0] as usize % CircuitEra::ALL.len()];
    let vk = era.key();
    let seed = derive_seed(data);

    let items = items_from_tx_stream(stream);
    if items.is_empty() {
        return;
    }
    // Pool-dimension parameterisation (W4a): control bits 6-7 pick the pool
    // composition to re-shape (0b01 Orchard-only, 0b10 Ironwood-only, else
    // mixed); the era bits (`% 3`) keep their pre-v6 meaning byte-for-byte.
    let refs: Vec<&OrchardItem> = match control[0] >> 6 {
        0b01 => items.iter().filter(|i| i.pool == Pool::Orchard).collect(),
        0b10 => items.iter().filter(|i| i.pool == Pool::Ironwood).collect(),
        _ => items.iter().collect(),
    };
    if refs.is_empty() {
        return;
    }

    // Empty batch: must validate on both paths (Agree(true)).
    if check_equivalence_refs(&[], vk, seed) != EquivReport::Agree(true) {
        panic!("ORCHARD COMPOSITION: empty batch is not vacuously valid, era={era:?}");
    }

    // Singleton: each single-element batch equals its single (a floor case, but
    // a good regression sentinel for queue handling).
    for item in &refs {
        let one = [*item];
        report(check_equivalence_refs(&one, vk, seed), "singleton", era, seed);
    }

    // Full batch base case.
    report(check_equivalence_refs(&refs, vk, seed), "full", era, seed);

    // Every prefix sub-batch stays consistent (compositionality).
    for v in check_subbatch_consistency(&refs, vk, seed) {
        escalate(v, era, seed);
    }

    // Order-independence and duplicate-consistency.
    if let Some(v) = check_order_invariance(&refs, vk, seed) {
        escalate(v, era, seed);
    }
    if let Some(v) = check_duplicate_consistency(&refs, vk, seed) {
        escalate(v, era, seed);
    }
});

fn report(r: EquivReport, shape: &str, era: CircuitEra, seed: u64) {
    match r {
        EquivReport::FalseAccept => panic!(
            "ORCHARD COMPOSITION FALSE-ACCEPT in {shape} shape — counterfeiting-class. \
             era={era:?}, seed={seed:#x}"
        ),
        EquivReport::FalseReject => {
            eprintln!("orchard composition false-reject ({shape}), era={era:?}, seed={seed:#x}")
        }
        EquivReport::Agree(_) => {}
    }
}

fn escalate(v: InvariantViolation, era: CircuitEra, seed: u64) {
    if v.is_critical() {
        panic!("ORCHARD COMPOSITION VIOLATION (critical): {v:?}, era={era:?}, seed={seed:#x}");
    } else {
        eprintln!("orchard composition invariant (liveness): {v:?}, era={era:?}");
    }
}
