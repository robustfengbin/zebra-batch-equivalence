//! Orchard `batch ⟺ single` equivalence — the primary soundness harness (M1).
//!
//! Input: a stream of concatenated V5+/V6 transaction wire bytes + a trailing
//! control byte selecting the circuit-era key (low bits, `% 3`) and the batch's
//! pool composition (bits 6-7: mixed / Orchard-only / Ironwood-only — a v6 tx
//! can carry a bundle of each pool). Every Orchard-protocol bundle becomes one
//! item; the selected items form one batch, checked under the full invariant
//! sweep.
//!
//! Unlike the coverage-guided predecessor (which only asserted panic-freedom —
//! "we do not assert verify=Ok"), every check here asserts a soundness property
//! and escalates a violation. Each is a differential over the *same* valid
//! bundles, so a failure is a real batching-glue bug, not an input artifact:
//!
//!   * **base equivalence** — batch(N) must equal AND(single_i). `batch Ok /
//!     some single rejects` is a false-accept: the counterfeiting-class break.
//!   * **order-independence** — the batch boolean must not depend on bundle
//!     order (orchard draws random scalars per queued position; a flip is
//!     unsound aggregation).
//!   * **duplicate-consistency** — duplicating bundles must not change agreement.
//!   * **era-routing / not-fail-open** — under every *wrong* circuit-era key the
//!     batch must be rejected by both paths, never accepted.
//!
//! false-accept / order-dependence / fail-open panic (libFuzzer captures the
//! reproducer); false-reject is logged.

#![no_main]

use libfuzzer_sys::fuzz_target;

use zebra_batch_equivalence::invariants::{
    check_duplicate_consistency, check_era_routing, check_order_invariance, InvariantViolation,
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
    let control = control[0];

    let items = items_from_tx_stream(stream);
    if items.is_empty() {
        return;
    }
    // Pool-dimension parameterisation (W4a): control bits 6-7 select the batch's
    // pool composition — 0b01 Orchard-only, 0b10 Ironwood-only, else every item
    // (mixed cross-pool batch). Era selection below (`% 3` over the same byte) is
    // untouched, so every pre-v6 corpus input behaves exactly as before.
    let refs: Vec<&OrchardItem> = match control >> 6 {
        0b01 => items.iter().filter(|i| i.pool == Pool::Orchard).collect(),
        0b10 => items.iter().filter(|i| i.pool == Pool::Ironwood).collect(),
        _ => items.iter().collect(),
    };
    if refs.is_empty() {
        return;
    }
    let seed = derive_seed(data);

    // Explore all three era keys — not only a corpus's native era.
    let era = CircuitEra::ALL[control as usize % CircuitEra::ALL.len()];
    let vk = era.key();

    // 1. Base equivalence.
    escalate_equivalence(check_equivalence_refs(&refs, vk, seed), &refs, era, seed);

    // 2. Order-independence.
    if let Some(v) = check_order_invariance(&refs, vk, seed) {
        escalate_violation(v, &refs, era, seed);
    }

    // 3. Duplicate-consistency.
    if let Some(v) = check_duplicate_consistency(&refs, vk, seed) {
        escalate_violation(v, &refs, era, seed);
    }

    // 4. Era-routing / not-fail-open (wrong keys must reject both paths).
    for v in check_era_routing(&refs, era, seed) {
        escalate_violation(v, &refs, era, seed);
    }
});

fn escalate_equivalence(report: EquivReport, items: &[&OrchardItem], era: CircuitEra, seed: u64) {
    match report {
        EquivReport::FalseAccept => panic!(
            "ORCHARD BATCH FALSE-ACCEPT: batch accepted a set single verification rejects — \
             counterfeiting-class soundness failure. era={era:?}, items={}, seed={seed:#x}",
            items.len(),
        ),
        EquivReport::FalseReject => eprintln!(
            "orchard batch FALSE-REJECT (liveness): items={}, era={era:?}, seed={seed:#x}",
            items.len(),
        ),
        EquivReport::Agree(_) => {}
    }
}

fn escalate_violation(v: InvariantViolation, items: &[&OrchardItem], era: CircuitEra, seed: u64) {
    if v.is_critical() {
        panic!(
            "ORCHARD BATCH INVARIANT VIOLATION (critical): {v:?} — soundness/fail-open break. \
             era={era:?}, items={}, seed={seed:#x}",
            items.len(),
        );
    } else {
        eprintln!("orchard batch invariant (liveness): {v:?}. era={era:?}, seed={seed:#x}");
    }
}
