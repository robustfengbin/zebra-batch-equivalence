//! Deep equivalence invariants a sound batch verifier must satisfy, beyond the
//! base `batch ⟺ single` check.
//!
//! Each is a differential over the *same* items — never fabricating an invalid
//! proof (that is the M2 adversarial-corpus job), only re-arranging valid ones —
//! so a violation over the valid corpus is a genuine bug in the batching glue,
//! not a property of the input:
//!
//! * **order-independence** — the batch boolean must not depend on the order
//!   bundles were added. Orchard draws random scalars per queued position; if the
//!   accept/reject flipped under a permutation, the aggregation is unsound.
//! * **duplicate-consistency** — duplicating bundles must not change agreement.
//! * **sub-batch compositionality** — a sound whole cannot hide an unsound part:
//!   every sub-batch of an agreeing batch must itself agree.
//! * **era-routing / not-fail-open** — items valid under their own era key must
//!   be rejected by *both* paths under every other era key (agree on `false`),
//!   never accepted. Wrong-key acceptance is a fail-open soundness break.
//!
//! These are the checks that make the harness "deep": the base equivalence would
//! pass trivially on a valid corpus, but these exercise the batching, key
//! selection, and composition logic where a real regression would hide.

use rand::seq::SliceRandom;

use crate::era::CircuitEra;
use crate::{check_equivalence_refs, seeded_rng, validate_batch, EquivReport, OrchardItem, VerifyingKey};

/// A specific invariant that failed, with enough context to reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantViolation {
    /// The base batch ⟺ single check disagreed.
    Equivalence(EquivReport),
    /// Permuting the batch changed the batch outcome; batch verification must be
    /// order-independent.
    OrderDependent { original: bool, permuted: bool },
    /// A batch containing duplicated bundles disagreed with its singles.
    DuplicateInconsistent(EquivReport),
    /// A contiguous sub-batch of an agreeing batch failed batch ⟺ single.
    SubBatchInconsistent { len: usize, report: EquivReport },
    /// Under the wrong era key the items were not rejected by both paths — a
    /// fail-open. The right key accepts; every wrong key must reject both.
    EraFailOpen {
        correct: CircuitEra,
        used: CircuitEra,
        report: EquivReport,
    },
}

impl InvariantViolation {
    /// Whether this violation is soundness-critical (a false-accept / fail-open /
    /// order-dependence) as opposed to a liveness-only signal.
    pub fn is_critical(&self) -> bool {
        match self {
            Self::Equivalence(r)
            | Self::DuplicateInconsistent(r)
            | Self::SubBatchInconsistent { report: r, .. } => r.is_false_accept(),
            // A wrong-era key that does anything other than reject-both is a
            // fail-open (batch and/or single accepted, or they disagreed).
            Self::EraFailOpen { report, .. } => *report != EquivReport::Agree(false),
            // Order-dependence of the batch boolean is never acceptable.
            Self::OrderDependent { .. } => true,
        }
    }
}

/// Batch validation must be order-independent: the batch boolean must not depend
/// on the order bundles were added. Compares the original order against a seeded
/// permutation. Needs at least two items to be meaningful.
pub fn check_order_invariance(
    items: &[&OrchardItem],
    vk: &VerifyingKey,
    seed: u64,
) -> Option<InvariantViolation> {
    if items.len() < 2 {
        return None;
    }
    let original = validate_batch(items, vk, seed);

    let mut permuted: Vec<&OrchardItem> = items.to_vec();
    permuted.shuffle(&mut seeded_rng(seed ^ 0x00d1_00d1_00d1_00d1));
    let permuted_ok = validate_batch(&permuted, vk, seed);

    if original != permuted_ok {
        Some(InvariantViolation::OrderDependent {
            original,
            permuted: permuted_ok,
        })
    } else {
        None
    }
}

/// A batch of duplicated bundles must agree with the corresponding singles.
/// (`[a, b]` → `[a, b, a, b]`.)
pub fn check_duplicate_consistency(
    items: &[&OrchardItem],
    vk: &VerifyingKey,
    seed: u64,
) -> Option<InvariantViolation> {
    if items.is_empty() {
        return None;
    }
    let mut doubled: Vec<&OrchardItem> = items.to_vec();
    doubled.extend_from_slice(items);
    let report = check_equivalence_refs(&doubled, vk, seed);
    report
        .is_disagreement()
        .then_some(InvariantViolation::DuplicateInconsistent(report))
}

/// Every contiguous prefix sub-batch must itself satisfy batch ⟺ single:
/// soundness is compositional, so an agreeing whole cannot contain a disagreeing
/// part. Prefixes (rather than all `2^N` subsets) keep the cost linear; each is
/// still a full SNARK batch, so callers on the hot path should bound `items`.
pub fn check_subbatch_consistency(
    items: &[&OrchardItem],
    vk: &VerifyingKey,
    seed: u64,
) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();
    for len in 1..items.len() {
        let report = check_equivalence_refs(&items[..len], vk, seed);
        if report.is_disagreement() {
            violations.push(InvariantViolation::SubBatchInconsistent { len, report });
        }
    }
    violations
}

/// Era routing / not-fail-open: items valid under `correct` era must be rejected
/// by **both** paths under every other era key (agreeing on `false`), never
/// accepted. Covers both the proof-era mismatch (wrong circuit key) and the
/// cross-address fail-closed path (`add_bundle` rejecting a disabled bundle under
/// a key that cannot constrain it).
pub fn check_era_routing(
    items: &[&OrchardItem],
    correct: CircuitEra,
    seed: u64,
) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();
    for used in CircuitEra::ALL {
        if used == correct {
            continue;
        }
        let report = check_equivalence_refs(items, used.key(), seed);
        if report != EquivReport::Agree(false) {
            violations.push(InvariantViolation::EraFailOpen {
                correct,
                used,
                report,
            });
        }
    }
    violations
}

/// Run the full invariant sweep over one same-era batch, returning every
/// violation found. Expensive (many SNARK batches): intended for the baseline
/// tests and periodic deep CI runs. The fuzz target samples individual checks
/// per input for throughput.
pub fn deep_check(items: &[&OrchardItem], era: CircuitEra, seed: u64) -> Vec<InvariantViolation> {
    let vk = era.key();
    let mut violations = Vec::new();

    let base = check_equivalence_refs(items, vk, seed);
    if base.is_disagreement() {
        violations.push(InvariantViolation::Equivalence(base));
    }
    if let Some(v) = check_order_invariance(items, vk, seed) {
        violations.push(v);
    }
    if let Some(v) = check_duplicate_consistency(items, vk, seed) {
        violations.push(v);
    }
    violations.extend(check_subbatch_consistency(items, vk, seed));
    violations.extend(check_era_routing(items, era, seed));

    violations
}
