//! Turnstile / migration soundness for the Orchard <-> Ironwood boundary.
//!
//! Milestone 3 names three properties, and the wording is the specification —
//! not a starting point we are free to reinterpret:
//!
//! > "turnstile/migration soundness target (**conservation**, **no
//! > double-migration**, **no forged residual value crossing**)"
//!
//! ## What a turnstile is here
//!
//! Ironwood (NU6.3 onward) reuses Orchard's Action and Halo2 machinery but is a
//! *separate pool*: its own note commitment tree, its own nullifier set, its own
//! chain value pool (`zebra-chain/src/ironwood.rs`, all citations relative to the
//! pinned base `f5c5277` — see the crate docs). Value moving between the two
//! passes through a boundary, and the three properties above are what a sound
//! boundary must guarantee: the same amount comes out as went in, nothing goes
//! through twice, and nothing comes out that never went in.
//!
//! ## Conservation is not "the two balances cancel"
//!
//! The obvious reading — a migration has `orchard_value_balance +
//! ironwood_value_balance == 0` — is wrong, and wrong in the direction that
//! looks like a finding. Measured over the 172 post-activation mainnet
//! transactions in `seeds-real/nu6_3_activation` (`examples/survey_turnstile.rs`):
//!
//! ```text
//! dual-pool                    77
//!   orchard +, ironwood -      74     the migration direction
//!   orchard +, ironwood +       3     both pools spending outward, also valid
//!   the two balances cancel     0     not one of the 77
//! ```
//!
//! Every one of those 77 is a legitimate mainnet transaction, and every one of
//! them fails the obvious test. What is missing is the fee: value leaves the
//! shielded pools to pay it, so the balances are not required to cancel — their
//! sum, less what goes out transparently, is the fee.
//!
//! So conservation is stated over *all* pools:
//!
//! ```text
//! sum(shielded value balances) - transparent_outputs = fee,  fee >= 0
//! ```
//!
//! On the same corpus that holds 172/172, with every fee a positive multiple of
//! 5000 zatoshi. **A test that turns the corpus red is not automatically finding
//! something; it can be measuring with the wrong ruler, and the two look
//! identical from the inside.**
//!
//! ## Where the fee cannot be computed, this says so
//!
//! A transparent *input* contributes value this crate cannot see: the amount
//! lives in the output being spent, which a bare transaction does not carry.
//! A coinbase input takes the same branch for a different reason. It spends no
//! prior output at all; what it creates is the block subsidy plus the fees of
//! every other transaction in its block, and those fees are not in this one.
//! [`check_conservation`] therefore returns [`Conservation::Indeterminate`]
//! rather than a pass. A soundness target that silently passes what it cannot
//! evaluate reports the same green as one that checked — which is the failure
//! this whole project exists to make impossible.
//!
//! ## Double-migration needs state, but not a chain
//!
//! Within one transaction, duplicate nullifiers are already rejected upstream by
//! `spend_conflicts` (`zebra-consensus/src/transaction/check.rs:384`). Across
//! transactions nothing in a single transaction can see the repeat, so
//! [`TurnstileState`] accumulates the nullifier sets and the two pool balances
//! as transactions are fed through it. That is an in-memory set over a corpus we
//! supply ourselves — it deliberately does not reach for `zebra-state`, which
//! would pull rocksdb into a crate that has stayed free of it.
//!
//! ## A corpus that does not start at genesis cannot be asked about pool floors
//!
//! "No forged residual value crossing" is observable as a pool balance that
//! goes negative — value coming out of a pool that never had it. That reading
//! needs to know what the pool held when the run started, and a sampled window
//! of mainnet does not say. [`Origin`] makes the caller state it, because the
//! default that looks harmless (start at zero) turns every ordinary spend in a
//! mid-chain window into a reported violation, and a check firing on correct
//! data is indistinguishable from a check finding something.
//!
//! ## The cross-pool nullifier question upstream leaves open
//!
//! `zebra-chain/src/ironwood.rs:20-23` states:
//!
//! > The Ironwood and Orchard nullifier sets are *disjoint* even when their bit
//! > patterns coincide: they live in separate column families and are checked
//! > separately.
//!
//! Disjointness there is structural — separate storage, separate checks — and
//! the sentence explicitly allows the bit patterns to collide. `spend_conflicts`
//! runs `check_for_duplicates` over the two sets independently, so the same 32
//! bytes in both pools is not a duplicate to it.
//!
//! Whether that is reachable is a question about nullifier derivation, not about
//! Zebra, and this module does not claim an answer. It *measures*: the same
//! bytes appearing in both pools is surfaced as
//! [`TurnstileViolation::CrossPoolNullifierReuse`] so the corpus can be asked.
//! On the real corpus there is no instance — which is the corpus having no
//! carrier, **not** the property holding. Those two look the same from a green
//! test, so the constructed carriers in [`crate::adversarial`] are what actually
//! exercise this one.

use std::collections::HashMap;

/// Re-exported so callers outside this workspace -- the fuzz targets, which do
/// not depend on `zebra-chain` directly -- can name the type this module's API
/// is built around. Same reason `sprout` re-exports `SigHash`.
pub use zebra_chain::transaction::Transaction;

/// The outcome of the conservation check for one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conservation {
    /// Value is conserved: the shielded pools and the transparent outputs
    /// account for each other, leaving this much fee (in zatoshi).
    Holds { fee: i64 },
    /// Value is not conserved: the sum implies a negative fee, meaning more
    /// value left the transaction than entered it.
    Violated { implied_fee: i64 },
    /// Not decidable from this transaction alone, with the reason. Nothing is
    /// asserted either way.
    Indeterminate(Indeterminacy),
}

/// Why conservation could not be decided for a transaction.
///
/// A reason rather than a flag, because the two cases are not interchangeable
/// and a caller may care which: transparent inputs are a property of the
/// transaction, while the Sprout gap is a property of *this crate's* reach.
/// Reporting both as a bare "could not decide" would hide a limitation of ours
/// among facts about the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indeterminacy {
    /// The transaction spends transparently. The value of a spent output lives
    /// in that output, which a bare transaction does not carry, so the fee has
    /// no computable value here. A coinbase input lands here too: it spends no
    /// output, but it claims the fees of the rest of its block, which are not in
    /// this transaction either.
    TransparentInputs(usize),
    /// The transaction carries Sprout JoinSplits, and `sprout_value_balance` is
    /// private in `zebra-chain`. The term is missing from the sum, so the
    /// arithmetic would be wrong rather than merely incomplete.
    SproutBalanceUnreachable,
}

/// A turnstile property that a transaction, or a run of them, violated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnstileViolation {
    /// More value left than entered (conservation).
    ValueCreated { implied_fee: i64 },
    /// A nullifier already spent in the same pool by an earlier transaction in
    /// this run: the note is being spent twice.
    DoubleSpend {
        pool: Pool,
        nullifier: [u8; 32],
        first_seen: String,
        again_in: String,
    },
    /// The same 32 bytes used as a nullifier in *both* pools. Upstream's two
    /// duplicate checks are per-pool, so this passes them; whether it is
    /// reachable is a question about nullifier derivation, and this reports it
    /// rather than assuming either answer.
    CrossPoolNullifierReuse {
        nullifier: [u8; 32],
        orchard_in: String,
        ironwood_in: String,
    },
    /// A pool's cumulative balance went negative: value came out of a pool that
    /// never had it. This is the "forged residual value crossing" case at the
    /// level where it is observable.
    PoolBalanceNegative { pool: Pool, balance: i64 },
}

/// Which shielded pool a turnstile observation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pool {
    Orchard,
    Ironwood,
}

/// Conservation over one transaction.
///
/// Sums every shielded pool's value balance, subtracts what leaves
/// transparently, and reports the remainder as the fee. Sprout is excluded
/// because `sprout_value_balance` is private in `zebra-chain`; a transaction
/// carrying JoinSplits is therefore reported as [`Conservation::Indeterminate`]
/// rather than measured with a term missing.
pub fn check_conservation(tx: &Transaction) -> Conservation {
    let transparent_inputs = tx.inputs().len();
    if transparent_inputs > 0 {
        return Conservation::Indeterminate(Indeterminacy::TransparentInputs(transparent_inputs));
    }
    if tx.has_sprout_joinsplit_data() {
        return Conservation::Indeterminate(Indeterminacy::SproutBalanceUnreachable);
    }

    let orchard: i64 = tx.orchard_value_balance().orchard_amount().into();
    let ironwood: i64 = tx.ironwood_value_balance().ironwood_amount().into();
    let sapling: i64 = tx.sapling_value_balance().sapling_amount().into();
    let transparent_out: i64 = tx.outputs().iter().map(|o| i64::from(o.value())).sum();

    let implied_fee = orchard + ironwood + sapling - transparent_out;
    if implied_fee < 0 {
        Conservation::Violated { implied_fee }
    } else {
        Conservation::Holds { fee: implied_fee }
    }
}

/// Whether the run being fed through the turnstile starts from an empty chain.
///
/// This is a required argument rather than a default because the wrong answer
/// is silent and points the wrong way. A mid-chain corpus fed to a turnstile
/// that assumes empty pools reports [`TurnstileViolation::PoolBalanceNegative`]
/// on the first transaction that moves value *out* of a pool — which is every
/// ordinary spend. The check would be firing on correct data, and firing looks
/// like finding something.
///
/// This is not hypothetical: the first version of this module defaulted to zero
/// and the NU6.3 corpus — 172 real, valid mainnet transactions — failed on the
/// first file, by 1,020,000 zatoshi of Orchard that had entered the pool
/// millions of blocks before the corpus window opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The run starts at genesis, so both pools begin empty and a negative
    /// balance means value came out of a pool that never had it.
    Genesis,
    /// The run starts partway along a chain, so the pools already hold an
    /// unknown amount. Balances are still accumulated and reported by
    /// [`TurnstileState::pool_balances`] as *changes*, but a negative one is
    /// not a violation: it says the window spends more than it receives, which
    /// any window of a live chain may legitimately do.
    MidChain,
}

/// Accumulated turnstile state over a run of transactions.
///
/// Holds what no single transaction can see: which nullifiers have already been
/// spent, and how each pool's balance has moved. See [`Origin`] for why the
/// starting point has to be stated.
#[derive(Debug)]
pub struct TurnstileState {
    origin: Origin,
    orchard_nullifiers: HashMap<[u8; 32], String>,
    ironwood_nullifiers: HashMap<[u8; 32], String>,
    /// Pool balances, in zatoshi. A positive value balance moves value *out* of
    /// the pool, so the pool's own balance moves by its negation.
    orchard_balance: i64,
    ironwood_balance: i64,
    fees: i64,
    indeterminate: usize,
    seen: usize,
}

impl TurnstileState {
    /// A turnstile for a run starting at [`Origin::Genesis`] — both pools empty,
    /// and a negative pool balance is a violation.
    pub fn from_genesis() -> Self {
        Self::with_origin(Origin::Genesis)
    }

    /// A turnstile for a run starting partway along a chain
    /// ([`Origin::MidChain`]): pool balances are accumulated as changes, and a
    /// negative one is not a violation.
    pub fn mid_chain() -> Self {
        Self::with_origin(Origin::MidChain)
    }

    fn with_origin(origin: Origin) -> Self {
        Self {
            origin,
            orchard_nullifiers: HashMap::new(),
            ironwood_nullifiers: HashMap::new(),
            orchard_balance: 0,
            ironwood_balance: 0,
            fees: 0,
            indeterminate: 0,
            seen: 0,
        }
    }

    /// Feed one transaction through the turnstile, returning every property it
    /// violates. An empty vector is a pass.
    ///
    /// `label` identifies the transaction in any violation reported later — a
    /// double-spend is only meaningful if it can say which two transactions.
    pub fn admit(&mut self, tx: &Transaction, label: &str) -> Vec<TurnstileViolation> {
        let mut violations = Vec::new();
        self.seen += 1;

        match check_conservation(tx) {
            Conservation::Holds { fee } => self.fees += fee,
            Conservation::Violated { implied_fee } => {
                violations.push(TurnstileViolation::ValueCreated { implied_fee })
            }
            Conservation::Indeterminate(_) => self.indeterminate += 1,
        }

        let orchard_nf: Vec<[u8; 32]> = tx.orchard_nullifiers().copied().map(Into::into).collect();
        let ironwood_nf: Vec<[u8; 32]> = tx.ironwood_nullifiers().map(Into::into).collect();

        // Cross-pool reuse, within this transaction and against everything seen.
        for n in &orchard_nf {
            if ironwood_nf.contains(n) {
                violations.push(TurnstileViolation::CrossPoolNullifierReuse {
                    nullifier: *n,
                    orchard_in: label.to_string(),
                    ironwood_in: label.to_string(),
                });
            } else if let Some(prev) = self.ironwood_nullifiers.get(n) {
                violations.push(TurnstileViolation::CrossPoolNullifierReuse {
                    nullifier: *n,
                    orchard_in: label.to_string(),
                    ironwood_in: prev.clone(),
                });
            }
        }
        for n in &ironwood_nf {
            if let Some(prev) = self.orchard_nullifiers.get(n) {
                violations.push(TurnstileViolation::CrossPoolNullifierReuse {
                    nullifier: *n,
                    orchard_in: prev.clone(),
                    ironwood_in: label.to_string(),
                });
            }
        }

        // Same-pool double spends, against everything seen so far.
        for (pool, nfs, set) in [
            (Pool::Orchard, &orchard_nf, &mut self.orchard_nullifiers),
            (Pool::Ironwood, &ironwood_nf, &mut self.ironwood_nullifiers),
        ] {
            for n in nfs {
                if let Some(first) = set.insert(*n, label.to_string()) {
                    violations.push(TurnstileViolation::DoubleSpend {
                        pool,
                        nullifier: *n,
                        first_seen: first.clone(),
                        again_in: label.to_string(),
                    });
                    // Put the original label back. `insert` returns the old
                    // value *and replaces it*, so without this a third sighting
                    // would name the second transaction as `first_seen` -- the
                    // field would be quietly wrong exactly when the history
                    // being reported is longest, and a two-sighting test cannot
                    // tell the difference.
                    set.insert(*n, first);
                }
            }
        }

        // Pool balances. A positive value balance takes value out of the pool.
        let orchard_vb: i64 = tx.orchard_value_balance().orchard_amount().into();
        let ironwood_vb: i64 = tx.ironwood_value_balance().ironwood_amount().into();
        self.orchard_balance -= orchard_vb;
        self.ironwood_balance -= ironwood_vb;
        if self.origin == Origin::Genesis {
            if self.orchard_balance < 0 {
                violations.push(TurnstileViolation::PoolBalanceNegative {
                    pool: Pool::Orchard,
                    balance: self.orchard_balance,
                });
            }
            if self.ironwood_balance < 0 {
                violations.push(TurnstileViolation::PoolBalanceNegative {
                    pool: Pool::Ironwood,
                    balance: self.ironwood_balance,
                });
            }
        }

        violations
    }

    /// Cumulative pool balance *changes*, in zatoshi, as `(orchard, ironwood)`.
    /// Under [`Origin::Genesis`] these are also the absolute balances.
    pub fn pool_balances(&self) -> (i64, i64) {
        (self.orchard_balance, self.ironwood_balance)
    }

    /// Total fee accounted for across every transaction whose fee was
    /// computable.
    pub fn total_fees(&self) -> i64 {
        self.fees
    }

    /// How many transactions could not be evaluated for conservation, and how
    /// many were seen in total. A target that does not report this cannot
    /// distinguish "all checked and passed" from "most were skipped".
    pub fn coverage(&self) -> (usize, usize) {
        (self.seen - self.indeterminate, self.seen)
    }
}
