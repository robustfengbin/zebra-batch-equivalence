//! What a cross-pool (Orchard <-> Ironwood) transaction actually looks like on
//! mainnet, measured rather than assumed.
//!
//! M3's turnstile target has three properties written into the grant:
//! **conservation**, **no double-migration**, and **no forged residual value
//! crossing**. Before designing a target for them, this answers the question
//! that decides how much machinery the target needs:
//!
//! > Which of the three can be decided from a single transaction, and which
//! > need state that spans transactions?
//!
//! It also checks upstream's own claim about the two nullifier sets. From
//! `zebra-chain/src/ironwood.rs:20-23` at the pinned base `f5c5277`:
//!
//! > The Ironwood and Orchard nullifier sets are *disjoint* even when their bit
//! > patterns coincide: they live in separate column families and are checked
//! > separately.
//!
//! That is a claim about *how* they are kept apart (separate storage, separate
//! checks), and it explicitly allows the bit patterns to collide. Whether they
//! collide in practice is a measurement, and `spend_conflicts`
//! (`zebra-consensus/src/transaction/check.rs:384`) runs `check_for_duplicates`
//! over the two sets *separately*, so a value appearing in both is not a
//! duplicate to it. This survey reports whether the corpus contains such a
//! value: not a finding either way, but the fact the turnstile target has to be
//! designed against.
//!
//! Run: `cargo run --example survey_turnstile [dir-name]`
//! (default `nu6_3_activation`, the post-NU6.3 mainnet corpus)

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::Transaction;

#[derive(Default)]
struct Survey {
    txs: usize,
    parse_failures: usize,

    orchard_only: usize,
    ironwood_only: usize,
    dual_pool: usize,
    neither: usize,

    /// Dual-pool transactions whose two shielded value balances sum to zero.
    /// A pure pool-to-pool move looks like this: one side negative by exactly
    /// what the other is positive by, with nothing entering or leaving.
    dual_net_zero: usize,
    /// Dual-pool transactions where they do not: value also enters or leaves
    /// through the transparent, Sapling or Sprout side of the same transaction.
    dual_net_nonzero: usize,

    /// Transactions with any transparent input. The corpus filter drops these
    /// (their ZIP-244 sighash folds in prevouts a bare transaction does not
    /// carry), so this should be zero -- and if it is, the transparent side of
    /// every transaction here is outputs only, which is what makes a fee
    /// computable without a UTXO set.
    with_transparent_inputs: usize,
    with_transparent_outputs: usize,
    /// Must be zero for the fee figures to mean anything (see above).
    with_sprout: usize,
    /// Sum of every shielded value balance minus transparent outputs. For a
    /// transaction with no transparent inputs this *is* the fee.
    fees: BTreeMap<i64, usize>,

    orchard_nullifiers: usize,
    ironwood_nullifiers: usize,
    /// The measurement upstream's comment leaves open: the same 32 bytes used
    /// as a nullifier in both pools.
    colliding_bit_patterns: usize,

    /// Every nullifier seen so far, by pool, so a repeat across *different*
    /// transactions is visible. Single-transaction repeats are what
    /// `spend_conflicts` already rejects; cross-transaction repeats are what a
    /// turnstile has to catch, and no single transaction can see them.
    seen_orchard: HashMap<[u8; 32], String>,
    seen_ironwood: HashMap<[u8; 32], String>,
    repeat_across_txs: Vec<String>,
}

fn main() {
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nu6_3_activation".to_string());
    let dir = PathBuf::from("seeds-real").join(&name);

    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    let mut s = Survey::default();
    // Per-transaction value-balance shapes, so the dual-pool population can be
    // described rather than just counted.
    let mut shapes: BTreeMap<(i64, i64), usize> = BTreeMap::new();

    for path in &files {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(_) => {
                s.parse_failures += 1;
                continue;
            }
        };
        let tx = match Transaction::zcash_deserialize(&bytes[..]) {
            Ok(t) => t,
            Err(_) => {
                s.parse_failures += 1;
                continue;
            }
        };
        s.txs += 1;
        let label = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();

        let has_orchard = tx.has_orchard_shielded_data();
        let has_ironwood = tx.has_ironwood_shielded_data();

        match (has_orchard, has_ironwood) {
            (true, true) => s.dual_pool += 1,
            (true, false) => s.orchard_only += 1,
            (false, true) => s.ironwood_only += 1,
            (false, false) => s.neither += 1,
        }

        // Value balances. Both accessors return a full `ValueBalance`, so the
        // pool amount is read off the matching field.
        let o_amt: i64 = tx.orchard_value_balance().orchard_amount().into();
        let i_amt: i64 = tx.ironwood_value_balance().ironwood_amount().into();

        if has_orchard && has_ironwood {
            *shapes
                .entry((o_amt.signum(), i_amt.signum()))
                .or_default() += 1;
            if o_amt + i_amt == 0 {
                s.dual_net_zero += 1;
            } else {
                s.dual_net_nonzero += 1;
            }
        }

        // The transparent side. Any input at all means a prevout value we do
        // not have, and therefore no computable fee.
        let n_in = tx.inputs().len();
        if n_in > 0 {
            s.with_transparent_inputs += 1;
        }
        let t_out: i64 = tx.outputs().iter().map(|o| i64::from(o.value())).sum();
        if t_out != 0 {
            s.with_transparent_outputs += 1;
        }

        // Sum over the shielded pools. `sprout_value_balance` is private in
        // zebra-chain, so Sprout is asserted absent rather than added: if a
        // JoinSplit did appear here the fee below would be wrong, and the count
        // makes that visible instead of silently skewing the number.
        if tx.has_sprout_joinsplit_data() {
            s.with_sprout += 1;
        }
        let sap: i64 = tx.sapling_value_balance().sapling_amount().into();
        if n_in == 0 && !tx.has_sprout_joinsplit_data() {
            let fee = o_amt + i_amt + sap - t_out;
            *s.fees.entry(fee).or_default() += 1;
        }

        // Nullifiers, by pool, as raw bytes so the two pools are comparable.
        let o_nf: Vec<[u8; 32]> = tx.orchard_nullifiers().copied().map(<[u8; 32]>::from).collect();
        let i_nf: Vec<[u8; 32]> = tx.ironwood_nullifiers().map(<[u8; 32]>::from).collect();
        s.orchard_nullifiers += o_nf.len();
        s.ironwood_nullifiers += i_nf.len();

        for n in &o_nf {
            if i_nf.contains(n) {
                s.colliding_bit_patterns += 1;
            }
            if let Some(prev) = s.seen_orchard.insert(*n, label.clone()) {
                s.repeat_across_txs
                    .push(format!("orchard nullifier repeats: {prev} -> {label}"));
            }
        }
        for n in &i_nf {
            if let Some(prev) = s.seen_ironwood.insert(*n, label.clone()) {
                s.repeat_across_txs
                    .push(format!("ironwood nullifier repeats: {prev} -> {label}"));
            }
        }
    }

    println!("corpus: seeds-real/{name}  ({} files)", files.len());
    println!("  parsed                {}", s.txs);
    println!("  parse failures        {}", s.parse_failures);
    println!();
    println!("pool membership");
    println!("  Orchard only          {}", s.orchard_only);
    println!("  Ironwood only         {}", s.ironwood_only);
    println!("  dual-pool             {}", s.dual_pool);
    println!("  neither               {}", s.neither);
    println!();
    println!("dual-pool value-balance shape  (sign of orchard, sign of ironwood)");
    for ((o, i), n) in &shapes {
        println!("  ({o:+}, {i:+})              {n}");
    }
    println!("  sum to zero           {}", s.dual_net_zero);
    println!("  sum non-zero          {}", s.dual_net_nonzero);
    println!();
    println!("transparent side");
    println!("  with transparent inputs   {}", s.with_transparent_inputs);
    println!("  with transparent outputs  {}", s.with_transparent_outputs);
    println!("  with sprout joinsplits    {}  (must be 0 for the fees below)", s.with_sprout);
    println!();
    println!("implied fee  (all shielded value balances - transparent outputs;");
    println!("              valid only because there are no transparent inputs)");
    for (fee, n) in &s.fees {
        println!("  {fee:>12} zatoshi   x{n}");
    }
    println!();
    println!("nullifiers");
    println!("  orchard               {}", s.orchard_nullifiers);
    println!("  ironwood              {}", s.ironwood_nullifiers);
    println!(
        "  same 32 bytes in both pools, same tx   {}",
        s.colliding_bit_patterns
    );
    println!(
        "  repeats across transactions           {}",
        s.repeat_across_txs.len()
    );
    for r in s.repeat_across_txs.iter().take(10) {
        println!("    {r}");
    }
}
