# Historical corpus — Sapling activation (419,200) → Canopy (1,046,400)

2,032 mainnet transactions carrying Groth16 JoinSplits and/or Sapling
spends/outputs, extracted from 2,509 blocks sampled every 250 heights across the
window where JoinSplits carry Groth16 proofs (earlier ones carry BCTV14, which no
shipping verifier accepts).

```
  687   Sprout JoinSplits   (Groth16 only)
1,261   Sapling spends
1,779   Sapling outputs
  850   of the 2,032 seeds carry transparent inputs — kept deliberately, see below
```

Filenames are `v<version>_<height>_<txid-prefix>.bin`, holding raw wire bytes.
Heights are **zero-padded to seven digits** so lexicographic order equals numeric
order: this window spans a digit-count boundary (419,200 is six digits, 1,046,400
is seven), and without padding `1000950` sorts before `419201`.

## Read this before taking a subset

**The pool composition drifts monotonically across this window.** Sprout is
progressively displaced by Sapling as the window advances:

| region | JoinSplits | Sapling spends |
|---|---|---|
| ~419,xxx (Sapling just activated) | 21 | 1 |
| ~1,00x,xxx (approaching Canopy)   | 2  | 22 |

*(measured over 40 blocks at each end)*

So **a prefix of this corpus is not a sample of it.** `take(N)` over sorted
filenames yields almost pure Sprout; a suffix yields almost pure Sapling. Both are
perfectly reproducible and both are biased — zero-padding fixed the ordering, not
the representativeness.

This differs from the M1 Orchard corpora, which are contiguous blocks within a
single era and roughly uniform in composition, so prefix sampling there happened
to be unbiased. That assumption does not carry over. **Any subset of this
directory must be stratified or randomised**, and the loader is expected to
enforce that rather than leave a prefix-sampling entry point that looks usable and
silently skews.

Whole-corpus figures are unaffected: the counts above come from a full traversal,
not a sample.

## Why transparent inputs are kept

The transparent-input filter exists so a sighash can be reconstructed from a bare
block dump. Whether it applies is a property of the **verifier**, not of the
transaction:

* Sprout's Groth16 proof is not bound to a sighash at all
  (`groth16::Item::verify_single` takes only the prepared verifying key), so
  those 850 seeds are usable there.
* Sapling's binding signature is bound to it, so the same seeds are not usable on
  that path.

Filtering at extraction time would have silently discarded usable Sprout corpus.
The filtering belongs in the loader, per verifier — the storage-layer form of
"split the stream by verifier, not by pool", which is also why this directory is
named for a height window rather than for a pool: one transaction commonly carries
both, and splitting by pool would store it twice.

Regenerate with:

```
cargo run --bin blocks_to_historical_corpus -- <blocks_dir> <out_dir> [max_blocks]
```
