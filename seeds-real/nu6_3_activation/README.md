# NU6.3 / Ironwood corpus — real mainnet transactions from the post-activation window

172 transactions, 249 verification items, every one in the **NU6.3-onward era**. This is
the first real third-era corpus in this repository: M1 shipped with builder-synthesized
NU6.3 vectors because no such traffic existed yet, and labelled them as synthetic.

## Provenance, stated precisely

| | |
|---|---|
| Source | our standing mainnet node, via `getblock <height> 0` |
| Extraction date | **2026-08-02** |
| Window | heights **3,428,150 - 3,433,400** (NU6.3 activated at 3,428,143) |
| Sampling | **every 50th block**, 106 blocks fetched, **zero misses** |
| Tool | `src/bin/blocks_to_orchard_corpus.rs` |

The window opens 7 blocks after activation, so the activation boundary itself is
represented. **The extraction ran on 2026-08-02, not at the activation instant** — the
blocks are the post-activation ones either way, but the date is stated rather than
implied, because "when the chain produced it" and "when we fetched it" are different
facts and only one of them is visible in the data.

## What is in it

**Two different populations are reported below and the distinction matters.** The first
block counts what the 106 *source blocks* contain; the second counts what is *in this
directory*, which is the shielded-only subset actually saved. They differ for Ironwood
and not for Orchard, purely because every Orchard action here happens to be
shielded-only.

Source blocks, measured by a pool survey over the same 106 blocks (the counts below are
reproducible from the block set alone):

```
blocks with shielded content   69 / 106
orchard actions             1,264   (all shielded-only)
ironwood actions              284   (216 shielded-only)
dual-pool transactions         77
sapling spends / outputs    47 / 38
joinsplits                      0
```

**In this directory** (172 transactions, 249 items): **1,264 Orchard actions, 216
Ironwood actions, 77 dual-pool transactions.** Quote these when describing the corpus;
the block-level figures above describe the window it was drawn from.

201 shielded transactions were found, **172 kept.** The 29 dropped carry
transparent inputs, whose ZIP-244 sighash folds in prevouts a bare transaction does not
carry — the same filter M1 applies, for the same reason.

**The dual-pool transactions are the notable part.** A single transaction carrying both
an Orchard-pool and an Ironwood-pool bundle is what cross-pool migration looks like in
practice, and 77 of them are here. M1 could only reason about that shape from
synthesized vectors.

## Using it

**This is a strided sample, not the full window.** Every 50th block, which is uniform
with respect to height. The distinction matters whenever a corpus is drawn from a range
whose pool composition drifts across it: there, a contiguous prefix is not a sample of
the range, it is a sample of one end of it. A prefix of *this* directory is a contiguous
run of early post-activation blocks — still a different thing from a random subset, but
at least not silently biased by pool.

Filenames are `v<version>_<height>_<txid prefix>.bin`, raw wire bytes, one transaction
per file — the same format as the other corpora here. Height is in the name because the
sighash depends on the network upgrade in force, and a transaction cannot always answer
that for itself.

**More blocks are available.** The window is sampled, not exhausted: the chain had 5,261
blocks past activation when this was taken. Re-running the extraction with a smaller
stride is the way to grow this corpus, and the tool is deterministic given the same
block set.
