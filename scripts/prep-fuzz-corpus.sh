#!/usr/bin/env bash
# Seed the four fuzz targets' corpora from the real-proof corpus (W7).
#
# Input models differ per target family:
#   * orchard_batch_equivalence / orchard_batch_composition take a tx-stream
#     plus ONE trailing control byte selecting the circuit-era key
#     (0 => pre-NU6.2, 1 => NU6.2, 2 => NU6.3-onward) — same format
#     `examples/dump_seeds.rs` emits.
#   * orchard_era_routing / orchard_single_deep take the raw tx-stream with no
#     control byte.
#
# CI smoke runs each seed at least once and every accepted seed drives real
# SNARK verification (hundreds of ms each), so we SAMPLE per era instead of
# copying all 800+ files — the full-corpus soundness sweep already runs as
# `cargo test` (corpus_agreement / nu6_2_agreement). Sampling is deterministic
# (lexicographic head -N) so CI runs are reproducible.
set -euo pipefail
cd "$(dirname "$0")/.."

SAMPLE_PER_ERA="${SAMPLE_PER_ERA:-6}"

# Where the seeded corpora are written. Defaults to the location `cargo fuzz
# run` reads, which is what CI and a local run want. ClusterFuzzLite's build
# script overrides it to stage seeds outside the source tree before zipping
# them, so that the seed-shape mapping below lives in exactly one place.
CORPUS_ROOT="${CORPUS_ROOT:-fuzz/corpus}"

# The manifest each corpus carries, naming which of its files reach which
# extractor. Hardcoded here and as `MANIFEST_NAME` in src/lib.rs; the test that
# re-measures it reads the constant, so a rename that misses this line fails
# there rather than silently seeding nothing.
MANIFEST_NAME="REACHES.txt"

# 🔴 Seeds are chosen by whether they reach an extractor, never by filename
# order. This used to be `ls | sort | head -n 6`, and in orchard_v5_pre_nu6_2 the
# first usable file is the *ninth*: 164 of its 550 files yield an Orchard item,
# and none of the six that shipped did. The four targets comparing batch against
# single were therefore fuzzing the June-5 era with six inputs their extractor
# declines — at full speed, with a healthy execution count, which is what a
# working target looks like from the outside.
#
# Striding instead of heading only lowers the odds: a step of 92 over that
# corpus lands on one usable file in six. The property has to be selected on
# directly, so it has to be measured, which is what the manifest holds.
#
# Regenerate after changing a corpus:
#     cargo run --release --example seed_reach_manifest
# tests/fuzz_input_reach.rs re-measures and fails if a manifest is stale.
reaching() { # $1 = corpus dir, $2 = extractor, $3 = how many
  local manifest="$1/$MANIFEST_NAME" col
  if [ ! -f "$manifest" ]; then
    echo "prep-fuzz-corpus: missing $manifest" >&2
    echo "  run: cargo run --release --example seed_reach_manifest" >&2
    exit 1
  fi
  case "$2" in
    orchard)   col=2 ;;
    sapling)   col=3 ;;
    redjubjub) col=4 ;;
    sprout)    col=5 ;;
    *) echo "prep-fuzz-corpus: unknown extractor '$2'" >&2; exit 1 ;;
  esac
  awk -F'\t' -v c="$col" '!/^#/ && NF >= 5 && $c + 0 > 0 { print $1 }' "$manifest" \
    | sort | head -n "$3"
}

# How many seeds each M3 target takes from the historical corpus. Scales with
# SAMPLE_PER_ERA so the ClusterFuzzLite build's "take everything" override
# (SAMPLE_PER_ERA=1000000) reaches this corpus too.
SAMPLE_HISTORICAL="${SAMPLE_HISTORICAL:-$((SAMPLE_PER_ERA * 2))}"

# 🔴 `sample` above must NOT be used on seeds-real/historical_419200_1046400.
#
# That corpus spans Sapling activation to Canopy, and its pool composition
# drifts monotonically across the window — its README measures 21 JoinSplits vs
# 1 Sapling spend at the low end and 2 vs 22 at the high end. Filenames are
# zero-padded so lexicographic order is height order, which means `head -n N`
# yields a prefix, and a prefix of this corpus is almost pure Sprout. That is
# perfectly reproducible and thoroughly biased.
#
# Even sampling across the sorted list instead, so every subset spans the whole
# window. Its own README asks the loader to enforce this rather than leave a
# prefix entry point that looks usable and silently skews; this is that.
stratified() { # $1 = source dir, $2 = wanted count
  local total step
  total=$(ls "$1"/*.bin 2>/dev/null | wc -l)
  [ "$total" -eq 0 ] && return 0
  if [ "$2" -ge "$total" ]; then
    ls "$1"/*.bin | xargs -n1 basename | sort
    return 0
  fi
  step=$(( (total + $2 - 1) / $2 ))
  ls "$1"/*.bin | xargs -n1 basename | sort | awk -v s="$step" 'NR % s == 1'
}

# `reaching` filtered, then strided — for a corpus that needs both, where
# taking either alone leaves a bias the other was there to remove.
reaching_stratified() { # $1 = corpus dir, $2 = extractor, $3 = how many
  local all total step
  all=$(reaching "$1" "$2" 1000000)
  total=$(printf '%s\n' "$all" | grep -c . || true)
  [ "$total" -eq 0 ] && return 0
  if [ "$3" -ge "$total" ]; then
    printf '%s\n' "$all"
    return 0
  fi
  step=$(( (total + $3 - 1) / $3 ))
  printf '%s\n' "$all" | awk -v s="$step" 'NR % s == 1'
}

# Both seeders take reaching files strided across the whole window, not the
# first N. A corpus is named by height, so the first N reaching files are the
# first N from the window's opening block: for nu6_3_activation that was six
# transactions from one block, all dual-pool, while 95 of its 172 files are
# single-pool. Filtering fixed "reaches nothing"; it did not fix "a prefix is a
# sample of the beginning", which the historical corpus below already knew.
seed_control() { # $1 = source dir, $2 = control byte (octal escape), $3 = dest dir, $4 = extractor
  local f
  for f in $(reaching_stratified "$1" "$4" "$SAMPLE_PER_ERA"); do
    cp "$1/$f" "$3/$f"
    printf "$2" >> "$3/$f"
  done
}

seed_raw() { # $1 = source dir, $2 = dest dir, $3 = extractor
  local f
  for f in $(reaching_stratified "$1" "$3" "$SAMPLE_PER_ERA"); do
    cp "$1/$f" "$2/$f"
  done
}

# 🔴 All three eras, including NU6.3-onward. The first two were here from M1,
# when no third-era traffic existed; nu6_3_activation arrived 2026-08-02 and the
# M3 targets below started drawing on it, but these four -- the *core*
# batch ⟺ single targets, the ones the grant's central claim rests on -- were
# not updated. The result read as full coverage: nine targets, all seeded, all
# green, and the pool the milestone is named after reaching none of the four
# targets that compare the two verification paths directly.
#
# Control byte 2 selects the NU6.3-onward circuit era, matching the corpus. The
# survey below measures 172 transactions / 249 Orchard items in it, so these
# seeds reach a verifier rather than merely existing.
for target in orchard_batch_equivalence orchard_batch_composition; do
  dest="$CORPUS_ROOT/$target"
  mkdir -p "$dest"
  # The dump_seeds vectors already carry their control byte.
  cp seeds-real/orchard_pre_nu6_2/seed_pre_nu6_2_* "$dest/"
  seed_control seeds-real/orchard_v5_pre_nu6_2 '\x00' "$dest" orchard
  seed_control seeds-real/orchard_v5_nu6_2 '\x01' "$dest" orchard
  seed_control seeds-real/nu6_3_activation '\x02' "$dest" orchard
done

for target in orchard_era_routing orchard_single_deep; do
  dest="$CORPUS_ROOT/$target"
  mkdir -p "$dest"
  seed_raw seeds-real/orchard_v5_pre_nu6_2 "$dest" orchard
  seed_raw seeds-real/orchard_v5_nu6_2 "$dest" orchard
  seed_raw seeds-real/nu6_3_activation "$dest" orchard
done

# --- M3 targets: the three M2 surfaces ------------------------------------
#
# Raw transaction stream, no control byte. Which corpus feeds which target is
# NOT symmetric, and the asymmetry was measured rather than assumed — run
# `cargo run --release --example survey_fuzz_seeds` to reproduce the table:
#
#   corpus                       orchard      sapling    redjubjub       sprout
#   historical_419200_1046400     0tx/0i       0tx/0i       0tx/0i   491tx/687i
#   nu6_3_activation          172tx/249i       2tx/2i      2tx/32i       0tx/0i
#   orchard_v5_nu6_2          250tx/250i       5tx/5i      5tx/13i       0tx/0i
#   orchard_v5_pre_nu6_2      164tx/164i     57tx/57i    57tx/169i       0tx/0i
#
# 🔴 The historical corpus yields NOTHING for Sapling or RedJubjub, despite
# holding 1,261 Sapling spends. Those transactions are v4: a v4 transaction does
# not state its consensus branch id, so `item_from_tx` cannot derive the network
# upgrade its sighash needs and returns None. M2's Sapling suite reads the
# in-tree block vectors, where the height supplies that answer; a bare
# transaction stream has no height.
#
# So the signature-bearing targets are seeded from the v5/v6 corpora, whose
# transactions can answer for themselves, and Sprout — whose Groth16 proofs are
# not bound to a sighash at all — takes the historical corpus and reaches all
# 687 JoinSplits in it.
#
# ⏭️ Known gap, not a silent one: 1,182 v4 Sapling transactions (2,032 minus the
# 850 with transparent inputs) are unreachable from a bare stream. Unlocking
# them needs an era-selector control byte in the input model, the same shape the
# Orchard targets already use. Deliberately not folded in here — it changes the
# input model, which is a corpus-format change, and this commit's job was to
# make these targets reach a verifier at all.
#
# These two select from separate manifest columns, and on every corpus here the
# columns name the same files (57/57, 5/5, 2/2, 0/0): each RedJubjub item comes
# from the Sapling item of the same transaction, so a file reaches one exactly
# when it reaches the other, short of malformed data. What differs is the item
# count per file (169 RedJubjub against 57 Sapling on orchard_v5_pre_nu6_2).
# Selecting per column costs nothing and keeps each target seeded by its own
# extractor rather than by an assumption that the two coincide.
for target in sapling_batch_equivalence redjubjub_batch_equivalence; do
  dest="$CORPUS_ROOT/$target"
  mkdir -p "$dest"
  case "$target" in
    sapling_batch_equivalence)   extractor=sapling ;;
    redjubjub_batch_equivalence) extractor=redjubjub ;;
  esac
  seed_raw seeds-real/orchard_v5_pre_nu6_2 "$dest" "$extractor"
  seed_raw seeds-real/orchard_v5_nu6_2 "$dest" "$extractor"
  seed_raw seeds-real/nu6_3_activation "$dest" "$extractor"
done

# The tower target takes the same v5/v6 stream plus ONE trailing control byte
# selecting the batch capacity — the thing that decides the partition. Seeded at
# 0x08 because the byte is only a starting point: the fuzzer mutates it, and the
# target derives a second, different capacity from it, so one seeded value
# already explores both sides of every comparison.
dest="$CORPUS_ROOT/tower_partition_equivalence"
mkdir -p "$dest"
for src in orchard_v5_pre_nu6_2 orchard_v5_nu6_2 nu6_3_activation; do
  seed_control "seeds-real/$src" '\x08' "$dest" orchard
done

# Sprout needs both filters, and in this order. The manifest first, because
# only 491 of the 2,032 files carry Groth16 JoinSplits — striding over the raw
# listing would spend three quarters of the budget on files Sprout declines.
# Then the stride, because this corpus's pool composition drifts monotonically
# across its window (see `stratified` above), so a head of the *filtered* list
# is still a prefix and still skewed.
dest="$CORPUS_ROOT/sprout_batch_equivalence"
mkdir -p "$dest"
for f in $(reaching_stratified seeds-real/historical_419200_1046400 sprout "$SAMPLE_HISTORICAL"); do
  cp "seeds-real/historical_419200_1046400/$f" "$dest/$f"
done

# --- turnstile: the one target whose seeds are not single transactions ------
#
# `turnstile_order_independence` returns on any stream holding fewer than two
# transactions — with one there is no arrival order to vary. Every other target
# above takes one transaction per seed file, and seeding this one the same way
# would hand it a corpus on which *every* input hits that early return: a target
# that builds, runs, reports a healthy execution rate, and has never once
# reached its assertion. That is the same failure `tests/fuzz_input_reach.rs`
# exists to catch for the signature-bearing targets, arriving by a different
# route — there the extractor rejected the material, here the target never gets
# past its own guard.
#
# So these seeds are concatenations. `tests/fuzz_input_reach.rs` asserts both
# halves of the reason: that one file yields exactly one transaction (so the
# guard would fire), and that a concatenation yields more than one (so it does
# not).
#
# Three sizes rather than one. The target doubles its input (`txs ++ txs`)
# before permuting, so a 2-transaction seed becomes a 4-element run, short
# enough that `reverse` and `evens-then-odds` agree on much of it; the larger
# seeds keep the two permutations distinct.
#
# Drawn from nu6_3_activation because the turnstile's subject is the
# Orchard<->Ironwood boundary, and that is the only corpus carrying dual-pool
# transactions — 77 of its 172.
#
# These counts deliberately do NOT scale with SAMPLE_PER_ERA. The override
# ClusterFuzzLite passes (SAMPLE_PER_ERA=1000000, "take everything") means
# something different for a target whose seed is one file per *run*: it would
# concatenate the whole corpus into a single 5 MB input. Fixed sizes, stated
# here so their absence from the scaling is a decision rather than an omission.
dest="$CORPUS_ROOT/turnstile_order_independence"
mkdir -p "$dest"

concat_seed() { # $1 = source dir, $2 = transactions, $3 = output name
  local f out="$dest/$3"
  : > "$out"
  for f in $(stratified "$1" "$2"); do
    cat "$1/$f" >> "$out"
  done
}

concat_seed seeds-real/nu6_3_activation 2 run_of_2.bin
concat_seed seeds-real/nu6_3_activation 8 run_of_8.bin
concat_seed seeds-real/nu6_3_activation 16 run_of_16.bin

for t in orchard_batch_equivalence orchard_batch_composition orchard_era_routing orchard_single_deep \
         sapling_batch_equivalence sprout_batch_equivalence redjubjub_batch_equivalence \
         tower_partition_equivalence turnstile_order_independence; do
  echo "$t: $(ls "$CORPUS_ROOT/$t" | wc -l) seed(s)"
done
