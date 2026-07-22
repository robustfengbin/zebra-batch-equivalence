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

sample() { ls "$1" | sort | head -n "$SAMPLE_PER_ERA"; }

seed_control() { # $1 = source dir, $2 = control byte (octal escape), $3 = dest dir
  local f
  for f in $(sample "$1"); do
    cp "$1/$f" "$3/$f"
    printf "$2" >> "$3/$f"
  done
}

seed_raw() { # $1 = source dir, $2 = dest dir
  local f
  for f in $(sample "$1"); do
    cp "$1/$f" "$2/$f"
  done
}

for target in orchard_batch_equivalence orchard_batch_composition; do
  dest="fuzz/corpus/$target"
  mkdir -p "$dest"
  # The dump_seeds vectors already carry their control byte.
  cp seeds-real/orchard_pre_nu6_2/seed_pre_nu6_2_* "$dest/"
  seed_control seeds-real/orchard_v5_pre_nu6_2 '\x00' "$dest"
  seed_control seeds-real/orchard_v5_nu6_2 '\x01' "$dest"
done

for target in orchard_era_routing orchard_single_deep; do
  dest="fuzz/corpus/$target"
  mkdir -p "$dest"
  seed_raw seeds-real/orchard_v5_pre_nu6_2 "$dest"
  seed_raw seeds-real/orchard_v5_nu6_2 "$dest"
done

for t in orchard_batch_equivalence orchard_batch_composition orchard_era_routing orchard_single_deep; do
  echo "$t: $(ls "fuzz/corpus/$t" | wc -l) seed(s)"
done
