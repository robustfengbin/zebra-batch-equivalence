#!/bin/bash -eu
#
# ClusterFuzzLite build script for the batch-equivalence oracle.
#
# Runs inside the base-builder-rust container; $OUT, $SRC and $WORK are provided
# by the build environment. Its job is to leave three kinds of file in $OUT:
# the fuzzer binaries, one `<target>_seed_corpus.zip` per target, and nothing
# else.

# cargo-fuzz needs nightly for `-Z sanitizer`, and rust-toolchain.toml in this
# repository asks for the `nightly` channel. Inside the container that pin must
# be overridden, but NOT with the literal string "nightly":
#
#   RUSTUP_TOOLCHAIN=nightly makes rustup resolve the channel, which means
#   downloading *that day's* nightly on every build. Measured here: it fetched
#   1.100.0-nightly (2026-08-27) into an image that already ships
#   nightly-2025-09-05. Two costs, and the second is the one that matters:
#   every build pays a toolchain download, and no two builds a day apart use
#   the same compiler — so a crash that reproduces on Monday's build need not
#   reproduce on Tuesday's, for reasons that have nothing to do with this code.
#
# Naming the image's own default instead makes the toolchain a property of the
# pinned base image, which is the thing the build environment already versions.
export RUSTUP_TOOLCHAIN="$(rustup default | cut -d' ' -f1)"
echo "building with toolchain: $RUSTUP_TOOLCHAIN"

# -O builds the fuzzers in release mode, the OSS-Fuzz Rust convention.
# Deliberately no --locked: cargo-fuzz does not accept it, and the fuzz
# workspace resolves independently of the parent (fuzz/Cargo.lock is its own).
# The lock-pinned, reproducible build is `cargo test --locked` in ci.yml.
cargo fuzz build -O

FUZZ_BIN_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"

# The target list is read from fuzz/Cargo.toml's [[bin]] entries, never globbed
# from fuzz_targets/*.rs: a target is published when it is declared, not when a
# file happens to exist. A glob that picks up one extra entry looks identical to
# one that does not.
#
# 🔴 This was a hand-maintained list, and it was two short: turnstile_order_
# independence and tower_partition_equivalence were added to the fuzz crate and
# never to this file. The build kept succeeding — nine targets compiled, seven
# binaries and seven seed zips were published, and nothing anywhere compared the
# two numbers. One of the missing pair is a Milestone 3 deliverable.
#
# A second list of the same thing is how one of them silently stops describing
# the other; `tests/fuzz_input_reach.rs` additionally checks that Cargo.toml and
# fuzz_targets/ agree, so all three stay in step.
mapfile -t TARGETS < <(
    awk '/^\[\[bin\]\]/{b=1;next} b && /^name = /{gsub(/["]/,"",$3); print $3; b=0}' \
        fuzz/Cargo.toml
)
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "error: no [[bin]] targets found in fuzz/Cargo.toml" >&2
    exit 1
fi
echo "publishing ${#TARGETS[@]} fuzz target(s): ${TARGETS[*]}"

for target in "${TARGETS[@]}"; do
    if [[ ! -x "$FUZZ_BIN_DIR/$target" ]]; then
        echo "error: $target did not build — refusing to publish a partial set" >&2
        exit 1
    fi
    cp "$FUZZ_BIN_DIR/$target" "$OUT/"
done

# --- seed corpora -------------------------------------------------------
#
# The seeds are real mainnet proofs, and the target families take different
# input shapes: a trailing era-selector byte for the two Orchard batch targets,
# a trailing capacity byte for the tower target, a raw transaction stream for
# the rest, and concatenated multi-transaction runs for the turnstile. That
# mapping is written down once, in scripts/prep-fuzz-corpus.sh, and this script
# calls it rather than restating it: two copies of the same mapping is how one
# of them ends up describing a format nothing produces any more.
#
# SAMPLE_PER_ERA stays at the smoke run's six, strided across each window. The
# first version took every seed, on the reasoning that a continuous fuzzer has
# no budget to protect. It has one: ClusterFuzzLite divides fuzz-seconds evenly
# across targets (3600 s / 9 = 400 s each in the daily run), and libFuzzer
# executes the starting corpus before it mutates anything; a budget that runs
# out during that pass ends the run there. An Orchard seed costs seconds, not
# milliseconds -- each drives real proof verification. Measured under OSS-Fuzz's
# base-runner on 2026-09-22, on a shared machine, with -max_total_time=400:
# orchard_batch_equivalence stopped 129 inputs into its 589 seeds, at 444 s, and
# reported INITED and DONE at the same count -- not one mutated input. Every
# daily run would have been green while the four Orchard targets fuzzed nothing. The permanent corpus grows from these seeds instead;
# more seeds should come back only after `cargo fuzz cmin` has cut them down.
SEED_ROOT="$WORK/seed-corpus"
rm -rf "$SEED_ROOT"
SAMPLE_PER_ERA=6 CORPUS_ROOT="$SEED_ROOT" ./scripts/prep-fuzz-corpus.sh

for target in "${TARGETS[@]}"; do
    seeds="$SEED_ROOT/$target"
    count=$(find "$seeds" -type f | wc -l)
    if [[ "$count" -eq 0 ]]; then
        echo "error: $target has an empty seed corpus" >&2
        exit 1
    fi
    # Zip from inside the directory so entries are bare filenames, which is the
    # layout ClusterFuzzLite unpacks into the target's corpus. Remove any archive
    # already there first: `zip` adds to an existing one rather than replacing
    # it, so a rebuild into a reused $OUT kept every earlier seed (measured: a
    # 589-seed archive stayed 589 after the seed count was cut to 21).
    rm -f "$OUT/${target}_seed_corpus.zip"
    (cd "$seeds" && zip -q -r "$OUT/${target}_seed_corpus.zip" .)
    echo "$target: $count seed(s) packed"
done
