#!/usr/bin/env bash
# AC3 "reproducible coverage" of the Orchard batch verification path (W2).
#
#   ./scripts/coverage.sh              # fast: fuzz-replay only (~30 min)
#   ./scripts/coverage.sh --with-tests # full: fuzz-replay + test-suite + MERGED (~50 min)
#
# The quantified AC (final requirements §4-W2) is judged on the MERGED column:
# both harnesses — coverage-guided fuzzing AND the deterministic test suite —
# exercise the same verifiers, so their union is the coverage the grant claims.
# Reporting all three columns separately is deliberate: the reject-arm coverage
# comes from the deterministic tests (mutation_smoke / add_reject_equivalence),
# not from a lucky fuzz hit, which is a stronger soundness story, not a weaker one.
#
# Corpus-format note: the equivalence target's input is `tx-stream ++ 1 era
# control byte`; the node-extracted `seeds-real/*.bin` are RAW tx bytes, so each
# gets its era byte appended (0x00 pre-NU6.2 / 0x01 NU6.2) — fed raw, the target
# eats the tx's real last byte as the control byte and deserialization fails.
set -euo pipefail
cd "$(dirname "$0")/.."

WITH_TESTS=0; [[ "${1:-}" == "--with-tests" ]] && WITH_TESTS=1

HOST=$(rustc +nightly -vV | awk '/^host:/{print $2}')
LLVMBIN="$(rustc +nightly --print sysroot)/lib/rustlib/$HOST/bin"
PROFDATA="$LLVMBIN/llvm-profdata"; COV="$LLVMBIN/llvm-cov"
FILT='bundle/batch.rs|plonk/verifier|reddsa-.*/src/batch.rs'
tidy() { sed 's#.*/\.cargo/registry/src/[^/]*/#reg: #; s#.*/zebra-batch-equivalence/##'; }

# --- fuzz-replay corpus (era-correct control bytes) ---
FZ=$(mktemp -d); trap 'rm -rf "$FZ"' EXIT
cp seeds-real/orchard_pre_nu6_2/seed_pre_nu6_2_* "$FZ/"
for f in seeds-real/orchard_v5_pre_nu6_2/*.bin; do o="$FZ/$(basename "$f" .bin)_c0"; cp "$f" "$o"; printf '\x00' >> "$o"; done
for f in seeds-real/orchard_v5_nu6_2/*.bin;     do o="$FZ/$(basename "$f" .bin)_c1"; cp "$f" "$o"; printf '\x01' >> "$o"; done
echo "fuzz-replay: $(ls "$FZ" | wc -l) seeds"
cargo +nightly fuzz coverage orchard_batch_equivalence "$FZ"

FUZZ_BIN="target/$HOST/coverage/$HOST/release/orchard_batch_equivalence"
FUZZ_PROF="fuzz/coverage/orchard_batch_equivalence/coverage.profdata"

echo "===== FUZZ-ONLY (Orchard verify path) ====="
"$COV" report -object "$FUZZ_BIN" --instr-profile="$FUZZ_PROF" 2>/dev/null | grep -E "Filename|$FILT" | tidy

if [[ $WITH_TESTS -eq 1 ]]; then
  WORK="fuzz/coverage/_merged"; rm -rf "$WORK"; mkdir -p "$WORK/prof"
  export CARGO_TARGET_DIR="$WORK/target-cov" RUSTFLAGS="-C instrument-coverage"
  mapfile -t TB < <(cargo +nightly test --tests --no-run --message-format=json 2>/dev/null \
    | jq -r 'select(.executable!=null and .profile.test==true)|.executable')
  LLVM_PROFILE_FILE="$PWD/$WORK/prof/cov-%p-%m.profraw" cargo +nightly test --tests >/dev/null 2>&1
  "$PROFDATA" merge -sparse "$WORK"/prof/*.profraw -o "$WORK/test.profdata"
  "$PROFDATA" merge -sparse "$WORK/test.profdata" "$FUZZ_PROF" -o "$WORK/merged.profdata"
  TOBJ=(); for b in "${TB[@]}"; do TOBJ+=(-object "$b"); done

  echo "===== TEST-ONLY ====="
  "$COV" report "${TOBJ[@]}" --instr-profile="$WORK/test.profdata" 2>/dev/null | grep -E "Filename|$FILT" | tidy
  echo "===== MERGED (AC judged here) ====="
  "$COV" report -object "$FUZZ_BIN" "${TOBJ[@]}" --instr-profile="$WORK/merged.profdata" 2>/dev/null | grep -E "Filename|$FILT" | tidy
fi
