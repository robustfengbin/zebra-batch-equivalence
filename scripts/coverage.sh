#!/usr/bin/env bash
# Reproducible coverage of the batch verification paths under the equivalence
# oracle — M1's AC3 (Orchard), extended in M2 to every verifier Zebra runs.
#
#   ./scripts/coverage.sh              # fast: fuzz-replay only (~30 min)
#   ./scripts/coverage.sh --with-tests # full: fuzz-replay + test-suite + MERGED (~60 min)
#
# NOTE ON WHICH COLUMN SHOWS WHAT: the fuzz-replay corpus drives the *Orchard*
# targets only, so pools with no fuzz target yet appear solely in TEST-ONLY and
# MERGED. That is not a coverage gap in those pools, it is which harness reaches
# them — read the MERGED column, which is what the AC is judged on.
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

# Which nightly to measure with. Region counts are NOT toolchain-independent —
# inlining decisions belong to the compiler, so the same source measured under a
# different nightly yields different region totals, silently and without error.
# `rust-toolchain.toml` pins the channel but not a date, so two machines that both
# say "nightly" can disagree. Override to reproduce a published set of figures:
#
#   NIGHTLY=nightly-2026-07-03 ./scripts/coverage.sh --with-tests
#
# (`reports/m2-coverage.md` names the toolchain its numbers were produced under.
# Note rustup's dated channels are named by *release* date, one day after the
# rustc commit date the compiler reports — nightly-2026-07-03 is the build that
# `rustc -vV` calls `c397dae80 2026-07-02`. Picking the channel that matches the
# printed commit date gets you the previous day's compiler.)
NIGHTLY="${NIGHTLY:-nightly}"

HOST=$(rustc "+$NIGHTLY" -vV | awk '/^host:/{print $2}')
LLVMBIN="$(rustc "+$NIGHTLY" --print sysroot)/lib/rustlib/$HOST/bin"
PROFDATA="$LLVMBIN/llvm-profdata"; COV="$LLVMBIN/llvm-cov"
# The measured surface, one alternative per verifier the oracle drives.
#
# Path shapes differ by dependency kind and the regexes must match that, not a
# convention: crates.io deps live under `registry/src/<index>/<name>-<version>/`,
# so `<name>-.*` works; git deps live under
# `git/checkouts/<repo>-<hash>/<7-char-rev>/<crate>/` — no version in the path at
# all, which is why tower-batch-control is matched by its crate directory rather
# than by a `-.*` version pattern.
SURFACES=(
  'bundle/batch.rs'                            # orchard  BatchValidator      (M1)
  'plonk/verifier'                             # halo2    batch + SingleVerifier
  'reddsa-.*/src/batch.rs'                     # reddsa   RedPallas *and* RedJubjub, see below
  'redjubjub-.*/src/batch\.rs'                 # redjubjub wrapper over reddsa   (M2)
  'sapling-crypto-.*/src/verifier'             # sapling  BatchValidator + single  (M2)
  'bellman-.*/src/groth16/verifier'            # sprout   groth16 batch + single   (M2)
  'tower-batch-control/src/(service|worker)\.rs'  # batch scheduling glue  (M2)
)
FILT=$(IFS='|'; printf '%s' "${SURFACES[*]}")

# A surface that matches nothing looks exactly like a surface that is fully covered:
# in both cases the table simply has no row for it, and nothing exits non-zero. That
# is not hypothetical — `tower-batch-control` was added to this filter on 2026-07-28
# and matched nothing from the moment it was written, because the crate was not in our
# dependency graph yet. It is one of the three objects the grant names, and the table
# looked complete without it. (It is measured now: `src/tower.rs` landed and drives it.
# The audit is what turned "silently absent" into a warning line in the meantime.)
#
# So every surface is audited against the report it was supposed to filter, and an
# empty one is announced. A regex that matches nothing is a claim we are not making.
audit_surfaces() {
  local label="$1" report="$2" pat empty=0
  for pat in "${SURFACES[@]}"; do
    grep -qE "$pat" <<<"$report" || { printf '  \033[33m⚠ %s: surface matched nothing: %s\033[0m\n' "$label" "$pat"; empty=$((empty + 1)); }
  done
  [[ $empty -eq 0 ]] && printf '  \033[32m✓ %s: all %d surfaces present\033[0m\n' "$label" "${#SURFACES[@]}"
}

# WHY redjubjub NEEDS ITS OWN ROW, and why the reddsa row stopped meaning what it
# meant in M1 (measured 2026-07-29, both claims reproducible with `cargo tree`):
#
#   RedPallas:  orchard        -> reddsa::batch::Verifier<orchard::{SpendAuth,Binding}>
#   RedJubjub:  sapling-crypto -> redjubjub::batch::Verifier   (127 lines of newtype)
#                                   -> reddsa::batch::Verifier<sapling::{SpendAuth,Binding}>
#
# Two consequences, and neither announces itself:
#
# 1. `redjubjub-0.8.0/src/batch.rs` is a separate source file that no pattern here
#    used to match. It is already being executed — Sapling's signature sub-batch is
#    that wrapper — so the table has been missing a file that was running, while
#    looking complete. Nothing errors when a regex matches one file fewer.
#
# 2. `reddsa/src/batch.rs` is now driven by BOTH verifiers through the SAME compiled
#    file (one reddsa 0.5.2 in the lock; the 0.5.1 also present in the registry is not
#    in this graph). The two monomorphisations land on the same source lines, so the
#    number is their union and RedJubjub's contribution is not separable from it —
#    not by any regex, only by running one suite at a time
#    (`scripts/coverage-attribution.sh`).
#
#    So the M1-vs-M2 comparison on this row is no longer like-for-like: M1's 100.0 was
#    RedPallas alone. Do not present a matching number here as "unchanged" — it is a
#    different measurement that happens to be close.
tidy() { sed 's#.*/\.cargo/registry/src/[^/]*/#reg: #; s#.*/zebra-batch-equivalence/##'; }

# --- fuzz-replay corpus (era-correct control bytes) ---
FZ=$(mktemp -d); trap 'rm -rf "$FZ"' EXIT
cp seeds-real/orchard_pre_nu6_2/seed_pre_nu6_2_* "$FZ/"
for f in seeds-real/orchard_v5_pre_nu6_2/*.bin; do o="$FZ/$(basename "$f" .bin)_c0"; cp "$f" "$o"; printf '\x00' >> "$o"; done
for f in seeds-real/orchard_v5_nu6_2/*.bin;     do o="$FZ/$(basename "$f" .bin)_c1"; cp "$f" "$o"; printf '\x01' >> "$o"; done
echo "fuzz-replay: $(ls "$FZ" | wc -l) seeds"
cargo "+$NIGHTLY" fuzz coverage orchard_batch_equivalence "$FZ"

FUZZ_BIN="target/$HOST/coverage/$HOST/release/orchard_batch_equivalence"
FUZZ_PROF="fuzz/coverage/orchard_batch_equivalence/coverage.profdata"

echo "===== FUZZ-ONLY (Orchard verify path) ====="
FUZZ_REPORT=$("$COV" report -object "$FUZZ_BIN" --instr-profile="$FUZZ_PROF" 2>/dev/null | grep -E "Filename|$FILT")
tidy <<<"$FUZZ_REPORT"
# Not audited: the fuzz corpus drives the Orchard targets only, so most surfaces are
# legitimately absent here. The audit belongs on MERGED, which is what the AC judges.

if [[ $WITH_TESTS -eq 1 ]]; then
  WORK="fuzz/coverage/_merged"; rm -rf "$WORK"; mkdir -p "$WORK/prof"
  export CARGO_TARGET_DIR="$WORK/target-cov" RUSTFLAGS="-C instrument-coverage"
  mapfile -t TB < <(cargo "+$NIGHTLY" test --tests --no-run --message-format=json 2>/dev/null \
    | jq -r 'select(.executable!=null and .profile.test==true)|.executable')
  # Kept, not discarded. `set -e` stops the script if a test fails, so a broken run
  # cannot silently produce a report from partial profraw — but without this log a
  # failure and a pass look identical from here, and the instrumented suite is the
  # longest run in the script to have to repeat blind. $WORK is gitignored.
  LLVM_PROFILE_FILE="$PWD/$WORK/prof/cov-%p-%m.profraw" cargo "+$NIGHTLY" test --tests > "$WORK/test-run.log" 2>&1
  "$PROFDATA" merge -sparse "$WORK"/prof/*.profraw -o "$WORK/test.profdata"
  "$PROFDATA" merge -sparse "$WORK/test.profdata" "$FUZZ_PROF" -o "$WORK/merged.profdata"
  TOBJ=(); for b in "${TB[@]}"; do TOBJ+=(-object "$b"); done

  echo "===== TEST-ONLY ====="
  "$COV" report "${TOBJ[@]}" --instr-profile="$WORK/test.profdata" 2>/dev/null | grep -E "Filename|$FILT" | tidy
  echo "===== MERGED (AC judged here) ====="
  MERGED_REPORT=$("$COV" report -object "$FUZZ_BIN" "${TOBJ[@]}" --instr-profile="$WORK/merged.profdata" 2>/dev/null | grep -E "Filename|$FILT")
  tidy <<<"$MERGED_REPORT"
  audit_surfaces "MERGED" "$MERGED_REPORT"
fi
