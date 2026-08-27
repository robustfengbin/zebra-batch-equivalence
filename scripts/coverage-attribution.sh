#!/usr/bin/env bash
# Per-test-binary coverage attribution — which verifier drives which measured file.
#
#   ./scripts/coverage-attribution.sh            # every test binary
#   ./scripts/coverage-attribution.sh sapling    # only binaries whose name matches
#
# WHY THIS EXISTS, separately from coverage.sh
#
# coverage.sh answers the acceptance criterion: it merges every harness and reports
# one number per measured file. That is the right shape for the AC — the grant names
# three measurement *objects* (`tower-batch-control`, `BatchValidator`, reddsa batch),
# not verifiers — but it cannot answer a question a reviewer will still ask:
#
#     "The bellman rows are Sprout's, right?"
#
# They are not. `bellman` reaches the dependency graph through `sapling-crypto`
# (Sapling's spend and output proofs are Groth16), so those rows light up from the
# Sapling suite alone, before a single line of Sprout exists. `cargo tree -i bellman`
# shows the same thing, but that is an argument about the dependency graph. This
# script is the measurement: run one test binary, see which files it lit.
#
# A crate is not a verifier. `reddsa/src/batch.rs` will be RedPallas + RedJubjub once
# both are wired, and the merged column will never say which contributed what. Whoever
# reads only the merged table will attribute coverage to whichever verifier they were
# thinking about — including us. Attribution is not an AC requirement; it is what stops
# the report from making a claim the numbers do not support.
#
# COST: the same test suite, run once per binary instead of once in total, and each
# binary re-parses the Sapling parameters. Budget an hour. It is reproducible rather
# than cheap, which is the trade the report needs — a reviewer can rerun any single
# row of the matrix in minutes without rerunning the whole thing.
set -euo pipefail
cd "$(dirname "$0")/.."

ONLY="${1:-}"

HOST=$(rustc +nightly -vV | awk '/^host:/{print $2}')
LLVMBIN="$(rustc +nightly --print sysroot)/lib/rustlib/$HOST/bin"
PROFDATA="$LLVMBIN/llvm-profdata"; COV="$LLVMBIN/llvm-cov"

# The measured surface, kept identical to coverage.sh — the attribution matrix is
# only useful if its rows are the same rows the AC is judged on.
FILT='bundle/batch.rs'                          # orchard  BatchValidator      (M1)
FILT+='|plonk/verifier'                         # halo2    batch + SingleVerifier
FILT+='|reddsa-.*/src/batch.rs'                 # reddsa   RedPallas *and* RedJubjub
FILT+='|redjubjub-.*/src/batch\.rs'             # redjubjub wrapper over reddsa   (M2)
FILT+='|sapling-crypto-.*/src/verifier'         # sapling  BatchValidator + single  (M2)
FILT+='|bellman-.*/src/groth16/verifier'        # sprout   groth16 batch + single   (M2)
FILT+='|tower-batch-control/src/(service|worker)\.rs'  # batch scheduling glue  (M2)

WORK="fuzz/coverage/_attribution"
rm -rf "$WORK"; mkdir -p "$WORK/rows"

# Deliberately OUTSIDE $WORK, which is wiped on every run: the instrumented build is
# the expensive part and nothing about it changes between a full run and a filtered
# one. Rebuilding it to re-measure a single row would make the per-row rerun — the
# whole reason a reviewer can check one line of the matrix cheaply — cost as much as
# the matrix.
export CARGO_TARGET_DIR="fuzz/coverage/_attribution-target" RUSTFLAGS="-C instrument-coverage"

echo "building instrumented test binaries..."
mapfile -t BINS < <(cargo +nightly test --lib --tests --no-run --message-format=json 2>/dev/null \
  | jq -r 'select(.executable!=null and .profile.test==true)|.executable')
[[ ${#BINS[@]} -gt 0 ]] || { echo "no test binaries built" >&2; exit 1; }

for bin in "${BINS[@]}"; do
  # target/<...>/deps/sapling_agreement-9f3c1e2a  ->  sapling_agreement
  name=$(basename "$bin"); name="${name%-*}"
  [[ -n "$ONLY" && "$name" != *"$ONLY"* ]] && continue

  d="$WORK/prof/$name"; mkdir -p "$d"
  echo "=== $name ==="
  # Run from the repository root: the corpus paths in the tests are relative to it.
  # Failures are not fatal — a red test still produced coverage, and hiding the run
  # would hide why a row is empty.
  if ! LLVM_PROFILE_FILE="$PWD/$d/cov-%p-%m.profraw" "$bin" --test-threads=4 >"$d/run.log" 2>&1; then
    echo "  (test binary exited non-zero — see $d/run.log)"
  fi
  "$PROFDATA" merge -sparse "$d"/*.profraw -o "$d/x.profdata"

  # Rows this binary actually reached. A measured file missing from the report was
  # not linked into this binary at all, which is itself an attribution answer and is
  # why the summary distinguishes "absent" from "0.00".
  #
  # `|| true` is load-bearing under `set -e -o pipefail`: a binary that links none of
  # the measured surfaces — the corpus tools, for one — makes grep exit 1 on an
  # entirely correct empty result, and the run would die on its first such binary.
  # An empty match is an answer here, not a failure.
  rows=$("$COV" report -object "$bin" --instr-profile="$d/x.profdata" 2>/dev/null \
    | { grep -E "$FILT" || true; } \
    | awk -v b="$name" '{
        f=$1; sub(/.*\/\.cargo\/registry\/src\/[^/]*\//,"",f); sub(/.*\/\.cargo\/git\/checkouts\/[^/]*\/[^/]*\//,"",f);
        # llvm-cov report columns: Filename Regions Missed Cover Functions ...
        print b "\t" f "\t" $4
      }')
  if [[ -z "$rows" ]]; then
    echo "  (links none of the measured surfaces — no column in the matrix)"
  else
    printf '%s\n' "$rows" | tee "$WORK/rows/$name.tsv"
  fi
done

echo
echo "===== ATTRIBUTION MATRIX (region coverage; '-' = file not linked into that binary) ====="
shopt -s nullglob; ROWS=("$WORK"/rows/*.tsv); shopt -u nullglob
[[ ${#ROWS[@]} -gt 0 ]] || { echo "no binary reached any measured surface — check the filter" >&2; exit 1; }
cat "${ROWS[@]}" > "$WORK/all.tsv"
awk -F'\t' '
  { cov[$2 SUBSEP $1]=$3; files[$2]=1; bins[$1]=1 }
  END {
    nb=0; for (b in bins) blist[++nb]=b
    # deterministic column order
    for (i=1;i<nb;i++) for (j=i+1;j<=nb;j++) if (blist[i]>blist[j]) { t=blist[i]; blist[i]=blist[j]; blist[j]=t }
    printf "%-46s", "file"
    for (i=1;i<=nb;i++) printf "%16s", blist[i]
    printf "\n"
    nf=0; for (f in files) flist[++nf]=f
    for (i=1;i<nf;i++) for (j=i+1;j<=nf;j++) if (flist[i]>flist[j]) { t=flist[i]; flist[i]=flist[j]; flist[j]=t }
    for (i=1;i<=nf;i++) {
      printf "%-46s", flist[i]
      for (j=1;j<=nb;j++) { k=flist[i] SUBSEP blist[j]; printf "%16s", (k in cov ? cov[k] : "-") }
      printf "\n"
    }
  }' "$WORK/all.tsv"
