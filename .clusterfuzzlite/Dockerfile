# ClusterFuzzLite build environment for the batch-equivalence oracle's fuzz suite.
#
# This is the M3 deliverable's *self-hosted* half: ClusterFuzzLite runs the same
# libFuzzer targets this repository already builds in CI, but continuously —
# on every pull request, on a schedule, and against a corpus that survives
# between runs. It needs no enrolment with any third party, so the acceptance
# criterion ("CI integration green and self-running") does not depend on an
# external merge decision.
#
# base-builder-rust ships the nightly toolchain and cargo-fuzz pre-installed:
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/
FROM gcr.io/oss-fuzz-base/base-builder-rust

# clang is the one system dependency beyond base-builder-rust. It is not for
# this crate's own code: `blake2b_simd` and the `zcash_proofs` bundled-prover
# closure reach C through bindgen, which needs libclang at build time.
#
# Deliberately *not* installed: cmake / protobuf-compiler / librocksdb. Those
# are what the full Zebra workspace needs, and the reason this harness does not
# is a design property worth preserving — it depends on `zebra-chain` and
# `tower-batch-control` only, never `zebra-state`, so no RocksDB and no FFI
# into zcash_script enters the graph. If a future target makes this line grow,
# that is a signal the dependency boundary moved, not a build detail.
RUN apt-get update && \
    apt-get install -y --no-install-recommends clang libclang-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . $SRC/zebra-batch-equivalence
COPY .clusterfuzzlite/build.sh $SRC/
WORKDIR $SRC/zebra-batch-equivalence
