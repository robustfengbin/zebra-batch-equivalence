# ZCG #332 — Milestone 2 Region Coverage Report

**Status: measured.** All six M2 deliverables have landed — four verifiers under the
equivalence oracle, the `tower-batch-control` scheduler driven directly, and the
adversarial corpus generator. §3 carries the final numbers, taken after the last of them.

§3 keeps its mid-build column beside the final one, because **the movement between them
is itself a measurement** — see the readings below the table. The attribution matrix in
§4 has been re-run on the same tree as §3, so both come from one commit.

Base: Zebra **v6.3.0** (`f5c5277fe41eba9c74f37098738f93f35dd70d60`), pinned by git rev.
All measurements below were produced on that base — re-measured on 2026-08-26 when the
pin moved from v6.2.3, rather than carried over. Both workspaces moved together: the
fuzz tree is a separate cargo workspace with its own lockfile, so a base bump that
updated only the root lock would have left the FUZZ-ONLY column on the old base while
MERGED — the column the AC is judged on — silently spanned two.

**Toolchain (this report's numbers depend on it):** `rustc 1.98.0-nightly (c397dae80
2026-07-02)`, via `rust-toolchain.toml`'s `channel = "nightly"`.

⚠️ **Region counts are not toolchain-independent, and this report is the only place that
says so.** The test suite is a set of behavioural assertions and reproduces from a clean
clone on any toolchain that builds the tree. Region *counts* do not: inlining decisions
belong to the compiler, so a different nightly can move them with the source byte-identical.
`rust-toolchain.toml` pins the channel but not a date, so `rustup update` is enough to
change what a reader measures. **To reproduce the numbers below, pin the nightly above:**

```
rustup toolchain install nightly-2026-07-03
NIGHTLY=nightly-2026-07-03 ./scripts/coverage.sh --with-tests
```

Note the date. rustup names a dated channel by its *release* date, one day after the
commit date `rustc -vV` prints — so `nightly-2026-07-02` installs `4c9d2bfe4 2026-07-01`,
the compiler before this one. Both call themselves `1.98.0-nightly` and neither errors.

---

## 1. What the milestone asks for

> *region-coverage report on `tower-batch-control` + `BatchValidator` + reddsa batch*

Three **measurement objects**, not four verifiers. That distinction drives the shape of
this report: the objects are crates and modules, the verifiers are what drive them, and
the mapping between the two is many-to-many. Section 4 is about exactly that.

| Object named in the grant | Measured files | Status |
|---|---|---|
| `BatchValidator` | `orchard-0.15.3/src/bundle/batch.rs` | measured (M1) |
| | `sapling-crypto-0.7.0/src/verifier/batch.rs` | measured |
| reddsa batch | `reddsa-0.5.2/src/batch.rs` | measured |
| | `redjubjub-0.8.0/src/batch.rs` | measured |
| `tower-batch-control` | `tower-batch-control/src/{service,worker}.rs` | **measured** (76.36 / 59.43 region) |

Two supporting surfaces are measured alongside them, because they are the independent
("layer 2") implementations the equivalence property is asserted against:

| Supporting surface | Measured files |
|---|---|
| halo2 single/batch verifier | `halo2_proofs-0.3.2/src/plonk/verifier{.rs,/batch.rs}` |
| Sapling single verifier | `sapling-crypto-0.7.0/src/verifier{.rs,/single.rs}` |
| bellman Groth16 verifier | `bellman-0.14.0/src/groth16/verifier{.rs,/batch.rs}` |

All four verifiers now drive these surfaces; Sprout's relationship to the bellman rows
is not the one the crate name suggests (§4) and the batch path it exercises is not one
Zebra runs (§5).

## 2. How it is measured

`scripts/coverage.sh` produces three columns from two harnesses:

- **FUZZ-ONLY** — replay of the committed seed corpus through the coverage-guided fuzz
  targets. Drives the Orchard path only, so most surfaces are legitimately absent here.
- **TEST-ONLY** — the deterministic test suite.
- **MERGED** — the union, and **the column the acceptance criterion is judged on**.

Reporting all three separately is deliberate rather than decorative: the reject-arm
coverage comes from the deterministic tests (`mutation_smoke`, `add_reject_equivalence`),
not from a lucky fuzz hit. A reader who sees only the merged number cannot tell whether
the negative paths were reached on purpose.

`--with-tests` produces all three and takes about an hour; the default run produces
FUZZ-ONLY in about thirty minutes.

## 3. Numbers

MERGED column, region % / line %. Sapling was added in M2; the M1 rows are repeated so
the effect of re-basing is visible.

Final figures first measured at `9a546ba` with every deliverable in place, and
**re-measured in full at `8ae8386` when the base moved to v6.3.0** — every one of the
twelve rows came back bit-identical. See the note under the table. The mid-build column
is what the same surfaces read before Sprout, RedJubjub and the tower layer had their own
suites — kept deliberately, because a coverage number is only meaningful against the
commit that produced it, and because three of the differences answer questions this
report had left open.

| Surface | M1 (v6.2.0) | M2 mid-build | **M2 final** |
|---|---|---|---|
| orchard `bundle/batch.rs` | 100.00 / 100.00 | 100.00 / 100.00 | **100.00 / 100.00** |
| halo2 `plonk/verifier/batch.rs` | 100.00 / 100.00 | 100.00 / 100.00 | **100.00 / 100.00** |
| halo2 `plonk/verifier.rs` | — / 98.4 | 95.11 / 98.37 | **95.11 / 98.37** |
| reddsa `src/batch.rs` | 100.00 / 100.00 | 98.97 / 100.00 | **98.97 / 100.00** ⚠ §4 |
| sapling `verifier/single.rs` | — | 100.00 / 100.00 | **100.00 / 100.00** |
| sapling `verifier.rs` | — | 97.09 / 96.34 | **97.09 / 96.34** |
| sapling `verifier/batch.rs` | — | 86.55 / 83.70 | **89.08 / 86.96** |
| bellman `groth16/verifier.rs` | — | 95.35 / 93.75 | **97.67 / 96.88** |
| bellman `groth16/verifier/batch.rs` | — | 56.31 / 61.07 | **94.59 / 94.63** |
| redjubjub `src/batch.rs` | — | 72.73 / 82.14 | **100.00 / 100.00** |
| **`tower-batch-control/src/service.rs`** | — | not driven | **76.36 / 81.20** |
| **`tower-batch-control/src/worker.rs`** | — | not driven | **59.43 / 65.90** |

*"M2 mid-build" = measured before Sprout, RedJubjub and the tower layer had their own
suites. Both columns are kept because the movement between them is evidence, not noise —
see below.*

The four M1 surfaces were re-measured on the new base and agree with M1 digit for digit
in **both** columns (fuzz-only and merged). The claim "the M1 numbers still hold after
re-basing" therefore rests on a re-run, not only on the source diff that motivated it.

**v6.2.3 → v6.3.0 re-measurement (2026-08-26).** The whole table was produced again at
the new base, on different hardware (24 cores under other load, rather than 6 idle), with
the toolchain held fixed at the nightly named above. **All twelve rows are identical to
the digit, in all three columns.**

That result is worth stating precisely, because one row was expected to move and did not.
`tower-batch-control/src/worker.rs` is driven through Zebra's real scheduler, whose batch
boundaries are decided by a `tokio::select!` race between "another item arrived" and "the
batch timer fired" — so which of its branches execute is not obviously determined, and
59.43 was flagged in advance as the row most likely to drift between runs. It came back
at 59.43 / 65.90 from a machine with four times the cores and a competing database
workload.

**This does not prove the row cannot drift**; it is two measurements, not a distribution.
What it does establish is that the figure is not an artefact of one machine's timing, and
that the re-measurement gives no reason to treat any row as base-dependent. Had a row
moved, the honest reading would have been the opposite, and this paragraph was written
before the numbers came back.

### What moved, and what each movement means

- 🔴 **bellman `groth16/verifier/batch.rs`: 56.31 → 94.59 (+38.28).** This is the largest
  movement in the table and it answers the question §4 deliberately refused to guess.
  That row was Sapling's alone at mid-build; Sprout landing added **38 points of regions
  Sapling never reached**. So the two Groth16 consumers overlap far less than a shared
  crate name suggests — Sprout is not redundant coverage of a path Sapling already
  exercised. Had the increase been small, the honest conclusion would have been the
  opposite, and the report was written to accept either.
- **redjubjub `src/batch.rs`: 72.73 → 100.00.** At mid-build this was a floor — what
  Sapling's signature sub-batch reaches incidentally. With RedJubjub driven as its own
  verifier the wrapper is fully covered.
- **sapling `verifier/batch.rs`: 86.55 → 89.08.** The adversarial generator moved it, as
  intended, but **it is still the lowest of the `BatchValidator` rows and this report does
  not present it as closed**. What remains uncovered is enumerated in §6 — and it is not
  the kind of gap that closing would improve.
- **`tower-batch-control`: first measurement, 76.36 (service) and 59.43 (worker).**
  `worker.rs` is the lowest number in the report and the reason is structural rather than
  an oversight: it is an async scheduling loop whose uncovered regions are shutdown paths,
  channel-closure handling and error propagation, none of which a test that drives batches
  to completion will enter. Covering them means faulting the service, not feeding it more
  items — a different kind of test than anything M2 built, and named here as future work
  rather than rounded off.

## 4. Attribution: a crate is not a verifier

The merged table above answers the acceptance criterion. It cannot answer a question a
reader will still ask — *which verifier covered this?* — and answering it wrongly is easy,
because the natural reading of a per-crate table is that each row belongs to one verifier.
Three rows in this table do not.

**`bellman` is reached through Sapling, not Sprout.** Sapling's spend and output proofs
are Groth16, so `sapling-crypto` depends on `bellman`. The matrix below was measured at
`26c44b7`, when no Sprout support existed at all — and those rows were already lit, by
Sapling alone, at 95.35 and 56.31. Read as Sprout's they would have credited coverage to
a verifier that had not been written.

Sprout has since landed, which turned that caveat into a measurement: **the row went
56.31 → 94.59.** A small increase would have meant the two verifiers largely overlap
there; this one means Sprout reaches a large body of code Sapling never does. The
prediction was left open on purpose and the answer came back at the far end of the range.

**`reddsa/src/batch.rs` is driven by both signature verifiers, through one compiled file.**
RedPallas reaches it directly from `orchard`; RedJubjub reaches it through
`redjubjub-0.8.0`, a 127-line newtype wrapper. Both monomorphisations land on the same
source lines, so the reported number is their **union** and no regex can separate them.
This also means the row is **not comparable to M1's**, where the same number described
RedPallas alone. A number that matches M1 here is a different measurement that happens to
be close, and this report does not present it as unchanged.

**`redjubjub-0.8.0/src/batch.rs` was executing before it was measured.** Sapling's
signature sub-batch *is* that wrapper. It was absent from the measured set until
2026-07-29 not because it was uncovered but because no pattern matched it — and a
surface that matches nothing is indistinguishable, in the output, from one that isn't
there. `scripts/coverage.sh` now audits every pattern against the report it filtered and
announces any that matched nothing.

### The measurement, not the argument

Dependency-graph reasoning (`cargo tree -i bellman`) supports all three claims, but it is
an argument about linkage. `scripts/coverage-attribution.sh` measures them instead: it
runs one test binary at a time and reports which surfaces that binary lit. Across all
eleven binaries, region %, showing which suite drives each surface:

| Surface | Which suites reach it (region %) | MERGED |
|---|---|---|
| `tower-batch-control/src/service.rs` | **`tower_batching` alone** 76.36 | 76.36 |
| `tower-batch-control/src/worker.rs` | **`tower_batching` alone** 59.43 | 59.43 |
| bellman `groth16/verifier/batch.rs` | `sapling_agreement` 56.31 / **`sprout_agreement` 44.59** / `adversarial_generator` 56.76 | **94.59** |
| bellman `groth16/verifier.rs` | `sprout_agreement` 97.67 / `sapling_agreement` 95.35 / lib units 37.21 | 97.67 |
| sapling `verifier/batch.rs` | `adversarial_generator` **89.08** / `sapling_agreement` 86.55 | 89.08 |
| sapling `verifier.rs` | `sapling_agreement` / `adversarial_generator` 97.09 | 97.09 |
| sapling `verifier/single.rs` | `sapling_agreement` **100.00** / `adversarial_generator` 48.00 | 100.00 |
| redjubjub `src/batch.rs` | **`redjubjub_agreement` 100.00** / `tower_batching` 78.79 / Sapling suites 72.73 | 100.00 |
| reddsa `src/batch.rs` | **twelve binaries**, peak `strategy_equivalence` 98.45, floor 84.02 | 98.97 |
| orchard `bundle/batch.rs` | eight Orchard binaries, 81.03–91.38 / **0.00 in every Sapling/Sprout suite** | 100.00 |
| halo2 `plonk/verifier/batch.rs` | eight Orchard binaries / **100.00 in `mutation_smoke` alone**, 92.59 elsewhere | 100.00 |
| halo2 `plonk/verifier.rs` | eight Orchard binaries, peak `strategy_equivalence` 94.87 | 95.11 |

**`bellman groth16/verifier/batch.rs` is now attributed both ways, and that is the row
worth reading twice.** Sapling's suite alone reaches 56.31; Sprout's alone reaches 44.59;
together they reach 94.59. Both single-suite figures are far below the merged one, which
says the two Groth16 consumers exercise largely *different* regions of the batch verifier
— the qualitative answer to the question §3 left open, now with each side measured
separately rather than inferred from a difference.

⚠️ **The obvious arithmetic on those three numbers is not available.** Coverage is a set,
not a quantity: 56.31 and 44.59 do not add, and 94.59 minus either is not "the other's
contribution". What the three figures support is the ordering — merged is much larger
than either alone — not a percentage of overlap. This report does not compute one.

Five things this settles that no merged column can:

1. **`tower-batch-control` is driven by exactly one suite.** `tower_batching` is the only
   binary that links it at all; every other reports it absent. The measurement object the
   grant names third, and had no number for until 2026-07-29, now has one with unambiguous
   provenance.
2. **The bellman rows are shared between Sapling and Sprout, not owned by either** — and
   before Sprout existed they were Sapling's alone, which is why reading them off the crate
   name would have credited a verifier that had not been written.
3. **`reddsa` is the widest-shared row**, lit by both signature verifiers: 84.02 from the
   Sapling suite (RedJubjub) and up to 98.45 from `strategy_equivalence` (RedPallas).
   The merged figure is their union and belongs to neither.
4. **The reject arms come from the deterministic tests, not from a lucky fuzz hit.**
   halo2's batch verifier reaches 100.00 in exactly one binary — `mutation_smoke` — and
   92.59 in every other. That claim was previously an intention stated in
   `scripts/coverage.sh`; here it is a measurement.
5. **The negative controls behave.** `era_routing_anchor` (a textual drift anchor) and
   the library's own unit tests report 0.00 across every surface: they are linked
   against these crates and never enter them. A row that stayed dark where it should be
   dark is what makes the lit rows worth believing.

Set against the merged column, two rows carry the whole argument:

| Surface | Sapling suite alone | MERGED (all harnesses) | |
|---|---|---|---|
| bellman `groth16/verifier{,/batch}.rs` | 95.35 / 56.31 | 95.35 / 56.31 | identical — nothing else contributes |
| redjubjub `src/batch.rs` | 72.73 | 72.73 | identical — same reason |
| reddsa `src/batch.rs` | 84.02 | 98.97 | **not** identical — two verifiers, one file |

Where the per-suite and merged figures agree exactly, one suite is the entire source of
that coverage, and the merged number can be attributed. Where they diverge — `reddsa`
alone — they cannot, and the report says so rather than picking a verifier to credit.

The `redjubjub` row makes the same point from the opposite side. It is **72.73 in both
columns** — the whole suite reaches exactly what the Sapling suite alone reaches, and
nothing else contributes a single region. That is the asymmetry between the two signature
verifiers made visible: RedPallas reaches `reddsa` directly from `orchard`, so it never
enters the wrapper, while RedJubjub can only get there through it. Two adjacent rows, one
shared between verifiers and one owned outright, and neither label says which it is.

Both figures come from the same merged profile as §3. Re-filtering an existing profile
costs seconds, so adding a surface to the list does not mean re-running the hour: the
numbers above were recovered from the 2026-07-28 profile after the `redjubjub` entry was
added on 07-29, not measured again.

Attribution is not required by the acceptance criterion. It is what keeps the report from
implying things the numbers do not support.

## 5. One row measures a path Zebra does not run

Zebra does not batch JoinSplit proofs. `JOINSPLIT_VERIFIER` is a bare `tower::service_fn`
that verifies each proof on its own (`zebra-consensus/src/primitives/groth16.rs:84-93`),
and the source says so twice — *"This service does not yet batch verifications"*, citing
[ZcashFoundation/zebra#3127](https://github.com/ZcashFoundation/zebra/issues/3127), and
*"there is no batch verification for JoinSplits"*.

⚠️ **That issue is closed, and this report checked rather than assumed it.** #3127 was
closed as **`not planned`** on 2022-03-15: most JoinSplits sit below the checkpoint
verifier and never reach proof verification, so the expected gain was judged small. The
closing note redirects to [#3153](https://github.com/ZcashFoundation/zebra/issues/3153),
a general performance tracker, with *"can be done if we detect it's a bottleneck"*.
Upstream's source comment still links #3127 as though it were open.

So JoinSplit batching is not merely unbuilt — it is **declined pending evidence that it
matters**. This report therefore does not describe the Sprout rows as covering code that
*will* run. They cover `bellman`'s batch path as this harness drives it, under Sprout's
parameters and real Sprout proofs.

Nothing in this report should be read as saying otherwise. In particular, coverage of
`bellman-0.14.0/src/groth16/verifier/batch.rs` is coverage of a batch path that **no
Zebra deployment currently takes**, and a batch-versus-single disagreement for Sprout
could not manifest on mainnet today.

That is worth stating as a strength rather than hiding as an asterisk, but only if it is
stated precisely:

**The equivalence gate exists before the batching does.** For the other three verifiers
this work checks a property of code already running. For Sprout it checks a property of
code Zebra has written, not yet switched on, and has an open issue about switching on.
The check is ready before the change it guards.

**And the two layers swap significance in this pool.** Everywhere else, layer 1 is
production and layer 2 is the independent implementation kept alongside it. Here it is
inverted: `Item::verify_single` — our layer 2 — *is* Zebra's production path, and the
batch verifier our layer 1 drives is the prospective one. So a layer-2 disagreement here
would be a live bug, while a layer-1 disagreement would be a bug in code awaiting
activation. They are not equally severe and this report does not present them as though
they were.

## 6. Reachable but non-discriminating: the Sapling gap, enumerated

`sapling-crypto/src/verifier/batch.rs` is the lowest `BatchValidator` row at 89.08 / 86.96.
Convention would report that as a gap to be closed. It is a gap that **should not** be
closed, and saying why is more useful than the number is.

`check_bundle` has five rejection points. The adversarial generator reaches one — spend-side
proof decode failure. The other four:

| Uncovered rejection point | What a tamper aimed at it would prove |
|---|---|
| output-side proof decode failure | reachable, and equivalent in kind to the spend-side case already covered |
| `rk` small-order rejection | **nothing — batch and single share this check** |
| ephemeral-key decode failure | **nothing — batch and single share this check** |
| `epk` small-order rejection | **nothing — batch and single share this check** |

The last three live in `SaplingVerificationContextInner`, the private context that
`BatchValidator` and `SaplingVerificationContext` **both** delegate to — the same shared-code
observation §4 makes from the attribution side. A tampered input that trips any of them makes
*both* paths reject, so the oracle reports agreement whatever the input was. The regions would
light up; the property this report asserts would be tested no further.

**So the honest reading of 89.08 is not "13% untested".** It is: the batch-versus-single
question has been asked everywhere the two paths are capable of answering differently, plus
one family of decode failures where they are. The remainder of the file is consensus checking
that both paths perform with the same lines of code.

**Stated as a limitation rather than used as one.** The internal coverage floor agreed during
M1 covers the *Orchard* verification path — `orchard::BatchValidator` + halo2 + RedPallas — and
Sapling's validator postdates it. Whether to extend that floor to new components is a decision,
not a compliance question, and it is recorded here as one.

What would raise this number *and* mean something: a tamper that makes `check_bundle` reject
**after** it has queued part of a bundle — a path the residue work has already shown to be
reachable. That is a different family from the four above, and it is where further adversarial
effort belongs.

## 7. What the oracle found

A coverage report is a statement about what was exercised. This section is the other
half: what came back when it was.

The headline result is agreement. Across the real-mainnet corpora — including the 249
post-activation NU6.3 verification items — batch and single verdicts matched on every
item, with zero false-accepts. That is the outcome the grant names as acceptable and
valuable: the property is now under machine-checked assertion rather than assumed.

Those two statements describe different inputs, and the distinction is worth
making before the next section rather than after it. The agreement result is over
**real mainnet data**, none of which contains an invalid bundle. The behaviour
below appears only under a **deliberately constructed** carrier, and when it does
appear it is a divergence in the *reject* direction — valid items in a shared
batch coming back rejected when they would pass individually. It is a liveness
effect, not a false-accept, and no real-mainnet input has produced one.

The oracle also surfaced one behaviour worth reporting, and it is reported here as
evidence that the instrument works rather than as a vulnerability claim, because that is
what it is.

### Rejected bundles leave residue in a shared Sapling batch

`sapling_crypto::BatchValidator::check_bundle` validates and enqueues in the same pass:
it reads a proof, checks it, queues it, then moves to the next. If a later item fails a
consensus check the function returns — and everything queued before that point is
already in the shared batch and cannot be withdrawn. Upstream states this plainly in its
own documentation:

> "some or all of the proofs and signatures from this bundle **may have already been
> added to the batch** even if it fails other consensus rules."

**So the residue itself is documented and intended.** What this milestone adds is a
measurement of its consequence one layer up, where Zebra drives that validator: the
failing item errors on its own, but the batch continues, and the flushed batch — residue
included — has its result broadcast to every other item that shared it. No upstream
discussion of that combination was found.

### The evidence is a controlled experiment, not an inference

`tests/adversarial_generator.rs` builds two carriers that differ in exactly one respect.
Both are themselves rejected; both sit beside three valid neighbours.

| carrier | construction | `check_bundle` behaviour | verdicts of the three valid neighbours |
|---|---|---|---|
| **A** | spend0 a decodable-but-wrong proof, spend1 undecodable | queues spend0's bad proof, then returns at spend1 | **`[false, false, false]`** |
| **B** | spend0 undecodable | returns immediately, queues nothing | **`[true, true, true]`** |

The only variable is whether residue entered the shared batch. This also exercises a
precondition the generator has to guarantee rather than hope for: a "decodable but wrong"
tamper must still parse, or `check_bundle` rejects at spend0, nothing is queued, carrier A
collapses into carrier B — and the test still passes, having demonstrated nothing.
`TamperTarget::is_discriminating` and `check_shape` exist to make that failure loud.

### What it is, and what it is not

It is **not** a soundness problem, and that is structural rather than unobserved: residue
can only come from a bundle already judged invalid, and it can only add proofs that may
fail. It can make a batch reject more; it cannot make one accept more. Zebra's `Fallback`
then re-verifies individually — where no other bundle's residue is present — so affected
transactions do pass. The cost is that the batch degrades into one-at-a-time verification.

That last guarantee has a load-bearing premise, and it is stated here rather than assumed:
it holds because Zebra composes the two layers in one specific order —
`Fallback::new(Batch::new(...), verify_single)` at `zebra-consensus/src/primitives/
sapling.rs:206-222`, with the fallback *outside* the batch. Single verification succeeds,
the request returns `Ok`, and no misbehaviour score is ever reached. Reverse the two and
the same residue stops being a delay: a batch failure would surface as a verification
error, and honest peers would score one another for traffic that is valid. Nothing
currently depends on that order being documented, which is the reason to write it down.

**That cost is a range, not a number: 4.5x–7.8x** across ten runs of
`examples/batch_speedup.rs` over the same corpus and seed, on two machines. It is a
wall-clock measurement of a debug build.

**Machine load is the one dispersion source that has been isolated**: on a single machine,
three runs under other load spanned 42% while three on the same machine idle spanned 11%.
**The rest has not been.** Idling did not merely tighten the spread, it moved it — the
idle runs sit below the loaded ones rather than among them — and the two machines do not
overlap even after load is removed. Frequency scaling and cache state are plausible and
untested. This report therefore quotes the range and the magnitude and does not explain
any individual measurement: a single figure would be one draw from that spread, and a
reader reproducing this would get a different one.

Amplification is linear and bounded: `MAX_BATCH_SIZE` is 64 and Sapling weights one unit
per bundle, so one crafted transaction reaches at most the 64 bundles sharing its batch.
Ten times the traffic means more batches, not wider blast radius.

A fix exists and is cheap: validate in two passes, queueing nothing until every check has
passed. The extra pass only decodes and range-checks; the number of proof verifications is
unchanged. Orchard's `add_bundle` is already this shape, though not because it was written
as two phases — it has exactly one rejection point, and it sits before any queueing.

**Not reported upstream as part of this milestone.** The underlying behaviour is already
documented by the library that exhibits it, together with a workaround; a report of it
alone would be answered by a citation. It is carried to M3, where a release-build figure
and a concrete patch can accompany it, and where the grant's upstream contributions land.

## 8. Reproducing this

```sh
./scripts/coverage.sh --with-tests        # the three columns of §3   (~1h)
./scripts/coverage-attribution.sh         # the full matrix of §4     (~1h)
./scripts/coverage-attribution.sh sapling # one row of it             (~minutes)
```

Both scripts take their measured surfaces from the same list, so a row added to one
appears in the other. The attribution build lives outside the directory each run wipes,
so re-measuring a single row after a full run does not rebuild anything.

**Every table here names the commit it was measured at**, and §3 and §4 name the same one.
An earlier matrix taken at `26c44b7` had no column for RedJubjub, Sprout or the tower
layer, and attributed their surfaces to whatever reached them incidentally; it was re-run
rather than carried forward with a caveat, because an attribution matrix is a statement
about a particular tree — add a verifier and a column appears, change one and a row moves.
A matrix and a numbers table from different commits invite exactly the comparison that
should not be made. The full
run costs longer than the hour above suggests: the Orchard suites each rebuild a halo2
verifying key under instrumentation, over ten minutes apiece, which is the argument for
being able to re-measure one row rather than all of them.

## 9. Dependency deltas against upstream

Our lockfile resolves two crates differently from Zebra v6.3.0's. A reviewer is
entitled to ask whether we measured what Zebra runs, so both are stated and both are
settled by comparing the surface actually used — not by comparing the crates.

| Crate | Zebra v6.3.0 | Ours | Resolution |
|---|---|---|---|
| `reddsa` | 0.5.1 | 0.5.2 | `src/batch.rs` and `verification_key.rs` identical; `hash.rs` differs only by `PhantomData::default()` → `PhantomData`. Everything else in the delta is new FROST functionality we never reach. |
| `tokio-util` | 0.7.18 | 0.7.19 | `tower-batch-control` uses exactly one item from this crate — `tokio_util::sync::PollSemaphore`, imported in `worker.rs:18` and `service.rs:18` and nowhere else. **`src/sync/poll_semaphore.rs` is byte-for-byte identical between the two versions.** The files that do differ are all under `codec/`, `io/` and `cancellation_token/`, none of which is reachable from here. |

Both deltas were re-checked at the v6.2.3 → v6.3.0 bump and are unchanged: Zebra still
resolves `reddsa` 0.5.1 and `tokio-util` 0.7.18 at v6.3.0, so the two resolutions above
carry over verbatim. (The bump did move one version *into* alignment: this crate pinned
`zcash_protocol` to `=0.10.1` to match what v6.3.0 resolves. Leaving it at `=0.10.0`
would have manufactured a third row in this table.)

The second one matters more than the first and deserves saying why, because the easy
move is to file it beside `reddsa` as another harmless version skew. It is not the same
situation: `reddsa` differs *beside* what M1 measured, while `tokio-util` is a direct
dependency of the very crate this milestone was asked to cover. A delta on the
scheduling infrastructure, in the milestone whose new object *is* the scheduler, needs
an argument rather than a precedent.

The argument is cheap because the surface is small. "Is the delta large?" is the wrong
question — `tokio-util` changed a dozen files between these versions. The right one is
"does the delta touch what this consumer uses?", and answering it took locating two
`use` statements.

## 10. Limitations, stated plainly

> ⚠️ **The first two bullets of this section used to read "`tower-batch-control` is not
> yet in the dependency graph" and "Sprout is not implemented". Both were written
> mid-build and were never updated; by the time §1 and §3 were finalised they contradicted
> them outright — §1 lists `tower-batch-control` as measured and §3 carries its numbers,
> and §3's largest single movement (+38.28) is the paragraph about Sprout landing.
> Corrected 2026-08-26. This is not the same thing as §3's deliberately-kept mid-build
> column: that one is retained evidence, these two were stale claims. In a section whose
> whole value is that its limitations are current, a stale limitation costs more than the
> gap it was describing — a reviewer who spots one starts discounting the rest.**

- **`worker.rs` is the lowest number in the report (59.43 region) and it will not move by
  adding batch tests.** Its uncovered regions are shutdown paths, channel-closure handling
  and error propagation — reachable only by *faulting* the service, and this harness's
  `BatchService::poll_ready` returns `Poll::Ready(Ok(()))` unconditionally, so it has no
  failure state to fault. Closing this means a different kind of test than anything M2
  built. Named as future work; see §3 for the full reading.
- **Sprout is implemented and measured, but Zebra does not batch-verify Sprout today and
  has no active plan to.** `JOINSPLIT_VERIFIER` is a per-item `tower::service_fn` —
  upstream's own comment at `groth16.rs:87` says "there is no batch verification for
  JoinSplits" — and #3127, the issue proposing batch support, was **closed as `not
  planned`** in 2022 (§5). So the Sprout rows measure `bellman`'s batch path as this
  harness drives it, not a path Zebra runs or currently intends to. That is a real limit
  on what the Sprout numbers mean, and it is a different statement from "Sprout is not
  implemented".
- **The four surfaces M2 added — Sapling, Sprout, RedJubjub and the tower layer — have
  deterministic-test coverage only, no fuzz coverage.** All four fuzz targets are Orchard
  (verified by their imports: no target references any M2 module), so the FUZZ-ONLY column
  is empty for these surfaces — §2 states this, and it is restated here because it is a
  limitation and not only a reading note. M2's adversarial input is *designed*
  (`src/adversarial.rs`: four enumerable tamper classes), not *evolved*. Evolved input
  against the M2 surfaces is M3 work, where the AC is "CI integration green and
  self-running".
- **`reddsa` cannot be split per verifier by measurement alone** — only by running one
  suite at a time, which §4 does. There is no way to present a single merged number for
  that file that means one verifier.
- **Coverage is not additive.** Where this report gives a per-suite number it is a
  separate measurement, never a subtraction of one merged figure from another. Two suites
  that both enter a region cannot be told apart by differencing the totals.
