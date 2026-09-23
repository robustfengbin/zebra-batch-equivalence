# ZCG #332 — Milestone 3 Delivery & Final Security Report

> Batch-vs-Single Verification Equivalence for Zebra's shielded verifiers
> Milestone 3 of 3 · repo: `https://github.com/robustfengbin/zebra-batch-equivalence`
> Base: Zebra **v6.3.0** (`f5c5277fe41eba9c74f37098738f93f35dd70d60`), pinned by git rev
> This is both the milestone report and the grant's **final security report**: what the
> whole machine covers, what it found across all three milestones, what it does not
> cover, and who runs it once the grant ends.
>
> **Where a number comes from.** Coverage figures are produced by `scripts/coverage.sh`
> and `scripts/coverage-attribution.sh`; test counts come from `cargo test`; corpus
> sizes from the committed corpus; timing ratios from the runs recorded in
> *Appendix B*. Every command that reproduces them is under *Reproducing this*.

---

## Summary

Milestone 1 built a **differential verification oracle** for Zebra's Orchard pipeline:
every input runs down the production *batch* path and the *single* path, and the two
verdicts must agree — on accept and on reject. A batch that accepts what single
verification rejects is a counterfeiting-class soundness failure, and nothing in Zebra
re-checks that the two agree. Milestone 2 extended that oracle to **every batch
verifier Zebra has**, added an adversarial generator that hides one invalid item among
valid ones, and measured how much of the batching glue the suite actually reaches.

Milestone 3 does three things to that machine.

It extends the oracle to the **Ironwood** pool — and "covered by the oracle" turns out
to be five surfaces rather than one, a distinction that matters because the claim is
true, and sounds complete, after doing only the first of them. Four are now done; the
fifth is fuzz, and section 3 says exactly where it stands.

It adds the **turnstile/migration** target, which is the one piece here that is not a
batch-vs-single comparison: the turnstile is an accumulator, not a verifier, so it has
no second path to compare against, so its fuzz target supplies one: a reference model
of what every double-spend report must say, checked report for report under several
arrival orders. It runs
against **real post-activation mainnet traffic**, not the spec adapter the grant
allowed as a fallback if Ironwood slipped.

And it turns the suite from something we run into something that runs on its own. That
is the part with the honest caveat, and it is reported as observed rather than as
configured: ClusterFuzzLite has run in the public repository since 2026-09-22 —
started by hand that day, and on its own daily schedule from 2026-09-23 — every
target fuzzed on its first run, and the corpus it accumulates is kept in its own
repository. The first run was also marked failed — by a false positive in this
harness, found by that run and fixed the same day (Findings).
On the delivery date the record is short, and is given as it stands: one run started
by the schedule (2026-09-23, run 35873955850), green, with all nine targets past their
corpus; three runs started by hand on 2026-09-22; 55 commits in the corpus repository.
The schedule is daily, so the record grows by one run a day from here.

**Result: no disagreement, anywhere, in three milestones.** Not on the real mainnet
corpora, not under the adversarial generators, not across circuit eras or batch
partitions or arrival orders. Milestone 2 surfaced one behaviour worth reporting —
rejected bundles leave residue in a shared Sapling batch — which is the evidence that
the instrument does more than agree with itself. Milestone 3 surfaced nothing new, and
says so plainly: two rulers it had to correct along the way were defects in the
instrument, caught before delivery, and they are recorded under methodology rather than
promoted into findings.

What the grant asked for at the outset was not a report saying "we looked and it was
fine". It was a machine that keeps asking, after the grant ends. This report is
therefore as specific about what the machine does not cover, and about which of its
parts still depends on someone remembering something, as it is about what it checks.

## Deliverables, against the grant's own wording

> Grant text for M3: *"equivalence oracle extended to the Ironwood verifier
> (spec-following adapter); turnstile/migration soundness target (conservation, no
> double-migration, no forged residual value crossing); full suite integrated into
> continuous CI (ClusterFuzzLite / OSS-Fuzz) with a permanent regression corpus;
> final security report."*

### 1. *"equivalence oracle extended to the Ironwood verifier (spec-following adapter)"*

**Reading of `(spec-following adapter)`.** The grant's Success Metrics say the oracle
must hold *"for all four production verifiers **+ the Ironwood verifier**"* — the
definite article, in all three places Ironwood is mentioned, alongside four verifiers
that already exist. The parenthetical therefore describes **how this harness attaches
to** Ironwood's verifier, not a request that the grantee write one. This report states
that reading and its basis rather than asking for a ruling, so the reviewer can
disagree with it in front of the evidence.

**"Covered by the oracle" is five surfaces, not one** — a claim that is true after
doing only the first of them, and sounds complete either way. Status as of
delivery (2026-09-24):

| Surface | Status | Where |
|---|---|---|
| ① base `batch ⟺ single` | done | `tests/nu6_3_agreement.rs`, incl. mixed-pool batches |
| ② deep invariants ×4 | done (M3) | `tests/deep_invariants.rs`, `nu6_3_activation` added to `REAL_ERAS` |
| ③ adversarial | done (M3) | `tests/cross_pool_adversarial.rs`, 4 tests |
| ④ turnstile / cross-pool | done (M3) | `src/turnstile.rs`, `tests/turnstile_soundness.rs` |
| ⑤ fuzz | done (M3) — running daily in the public repository (§3) | `fuzz/`, `.clusterfuzzlite/` |

**② Deep invariants.** `tests/deep_invariants.rs` drove its four invariants —
order-independence, duplicate-consistency, sub-batching, era-routing — over a
`REAL_ERAS` list holding **two** eras, while `CircuitEra::ALL` holds **three**. The
Ironwood-bearing era was in neither the list nor any failure message: the sweep ran on
the eras it was handed and reported success for them, and nothing in the compiler
relates two constants that are merely supposed to agree. The only thing that could
expose it is a check that compares the two lists, and
`real_eras_cover_every_circuit_era` now does exactly that — every entry of
`CircuitEra::ALL` must have a landing site in `REAL_ERAS`. Cost of the fix: the
sampled sweep went from 115 s to 132 s.

Adding the era was a one-line change, and it would have delivered half of what it
looks like. `common::seeds_real_corpus` uses the **singular** `item_from_tx` — at most
one item per transaction — so on the NU6.3 corpus every double-pool transaction would
have kept its Orchard half and dropped its Ironwood half **silently**: every
equivalence assertion still passes, 77 of the corpus's 249 items drop out (Ironwood
falls from 106 items to the 29 that are single-pool), and nothing anywhere says so.
`tests/nu6_3_agreement.rs` already carried a test named for this trap. The fix is
`common::seeds_real_corpus_all_pools` (plural `items_from_tx`) plus
`nu6_3_entry_loads_both_pools`, which requires both pool counts to be non-zero — so
"the NU6.3 era is covered" cannot again be true of only its Orchard half.

**③ Adversarial.** Every fixture in `tests/adversarial_generator.rs` was a
`SaplingItem`. That satisfied M2's acceptance criterion, which named no pool; M3's
names Ironwood. `tests/cross_pool_adversarial.rs` adds four tests, and the shape that
matters is the mixed-pool batch: Orchard-pool and Ironwood-pool members in one batch,
one member corrupted, **both** pools' members required to be rejected — aggregation
must not let one layer mask another.

Three details are what make it a test rather than a gesture. It corrupts in **both
directions**, because a one-directional test passes just as well when the two pools
are asymmetric. It corrupts the **binding signature** separately from the proof: a
`BatchValidator` queues RedPallas signatures alongside halo2 proofs, so damaging only
a proof leaves the signature layer of a mixed batch untouched — and that layer is one
of the places a per-pool path could hide. And it includes an **Ironwood-only** batch,
because in a mixed batch a single Orchard member is by itself sufficient reason to
reject; only an Ironwood-only batch has the shape "the corrupted member is the only
reason". A guard test, `the_base_is_actually_mixed`, runs first, so the mixed-pool
tests cannot quietly degrade into single-pool ones.

**④ Turnstile and cross-pool.** Section 2.

### 2. *"turnstile/migration soundness target (conservation, no double-migration, no forged residual value crossing)"*

Three clauses, three checks, in `src/turnstile.rs`:

```
conservation        Σ(orchard + ironwood + sapling value balance) − transparent_out = fee, fee ≥ 0
no double-migration single-transaction case via spend_conflicts; cross-transaction via an
                    in-memory nullifier set (no zebra-state / rocksdb dependency)
no forged residual  pool balances may not go negative
```

**The first ruler we built was the wrong one.** The obvious reading of conservation —
`orchard + ironwood == 0` for a migration — passes **0 of 77** real double-pool
transactions in the `nu6_3_activation` corpus. The rule that holds is the fee identity
above: **172/172** transactions pass it, with every fee a positive multiple of 5000
zatoshi.

**A checker can fire on correct data.** The first `TurnstileState` started every pool
at zero, so the first of 172 legitimate mainnet transactions was reported as a
violation — the corpus is a window in the middle of the chain, where the Orchard pool
already holds value. `Origin::{Genesis, MidChain}` is now a required argument with no
default, and it has **its own test**: the same corpus fed as `Genesis` **must** report a
floor violation, or `Origin` is a flag nobody can show does anything.

Four of the turnstile's tests are about the test suite rather than about Zcash, and
they are listed because the grant asks for a machine that keeps working after we stop
watching it:

- **The wrong ruler is pinned in place.** `the_obvious_conservation_rule_rejects_every_real_migration`
  asserts that the intuitive rule fails on 77 of 77 real migrations. If someone later
  "simplifies" the fee identity back to it, a test says why that was already tried.
- **`Origin` proves itself.** Feeding the same mid-chain corpus as `Genesis` must
  report a floor violation. Without that test, `Origin` is a parameter nobody can
  demonstrate has any effect.
- **`ValueCreated` has a constructed carrier.** No mainnet transaction creates value
  out of nothing, so on real corpora that branch has never executed — and a detector
  that has never fired produces output identical to one that cannot fire. A synthetic
  carrier makes the difference observable.
- **`every_violation_variant_has_a_test`** matches exhaustively over the violation
  enum, so adding a variant without adding a test is a compile error rather than a
  silent gap.

`Conservation::Indeterminate` also carries its reason now
(`Indeterminacy::TransparentInputs(n)`, `SproutBalanceUnreachable`). It previously
reported `transparent_inputs: 0` for the Sprout case, which filed a limitation of ours
— `sprout_value_balance` is private upstream — inside a statement about the data.

**Order-independence, not batch-vs-single.** The turnstile has no two paths to compare,
so its differential property is a different one: the same transactions, in any arrival
order, must produce the same set of flagged `(pool, nullifier)` pairs. Comparison
granularity is the part that is easy to get wrong, and it was verified both ways:
comparing `(pool, nullifier)` passes; adding `first_seen` fails, correctly — that field
names which transaction arrived first, which is exactly what the order decides.

### 3. *"full suite integrated into continuous CI (ClusterFuzzLite / OSS-Fuzz) with a permanent regression corpus"*

Two routes, both real, and they answer different halves of the criterion. The word
that has to be earned is **self-running**.

#### Route A — OSS-Fuzz, against upstream Zebra

This is the route on which "no further involvement from the grantee" is literally
true: the targets run on Google's infrastructure, on upstream's code, and nobody has
to remember they exist.

**As of 2026-09-18 that route exists.** `google/oss-fuzz#15900` — opened 2026-07-23,
carried through review, and merged on 2026-09-18 — enrolled Zebra as an OSS-Fuzz
project. Google now builds and fuzzes 14 Zebra targets continuously, against upstream
`main`, seeded from `ZcashFoundation/zebra-fuzz-corpora`, with
`primary_contact: security@zfnd.org`. The two red configurations that held it up were
upstream API drift, repaired by `ZcashFoundation/zebra#11394` (merged 2026-09-18 as
`7dd43d1`), which the enrolment picks up because its Dockerfile clones upstream at
HEAD.

The groundwork under that was delivered during earlier milestones of this grant:
`ZcashFoundation/zebra#11221` — 30 files, +12,455 — merged upstream on 2026-08-17, and
the `zebra-fuzz/` directory it created is ours.

**What this changes for Milestone 3, stated precisely.** None of those 14 targets is an
equivalence oracle: they cover parsing, P2P, script, RPC and codec surfaces. What the
enrolment provides is a **pipeline that now exists and runs** — a harness added to
`zebra-fuzz/fuzz/fuzz_targets/`, listed in the enrolment's build allowlist, and given a
seed archive in `ZcashFoundation/zebra-fuzz-corpora` is fuzzed continuously by Google
from that day on, with no infrastructure of ours in the path.

So upstreaming is no longer the milestone's optional extra credit. It is the route on
which the acceptance criterion's own words are satisfied without qualification, and the
step that unlocks it is the issue that is already drafted and unfiled.

#### Route B — ClusterFuzzLite, in this repository

This is the route that is entirely under our control, and it is what the milestone's
CI criterion rests on. Nine targets, three workflows:

```
.clusterfuzzlite/Dockerfile      on gcr.io/oss-fuzz-base/base-builder-rust
.clusterfuzzlite/build.sh        cargo fuzz build -O, allowlist copy, seed packing
.github/workflows/cflite_batch.yml   daily: prune (up to 18000s), fuzz 10800s  <- the criterion rests here
.github/workflows/cflite_cron.yml    weekly coverage
.github/workflows/cflite_pr.yml      per-PR code-change fuzzing, 600s
```

**`cflite_batch.yml` is the one carrying the acceptance criterion**, and saying so
matters: the public repository is a one-way export with no pull requests, so
`cflite_pr.yml` will almost never fire here. It exists for after upstreaming and for
external forks. A reader who assumes all three are running would be counting two jobs
that are not.

What has been established by running it, rather than by configuring it:

```
docker build                                    EXIT=0, image 4.46 GB
compile, inside the container                   EXIT=0, 7 fuzzer binaries + 7 seed zips
OSS-Fuzz test_all.py (bad-build check)          EXIT=0, all four M1 targets pass
run_fuzzer under base-runner, real parameters    runs; four minutes, zero ALARMs
```

#### What the seeding was doing, before this milestone looked

Nine targets, all building, all seeded, all green. Underneath that, the seeds for the
four **core** targets — the ones that compare batch against single, which is the claim
this grant exists to make — were picked by filename order: `ls | sort | head -n 6`.

In `orchard_v5_pre_nu6_2`, 164 of 550 files yield an Orchard item, **and the first one
that does is the ninth**. So the six seeds shipped for that era reached the extractor
zero times. libFuzzer ran them at full speed and reported a healthy execution count,
which is precisely what a working target looks like from the outside — the failure this
repository's `tests/fuzz_input_reach.rs` was written for in M2, arriving through a door
that suite did not cover: it measured whether a *corpus* reaches a verifier, while the
script ships six *files* from it, and those are different questions.

The era in question is `PreNu6_2` — the original under-constrained Orchard circuit, the
one the June 5 incident lived in, and the reason the grant names Orchard first.

Two smaller instances of the same shape came out with it. The four core targets had no
NU6.3 corpus at all: they were written when only two eras existed, the third-era corpus
arrived in August, the M3 targets began drawing on it, and these four were never
revisited — so Ironwood reached none of the four targets that compare the two paths
directly. And Sprout's seeds were strided across the historical corpus without
filtering, where only 491 of 2,032 files carry Groth16 JoinSplits, so roughly three
quarters of its budget went to files its extractor declines.

**A fourth instance, in a different file.** Three places name the fuzz targets:
`fuzz/Cargo.toml`, `.clusterfuzzlite/build.sh`, and the CI smoke run. The latter two
carried hand-written lists of **seven**, while the crate had **nine** —
`tower_partition_equivalence` and `turnstile_order_independence` were added during M3
and never reached either list. `cargo fuzz build` compiled all nine and reported
success; seven binaries and seven seed archives were published; the smoke run exercised
seven. Nothing compared the counts, and one of the two missing is a Milestone 3
deliverable in its own right. Both consumers now enumerate from `fuzz/Cargo.toml`, and
a test asserts that they still do — because the day a hand-written list is pasted back
in, it is correct.

**The fix is selection by the property that matters.** Striding instead of heading only
lowers the odds — a stride of 92 over that corpus lands on one usable file in six — so
each corpus now carries a committed `REACHES.txt` measuring, per file, how many items
each of the four extractors gets from it. `scripts/prep-fuzz-corpus.sh` selects through
that; `examples/seed_reach_manifest.rs` regenerates it; and
`tests/fuzz_input_reach.rs` re-measures every corpus from scratch and fails if a
manifest and its directory disagree — because a committed derived artefact is only safe
to depend on if going stale is loud.

```
corpus                        files   orchard  sapling  redjubjub  sprout
orchard_v5_pre_nu6_2            550       164       57         57       0
orchard_v5_nu6_2                250       250        5          5       0
nu6_3_activation                172       172        2          2       0
historical_419200_1046400     2,032         0        0          0     491
```

The columns count *files* that yield at least one item, and they are measured
before the oracle's transparent-input filter: fuzzing needs an input to reach the
verifier, the equivalence tests need a verdict that can be trusted, and
`tests/fuzz_input_reach.rs::the_transparent_input_rule_is_per_verifier_not_global`
pins which extractor applies which rule. That is why `orchard_v5_pre_nu6_2` shows 164
here and 162 in the Corpus section: two of its reaching files spend transparently.

The Sapling and RedJubjub columns name the same files on every corpus (57/57, 5/5,
2/2), and must: each RedJubjub item derives from the same transaction's Sapling item.
What differs is the item count per file — 169 RedJubjub items against 57 Sapling on
`orchard_v5_pre_nu6_2`. The two targets still select through their own columns, so
neither is seeded on the assumption that the columns agree.

#### What has run, and what it showed

The permanent corpus needed a storage repository and a token for it, both on the
grant holder's account, and the export runbook required both to exist *before* the
code. On 2026-09-22 they did: `robustfengbin/zebra-batch-equivalence-corpora` was
created, the token stored as `PERSONAL_ACCESS_TOKEN`, and only then was this
configuration exported (public `3d7682f`).

The first ClusterFuzzLite run (public run 35696552461, started by hand the same day):

- the `corpus-store` job chose **permanent** storage — the warning it emits without
  the secret did not appear;
- every target fuzzed past its corpus: the four Orchard targets for 812 to 14,378
  executions, the other five for 9,105 to 391,203;
- the corpus repository received one commit per target;
- the run was marked failed, by the harness false positive described under Findings,
  fixed in public `013adc7`.

A `corpus-store` job runs ahead of every fuzzing job and decides the mode; without the
secret, fuzzing still runs and the run carries a warning naming what it does not
satisfy. That fallback is designed, not observed — the secret was in place before the
first run. A `fuzz-health` job after every daily run reads the fuzzing log and says,
per target, whether it fuzzed or only executed its stored corpus (see *Limitations*).

The runs on 2026-09-22 were all started by hand. The first run started by the schedule
itself came on 2026-09-23 (public run 35873955850): it pruned the corpus in 40 minutes,
fuzzed for 3 h 07 min, and finished green. Every one of the nine targets fuzzed — the
`fuzz-health` job raised no warning, and the corpus repository received one upload per
target during the fuzzing stage, each adding new inputs.

**Scheduled runs on this account start late.** The workflow is set for 09:43 UTC; the
first one started at 14:24. Another repository on the same account has been running
its scheduled jobs 2–6 hours after their set times since early September. GitHub documents
scheduled runs as best-effort, so this report says "daily" and does not state a clock
time. This repository's slot at 04:31 UTC on 2026-09-23, before the time was moved,
never produced a run, and why is not known.

#### The nightly full-suite run, and the chain of "who remembers"

The development repository has no CI of its own, so the deterministic suite is
verified by hand — and in practice by `cargo check --all-targets` plus the suites a
change touches, with the rest *judged* unaffected. That judgement is usually right,
and when it is wrong nothing says so. A nightly job on a separate worktree
(`fetch → reset --hard → git clean → cargo test --all-targets --locked`) turns it
from permanently unverified into verified within a day, and it prints the commit SHA
under test and every suite's `test result` line on both success and failure — because
a green that does not name what it ran is a green about nothing in particular.

That job cannot send a message; it writes its state into a file and pushes it. Which
is worth stating rather than smoothing over, because it is the shape of the whole
section: each layer of automation removes one "somebody has to remember" and exposes
the next — CI has to remember to run, the script has to remember to report, the push
has to succeed, and someone has to read it. The chain is not infinite, and each step
inward the remaining human step gets smaller and easier to name. The last one is
named here, in the crontab comment, and in both operators' notes. **A mechanism that
states its own ceiling is worth more than one that claims to have none.**

### 4. *"final security report"*

This file.

### Acceptance criteria

| Criterion | Status |
|---|---|
| Ironwood verifier covered by the oracle | **Met, on all five surfaces** — base equivalence, deep invariants, adversarial, turnstile, and fuzz. The fuzz targets that reach Ironwood run in the daily ClusterFuzzLite job (section 3). |
| turnstile soundness target runs against testnet/activated code (or its spec adapter if Ironwood slips) | **Met, on the stronger branch.** Ironwood did not slip: the corpus is real *mainnet* post-activation traffic (heights 3,428,150–3,433,400, extracted 2026-08-02), so the spec-adapter fallback the criterion allows was not needed. Of the three clauses, conservation and no double-migration are checked on that corpus; no forged residual value cannot be read from a mid-chain window and is evidenced on constructed runs only (Appendix A). |
| CI integration green and self-running | **Met, with a short record.** Self-running since 2026-09-23: one scheduled run to the delivery date, green, all nine targets fuzzed (run 35873955850); the runs of 2026-09-22 were started by hand. ClusterFuzzLite runs daily in the public repository with a permanent corpus in its own repository; its first run fuzzed every target and was marked failed by a harness false positive, fixed the same day (section 3, Findings). The weekly coverage workflow's only run so far, started by hand on 2026-09-22, is red: its pruning job timed out, and pruning has since moved into the daily workflow. Separately, Zebra itself is enrolled in OSS-Fuzz since 2026-09-18 (`google/oss-fuzz#15900`), on the `zebra-fuzz/` harnesses contributed upstream during this grant; the equivalence targets are not among them (After the grant). |
| final report delivered | This file. |

## What the oracle found — across all three milestones

Three milestones, one instrument. This section is the only place a reader has to
look to see everything it surfaced.

**Milestone 1 — no disagreement.** 415 real mainnet Orchard proofs replayed through
803 corpus seeds, four coverage-guided fuzz targets, three circuit eras, mechanical
mutations of real proofs, and synthetic NU6.3-era vectors: the batch path and the
single path never disagreed, on accept or on reject.

**Milestone 2 — one behaviour, surfaced by the adversarial generator.** A rejected
bundle leaves residue in a shared Sapling batch. It is written up in full in
`reports/m2-delivery.md` (Appendix A) and is reported here as evidence that the
instrument does more than agree with itself. An upstream issue for it is drafted;
whether it has been filed is recorded once, under *Upstreaming*.

**Milestone 3 — no new disagreement about Zcash, and three findings about this suite.** Ironwood
entered every surface in the table above and the two paths agreed throughout; the
turnstile flagged nothing on the real corpus that a mainnet transaction should not have
been flagged for.

The findings this milestone did produce are about the instrument. First, the fuzz seeds for the
four core batch-vs-single targets had been selected by filename order, and for the
`PreNu6_2` era — the under-constrained circuit the June 5 incident lived in — not one of
the six shipped seeds reached the extractor at all. Section 3 gives it in full. It is
recorded here rather than under methodology, unlike the two ruler corrections, because
the other two produced a wrong answer that a test caught, while this one produced **no
answer at all, indistinguishable from a correct one** — nine green targets, healthy
execution counts, and one of them fuzzing nothing.

The second has the same shape and was caught in review before delivery. The turnstile
fuzz target asserted that the *set* of flagged nullifiers is the same in three arrival
orders. For an accumulator that only ever inserts, that set is the nullifiers seen at
least twice — a count, which no order can change — so the assertion could not fail,
and it excluded the one part of a report that does move with the order, the name of
the first sighting, which is where the module's one real bug had been. The target now
checks every report against a reference model under each order, on a run fed three
times; with that earlier bug put back it fails on the first seed input.

The third was found by the continuous run itself, on its first day. ClusterFuzzLite
stopped `orchard_batch_equivalence` with a critical `EraFailOpen { correct: Nu6_2,
used: Nu6_3Onward }`. The reproducer is a real NU6.3 Orchard bundle whose trailing
control byte a mutation had turned from `0x02` into `0x4f`, which the target reads as
era `Nu6_2`; under the three circuit keys it verifies exactly as it should — only its
own era accepts it. The harness had passed the byte's claim to the era-routing check
as the batch's correct era, so the bundle's own key accepting it read as a fail-open.
The check now runs only when the batch verifies under the claimed era; "at most one
era accepts any input" was already asserted by two other targets. The reproducer is
kept unmodified under `fuzz/regressions/`, with a test that pins what the keys do and
what each form of the check says. It is listed with the other two because it has
their shape inverted: they produced no answer where one was due, this produced a
critical answer where none was — and both kinds read as results.

Beyond that false positive, the continuous run has reported nothing. That is the
answer of a surface that has run — every target past its corpus on every run so far —
not of one that has not. It is also only days of fuzzing: four runs of the daily workflow to the
delivery date, three of them started by hand.

Two things this milestone corrected are **not** findings about Zcash, and are
deliberately not listed as such: the conservation rule we first wrote was wrong
(section 2), and the turnstile's initial pool state was wrong. Both were defects in
the instrument, caught before delivery. They appear under methodology because
promoting them to findings would misdescribe what happened — and because the reason
they were caught is itself the method: a check is only trusted here after it has been
shown to be able to fail.

## Cost of the check

Batch verification is **5.1–5.8×** faster than single verification (same machine,
n=40 — 20 per build profile — alternating runs) — the measurement that makes the equivalence assertion worth
having, because if the two paths cost the same there would be no reason to keep the
batch path at all, and no aggregation glue for a soundness bug to live in.

That range deliberately spans both build profiles and both load conditions rather than
quoting the narrowest slice; the per-configuration numbers are in Appendix B.

M2 reported **4.5–7.8×** across two machines in non-alternating runs. Both figures are
stated here side by side, not one replacing the other: M2's range is the correct
expression of the data M2 had, and M3 identifies the largest source of the spread M2
explicitly said it had not isolated — the machine itself.

```
M2, published    two machines, non-alternating, debug        4.5 – 7.8x    spread 73%
M3               one machine, alternating, debug, n=20       5.6 – 5.8x    spread  5%
M3               one machine, alternating, release, n=20     5.1 – 5.6x    spread  9%
```

M2's Appendix A wrote: *"Machine load is the one dispersion source that has been
isolated … The rest has not been."* This is that promise being paid, and it could only
be paid because M2 wrote down what it had not established instead of rounding it off.

## Test suite

Measured 2026-09-23, `cargo test --workspace --locked`, on the development tree the `m3`
tag was exported from (the export differs from it only in documentation and CI
configuration; the public CI runs the same suite on the tag):

```
22 test harnesses, 19 of them carrying tests
113 passed · 0 failed · 1 ignored · exit 0 · 21 min wall-clock (debug build)
```

The same command gave 110 on 2026-09-18; the three since then are the regression and
guard tests added with the fixes of 2026-09-22 (the era-routing false positive, the
turnstile assertion, and the seed-list guard).

**An earlier internal note carried 100, and how it went stale is worth one line**,
because it is the same failure mode this project is built around. The 100 was measured
at an earlier commit; later commits added tests; and the note forwarding it reasoned
that the tree was byte-identical *since anyone last looked*, which is a different claim
from *since the number was taken*. The two sentences read identically. Six tests
separated them — and four more were added during this milestone, which is the rest of
the gap. It had not been published anywhere (M2's delivery text quotes 82, which is
M2's own correctly-measured figure), so nothing external needs correcting. The rule
that caught it is the one worth keeping: **a count that will appear in delivered text
is re-measured against the tree it describes, never inherited.**

Per suite:

```
src/lib.rs (unit)                19      tests/mutation_smoke.rs           2
tests/add_reject_equivalence.rs   5      tests/nu6_2_agreement.rs          2
tests/adversarial_generator.rs    5      tests/nu6_3_agreement.rs          3
tests/baseline_agreement.rs       3      tests/redjubjub_agreement.rs      8
tests/corpus_agreement.rs         1      tests/sapling_agreement.rs        4
tests/cross_pool_adversarial.rs   4      tests/sprout_agreement.rs         5
tests/deep_invariants.rs          7      tests/strategy_equivalence.rs     6
                                  (+1 ignored)
tests/era_routing_anchor.rs       2      tests/tower_batching.rs           5
tests/fuzz_input_reach.rs         9      tests/turnstile_soundness.rs     13
                                         tests/v6_pool_dimensions.rs       7
```

Which suites ran is part of the result, not a detail: a green over three suites and a
green over twenty-two exit with the same code. The two slowest are `nu6_3_agreement`
and `nu6_2_agreement`, both dominated by real SNARK verification over the mainnet
corpora, and `v6_pool_dimensions` is slow because
`cross_pool_batch_agrees_under_every_era_in_every_order` crosses every era with every
ordering — the orderings are the point.

`fuzz_input_reach` is the suite that grew most this milestone, from 5 tests to 9, and
all four additions check the *seeding* rather than the verifiers: that the turnstile's
seeds are runs rather than single transactions, that the core targets are seeded from
every circuit era, that the committed reach manifests still describe their corpora, and
that every declared fuzz target is actually published. Section 3 says what each of them
was written after finding.

## Corpus

Five real-mainnet corpora, all extracted from a standing mainnet node and committed to
the repository. File counts and *item* counts differ, and the distinction is kept
everywhere it matters — a file is a transaction's wire bytes, an item is one
verification unit, and one transaction can carry several or none.

```
seeds-real/orchard_pre_nu6_2          3 files    in-tree fixtures
seeds-real/orchard_v5_pre_nu6_2     550 files    162 items used
seeds-real/orchard_v5_nu6_2         250 files
seeds-real/nu6_3_activation         172 files    249 items   <- the Ironwood corpus
seeds-real/historical_419200_1046400  2,032 files  Sprout Groth16 + Sapling
```

M1's Orchard figure of **415 real proofs over 803 stored files** is unchanged and is
the arithmetic of the first three rows.

**The NU6.3 corpus is real post-activation mainnet traffic, not a synthetic stand-in.**
Extracted 2026-08-02 from heights **3,428,150–3,433,400** — NU6.3 activated at
3,428,143, so the window opens seven blocks after activation and the boundary itself is
represented. Every 50th block, 106 blocks fetched, zero misses. Of 201 shielded
transactions found, **172 were kept**; the 29 dropped carry transparent inputs, whose
ZIP-244 sighash folds in prevouts a bare transaction does not carry — the same filter
M1 applies, for the same reason.

Contents: **1,264 Orchard actions, 216 Ironwood actions, and 77 dual-pool
transactions.** The dual-pool count is the part that matters here: a single transaction
carrying both an Orchard-pool and an Ironwood-pool bundle is what cross-pool migration
looks like in practice, and M1 could only reason about that shape from synthesized
vectors.

Turnstile measurements over that corpus: conservation holds **172/172** with every fee
a positive multiple of 5000 zatoshi; dual-pool **77** (74 in the migration direction,
3 with both pools spending outward, both legitimate); transparent-input transactions
**0**; Sprout **0**; cross-pool nullifier bit collisions **0**; cross-transaction
nullifier repeats **0**.

Two corpus properties are recorded because they are the kind that quietly invalidate a
later subset:

- The NU6.3 corpus is a **strided sample, not a prefix** — every 50th block, uniform
  with respect to height. Whenever a window's pool composition drifts across it, a
  contiguous prefix is not a sample of the window; it is a sample of its beginning.
- In the historical corpus, filenames zero-pad heights to seven digits so lexicographic
  order equals numeric order. The window crosses a digit-count boundary (419,200 to
  1,046,400), and without padding `1000950` sorts before `419201` — a subset taken with
  `head` would silently not be the subset it looks like.

Seeds shipped per target, after selection by reach:

```
orchard_batch_equivalence     21      sapling_batch_equivalence     13
orchard_batch_composition     21      redjubjub_batch_equivalence   13
orchard_era_routing           18      sprout_batch_equivalence      12
orchard_single_deep           18      tower_partition_equivalence   18
                                      turnstile_order_independence   3
```

Sapling and RedJubjub ship 13 rather than 18 because their corpora hold fewer reaching
files than the sample asks for — 5 in `orchard_v5_nu6_2`, 2 in `nu6_3_activation`. That
is the corpus's shape showing through the selection, which is the intended behaviour:
the alternative is padding the count with files the extractor declines.

The seeds are not minimised with `cargo fuzz cmin`. The minimisation that matters
happens on the permanent corpus instead: ClusterFuzzLite's prune step merges it every
day before fuzzing (*Limitations*), and that corpus, not the seed sample, is what each
run starts from. The seed sample stays small enough to replay inside the PR budget.

## Reproducing this

```sh
git clone --branch m3 https://github.com/robustfengbin/zebra-batch-equivalence
cd zebra-batch-equivalence
cargo test                                   # the full suite

cargo run --example survey_turnstile         # the turnstile figures quoted in section 2

rustup toolchain install nightly-2026-07-03
NIGHTLY=nightly-2026-07-03 ./scripts/coverage.sh --with-tests   # the three columns  (~1h)
./scripts/coverage-attribution.sh                               # the attribution matrix
```

To run a fuzz target locally (nightly toolchain, `cargo-fuzz` installed):

```sh
./scripts/prep-fuzz-corpus.sh                 # seeds per target, selected by REACHES.txt
cargo +nightly fuzz run orchard_batch_equivalence fuzz/corpus/orchard_batch_equivalence

# or start from what the daily runs have accumulated:
git clone https://github.com/robustfengbin/zebra-batch-equivalence-corpora
cargo +nightly fuzz run orchard_batch_equivalence \
  zebra-batch-equivalence-corpora/corpus/orchard_batch_equivalence
```

A crash reproduces with `cargo +nightly fuzz run <target> <crash-file>`; the one found
so far is kept under `fuzz/regressions/`.

The nightly pin applies to the coverage tables only. The test suite is a set of
behavioural assertions and reproduces on any toolchain that builds the tree; region
*counts* do not, because inlining decisions belong to the compiler.

The one test that dominates wall-clock is
`v6_pool_dimensions::cross_pool_batch_agrees_under_every_era_in_every_order` — every
era crossed with every ordering, over real double-pool transactions. It is slow on
purpose: the orderings are the point.

## Scope and honest limitations

- **No divergence found is not equivalence proven.** This is empirical assurance
  carried by permanent assertions, not a formal proof. It has been the standing
  caveat since M1 and it does not weaken with the number of milestones behind it.

- **The oracle compares two paths, so a fault in both is invisible to it.** If a
  public input were assembled wrongly but identically on each side, the two verdicts
  would agree and the suite would stay green. M2 stated this; it stays stated.

- **The base is pinned to Zebra v6.3.0 (`f5c5277`), by git rev in all three
  dependency pins.** That is still upstream's newest release: re-checked 2026-09-18,
  the release list ends at v6.3.0 (2026-08-10) and its target commit *is* `f5c5277`,
  even though `main` has moved a long way since (`ec8f29e`, 2026-09-17). Upstream
  `#10461` (merged 2026-08-22, in no release) rewrites `Transaction` from an enum into
  newtypes. Nothing interrupts this
  harness — the pins are revs, not version ranges — but a future rebase is not a
  mechanical edit. v6.3.0's `sprout_groth16_joinsplits` filters out BCTV14 proofs by
  matching on enum variants; with the enum gone, that filter has no implementation
  basis upstream (the replacement distinguishes them via `groth_proof_bytes()`
  returning an `Option`). `src/bin/blocks_to_historical_corpus.rs:89` depends on that
  filter, and the 2,032 historical corpus files (one transaction each) were selected by it. Rebasing therefore
  means re-arguing a corpus-generation premise, and re-running coverage — but not
  re-arguing equivalence: the verification backends themselves are unchanged
  (`orchard` 0.15.3, `sapling-crypto` 0.7.0, `bellman` 0.14.0, `zcash_proofs` 0.30.0,
  `zcash_protocol` 0.10.1 are identical across the refactor).

- **Ironwood coverage is against activated code, but a short window of it.** NU6.3
  activated on mainnet at height 3,428,143 on 2026-07-28, so the spec-adapter fallback
  the grant allowed was not needed. The Ironwood corpus is 172 real mainnet transactions
  from heights 3,428,150–3,433,400, extracted on 2026-08-02 from a synced node — five
  days of traffic shortly after activation. Whatever shapes Ironwood transactions take
  later are not in it; the fuzz targets reach beyond it only as far as mutation does.

- **Fuzz seeds are a sample, and now a measured one.** Every accepted seed drives a
  real SNARK verification, so the targets ship a handful of seeds per corpus rather
  than the whole corpus; the full-corpus sweep is what `cargo test` is for. Since this
  milestone the handful is selected by what reaches the extractor (§3), which fixed a
  case where it reached nothing. The remaining limitation is the sample size itself,
  not its composition.

- **1,182 v4 Sapling transactions remain unreachable from a bare transaction stream.**
  A v4 transaction does not state its consensus branch id, so the sighash cannot be
  derived without a height, which a stream does not carry. Unlocking them needs an
  era-selector byte in the input model — the same shape the Orchard targets use — and
  that is a corpus-format change rather than a code fix. Named here because it is the
  largest single block of real material the fuzz surface cannot currently see.

- **A crate is not a verifier.** The coverage attribution matrix in
  `reports/m2-delivery.md` stands as written; percentages against a whole crate
  overstate or understate depending on what else that crate contains.

- **Drift detection has a blind spot.** The upstream drift watch, which runs outside
  this repository, compares the sha256 of the upstream source files this harness
  mirrors. It cannot see *which release* carries `#10461`, which is the
  event that should trigger a rebase decision. A release detector is the missing
  piece, and it is named here rather than quietly omitted.

- **Continuous fuzzing has a wall, and hitting it is green.** ClusterFuzzLite
  divides each run's time evenly across the nine targets, and libFuzzer executes a
  target's stored corpus before it mutates anything; a budget that runs out during
  that pass ends the run there. An Orchard input costs
  seconds, because both paths do real proof verification, so the per-target budget
  is also a ceiling on how large an Orchard corpus can grow and still be fuzzed
  past. A target that hits it is stopped and reported as having found nothing,
  which is indistinguishable from a target that fuzzed and found nothing. Measured
  under OSS-Fuzz's base-runner: with every seed shipped and a 400 s budget,
  `orchard_batch_equivalence` stopped 129 inputs into its 589 seeds, at 444 s, and
  reported `INITED` and `DONE` at the same count — not one mutated input. With six
  seeds per era it initialised after 23 executions and went on to 1,454 in the
  same budget, adding 216 inputs. Seeds are now six per era.

  The corpus then grows on its own, which is the point of keeping it: 21 seeds
  became 360 to 1,609 inputs a target in two days of running. Pruning bounds that,
  and costs the same kind of time — merging one target's corpus, measured in
  base-runner on exactly that corpus, took 456 s to 1,644 s and removed 20-35%,
  not most, of it. It therefore runs daily, ahead of each day's fuzzing, rather
  than weekly: the weekly cadence it replaced timed out on its first target and
  left the other eight unpruned, on its first real run. Budgets are sized against
  those measurements. That makes the wall unlikely, not visible. What
  makes it visible is `scripts/cflite-health.py`, run as a `fuzz-health` job after
  every daily run: per target, the corpus it started from, where libFuzzer
  initialised, and how many executions followed, with a warning for any target that
  did not get past its corpus. On the first run's log it reports all nine fuzzed; on
  the 589-seed log above it warns. (Its first version miscounted the Orchard targets,
  which overshoot their budget and are killed before libFuzzer prints a total; it
  was caught on that real log before it was committed.)
  Since 2026-09-23 it also checks the log against the targets `fuzz/Cargo.toml`
  declares: a target that never started leaves no lines to judge, and the first
  version passed such a target by saying nothing. The summary now opens with "N/M
  targets fuzzed", so a green step with a warning no longer looks like a clean one.
  On the one scheduled run so far it raised no warning. That run used the version
  before this change; the version with the "N/M" line has not yet run on a real log.

- **NU7 changes what the Sprout surface protects.** NU7 (mainnet targeted for
  2026-11-05) disallows v4 transactions (ZIP 2003), and v5 and later carry no
  Sprout component, so no new Sprout proof can enter the chain after activation.
  Zebra still verifies the historical ones when it syncs from genesis, so the
  Sprout surface goes on guarding that path — historical verification, not new
  traffic. Sapling is unaffected: v5 and v6 carry it, and the disabling of new
  Sapling value (ZIP 219) is a reserved number, not part of NU7. The same upgrade
  shortens block spacing to 25 seconds (ZIP 218), so batches will close sooner and
  hold fewer items; `tower_partition_equivalence` already takes the batch capacity
  from its input, so smaller batches are inside what it fuzzes. None of this touches the pinned v6.3.0 base.
  (NU7 dates as of 2026-09-24: code complete 2026-09-30, testnet 2026-10-06, the
  mainnet go/no-go and activation height 2026-10-20.)


## Upstreaming

**The relationship already exists, and it is positive.** Issue
`ZcashFoundation/zebra#11166` (opened 2026-08-01) drew *"we will discuss as a team"*
(natalieesk), *"Congrats … that was the one risk I saw in your grant application"*
(alchemydc — a maintainer who had read the grant application), and *"We'd be happy to
point this at upstream Zebra … Please submit the PR"* (mpguerra). The resulting PR
`#11221` was merged on 2026-08-17 (30 files, +12,455). M3's upstreaming therefore
continues an existing conversation rather than opening one, and an issue may state
outright that this is ZCG #332 M3 without re-explaining the background.

**But the equivalence oracle is not that work.** `#11166` is general coverage-guided
fuzzing — parsing, P2P, script, 15 targets. The oracle is a different claim about a
different property, and belongs in its own issue that cites `#11166` for context
rather than extending it.

**Status as of 2026-09-24.** The equivalence targets are proposed upstream in
`ZcashFoundation/zebra#11492`, filed on 2026-09-23. It offers the full suite and
suggests starting with two targets — `orchard_batch_equivalence`, which reaches
Ironwood, and `tower_partition_equivalence`, which covers the `tower-batch-control`
layer — because OSS-Fuzz divides a project's compute across its targets and every
input here runs real proof verification. Zebra's contribution guidelines are
issue-first, so no PR exists until a maintainer answers; as of this date the issue
carries the `external-contribution` label and no reply. The same day a maintainer
closed `#11166` as completed, citing `#11221` and `google/oss-fuzz#15900`. A second
issue, on the Sapling residue (*What the oracle found*, Milestone 2), is drafted and deliberately not filed the
same day.

**One upstream event is worth recording, both for what it did and for which code it
touched.** `ZcashFoundation/zebra#11394` repaired three fuzz targets and the seed
generator under `zebra-fuzz/`, broken by the transaction newtype refactor in `#10461`.
All seven of its changed files are in `zebra-fuzz/` — the parse-time, P2P and
v6-semantic targets from the OSS-Fuzz integration line. **None of this project's code
was involved**; the equivalence oracle has not been upstreamed yet. It mattered here
only through scheduling: it was what the red configurations on `google/oss-fuzz#15900`
were waiting for. It merged on 2026-09-18 as `7dd43d1`, and the enrolment merged the
same day.


## After the grant

The grant's third user story asks for *"a durable, open checking machine, not a
one-off report"*, and the maintainer story asks for it to re-run *"with no further
involvement from the grantee"*. Those two sentences are the acceptance test for this
section, and they are not satisfied by a suite that merely exists and is green today.

There are two routes, and they differ in exactly this respect:

**Route A — OSS-Fuzz.** The targets run on Google's infrastructure against upstream
Zebra, and no one has to remember they exist. This is the route that literally
satisfies "no further involvement from the grantee", and since 2026-09-18 it is a route
that exists: `google/oss-fuzz#15900` merged, and Zebra is an enrolled OSS-Fuzz project
with `security@zfnd.org` as its contact. Landing the equivalence harness there is three
steps — a target upstreamed into `zebra-fuzz/`, a line added to the enrolment's
allowlist, and a `<target>_seed_corpus.zip` in `zebra-fuzz-corpora`, which the
enrolment's `build.sh` copies unguarded, so a listed target without one fails the build
by design. The first of those is issue-first; the issue is `#11492`, filed 2026-09-23
(*Upstreaming*).

**Route B — ClusterFuzzLite in this repository.** Under our control, and it runs on a
schedule: pruning and fuzzing daily, coverage weekly — published at
`robustfengbin.github.io/zebra-batch-equivalence-corpora/coverage/latest/report/linux/report.html`.
Its permanent corpus is
`robustfengbin/zebra-batch-equivalence-corpora`, written from the first run on
2026-09-22. What keeps it running is the repository, the storage repository and one
token (expiring 2026-12-21) — all on the grant holder's account, which is the
difference from route A.

**On the delivery date, route B is the one that is live, and it lives in the grantee's
repository.** "Self-running" is true of it — nobody starts the daily run — but it is
not yet "no further involvement from the grantee": the token that writes the corpus
expires on 2026-12-21, and renewing it is the grantee's to do. Route A is the hand-off
path, and it waits on the answer to `#11492`. Until then:

- **What a red run looks like.** A crash fails the daily run, which shows red in the
  public repository's Actions list, and its reproducer is attached to that run as an
  artifact named `crashes-<target>`. Artifacts expire after 90 days, so a crash file
  should be downloaded when the run goes red. The one crash so far (run 35696552461)
  was kept that way, and a copy is under `fuzz/regressions/`. A target that ran but did not fuzz does not turn the run
  red — it raises a `fuzz-health` warning and lowers the "N/M targets fuzzed" line at
  the top of the run summary. Those are the two things to look at.
- **A disagreement is the one result that needs a person.** Every target asserts that
  the batch path never accepts what the single path rejects; a failure of that
  assertion is a possible counterfeiting-class bug in shipping verification code, not
  a test to be fixed. It should go to `security@zfnd.org` privately, with the crash
  file, and not to a public issue. The grantee (`robustfengbin` on GitHub) should be
  told as well, since a harness fault is the first thing to rule out — the one
  critical this suite has raised so far was a harness false positive (*Findings*).
- **Everything else** — a target that stops building after an upstream change, a
  storage token that expires — is maintenance, and goes to the grantee.

**One gap named rather than left to be discovered.** The upstream drift watch compares
the sha256 of upstream source files, which is the right signal for "the code we mirror
changed". It cannot see *which release carries `#10461`* — and that release, not the
merge, is the event that should trigger a rebase decision, for the corpus-generation
reason in *Limitations*. A release detector is the missing piece.

## Appendix A — what the turnstile target does not decide

The turnstile checks three properties over a corpus we supply. Each of the three has an
edge it does not reach, and each edge is reported by the code rather than rounded off
into a pass.

**Conservation is indeterminate, not green, where the fee cannot be computed.** A
transparent *input* carries value this crate cannot see — the amount lives in the
output being spent, which a bare transaction does not carry. `check_conservation`
returns `Conservation::Indeterminate` there. The Sprout case is separate and is
labelled separately (`Indeterminacy::SproutBalanceUnreachable`): `sprout_value_balance`
is private upstream, so that gap is a limit of *this crate's reach*, not a property of
the transaction. Collapsing both into one "could not decide" would have filed our own
limitation among facts about the data — which is what the earlier version did when it
reported `transparent_inputs: 0` for a Sprout transaction.

**Double-migration is checked across the corpus, not across the chain.**
`TurnstileState` accumulates nullifier sets and pool balances in memory as transactions
are fed through it. Within one transaction, upstream `spend_conflicts` already rejects
duplicates; across transactions, this is the only thing that can see a repeat. It is
deliberately not wired to `zebra-state`, which would pull rocksdb into a crate that has
stayed free of it — so the guarantee is "no double-migration within the set of
transactions supplied", and the size of that set is the size of the claim.

**Pool floors are only meaningful if the caller says where the run starts.** A negative
pool balance is how forged residual value would show, and reading it requires knowing
what the pool held at the start. A sampled mid-chain window does not say. `Origin` is
therefore a required argument with no default, and the corpus used here is `MidChain`
— which means the third clause is **not evaluated on real data at all**. Its evidence is
a constructed run from `Genesis` that checks both directions: value entering a pool and
less of it leaving must stay quiet, and the first zatoshi beyond what entered must
breach the floor, once, for the right pool
(`the_floor_holds_while_a_pool_covers_its_outflow_and_fires_beyond_it`). Before that
test, the floor had only ever been seen firing, and a floor that always fires passed
every test in the suite.

**One open question is measured, not answered.**
`zebra-chain/src/ironwood.rs:20-23` states that the Ironwood and Orchard nullifier sets
are disjoint *even when their bit patterns coincide* — separate column families,
separate checks — and `spend_conflicts` runs `check_for_duplicates` over the two sets
independently, so the same 32 bytes in both pools is not a duplicate to it. Whether
that is reachable is a question about nullifier derivation, not about Zebra, and this
module claims no answer. It surfaces the case as
`TurnstileViolation::CrossPoolNullifierReuse` so a corpus can be asked. The real corpus
contains no instance — which is **the corpus having no carrier, not the property
holding**. Those two are indistinguishable from a green test, which is why the
constructed carriers in `crate::adversarial` are what actually exercise this one.

## Appendix B — the batch/single measurement, per configuration

`examples/batch_speedup.rs`, same corpus and same seed throughout, run on one machine
with the two paths alternating, ten rounds per configuration. Both rounds ran on an
idle machine, one busier than the other (load average across the two: 1.3–3.1):

```
                       n      min      max     spread
busier   debug        10     5.60x    5.82x     3.9%
busier   release      10     5.26x    5.60x     6.5%
quieter  debug        10     5.56x    5.82x     4.7%
quieter  release      10     5.12x    5.57x     8.8%
──────────────────────────────────────────────────────
combined debug        20     5.56x    5.82x     4.7%
combined release      20     5.12x    5.60x     9.4%

per-round release/debug ratio            0.915 – 0.980
```

**The mechanism was written down before the numbers were seen, and then checked
against them.** The gap is algorithmic — batch verification aggregates N pairing
checks into one — not an artefact of optimisation level. The prediction that follows
is specific: an optimisation switch moves both paths' absolute times and leaves their
*ratio* alone. The per-round release/debug ratios sitting against 1 are that
prediction's shape. Before this run, the open question was whether the finding
survived `--release` at all, or collapsed toward 1.05x. It did not.

**Two things this appendix does not claim.**

*Load.* The quieter rounds have the **wider** spread, not the narrower one, so across the
load range actually sampled (1.3–3.1), load is not the dominant dispersion source.
That is not the same as "load does not matter" — M2's Appendix A recorded a 42%-busy
machine, which is plausibly a different regime entirely. Both rounds here were idle;
one was merely more idle than the other.

*Why release disperses about twice as widely as debug* (9.4% vs 4.7%, same direction
in both rounds) — we have not established why. There is a plausible explanation
(release is faster, so the same absolute jitter is a larger fraction of a shorter run)
and it is even testable by recording absolute times rather than ratios, but it has not
been tested, so it is not offered here as a reason.
