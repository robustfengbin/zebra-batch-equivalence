#!/usr/bin/env python3
"""Did every ClusterFuzzLite target fuzz, or only load its corpus?

ClusterFuzzLite divides a run's time evenly across targets, and libFuzzer
executes a target's starting corpus before it mutates anything. A target whose
corpus takes longer to execute than its share is stopped and logged as
"finished with no crashes discovered" -- the same line, and the same green run,
as a target that fuzzed for its whole share and found nothing. For the Orchard
targets, whose inputs cost seconds each, that is not hypothetical: with every
seed shipped and a 400 s budget, one of them stopped 129 inputs into its 589
seeds and reported INITED and DONE at the same count -- no mutation at all.

This reads the fuzzing job's log and reports, per target, whether libFuzzer
finished loading (`INITED`) and how many executions followed. A target that
never initialised, or whose executions did not exceed what initialising took,
mutated nothing. It warns rather than fails, like the corpus-store check: the
run itself is not wrong, but it must not read as coverage it did not do.

Usage: cflite-health.py <job-log-file>   (writes a table to $GITHUB_STEP_SUMMARY
if set; exits 0 always, prints ::warning:: lines for GitHub Actions)
"""

import os
import re
import sys

# GitHub prefixes every log line with an ISO timestamp; ClusterFuzzLite's own
# logging adds a level. Both are stripped before matching.
TS = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z\s?")
RUNNING = re.compile(r"Running fuzzer: ([A-Za-z0-9_]+)\.")
INITED = re.compile(r"^#(\d+)\s+INITED\b.*?\bcorp: (\d+)/")
# libFuzzer's status lines are `#<n><TAB><event>`. Stack frames in a crash report
# are `#<n> 0x...`, so the tab and the event name keep them out.
STATUS = re.compile(r"^#(\d+)\t(?:INITED|NEW|REDUCE|pulse|RELOAD|DONE)\b")
DONE = re.compile(r"^Done (\d+) runs in (\d+) second")


def parse(lines):
    targets = {}
    order = []
    current = None
    for raw in lines:
        line = TS.sub("", raw.rstrip("\n"))
        m = RUNNING.search(line)
        if m:
            current = m.group(1)
            if current not in targets:
                order.append(current)
            targets[current] = {"inited_at": None, "corpus": None, "runs": None,
                                "secs": None, "last": 0}
            continue
        if current is None:
            continue
        stripped = line.strip()
        m = STATUS.match(stripped)
        if m:
            targets[current]["last"] = max(targets[current]["last"], int(m.group(1)))
        m = INITED.match(stripped)
        if m:
            targets[current]["inited_at"] = int(m.group(1))
            targets[current]["corpus"] = int(m.group(2))
            continue
        m = DONE.match(stripped)
        if m:
            targets[current]["runs"] = int(m.group(1))
            targets[current]["secs"] = int(m.group(2))
    return order, targets


def executions(t):
    # `Done N runs` is printed only when libFuzzer stops on its own. A slow target
    # overshoots its budget and is killed instead, with no total -- measured on
    # the first public run, all four Orchard targets ended that way after
    # thousands of executions -- so the highest status-line counter is the count.
    return t["runs"] if t["runs"] is not None else t["last"]


def verdict(t):
    if t["inited_at"] is None:
        return "never finished loading its corpus"
    if executions(t) <= t["inited_at"]:
        return "no executions after loading its corpus"
    return None


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-3], file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
        order, targets = parse(f)

    rows = ["| target | corpus at start | executions | seconds | |", "|---|---:|---:|---:|---|"]
    if not order:
        print("::warning title=Fuzz health unknown::No 'Running fuzzer:' lines in the "
              "fuzzing job's log, so no target could be checked. The log format may "
              "have changed; this check is then saying nothing.")
    for name in order:
        t = targets[name]
        problem = verdict(t)
        if problem:
            print(f"::warning title={name} did not fuzz::{name} {problem}. Its share of "
                  "the run went to executing stored inputs, not to new ones; the run "
                  "reports it as having found nothing either way.")
        rows.append("| `{}` | {} | {} | {} | {} |".format(
            name,
            t["corpus"] if t["corpus"] is not None else "—",
            executions(t),
            t["secs"] if t["secs"] is not None else "killed at budget",
            problem or "fuzzed"))
        print(f"{name}: corpus={t['corpus']} inited_at={t['inited_at']} "
              f"executions={executions(t)} secs={t['secs']} -> {problem or 'fuzzed'}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### Fuzz health\n\n" + "\n".join(rows) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
