//! Do the fuzz targets' seeds actually reach a verifier? (ZCG #332 · M3)
//!
//! A fuzz target seeded with material its extractor rejects is not a failing
//! target. It builds, it runs, it exits zero, and libFuzzer reports a healthy
//! execution rate — because every input returns before reaching a verifier.
//! Nothing in the fuzz job distinguishes that from a target that works, and the
//! faster it runs the healthier it looks.
//!
//! That is not hypothetical: the first version of the M3 targets seeded Sapling
//! and RedJubjub from the historical corpus, which holds 1,261 Sapling spends
//! and yields exactly zero Sapling items. This suite exists so that particular
//! mistake fails here, in seconds, instead of running green for a milestone.
//!
//! Cheap by construction: it counts extracted items and never verifies one, so
//! no proof or signature is checked anywhere below.

mod common;

use common::historical_transactions;
use zebra_batch_equivalence::fuzz_input::{redjubjub_items, sapling_items, sprout_items};
use zebra_batch_equivalence::items_from_tx_stream_with;
use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::Transaction;

/// Every transaction in one `seeds-real/<dir>`, in filename order.
///
/// Deliberately not one of `common`'s loaders: those already apply the very
/// filters this suite is checking, so measuring through them would confirm
/// their own premises.
fn raw_transactions(dir_name: &str) -> Vec<Transaction> {
    let dir = format!("{}/seeds-real/{dir_name}", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        // `.bin` rather than "everything but the READMEs": these corpora also
        // carry a REACHES.txt manifest, and a directory listing that was written
        // before it existed reads it as a transaction and fails on the parse.
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();

    files
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path).expect("read corpus file");
            Transaction::zcash_deserialize(&bytes[..]).unwrap_or_else(|e| {
                panic!("corpus file {} failed to deserialize: {e}", path.display())
            })
        })
        .collect()
}

/// The corpora `scripts/prep-fuzz-corpus.sh` seeds the two signature-bearing
/// targets from. Keep in step with that script: if a corpus is added there and
/// not here, this suite stops covering what actually ships.
const SIGNATURE_TARGET_CORPORA: [&str; 3] = [
    "orchard_v5_pre_nu6_2",
    "orchard_v5_nu6_2",
    "nu6_3_activation",
];

#[test]
fn sapling_target_seeds_reach_the_verifier() {
    let mut txs = 0usize;
    let mut items = 0usize;
    for dir in SIGNATURE_TARGET_CORPORA {
        for tx in raw_transactions(dir) {
            let n = sapling_items(&tx).len();
            if n > 0 {
                txs += 1;
                items += n;
            }
        }
    }
    assert!(
        items > 0,
        "the Sapling fuzz target's seed corpora yielded no items at all — the target would \
         build, run, exit zero and verify nothing. Reproduce with \
         `cargo run --release --example survey_fuzz_seeds`."
    );
    eprintln!("sapling: {txs} transactions, {items} items across {SIGNATURE_TARGET_CORPORA:?}");
}

#[test]
fn redjubjub_target_seeds_reach_the_verifier() {
    let mut txs = 0usize;
    let mut items = 0usize;
    for dir in SIGNATURE_TARGET_CORPORA {
        for tx in raw_transactions(dir) {
            let n = redjubjub_items(&tx).len();
            if n > 0 {
                txs += 1;
                items += n;
            }
        }
    }
    assert!(
        items > 0,
        "the RedJubjub fuzz target's seed corpora yielded no items at all — see \
         `sapling_target_seeds_reach_the_verifier`."
    );
    eprintln!("redjubjub: {txs} transactions, {items} items across {SIGNATURE_TARGET_CORPORA:?}");
}

#[test]
fn sprout_target_seeds_reach_the_verifier() {
    let mut txs = 0usize;
    let mut items = 0usize;
    for (_, tx) in historical_transactions() {
        let n = sprout_items(&tx).len();
        if n > 0 {
            txs += 1;
            items += n;
        }
    }
    assert!(
        items > 0,
        "the Sprout fuzz target's seed corpus yielded no items at all — see \
         `sapling_target_seeds_reach_the_verifier`."
    );
    eprintln!("sprout: {txs} transactions, {items} JoinSplit items in the historical corpus");
}

/// The mistake this suite was written for, pinned as a fact rather than left as
/// a memory.
///
/// The historical corpus documents 1,261 Sapling spends and yields no Sapling
/// items, because those transactions are v4: a v4 transaction does not state its
/// consensus branch id, so nothing in a bare transaction says which network
/// upgrade its sighash belongs to. M2's Sapling suite never met this — it reads
/// the in-tree block vectors, where the height answers that question — and a
/// fuzz target reading a bare transaction stream has no height.
///
/// If this test ever fails, the input model gained a way to name an era (the
/// planned control byte, or something upstream). That is good news, and it means
/// this corpus should be seeded to the signature targets — which is why the
/// assertion is worth keeping rather than deleting as an oddity.
#[test]
fn the_historical_corpus_still_yields_no_sapling_items() {
    let mut sapling = 0usize;
    let mut redjubjub = 0usize;
    let mut sprout = 0usize;
    for (_, tx) in historical_transactions() {
        sapling += sapling_items(&tx).len();
        redjubjub += redjubjub_items(&tx).len();
        sprout += sprout_items(&tx).len();
    }
    assert!(
        sprout > 0,
        "the historical corpus is the Sprout target's only source and yielded nothing"
    );
    assert_eq!(
        (sapling, redjubjub),
        (0, 0),
        "the historical corpus now yields Sapling material ({sapling} Sapling, {redjubjub} \
         RedJubjub items). Something taught the input model to name an era — seed the two \
         signature targets from this corpus in scripts/prep-fuzz-corpus.sh and update this test."
    );
}

/// The rule that is easy to unify and must not be: a transaction with
/// transparent inputs is unusable for the signature-bearing paths and perfectly
/// ordinary material for Sprout.
///
/// Unifying the three extractors — "filter transparent inputs everywhere, it is
/// the safe default" — would silently discard 850 of the historical corpus's
/// 2,032 seeds from the one pool that can use them. Nothing would fail: the
/// Sprout target would keep working on a corpus 40% smaller.
#[test]
fn the_transparent_input_rule_is_per_verifier_not_global() {
    let mut checked = 0usize;
    for (_, tx) in historical_transactions() {
        if tx.inputs().is_empty() {
            continue;
        }
        // Transparent inputs present. Sapling and RedJubjub must decline it...
        assert!(
            sapling_items(&tx).is_empty(),
            "a transaction with transparent inputs reached the Sapling extractor"
        );
        assert!(
            redjubjub_items(&tx).is_empty(),
            "a transaction with transparent inputs reached the RedJubjub extractor"
        );
        // ...and Sprout must not, when it carries JoinSplits.
        if sprout_items(&tx).is_empty() {
            continue;
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "no transaction in the corpus has both transparent inputs and Groth16 JoinSplits, so \
         this test asserted nothing. That is a corpus change, not a passing test."
    );
    eprintln!(
        "{checked} transactions carry both transparent inputs and JoinSplits — declined by the \
         two signature paths, used by Sprout"
    );
}

/// The turnstile target's seeds are concatenations, and this asserts both
/// halves of why.
///
/// `turnstile_order_independence` returns on any stream carrying fewer than two
/// transactions — with one there is no arrival order to vary. Every other target
/// in this repository takes one transaction per seed file, so seeding the
/// turnstile the same way would produce a corpus on which every input hits that
/// guard: full speed, healthy execution count, assertion never reached.
///
/// Both halves are checked, because only the pair is an argument. That one file
/// yields exactly one transaction is what makes the guard real rather than
/// hypothetical; that two files concatenated yield two is what makes the fix
/// work. Checking only the second would leave "concatenating was necessary" as
/// a claim in a comment, and a comment cannot fail.
#[test]
fn the_turnstile_target_needs_concatenated_seeds() {
    let dir = format!("{}/seeds-real/nu6_3_activation", env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed corpus dir {dir}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    files.sort();
    assert!(
        files.len() >= 2,
        "the turnstile seed shape needs at least two corpus files to concatenate; \
         {} were found in {dir}",
        files.len()
    );

    let first = std::fs::read(&files[0]).expect("read corpus file");
    let alone = items_from_tx_stream_with(&first, |tx| vec![tx.clone()]);
    assert_eq!(
        alone.len(),
        1,
        "one corpus file yielded {} transactions, not one. The turnstile seeds are \
         concatenations because a single file trips the target's `len() < 2` guard — \
         if a file already carries several, that premise has changed and \
         scripts/prep-fuzz-corpus.sh should be revisited rather than trusted.",
        alone.len()
    );

    let mut concatenated = first;
    concatenated.extend_from_slice(&std::fs::read(&files[1]).expect("read corpus file"));
    let together = items_from_tx_stream_with(&concatenated, |tx| vec![tx.clone()]);
    assert!(
        together.len() >= 2,
        "two concatenated corpus files yielded {} transactions. The stream parser is \
         supposed to continue past the first transaction's end; if it stops there, every \
         turnstile seed is a one-transaction run and the target never reaches its \
         assertion.",
        together.len()
    );

    eprintln!(
        "turnstile seed shape: 1 file -> {} transaction (target would return), \
         2 files -> {} transactions (target proceeds)",
        alone.len(),
        together.len()
    );
}

/// The four core `batch ⟺ single` targets must be seeded from every circuit
/// era, and the seeds must be chosen by whether they reach the extractor.
///
/// This is the check that would have caught what it now guards, and the defect
/// had two layers. Those four targets — the ones comparing the two verification
/// paths directly, which is the claim this project rests on — were seeded from
/// two eras, because they were written when only two existed; the third-era
/// corpus arrived later and they were not revisited. Underneath that, the
/// seeding picked files by filename order, and in `orchard_v5_pre_nu6_2` the
/// first file yielding an Orchard item is the ninth — so the six that shipped
/// for the June-5 era reached nothing at all.
///
/// Both layers look identical from outside: nine targets, every one seeded,
/// every one green, healthy execution counts throughout.
#[test]
fn the_core_targets_are_seeded_from_every_circuit_era() {
    use zebra_batch_equivalence::era::CircuitEra;
    use zebra_batch_equivalence::MANIFEST_NAME;

    /// The script's default `SAMPLE_PER_ERA`, mirrored so this test can ask the
    /// question the script's behaviour actually depends on: are there at least
    /// this many *usable* files, not merely files.
    const SAMPLE_PER_ERA: usize = 6;

    // Corpus directory -> the era its transactions belong to. The control byte
    // prep-fuzz-corpus.sh appends is this era's index.
    const CORE_ERAS: [(&str, CircuitEra); 3] = [
        ("orchard_v5_pre_nu6_2", CircuitEra::PreNu6_2),
        ("orchard_v5_nu6_2", CircuitEra::Nu6_2),
        ("nu6_3_activation", CircuitEra::Nu6_3Onward),
    ];

    // 1. Exhaustive over the enum, compared as two lists rather than trusted.
    //    A missing era is invisible otherwise: the sweep runs over the eras it
    //    was handed and reports success for them.
    for era in CircuitEra::ALL {
        assert!(
            CORE_ERAS.iter().any(|(_, e)| *e == era),
            "{era:?} has no corpus in CORE_ERAS, so the core batch-vs-single targets are \
             seeded from a strict subset of the eras they verify. Add its corpus here and \
             to the orchard block of scripts/prep-fuzz-corpus.sh."
        );
    }

    // 2. Each era has enough files that actually reach the Orchard extractor to
    //    fill the sample. Read from the manifest, whose accuracy is the subject
    //    of `manifests_match_the_corpora` below — so this asserts the seeding
    //    outcome, not the measurement.
    let mut problems: Vec<String> = Vec::new();
    for (dir, era) in CORE_ERAS {
        let manifest = format!(
            "{}/seeds-real/{dir}/{MANIFEST_NAME}",
            env!("CARGO_MANIFEST_DIR")
        );
        let text = std::fs::read_to_string(&manifest).unwrap_or_else(|e| {
            panic!("{manifest}: {e}\nrun: cargo run --release --example seed_reach_manifest")
        });
        let usable = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .filter(|l| {
                l.split('\t')
                    .nth(1)
                    .and_then(|n| n.parse::<usize>().ok())
                    .is_some_and(|n| n > 0)
            })
            .count();
        eprintln!("{dir} ({era:?}): {usable} files reach the Orchard extractor");
        if usable < SAMPLE_PER_ERA {
            problems.push(format!(
                "seeds-real/{dir} ({era:?}) has only {usable} files reaching the Orchard \
                 extractor, fewer than the {SAMPLE_PER_ERA} seeds the script ships"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "an era whose seeds reach no verifier fuzzes nothing, at full speed:\n  {}",
        problems.join("\n  ")
    );

    // 3. The script names each corpus in the blocks that seed those targets, and
    //    selects through the manifest rather than by filename order. Both halves
    //    are needed: naming the corpus while taking a lexicographic head is
    //    exactly the state this test was written for.
    let script = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/prep-fuzz-corpus.sh"
    ))
    .expect("read prep-fuzz-corpus.sh");
    assert!(
        script.contains(MANIFEST_NAME),
        "scripts/prep-fuzz-corpus.sh does not mention {MANIFEST_NAME}, so it is selecting \
         seeds some other way than by what reaches an extractor"
    );
    for marker in [
        "for target in orchard_batch_equivalence orchard_batch_composition; do",
        "for target in orchard_era_routing orchard_single_deep; do",
    ] {
        let start = script
            .find(marker)
            .unwrap_or_else(|| panic!("prep-fuzz-corpus.sh no longer contains: {marker}"));
        let rest = &script[start..];
        let block = &rest[..rest.find("\ndone").expect("unterminated loop in script")];
        for (dir, era) in CORE_ERAS {
            assert!(
                block.contains(dir),
                "scripts/prep-fuzz-corpus.sh does not seed {dir} ({era:?}) into the block \
                 starting `{marker}`. The targets there compare batch against single, so an \
                 era missing from them is an era whose equivalence is never fuzzed."
            );
        }
    }
}

/// The committed manifests still describe the corpora they name.
///
/// `scripts/prep-fuzz-corpus.sh` picks seeds from these files, and it runs
/// without a toolchain — inside the ClusterFuzzLite build, among other places —
/// so the measurement has to be committed rather than taken at seeding time.
/// That is only safe if going stale is loud, which is this test. It re-measures
/// every corpus from scratch and compares row for row.
///
/// The failure it exists for is silent by construction: a manifest that no
/// longer matches its directory still parses, still names real files, and still
/// yields seeds. They are just the wrong ones.
#[test]
fn manifests_match_the_corpora() {
    use zebra_batch_equivalence::{items_from_tx, MANIFEST_NAME};

    for corpus in [
        "orchard_v5_pre_nu6_2",
        "orchard_v5_nu6_2",
        "nu6_3_activation",
        "historical_419200_1046400",
    ] {
        let dir = format!("{}/seeds-real/{corpus}", env!("CARGO_MANIFEST_DIR"));
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("corpus dir {dir}: {e}"))
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "bin"))
            .collect();
        files.sort();

        let mut measured: Vec<String> = Vec::new();
        for path in &files {
            let bytes = std::fs::read(path).expect("read corpus file");
            let Ok(tx) = Transaction::zcash_deserialize(&bytes[..]) else {
                continue;
            };
            let counts = [
                items_from_tx(&tx).len(),
                sapling_items(&tx).len(),
                redjubjub_items(&tx).len(),
                sprout_items(&tx).len(),
            ];
            if counts.iter().all(|n| *n == 0) {
                continue;
            }
            measured.push(format!(
                "{}\t{}\t{}\t{}\t{}",
                path.file_name().unwrap().to_string_lossy(),
                counts[0],
                counts[1],
                counts[2],
                counts[3]
            ));
        }

        let manifest_path = format!("{dir}/{MANIFEST_NAME}");
        let text = std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
            panic!("{manifest_path}: {e}\nrun: cargo run --release --example seed_reach_manifest")
        });
        let listed: Vec<String> = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(str::to_owned)
            .collect();

        assert_eq!(
            listed.len(),
            measured.len(),
            "{corpus}: manifest lists {} files, re-measuring finds {}. Regenerate: \
             cargo run --release --example seed_reach_manifest",
            listed.len(),
            measured.len()
        );
        for (i, (l, m)) in listed.iter().zip(measured.iter()).enumerate() {
            assert_eq!(
                l, m,
                "{corpus}: manifest row {i} says `{l}`, re-measuring gives `{m}`. Regenerate: \
                 cargo run --release --example seed_reach_manifest"
            );
        }

        // The header's scanned count is what makes "listed" interpretable: the
        // difference between them is the part of the corpus that reaches
        // nothing, and a manifest that reported only the listed count would look
        // identical whether it scanned 550 files or 6.
        let scanned = text
            .lines()
            .find_map(|l| l.strip_prefix("# files scanned: "))
            .and_then(|n| n.trim().parse::<usize>().ok())
            .unwrap_or_else(|| panic!("{corpus}: manifest has no `# files scanned:` header"));
        assert_eq!(
            scanned,
            files.len(),
            "{corpus}: manifest says it scanned {scanned} files, the directory holds {}",
            files.len()
        );

        eprintln!("{corpus}: {} of {} files reach an extractor", listed.len(), files.len());
    }
}

/// Three places name the fuzz targets, and all three must name the same nine.
///
/// They drifted. `fuzz/Cargo.toml` and `fuzz/fuzz_targets/` gained
/// `turnstile_order_independence` and `tower_partition_equivalence` during M3;
/// `.clusterfuzzlite/build.sh` kept a hand-written list of seven. The build
/// went on succeeding — nine targets compiled, seven binaries and seven seed
/// archives were published — because nothing compared the counts. One of the
/// two missing is a Milestone 3 deliverable.
///
/// build.sh now derives its list from Cargo.toml, so the pair that can still
/// drift is Cargo.toml against the directory, which is what this checks. It
/// also checks that build.sh and ci.yml are still deriving rather than
/// restating, by running the extraction they run: a future edit that pastes the
/// list back is exactly how this returns.
#[test]
fn every_fuzz_target_is_declared_and_published() {
    let root = env!("CARGO_MANIFEST_DIR");

    let mut on_disk: Vec<String> = std::fs::read_dir(format!("{root}/fuzz/fuzz_targets"))
        .expect("fuzz/fuzz_targets")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();

    let cargo = std::fs::read_to_string(format!("{root}/fuzz/Cargo.toml")).expect("fuzz/Cargo.toml");
    let mut declared: Vec<String> = Vec::new();
    let mut in_bin = false;
    for line in cargo.lines() {
        if line.trim() == "[[bin]]" {
            in_bin = true;
        } else if in_bin {
            if let Some(name) = line.trim().strip_prefix("name = ") {
                declared.push(name.trim_matches('"').to_owned());
                in_bin = false;
            }
        }
    }
    declared.sort();

    assert_eq!(
        declared, on_disk,
        "fuzz/Cargo.toml declares {declared:?} but fuzz/fuzz_targets holds {on_disk:?}. A target \
         that exists as a file and not as a [[bin]] is never built; one declared without a file \
         breaks the build. Neither is visible from the published artefacts."
    );

    // Both consumers must still be deriving rather than restating. A future
    // edit that pastes the list back into either file is exactly how this
    // returns, and it would return silently: the pasted list is correct on the
    // day it is written.
    //
    // This used to be `text.contains("fuzz/Cargo.toml")`, which both files
    // satisfy in their comments alone, so it passed with the list pasted back.
    // Now: the extraction must sit on a line that is not a comment, and running
    // it must print exactly what this test parsed. The second half also pins
    // the awk parse and the Rust parse above to the same answer, so the three
    // readers of `[[bin]]` cannot quietly disagree about the same file.
    const ENUMERATE: &str =
        r#"/^\[\[bin\]\]/{b=1;next} b && /^name = /{gsub(/["]/,"",$3); print $3; b=0}"#;
    let invocation = format!("awk '{ENUMERATE}'");
    for (path, what) in [
        (".clusterfuzzlite/build.sh", "publishes the binaries and seed archives"),
        (".github/workflows/ci.yml", "smoke-runs every target"),
    ] {
        let text = std::fs::read_to_string(format!("{root}/{path}"))
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        let code: Vec<&str> =
            text.lines().filter(|l| !l.trim_start().starts_with('#')).collect();
        assert!(
            code.iter().any(|l| l.contains(&invocation)),
            "{path}, which {what}, no longer runs the Cargo.toml extraction on a line that is \
             not a comment. A second hand-maintained list is how seven of nine targets shipped \
             for a milestone without a single failing check."
        );
        // A pasted list names targets outside comments. ci.yml legitimately
        // names three, only to give them a longer smoke budget.
        for line in code.iter().filter(|l| !l.contains("budget=")) {
            if let Some(t) = declared.iter().find(|t| line.contains(t.as_str())) {
                panic!("{path} names the target `{t}` outside a comment: {line:?}");
            }
        }
    }
    let run = std::process::Command::new("awk")
        .arg(ENUMERATE)
        .arg(format!("{root}/fuzz/Cargo.toml"))
        .output()
        .expect("awk runs");
    assert!(run.status.success(), "awk failed: {}", String::from_utf8_lossy(&run.stderr));
    let mut derived: Vec<String> =
        String::from_utf8_lossy(&run.stdout).lines().map(str::to_owned).collect();
    derived.sort();
    assert_eq!(
        derived, declared,
        "the consumers' extraction reads fuzz/Cargo.toml differently from this test"
    );

    eprintln!("{} fuzz targets, declared and on disk: {}", declared.len(), declared.join(", "));
}

/// The three ClusterFuzzLite workflows name one corpus repository.
///
/// Each of them writes to the storage repository it names. If two named
/// different ones, each would grow a corpus of its own and none of them would
/// be the permanent one — with every run green. The URL is written out four
/// times (the cron workflow has two jobs), and nothing else compares the
/// copies.
#[test]
fn the_cflite_workflows_share_one_corpus_repository() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut seen: Vec<(String, String)> = Vec::new();
    for name in ["cflite_pr.yml", "cflite_batch.yml", "cflite_cron.yml"] {
        let path = format!("{root}/.github/workflows/{name}");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("storage-repo:"))
            .collect();
        assert!(!lines.is_empty(), "{name} names no storage-repo, so its corpus is not kept");
        seen.extend(lines.into_iter().map(|l| (name.to_owned(), l.to_owned())));
    }
    let first = &seen[0].1;
    for (name, line) in &seen {
        assert_eq!(line, first, "{name} writes its corpus somewhere else than {}", seen[0].0);
    }
    assert!(
        first.contains("github.com/robustfengbin/zebra-batch-equivalence-corpora.git"),
        "the shared storage-repo is not the corpus repository: {first}"
    );
    assert_eq!(seen.len(), 4, "expected four storage-repo lines (pr, batch, cron x2): {seen:?}");
}
