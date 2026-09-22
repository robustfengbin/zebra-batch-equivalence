//! Which corpus actually feeds which fuzz target — measured, not assumed.
//!
//! A fuzz target whose seeds yield no items is not a failing target. It builds,
//! it runs, it exits zero, and libFuzzer reports a healthy execution rate —
//! because every input returns before reaching a verifier. Nothing in CI can
//! tell that apart from a target that is working, which makes "seeds produce
//! items" a thing to measure rather than to assume.
//!
//! For each corpus directory under `seeds-real/`, this reports, per pool: how
//! many transactions yield at least one item, and how many items in total. The
//! extraction is [`zebra_batch_equivalence::fuzz_input`] — the same code the
//! targets run, so a number here is a claim about the target and not about a
//! second implementation of its rules.
//!
//! ```text
//! cargo run --release --example survey_fuzz_seeds
//! ```
//!
//! A zero column means that corpus has nothing for that pool. That is expected
//! for most pairs — the Orchard corpora predate Sapling's batch surface being
//! interesting and carry no JoinSplits at all — and is a finding only where a
//! target is seeded from that corpus.

use std::fs;
use std::path::Path;

use zebra_batch_equivalence::fuzz_input::{redjubjub_items, sapling_items, sprout_items};
use zebra_batch_equivalence::MANIFEST_NAME;
use zebra_batch_equivalence::items_from_tx;
use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::Transaction;

#[derive(Default)]
struct Count {
    /// Transactions that yielded at least one item.
    txs: usize,
    /// Items yielded in total.
    items: usize,
}

impl Count {
    fn add(&mut self, n: usize) {
        if n > 0 {
            self.txs += 1;
            self.items += n;
        }
    }
}

#[derive(Default)]
struct Row {
    seeds: usize,
    unparseable: usize,
    orchard: Count,
    sapling: Count,
    redjubjub: Count,
    sprout: Count,
}

fn survey(dir: &Path) -> Row {
    let mut row = Row::default();
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("corpus directory")
        .filter_map(Result::ok)
        .map(|e| e.path())
        // Every file except the corpus READMEs and the reach manifest. Not a
        // `.bin` filter: the M1 Orchard seeds are named `seed_pre_nu6_2_000`
        // with no extension at all, so an extension filter reports that corpus
        // as empty — which reads exactly like "this corpus has nothing for any
        // pool". The manifest is excluded by name rather than by extension, so
        // renaming it cannot leave this counting it as an unparseable seed.
        .filter(|p| p.file_name().is_some_and(|n| n != AsRef::<std::ffi::OsStr>::as_ref(MANIFEST_NAME)))
        .filter(|p| p.extension().is_none_or(|x| x != "md"))
        .collect();
    entries.sort();

    for path in entries {
        row.seeds += 1;
        let bytes = fs::read(&path).expect("read seed");
        let Ok(tx) = Transaction::zcash_deserialize(&bytes[..]) else {
            row.unparseable += 1;
            continue;
        };
        // Each extractor is the one its target runs, transparent-input rule and
        // all. Wrapped because sighasher construction can panic on a
        // deserialized-but-incoherent transaction, exactly as it can during
        // fuzzing; a panic costs that transaction, not the survey.
        let orchard = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| items_from_tx(&tx)))
            .map(|v| v.len())
            .unwrap_or(0);
        let sapling = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sapling_items(&tx)))
            .map(|v| v.len())
            .unwrap_or(0);
        let redjubjub =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| redjubjub_items(&tx)))
                .map(|v| v.len())
                .unwrap_or(0);
        let sprout = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sprout_items(&tx)))
            .map(|v| v.len())
            .unwrap_or(0);

        row.orchard.add(orchard);
        row.sapling.add(sapling);
        row.redjubjub.add(redjubjub);
        row.sprout.add(sprout);
    }
    row
}

fn main() {
    // With no argument: every corpus under `seeds-real/`, which answers "what
    // material exists". With a directory argument: that one directory, which
    // answers the sharper question — "do the seeds this target actually got
    // reach its verifier?" A corpus can be rich in a pool and a six-file sample
    // of it still be empty, so the two questions have different answers and the
    // second is the one a target's health depends on.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut dirs: Vec<_> = if args.is_empty() {
        let root = Path::new("seeds-real");
        let mut d: Vec<_> = fs::read_dir(root)
            .expect("seeds-real must exist; run from the repository root")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        d.sort();
        d
    } else {
        args.iter().map(|a| Path::new(a).to_path_buf()).collect()
    };
    dirs.sort();

    println!(
        "{:<34} {:>6} {:>5}  {:>13} {:>13} {:>13} {:>13}",
        "corpus", "seeds", "bad", "orchard", "sapling", "redjubjub", "sprout"
    );
    println!("{}", "-".repeat(34 + 7 + 6 + 14 * 4));

    for dir in dirs {
        let row = survey(&dir);
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        println!(
            "{:<34} {:>6} {:>5}  {:>13} {:>13} {:>13} {:>13}",
            name,
            row.seeds,
            row.unparseable,
            format!("{}tx/{}i", row.orchard.txs, row.orchard.items),
            format!("{}tx/{}i", row.sapling.txs, row.sapling.items),
            format!("{}tx/{}i", row.redjubjub.txs, row.redjubjub.items),
            format!("{}tx/{}i", row.sprout.txs, row.sprout.items),
        );
    }

    println!(
        "\n`Ntx/Mi` = N transactions yielded at least one item, M items in total.\n\
         A target seeded from a corpus whose column is 0tx/0i never reaches its verifier."
    );
}
