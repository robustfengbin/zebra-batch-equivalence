//! Which corpus files reach which extractor — measured, and written down.
//!
//! `scripts/prep-fuzz-corpus.sh` ships a handful of seeds per corpus, not the
//! whole corpus: every accepted seed drives a real SNARK verification, and the
//! full-corpus sweep is what `cargo test` is for. Picking that handful by
//! filename order is where this went wrong. In `orchard_v5_pre_nu6_2`, 164 of
//! 550 files yield an Orchard item and **the first usable one is the ninth**, so
//! a lexicographic `head -n 6` shipped six inputs the extractor declines — for
//! the four targets that compare batch against single, in the era the June-5
//! bug lived in. libFuzzer runs them at full speed and reports a healthy
//! execution count, which is exactly what a working target looks like.
//!
//! Selecting by *stride* instead does not fix it, it only makes it less likely:
//! a step of 92 over that corpus lands on one usable file out of six. The fix
//! has to be selection by the property that matters — does this file reach the
//! extractor — which means measuring it, which means a manifest.
//!
//! The manifest is committed, so the seeding script needs no toolchain, and
//! `tests/fuzz_input_reach.rs` re-measures and fails if the file and the
//! directory disagree. A stale manifest is therefore loud, which is the only
//! reason a committed derived artefact is safe to rely on.
//!
//! Usage: `cargo run --release --example seed_reach_manifest`

use std::fmt::Write as _;
use std::path::Path;

use zebra_batch_equivalence::fuzz_input::{redjubjub_items, sapling_items, sprout_items};
use zebra_batch_equivalence::{items_from_tx, MANIFEST_HEADER, MANIFEST_NAME};
use zebra_chain::serialization::ZcashDeserialize;
use zebra_chain::transaction::Transaction;

/// The corpora the seeding script samples from. `orchard_pre_nu6_2` is absent
/// deliberately: its three files are copied wholesale, not sampled, so there is
/// nothing for a manifest to select.
const CORPORA: [&str; 4] = [
    "orchard_v5_pre_nu6_2",
    "orchard_v5_nu6_2",
    "nu6_3_activation",
    "historical_419200_1046400",
];

fn main() {
    for corpus in CORPORA {
        let dir = format!("{}/seeds-real/{corpus}", env!("CARGO_MANIFEST_DIR"));
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("corpus dir {dir}: {e}"))
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "bin"))
            .collect();
        files.sort();

        let mut rows = String::new();
        let mut listed = 0usize;
        for path in &files {
            let bytes = std::fs::read(path).expect("read corpus file");
            let Ok(tx) = Transaction::zcash_deserialize(&bytes[..]) else {
                // Not a bare transaction. Reported by omission rather than
                // skipped silently: the scanned count below will not match the
                // listed count, and the header says both.
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
            listed += 1;
            let name = path.file_name().unwrap().to_string_lossy();
            writeln!(
                rows,
                "{name}\t{}\t{}\t{}\t{}",
                counts[0], counts[1], counts[2], counts[3]
            )
            .unwrap();
        }

        let out = Path::new(&dir).join(MANIFEST_NAME);
        let body = format!(
            "{MANIFEST_HEADER}# corpus: {corpus}\n# files scanned: {}\n# files listed: {listed}\n\
             #\n# file\torchard\tsapling\tredjubjub\tsprout\n{rows}",
            files.len()
        );
        std::fs::write(&out, body).expect("write manifest");
        println!(
            "{corpus}: {listed} of {} files reach at least one extractor -> {}",
            files.len(),
            out.display()
        );
    }
}
