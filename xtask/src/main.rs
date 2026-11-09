// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Repository tasks. Today: building the benchmark corpus.
//!
//! The corpus is never committed and never redistributed. What is committed is
//! a lockfile of upstream URLs with their hashes, plus the sampling recipe --
//! enough for anyone to reconstruct the same bytes, without this repository
//! shipping content it does not own.

mod corpus;

use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage: cargo run -p xtask -- <command>

  corpus add <url> [--id ID] [--license L] [--population P] [--note TEXT]
      Download, hash and record a source in corpus/oss.lock.toml.

  corpus fetch [--jobs N]
      Download every locked source, verify its hash, and extract it into
      corpus/cache/. Re-running is cheap: already-correct downloads are kept.

  corpus build [--target-bytes N] [--segment N] [--large N] [--precompressed N]
               [--seed N] [--group-depth N] [--group-share-pct N]
      Sample continuous segments out of corpus/cache/ into corpus/segments/,
      and write corpus/manifest.tsv.

  corpus build-system [--target-bytes N] [--segment N] [--seed N]
               [--group-depth N] [--group-share-pct N]
      Tier B: sample real macOS system content (dyld caches, AssetsV2,
      /System + /Library) directly off THIS machine into
      corpus/segments/system/, and write corpus/manifest_system.tsv. No
      lockfile — content and proportions are measured fresh each run, since
      what's installed varies by machine and by day. Never distributed.

  corpus manifest [--quick] [--large]
      Print the segment paths the bench consumes, one per line.

  corpus status
      Summarize what is locked, fetched and built."
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(a), Some(b)) = (args.first(), args.get(1)) else {
        return usage();
    };
    let rest = &args[2..];
    let result = match (a.as_str(), b.as_str()) {
        ("corpus", "add") => corpus::add(rest),
        ("corpus", "fetch") => corpus::fetch(rest),
        ("corpus", "build") => corpus::build(rest),
        ("corpus", "build-system") => corpus::build_system(rest),
        ("corpus", "manifest") => corpus::manifest(rest),
        ("corpus", "status") => corpus::status(rest),
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
