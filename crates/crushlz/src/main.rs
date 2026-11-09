// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use crushlz::Algo;

#[derive(Parser, Debug)]
#[command(
    name = "crushlz",
    version,
    about = "Compress and decompress LZFSE, LZVN, LZBITMAP and LZ4 streams",
    long_about = "Emits raw codec streams with no container of its own, so output stays \
                  readable by Apple's libcompression and by the kernel's decmpfs path. \
                  Decoding identifies the format from the stream's own magic.\n\n\
                  Use - for stdin/stdout."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Compress a file.
    #[command(visible_alias = "c")]
    Encode {
        input: PathBuf,
        output: PathBuf,
        #[arg(long, value_enum, default_value_t = AlgoArg::Lzfse)]
        algo: AlgoArg,
        /// Higher is denser and slower. Defaults to the algorithm's own default.
        /// Negative levels are valid, they sit below Apple's own encoder, so
        /// this must accept a leading minus rather than read it as a flag.
        #[arg(short, long, allow_negative_numbers = true)]
        level: Option<i32>,
        /// Worker threads for LZBITMAP's independent chunks. 0 uses one per
        /// core. Every other algorithm and level ignores this: LZFSE/LZVN's
        /// optimal-parse levels encode one 64 KiB piece per call, and
        /// everything else already streams on one thread.
        #[arg(short = 'T', long, default_value_t = 0)]
        threads: usize,
        /// Refuse to run if estimated encoder memory exceeds this many MiB.
        /// Scratch is per worker, so --threads on LZBITMAP can ask for more
        /// than expected.
        #[arg(long, default_value_t = 8192)]
        max_memory: usize,
        /// Decode the result and compare against the input before writing it.
        #[arg(long)]
        verify: bool,
        /// Overwrite the output if it already exists.
        #[arg(short, long)]
        force: bool,
    },
    /// Decompress a file, detecting its format automatically.
    #[command(visible_alias = "d")]
    Decode {
        input: PathBuf,
        output: PathBuf,
        /// Force a format instead of detecting it. Required for raw LZVN,
        /// which carries no magic to detect.
        #[arg(long, value_enum)]
        algo: Option<AlgoArg>,
        #[arg(short, long)]
        force: bool,
    },
    /// Decompress without writing anything, to check a stream is intact.
    #[command(visible_alias = "t")]
    Test {
        input: PathBuf,
        /// Force a format instead of detecting it. Required for raw LZVN.
        #[arg(long, value_enum)]
        algo: Option<AlgoArg>,
    },
    /// Report what a file is without decompressing it.
    Info { input: PathBuf },
    /// List the algorithms and their level ranges.
    Limits,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum AlgoArg {
    /// CrushLZFSE. Emits LZVN blocks where LZVN wins; the same decoder reads both.
    Lzfse,
    /// Raw LZVN, no container. The shape an ipsw payload uses. Carries no
    /// magic, so decoding one needs --algo lzvn.
    Lzvn,
    Lzbitmap,
    Lz4,
    /// Apple LZMESH format (0xE05).
    Lzmesh,
}

impl From<AlgoArg> for Algo {
    fn from(a: AlgoArg) -> Self {
        match a {
            AlgoArg::Lzfse => Algo::Lzfse,
            AlgoArg::Lzvn => Algo::Lzvn,
            AlgoArg::Lzbitmap => Algo::Lzbitmap,
            AlgoArg::Lz4 => Algo::Lz4,
            AlgoArg::Lzmesh => Algo::Lzmesh,
        }
    }
}

fn is_stdio(p: &Path) -> bool {
    p.as_os_str() == "-"
}

/// Decode `encoded` and compare it against `original`, returning a
/// description of which decoders actually ran.
///
/// Our decoder always runs. Apple's runs too where `libcompression` provides
/// it, and that is the one that matters most: it is what the kernel reads
/// decmpfs files with, and an encoder and decoder from the same source can
/// agree with each other about something the format does not mean.
///
/// `decode_as` rather than `decode`, because raw LZVN carries no magic to
/// detect and the algorithm is already known here. Detecting instead made
/// `--algo lzvn --verify` fail on every input.
fn verify_encoded(
    algo: Algo,
    encoded: &[u8],
    original: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let back = crushlz::decode_as(algo, encoded)
        .map_err(|e| format!("verify: the output did not decode ({e})"))?;
    if back != original {
        return Err("verify: decoded output does not match the input".into());
    }

    #[cfg(target_os = "macos")]
    {
        if crushlz::apple::supports(algo) {
            match crushlz::apple::decode(algo, encoded, original.len()) {
                Some(ref apple_back) if apple_back == original => {
                    return Ok("crush-lz + apple".into())
                }
                Some(_) => {
                    return Err("verify: Apple's decoder returned different bytes than ours. \
                                Do not use this output; please report it."
                        .into())
                }
                None => {
                    return Err("verify: Apple's decoder rejected output our own decoder \
                                accepted. Do not use this output; please report it."
                        .into())
                }
            }
        }
        // Only reachable for LZVN, whose libcompression entry point is not a
        // public constant. Unavailable is a fact about this OS, not about the
        // user's data, so it must not read as a verification failure.
        Ok("crush-lz only: Apple's lzvn decoder is unavailable on this OS".into())
    }

    #[cfg(not(target_os = "macos"))]
    Ok("crush-lz only: Apple's decoder is macOS-only".into())
}

fn read_input(path: &Path) -> std::io::Result<Vec<u8>> {
    if is_stdio(path) {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        fs::read(path)
    }
}

fn write_output(path: &Path, data: &[u8], force: bool) -> Result<(), Box<dyn std::error::Error>> {
    if is_stdio(path) {
        std::io::stdout().write_all(data)?;
        return Ok(());
    }
    // Refuse to destroy an existing file by accident. Compression tools are
    // routinely run in loops over directories, where a wrong argument order
    // silently overwrites a source file with its own compressed form.
    if path.exists() && !force {
        return Err(format!("{}: already exists (pass --force to overwrite)", path.display()).into());
    }
    fs::write(path, data)?;
    Ok(())
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Encode { input, output, algo, level, threads, max_memory, verify, force } => {
            let algo: Algo = algo.into();
            let level = level.unwrap_or_else(|| algo.default_level());

            let need = crushlz::encode_memory_estimate(algo, level, threads);
            let cap = max_memory.saturating_mul(1 << 20);
            if need > cap {
                return Err(format!(
                    "estimated encoder memory {:.1} GiB exceeds the {:.1} GiB limit. \
                     Scratch is per worker, so lower --threads or raise --max-memory.",
                    need as f64 / (1u64 << 30) as f64,
                    cap as f64 / (1u64 << 30) as f64
                )
                .into());
            }

            let data = read_input(&input)?;
            let encoded = crushlz::encode_with_threads(algo, &data, level, threads)?;

            let verified_by = if verify { Some(verify_encoded(algo, &encoded, &data)?) } else { None };

            write_output(&output, &encoded, force)?;
            let pct = if data.is_empty() {
                0.0
            } else {
                100.0 * (1.0 - encoded.len() as f64 / data.len() as f64)
            };
            eprintln!(
                "{} level {level}: {} -> {} bytes ({pct:.2}% saved){}",
                algo,
                data.len(),
                encoded.len(),
                match &verified_by {
                    Some(who) => format!(", verified ({who})"),
                    None => String::new(),
                }
            );
        }
        Command::Decode { input, output, algo, force } => {
            let data = read_input(&input)?;
            let decoded = match algo {
                Some(a) => crushlz::decode_as(a.into(), &data)?,
                None => crushlz::decode(&data)?,
            };
            write_output(&output, &decoded, force)?;
            eprintln!("{} -> {} bytes", data.len(), decoded.len());
        }
        Command::Test { input, algo } => {
            let data = read_input(&input)?;
            let algo: Algo = match algo {
                Some(a) => a.into(),
                None => crushlz::detect(&data).ok_or(crushlz::Error::UnknownFormat)?,
            };
            let decoded = crushlz::decode_as(algo, &data)?;
            eprintln!("{}: {algo}, {} bytes, intact", input.display(), decoded.len());
        }
        Command::Info { input } => {
            let data = read_input(&input)?;
            match crushlz::detect(&data) {
                Some(algo) => println!("{algo}"),
                // Raw LZVN lands here: nothing in the stream identifies it.
                None => return Err(Box::new(crushlz::Error::UnknownFormat)),
            }
        }
        Command::Limits => {
            println!("{:<10} {:<10} DEFAULT", "ALGO", "LEVELS");
            for algo in [Algo::Lzfse, Algo::Lzvn, Algo::Lzbitmap, Algo::Lz4, Algo::Lzmesh] {
                let (min, max) = algo.level_range();
                let levels = format!("{min}..{max}");
                println!("{:<10} {:<10} {}", algo.to_string(), levels, algo.default_level());
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("crushlz: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("crushlz").chain(args.iter().copied()))
    }

    // <=65536 bytes: every LZFSE/LZVN level now rejects anything larger
    // per call.
    fn sample() -> Vec<u8> {
        (0..65_536u32).map(|i| (i % 251) as u8).collect()
    }

    /// Every algorithm must survive `--verify`, LZVN included.
    ///
    /// LZVN is the reason this test exists: `--verify` used to decode by magic
    /// detection, and raw LZVN has none, so `--algo lzvn --verify` failed on
    /// every input regardless of whether the output was good. Nothing caught
    /// it, because the tests here only ever exercised argument parsing.
    #[test]
    fn verify_accepts_good_output_for_every_algo() {
        let data = sample();
        for algo in [Algo::Lzfse, Algo::Lzvn, Algo::Lzbitmap, Algo::Lz4] {
            let encoded = crushlz::encode(algo, &data, 6).expect("encode failed");
            let who = verify_encoded(algo, &encoded, &data)
                .unwrap_or_else(|e| panic!("{algo} failed verification: {e}"));
            assert!(who.starts_with("crush-lz"), "{algo} reported an odd verifier: {who}");
        }
    }

    /// Truncation is the cheapest damage that every decoder here should
    /// notice.
    #[test]
    fn verify_rejects_damaged_output() {
        let data = sample();
        for algo in [Algo::Lzfse, Algo::Lzvn, Algo::Lzbitmap, Algo::Lz4] {
            let encoded = crushlz::encode(algo, &data, 6).expect("encode failed");
            let damaged = &encoded[..encoded.len() * 3 / 4];
            assert!(
                verify_encoded(algo, damaged, &data).is_err(),
                "{algo} accepted a truncated stream"
            );
        }
    }

    /// On macOS `--verify` claims to consult Apple's decoder. If that claim is
    /// silently downgraded the message is the only place it shows, so pin it.
    #[cfg(target_os = "macos")]
    #[test]
    fn verify_consults_apple_where_it_is_available() {
        let data = sample();
        for algo in [Algo::Lzfse, Algo::Lzbitmap, Algo::Lz4] {
            let encoded = crushlz::encode(algo, &data, 6).expect("encode failed");
            let who = verify_encoded(algo, &encoded, &data).expect("verification failed");
            assert_eq!(who, "crush-lz + apple", "{algo} did not reach Apple's decoder");
        }
    }

    #[test]
    fn clap_definition_is_internally_valid() {
        // Catches conflicting shorts, duplicate names and bad defaults, which
        // otherwise only surface at runtime.
        Cli::command().debug_assert();
    }

    #[test]
    fn encode_defaults() {
        let cli = parse(&["encode", "in", "out"]).expect("should parse");
        match cli.command {
            Command::Encode { algo, level, threads, verify, force, .. } => {
                assert_eq!(algo, AlgoArg::Lzfse, "lzfse is the default algorithm");
                assert_eq!(level, None, "level defaults lazily, per algorithm");
                assert_eq!(threads, 0, "0 means one worker per core");
                assert!(!verify);
                assert!(!force);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn encode_accepts_every_flag() {
        let cli = parse(&[
            "encode", "in", "out", "--algo", "lzbitmap", "--level", "5",
            "--threads", "4", "--max-memory", "512", "--verify", "--force",
        ])
        .expect("should parse");
        match cli.command {
            Command::Encode { algo, level, threads, max_memory, verify, force, .. } => {
                assert_eq!(algo, AlgoArg::Lzbitmap);
                assert_eq!(level, Some(5));
                assert_eq!(threads, 4);
                assert_eq!(max_memory, 512);
                assert!(verify && force);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn negative_levels_parse() {
        // Both codecs have levels below zero, which is exactly the shape a
        // naive parser treats as an unknown flag.
        for spec in [["-l", "-1"], ["--level", "-1"]] {
            let cli = parse(&["encode", "in", "out", spec[0], spec[1]]).expect("should parse");
            match cli.command {
                Command::Encode { level, .. } => assert_eq!(level, Some(-1)),
                _ => panic!("wrong subcommand"),
            }
        }
    }

    #[test]
    fn short_flags_work() {
        let cli = parse(&["encode", "in", "out", "-l", "3", "-f", "-T", "2"]).expect("should parse");
        match cli.command {
            Command::Encode { level, force, threads, .. } => {
                assert_eq!(level, Some(3));
                assert!(force);
                assert_eq!(threads, 2);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn aliases_resolve() {
        assert!(matches!(parse(&["c", "a", "b"]).unwrap().command, Command::Encode { .. }));
        assert!(matches!(parse(&["d", "a", "b"]).unwrap().command, Command::Decode { .. }));
        assert!(matches!(parse(&["t", "a"]).unwrap().command, Command::Test { .. }));
    }

    #[test]
    fn stdio_placeholder_is_just_a_path() {
        let cli = parse(&["encode", "-", "-"]).expect("- must not be read as a flag");
        match cli.command {
            Command::Encode { input, output, .. } => {
                assert!(is_stdio(&input) && is_stdio(&output));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn bad_input_is_rejected() {
        assert!(parse(&["encode", "in"]).is_err(), "output is required");
        assert!(parse(&["encode"]).is_err(), "input is required");
        assert!(parse(&[]).is_err(), "a subcommand is required");
        assert!(parse(&["frobnicate", "in", "out"]).is_err(), "unknown subcommand");
        assert!(parse(&["encode", "in", "out", "--algo", "brotli"]).is_err(), "unknown algo");
        assert!(parse(&["encode", "in", "out", "--level", "x"]).is_err(), "non-numeric level");
        assert!(parse(&["limits", "extra"]).is_err(), "limits takes no arguments");
    }

    #[test]
    fn decode_algo_is_optional_and_defaults_to_detection() {
        // --algo on decode exists for raw LZVN, which carries no magic to
        // detect. Every other format still identifies itself, so omitting it
        // has to keep working.
        match parse(&["decode", "in", "out"]).unwrap().command {
            Command::Decode { algo, .. } => assert_eq!(algo, None, "decode detects by default"),
            other => panic!("expected Decode, got {other:?}"),
        }
        match parse(&["decode", "in", "out", "--algo", "lzvn"]).unwrap().command {
            Command::Decode { algo, .. } => assert_eq!(algo, Some(AlgoArg::Lzvn)),
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[test]
    fn lzvn_is_selectable_for_encoding() {
        match parse(&["encode", "in", "out", "--algo", "lzvn"]).unwrap().command {
            Command::Encode { algo, .. } => assert_eq!(algo, AlgoArg::Lzvn),
            other => panic!("expected Encode, got {other:?}"),
        }
    }
}
