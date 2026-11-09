// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

//! One interface over the LZFSE, LZVN, LZBITMAP and LZ4 encoders and
//! decoders in this workspace, and the library behind the `crushlz` CLI.
//!
//! [`encode`] takes the algorithm explicitly, since the choice is usually
//! forced by what will read the result; [`decode`] identifies LZFSE, LZBITMAP
//! and LZ4 from their magic, and [`decode_as`] handles raw LZVN, which has
//! none. Every level of LZFSE and LZVN, greedy or optimal-parse, accepts at
//! most one already-independent 64 KiB piece per call (decmpfs's own chunk
//! size) and fails on anything larger; LZBITMAP and LZ4 are the only
//! algorithms that chunk arbitrarily large input internally, and LZBITMAP's
//! chunks can run on several threads with [`encode_with_threads`].

use std::fmt;

#[cfg(target_os = "macos")]
pub mod apple;

const LZFSE_MAGIC_PREFIX: &[u8] = b"bvx";
const LZBITMAP_MAGIC: &[u8] = b"ZBM\x09";
const LZ4_MAGIC_COMPRESSED: &[u8] = b"bv41";
const LZ4_MAGIC_STORED: &[u8] = b"bv4-";
const LZ4_MAGIC_END: &[u8] = b"bv4$";

/// A compression format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    /// LZFSE, decmpfs types 11 and 12. Small inputs may come back as an LZVN
    /// block inside the LZFSE stream, as Apple's encoder does.
    Lzfse,
    /// Raw LZVN, decmpfs types 7 and 8. Carries no magic.
    Lzvn,
    /// LZBITMAP, decmpfs types 13 and 14.
    Lzbitmap,
    /// LZ4 in Apple's frame, decmpfs types 15 and 16.
    Lz4,
    /// LZMESH, Apple algorithm enum 0xE05.
    Lzmesh,
}

impl Algo {
    /// The lowest and highest level this algorithm accepts.
    pub fn level_range(self) -> (i32, i32) {
        match self {
            Algo::Lzfse => (crushlzfse::Level::MIN.0, crushlzfse::Level::MAX.0),
            Algo::Lzvn => (crushlzfse::lzvn::Level::MIN.0, crushlzfse::lzvn::Level::MAX.0),
            Algo::Lzbitmap => (lzbitmap::Level::MIN.0, lzbitmap::Level::MAX.0),
            Algo::Lz4 => (crushlz4::Level::MIN.0, crushlz4::Level::MAX.0),
            Algo::Lzmesh => (lzmesh::Level::MIN.0, lzmesh::Level::MAX.0),
        }
    }

    /// The level used when none is given.
    pub fn default_level(self) -> i32 {
        match self {
            Algo::Lzfse => crushlzfse::Level::DEFAULT.0,
            Algo::Lzvn => crushlzfse::lzvn::Level::DEFAULT.0,
            Algo::Lzbitmap => lzbitmap::Level::DEFAULT.0,
            Algo::Lz4 => crushlz4::Level::DEFAULT.0,
            Algo::Lzmesh => lzmesh::Level::DEFAULT.0,
        }
    }

    /// Whether a stream of this format can be recognised by [`detect`].
    pub fn is_self_describing(self) -> bool {
        !matches!(self, Algo::Lzvn | Algo::Lzmesh)
    }
}

impl fmt::Display for Algo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Algo::Lzfse => "lzfse",
            Algo::Lzvn => "lzvn",
            Algo::Lzbitmap => "lzbitmap",
            Algo::Lz4 => "lz4",
            Algo::Lzmesh => "lzmesh",
        })
    }
}

/// What can go wrong.
#[derive(Debug)]
pub enum Error {
    /// The stream starts with no magic this crate knows.
    UnknownFormat,
    /// The level is outside the algorithm's range.
    LevelOutOfRange { algo: Algo, level: i32, min: i32, max: i32 },
    /// The encoder failed; the message is the codec crate's.
    Encode(String),
    /// The decoder rejected the stream; the message is the codec crate's.
    Decode(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownFormat => write!(
                f,
                "unrecognized format (expected an LZFSE 'bvx', LZBITMAP 'ZBM', \
                 or LZ4 'bv41'/'bv4-' magic; if this is raw LZVN or LZMESH, pass --algo)"
            ),
            Error::LevelOutOfRange { algo, level, min, max } => {
                write!(f, "{algo}: level {level} is outside {min}..={max}")
            }
            Error::Encode(m) => write!(f, "encode failed: {m}"),
            Error::Decode(m) => write!(f, "decode failed: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Identifies a stream from its magic. Raw LZVN and LZMESH have none and return `None`.
pub fn detect(src: &[u8]) -> Option<Algo> {
    if src.starts_with(LZBITMAP_MAGIC) {
        Some(Algo::Lzbitmap)
    } else if src.starts_with(LZ4_MAGIC_COMPRESSED)
        || src.starts_with(LZ4_MAGIC_STORED)
        || src.starts_with(LZ4_MAGIC_END)
    {
        Some(Algo::Lz4)
    } else if src.starts_with(LZFSE_MAGIC_PREFIX) {
        Some(Algo::Lzfse)
    } else {
        None
    }
}

/// Compresses `src` with one algorithm at one level, on one thread.
pub fn encode(algo: Algo, src: &[u8], level: i32) -> Result<Vec<u8>, Error> {
    encode_with_threads(algo, src, level, 1)
}

/// Like [`encode`]. `threads` (0 means one per core) only matters for
/// [`Algo::Lzbitmap`], the only algorithm with independent chunks left to
/// parallelize: every LZFSE/LZVN level, greedy or optimal-parse, always runs
/// single-shot on one thread (bounded to one 64 KiB piece, so there is
/// nothing to split). The output does not depend on the thread count.
pub fn encode_with_threads(algo: Algo, src: &[u8], level: i32, threads: usize) -> Result<Vec<u8>, Error> {
    let (min, max) = algo.level_range();
    if level < min || level > max {
        return Err(Error::LevelOutOfRange { algo, level, min, max });
    }
    let enc = |m: &dyn fmt::Display| Error::Encode(m.to_string());
    match algo {
        Algo::Lzfse => {
            let params = crushlzfse::Params::for_level(crushlzfse::Level(level)).0;
            crushlzfse::compress_with(src, &params).map_err(|e| enc(&e))
        }
        Algo::Lzvn => {
            let params = crushlzfse::lzvn::Params::for_level(crushlzfse::lzvn::Level(level)).0;
            crushlzfse::lzvn::compress_with(src, &params).map_err(|e| enc(&e))
        }
        Algo::Lzbitmap => {
            let level = lzbitmap::Level(level);
            if threads == 1 {
                lzbitmap::compress(src, level).map_err(|e| enc(&e))
            } else {
                lzbitmap::compress_parallel(src, level, threads).map_err(|e| enc(&e))
            }
        }
        Algo::Lz4 => crushlz4::compress(src, crushlz4::Level(level)).map_err(|e| enc(&e)),
        Algo::Lzmesh => lzmesh::compress(src, lzmesh::Level(level)).map_err(|e| enc(&e)),
    }
}

/// Bytes of encoder scratch an `encode_with_threads` call will hold at once.
pub fn encode_memory_estimate(algo: Algo, level: i32, threads: usize) -> usize {
    match algo {
        // Every level runs single-shot single-threaded, so its scratch is a
        // fixed size for the level with no worker multiply: there is no
        // chunking left to parallelize.
        Algo::Lzfse => {
            let params = crushlzfse::Params::for_level(crushlzfse::Level(level)).0;
            crushlzfse::scratch_size(&params)
        }
        Algo::Lzvn => {
            let params = crushlzfse::lzvn::Params::for_level(crushlzfse::lzvn::Level(level)).0;
            crushlzfse::lzvn::scratch_size(&params)
        }
        // Sized for the level in hand, like the other three: the row levels
        // take a flat 1.07 MiB where the DP levels add candidate tables on
        // top, so the top of the ladder over-reports by a third. LZBITMAP's
        // own chunking is the one case `threads` still multiplies.
        Algo::Lzbitmap => {
            let workers = if threads == 0 { num_cpus_or(1) } else { threads };
            let (params, _) = lzbitmap::Params::for_level(lzbitmap::Level(level));
            lzbitmap::scratch_size(&params).saturating_mul(workers)
        }
        // Single-threaded here, so no per-worker multiply. Scratch is a step
        // at the mode boundary rather than a slope: the FAST levels (-2..0)
        // want upstream's 16 KiB hash table and the HC levels a 256 KiB
        // chain, with nothing in between and no growth inside either.
        Algo::Lz4 => {
            let (params, _) = crushlz4::Params::for_level(crushlz4::Level(level));
            crushlz4::scratch_size(&params)
        }
        Algo::Lzmesh => {
            let params = lzmesh::Params::for_level(lzmesh::Level(level));
            lzmesh::scratch_size(&params)
        }
    }
}

fn num_cpus_or(fallback: usize) -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(fallback)
}

/// Decompresses a stream whose format [`detect`] can identify.
pub fn decode(src: &[u8]) -> Result<Vec<u8>, Error> {
    decode_as(detect(src).ok_or(Error::UnknownFormat)?, src)
}

/// Decompresses a stream of a known format; the only way to decode raw LZVN.
pub fn decode_as(algo: Algo, src: &[u8]) -> Result<Vec<u8>, Error> {
    let dec = |m: &dyn fmt::Display| Error::Decode(m.to_string());
    match algo {
        Algo::Lzfse => crushlzfse::decompress(src).map_err(|e| dec(&e)),
        Algo::Lzvn => crushlzfse::lzvn::decompress(src).map_err(|e| dec(&e)),
        Algo::Lzbitmap => lzbitmap::decompress(src).map_err(|e| dec(&e)),
        Algo::Lz4 => crushlz4::decompress(src).map_err(|e| dec(&e)),
        Algo::Lzmesh => lzmesh::decompress(src).map_err(|e| dec(&e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i / 7) ^ (i * 31)) as u8).collect()
    }

    #[test]
    fn any_size_is_accepted_at_every_level() {
        // Lzfse/Lzvn accept only one <=65536-byte piece per call, greedy or
        // optimal-parse alike; Lzbitmap and Lz4 chunk arbitrarily large
        // input internally and are unaffected.
        let small = sample(65_536);
        let large = sample(65_536 * 3 + 1);
        for algo in [Algo::Lzfse, Algo::Lzvn, Algo::Lzbitmap, Algo::Lz4, Algo::Lzmesh] {
            let (min, max) = algo.level_range();
            for level in [min, 0, max] {
                let enc = encode(algo, &small, level).unwrap_or_else(|e| panic!("{algo} level {level}: {e}"));
                assert_eq!(decode_as(algo, &enc).unwrap(), small, "{algo} level {level}");
            }
        }
        for algo in [Algo::Lzbitmap, Algo::Lz4, Algo::Lzmesh] {
            let (min, max) = algo.level_range();
            for level in [min, 0, max] {
                let enc = encode(algo, &large, level)
                    .unwrap_or_else(|e| panic!("{algo} level {level} (large): {e}"));
                assert_eq!(decode_as(algo, &enc).unwrap(), large, "{algo} level {level} (large)");
            }
        }
        for algo in [Algo::Lzfse, Algo::Lzvn] {
            let (min, max) = algo.level_range();
            // Every level of each is now bounded to one 64 KiB piece per
            // call; oversized input must error rather than silently chunk
            // or stream, whether the level is greedy or optimal-parse.
            for level in [min, 0, max] {
                assert!(encode(algo, &large, level).is_err(), "{algo} level {level} accepted oversized input");
            }
        }
    }

    #[test]
    fn roundtrip_every_algo() {
        for algo in [Algo::Lzfse, Algo::Lzvn, Algo::Lzbitmap, Algo::Lz4, Algo::Lzmesh] {
            // Lzfse/Lzvn now reject anything over 65536 bytes at every
            // level, so only Lzbitmap, Lz4 and Lzmesh, which chunk arbitrarily
            // large input internally, are exercised past that size here.
            let lens: &[usize] = match algo {
                Algo::Lzfse | Algo::Lzvn => &[0, 1, 1000, 65536],
                Algo::Lzbitmap | Algo::Lz4 | Algo::Lzmesh => &[0, 1, 1000, 65536, 65537, 300_000],
            };
            for &len in lens {
                let data = sample(len);
                let enc = encode(algo, &data, algo.default_level())
                    .unwrap_or_else(|e| panic!("{algo} encode len {len}: {e}"));
                let dec = decode_as(algo, &enc).unwrap_or_else(|e| panic!("{algo} decode len {len}: {e}"));
                assert_eq!(dec, data, "{algo} roundtrip failed at len {len}");
            }
        }
    }

    #[test]
    fn detect_recognizes_what_we_emit() {
        for algo in [Algo::Lzfse, Algo::Lzbitmap, Algo::Lz4] {
            let enc = encode(algo, &sample(4096), algo.default_level()).unwrap();
            assert_eq!(detect(&enc), Some(algo));
        }
        assert_eq!(detect(b"not a codec stream"), None);
        assert_eq!(detect(b""), None);
    }

    #[test]
    fn level_out_of_range_is_rejected() {
        let e = encode(Algo::Lzfse, &sample(64), 999);
        assert!(matches!(e, Err(Error::LevelOutOfRange { .. })));
    }

    #[test]
    fn thread_count_does_not_change_the_output() {
        // Lzbitmap is the only algorithm left with independent chunks to
        // parallelize; every LZFSE/LZVN level always runs single-shot.
        let data = sample(700_000);
        let level = 6;
        let single = encode_with_threads(Algo::Lzbitmap, &data, level, 1).unwrap();
        for threads in [2, 4, 0] {
            let many = encode_with_threads(Algo::Lzbitmap, &data, level, threads).unwrap();
            assert_eq!(many, single, "lzbitmap: output differed at {threads} threads");
            assert_eq!(decode_as(Algo::Lzbitmap, &many).unwrap(), data);
        }
    }

    #[test]
    fn memory_estimate_scales_with_threads() {
        let one = encode_memory_estimate(Algo::Lzfse, 8, 1);
        assert!(one > 1 << 20, "a real scratch figure, not zero: {one}");
        // LZFSE/LZVN never chunk at any level, so threads never multiply
        // their scratch.
        assert_eq!(encode_memory_estimate(Algo::Lzfse, 8, 4), one);

        let lzbitmap_one = encode_memory_estimate(Algo::Lzbitmap, 6, 1);
        assert!(lzbitmap_one > 1 << 20, "a real scratch figure, not zero: {lzbitmap_one}");
        assert_eq!(encode_memory_estimate(Algo::Lzbitmap, 6, 4), lzbitmap_one * 4);

        // LZ4's figure is per level, not a flat ladder maximum, but it is a
        // step and not a slope: every FAST level reports upstream's 16 KiB
        // hash table and every HC level its 256 KiB chain.
        let lz4_default = encode_memory_estimate(Algo::Lz4, 0, 1);
        let lz4_max = encode_memory_estimate(Algo::Lz4, 10, 1);
        assert!(lz4_default >= 1 << 14, "a real scratch figure, not zero: {lz4_default}");
        assert!(lz4_max > lz4_default * 4, "{lz4_max} vs {lz4_default}");
        assert_eq!(encode_memory_estimate(Algo::Lz4, -2, 1), lz4_default);
        assert_eq!(encode_memory_estimate(Algo::Lz4, 1, 1), lz4_max);
    }
}
