// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! An LZBITMAP encoder and decoder for Apple's `COMPRESSION_LZBITMAP`, the
//! format behind decmpfs types 13 and 14.
//!
//! Any input size is accepted. Levels -1 to -5 trade ratio for throughput
//! below the default (0), -3 to -5 with the fast strategy, which searches only
//! where the period in force fails; levels 7 and up choose the period
//! sequence by dynamic programming. Levels outside
//! [`Level::MIN`]`..=`[`Level::MAX`] are clamped.
//!
//! No call site needs `unsafe`; every FFI call lives inside this crate.

mod chunk;
mod compress;
mod decompress;
mod error;
mod ffi;
mod params;
mod scratch;

pub use chunk::{CHUNK_SIZE, compress_chunk, compress_parallel};
pub use compress::{compress, compress_bound, compress_into, compress_into_with, compress_with};
pub use decompress::{decoded_len, decompress, decompress_into};
pub use error::Error;
pub use params::{Capabilities, Level, Params, capabilities};
pub use scratch::{Scratch, scratch_size};

#[cfg(test)]
mod tests {
    use super::*;

    const SIZES: [usize; 7] = [0, 1, 4095, 32767, 32768, 32769, 300_000];

    fn levels() -> impl Iterator<Item = Level> {
        (Level::MIN.0..=Level::MAX.0).map(Level)
    }

    /// Deterministic xorshift, so the crate needs no RNG dependency.
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut x: u32 = 0x2545_F491;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 0xff) as u8
            })
            .collect()
    }

    /// Semi-compressible: periodic runs with noise sprinkled in, so both
    /// stored and compressed chunks appear.
    fn mixed(len: usize) -> Vec<u8> {
        let noise = pseudo_random(len);
        (0..len).map(|i| if i % 11 == 0 { noise[i] } else { (i % 251) as u8 }).collect()
    }

    #[test]
    fn every_level_roundtrips_every_size() {
        for len in SIZES {
            let data = mixed(len);
            for level in levels() {
                let packed = compress(&data, level).unwrap_or_else(|e| panic!("len {len} level {level:?}: {e}"));
                assert_eq!(decompress(&packed).unwrap(), data, "len {len} level {level:?}: round-trip mismatch");
                assert!(packed.len() <= compress_bound(len), "len {len} level {level:?}: over the bound");
            }
        }
    }

    #[test]
    fn random_and_periodic_roundtrip() {
        for data in [pseudo_random(65536), (0..65536u32).map(|i| (i % 8) as u8).collect(), vec![0u8; 100_000]] {
            for level in [Level::MIN, Level(0), Level::DEFAULT, Level::MAX] {
                assert_eq!(decompress(&compress(&data, level).unwrap()).unwrap(), data);
            }
        }
    }

    #[test]
    fn compress_into_too_small_is_output_too_small() {
        let data = mixed(100_000);
        let mut scratch = Scratch::new();
        for len in [0usize, 1, 4, 100, 10_000] {
            let mut dst = vec![0u8; len];
            assert_eq!(
                compress_into(&mut dst, &data, Level::DEFAULT, &mut scratch).unwrap_err(),
                Error::OutputTooSmall { written: 0 },
                "dst of {len} bytes"
            );
            assert_eq!(
                compress_into_with(&mut dst, &data, &Params::row_default(), &mut scratch).unwrap_err(),
                Error::OutputTooSmall { written: 0 },
                "dst of {len} bytes"
            );
        }
        let mut dst = vec![0u8; compress_bound(data.len())];
        let n = compress_into(&mut dst, &data, Level::DEFAULT, &mut scratch).unwrap();
        assert_eq!(dst[..n], compress(&data, Level::DEFAULT).unwrap()[..]);
    }

    #[test]
    fn scratch_reuse_is_deterministic() {
        let data = mixed(70_000);
        let mut scratch = Scratch::new();
        let mut dst = vec![0u8; compress_bound(data.len())];
        for level in [Level::MAX, Level::MIN, Level::DEFAULT, Level::MAX, Level::MIN] {
            let n = compress_into(&mut dst, &data, level, &mut scratch).unwrap();
            assert_eq!(dst[..n], compress(&data, level).unwrap()[..], "level {level:?} differs after reuse");
        }
    }

    #[test]
    fn decompress_into_reports_sizes() {
        let data = mixed(50_000);
        let packed = compress(&data, Level::DEFAULT).unwrap();
        let mut exact = vec![0u8; data.len()];
        assert_eq!(decompress_into(&mut exact, &packed).unwrap(), data.len());
        assert_eq!(exact, data);
        // 50_000 bytes is two chunks (32_768 + 17_232); one byte short of
        // the true total falls entirely within the second chunk, so the
        // first (32_768 bytes) fully completes first.
        let mut short = vec![0u8; data.len() - 1];
        assert_eq!(
            decompress_into(&mut short, &packed).unwrap_err(),
            Error::OutputTooSmall { written: ffi::CRUSHLZBITMAP_CHUNK_SIZE }
        );
        let mut empty = [0u8; 0];
        assert_eq!(decompress_into(&mut empty, &compress(&[], Level::DEFAULT).unwrap()).unwrap(), 0);
    }

    #[test]
    fn decoded_len_matches_the_real_size_and_honors_a_cap() {
        let data = mixed(150_000);
        let packed = compress(&data, Level::DEFAULT).unwrap();
        assert_eq!(decoded_len(&packed, usize::MAX).unwrap(), data.len());
        assert_eq!(decoded_len(&packed, data.len()).unwrap(), data.len());
        // 150_000 bytes is five chunks (four full 32_768s, then 18_928);
        // one byte short of the true total falls entirely within the last,
        // so the first four (131_072 bytes) fully complete first.
        assert_eq!(
            decoded_len(&packed, data.len() - 1).unwrap_err(),
            Error::OutputTooSmall { written: 4 * ffi::CRUSHLZBITMAP_CHUNK_SIZE }
        );
        assert_eq!(decoded_len(&packed, 0).unwrap_err(), Error::OutputTooSmall { written: 0 });
        assert_eq!(decoded_len(&compress(&[], Level::DEFAULT).unwrap(), 0).unwrap(), 0);
    }

    #[test]
    fn try_zeroed_reports_an_impossible_allocation_instead_of_aborting() {
        assert_eq!(decompress::try_zeroed(usize::MAX / 2).unwrap_err(), Error::OutputTooSmall { written: 0 });
    }

    #[test]
    fn corrupted_input_is_invalid() {
        assert_eq!(decompress(b"not a real lzbitmap stream").unwrap_err(), Error::InvalidInput);
        assert_eq!(decompress(&[]).unwrap_err(), Error::InvalidInput);
        let data = mixed(80_000);
        let packed = compress(&data, Level::DEFAULT).unwrap();
        for cut in [1usize, 5, 13, packed.len() / 2, packed.len() - 1] {
            assert!(decompress(&packed[..cut]).is_err(), "truncated to {cut} bytes still decoded");
        }
        let mut bad = packed.clone();
        bad[0] ^= 0xff;
        assert_eq!(decompress(&bad).unwrap_err(), Error::InvalidInput);
    }

    #[test]
    fn parallel_matches_serial_at_every_level() {
        let data = mixed(300_000);
        for level in levels() {
            assert_eq!(
                compress_parallel(&data, level, 0).unwrap(),
                compress(&data, level).unwrap(),
                "level {level:?}: parallel output differs"
            );
        }
        for len in SIZES {
            let data = mixed(len);
            assert_eq!(compress_parallel(&data, Level::DEFAULT, 0).unwrap(), compress(&data, Level::DEFAULT).unwrap());
        }
        for threads in [1usize, 2, 3, 8] {
            let data = mixed(150_000);
            assert_eq!(
                compress_parallel(&data, Level::DEFAULT, threads).unwrap(),
                compress(&data, Level::DEFAULT).unwrap(),
                "threads {threads}: parallel output differs"
            );
        }
    }

    #[test]
    fn chunk_api_matches_whole_buffer_api() {
        let data = mixed(100_000);
        let (params, _) = Params::for_level(Level::DEFAULT);
        let mut scratch = Scratch::new();
        let n_chunks = data.len().div_ceil(CHUNK_SIZE) + 1;
        let mut manual = Vec::new();
        for index in 0..n_chunks {
            manual.extend_from_slice(&compress_chunk(&data, index, &params, &mut scratch).unwrap());
        }
        assert_eq!(manual, compress_with(&data, &params).unwrap());
        assert_eq!(decompress(&manual).unwrap(), data);
        assert_eq!(compress_chunk(&data, usize::MAX, &params, &mut scratch).unwrap_err(), Error::Encode);
    }

    #[test]
    fn params_defaults_match_levels() {
        let data = mixed(65536);
        assert_eq!(compress_with(&data, &Params::for_level(Level::DEFAULT).0).unwrap(), compress(&data, Level::DEFAULT).unwrap());
        assert!(matches!(Params::for_level(Level::MIN).0, Params::Fast { .. }));
        assert!(matches!(Params::for_level(Level(-3)).0, Params::Fast { windows: 8, .. }));
        assert!(matches!(Params::for_level(Level(-2)).0, Params::Row { .. }));
        assert!(matches!(Params::for_level(Level::DEFAULT).0, Params::Row { .. }));
        assert!(matches!(Params::for_level(Level::MAX).0, Params::Beam { lookahead: 1, .. }));
        assert!(matches!(Params::for_level(Level(0)).0, Params::Row { .. }));
        assert!(matches!(Params::for_level(Level(-1)).0, Params::Row { .. }));
        assert!(matches!(Params::for_level(Level(1)).0, Params::Row { lookahead: 1, .. }));
        assert!(matches!(Params::for_level(Level(6)).0, Params::Row { depth: 16, .. }));
    }

    #[test]
    fn invalid_beam_width_is_rejected_before_allocation() {
        for width in [0, -1, 3, 65, i32::MAX] {
            let mut p = Params::beam_default();
            if let Params::Beam { beam_width, .. } = &mut p { *beam_width = width; }
            assert_eq!(compress_with(b"test", &p).unwrap_err(), Error::InvalidParams);
        }
    }

    #[test]
    fn levels_clamp_and_report_what_was_used() {
        assert_eq!(Params::for_level(Level(i32::MIN)), Params::for_level(Level::MIN));
        assert_eq!(Params::for_level(Level(i32::MAX)), Params::for_level(Level::MAX));
        assert_eq!(Params::for_level(Level(Level::MIN.0 - 1)), Params::for_level(Level::MIN));
        assert_ne!(Params::for_level(Level(Level::MIN.0 + 1)), Params::for_level(Level::MIN));
        assert_ne!(Params::for_level(Level::MIN), Params::for_level(Level::MAX), "the level table is degenerate");
        assert_eq!(Params::for_level(Level(i32::MIN)).1, Level::MIN);
        assert_eq!(Params::for_level(Level(i32::MAX)).1, Level::MAX);
        // Every level in range resolves to and reports itself.
        for lv in Level::MIN.0..=Level::MAX.0 {
            assert_eq!(Params::for_level(Level(lv)).1, Level(lv));
        }
        let data = mixed(40_000);
        assert_eq!(compress(&data, Level(i32::MIN)).unwrap(), compress(&data, Level::MIN).unwrap());
        assert_eq!(compress(&data, Level(i32::MAX)).unwrap(), compress(&data, Level::MAX).unwrap());
    }

    #[test]
    fn custom_params_roundtrip() {
        let data = mixed(65536);
        let dp = match Params::for_level(Level(7)).0 {
            Params::Dp { hash_bits, depth, dist_cache_size, accept_diff, scan_window, lookahead, .. } => Params::Dp {
                hash_bits,
                depth,
                dist_cache_size,
                accept_diff,
                scan_window,
                lookahead,
                max_candidates: 4,
                iterations: 2,
            },
            other => panic!("Level 7 should be the DP strategy, got {other:?}"),
        };
        let row = |hash_bits, depth, dist_cache_size, accept_diff, scan_window, lookahead| Params::Row {
            hash_bits,
            depth,
            dist_cache_size,
            accept_diff,
            scan_window,
            lookahead,
        };
        let fast = |hash_bits, windows, dist_cache_size, accept_diff, skip_shift| Params::Fast {
            hash_bits,
            windows,
            dist_cache_size,
            accept_diff,
            skip_shift,
        };
        for params in [
            Params::dp_default(),
            Params::beam_default(),
            Params::row_default(),
            Params::fast_default(),
            fast(10, 1, 0, 0, 0),
            fast(16, 8, 2, 7, 11),
            fast(12, 2, 1, 3, 1),
            fast(14, 4, 2, 0, 4),
            dp,
            row(8, 1, 0, 0, 0, 0),
            row(16, 4, 4, 8, 32, 1),
            row(14, 1, 4, 2, 0, 0),
            row(16, 2, 4, 1, 16, 1),
            row(12, 2, 2, 3, 32, 0),
            row(15, 8, 8, 1, 64, 1),
            row(16, 4, 4, 8, 32, 0),
            row(14, 16, 8, 0, 256, 1),
        ] {
            let packed = compress_with(&data, &params).unwrap_or_else(|e| panic!("{params:?}: {e}"));
            assert_eq!(decompress(&packed).unwrap(), data, "{params:?}: round-trip mismatch");
        }
    }

    #[test]
    fn out_of_range_params_are_rejected() {
        let data = b"hello";
        let dp_with = |f: &dyn Fn(&mut Params)| {
            let mut p = Params::dp_default();
            f(&mut p);
            p
        };
        let row = |hash_bits, depth, dist_cache_size, accept_diff, scan_window, lookahead| Params::Row {
            hash_bits,
            depth,
            dist_cache_size,
            accept_diff,
            scan_window,
            lookahead,
        };
        let bad = [
            dp_with(&|p| if let Params::Dp { hash_bits, .. } = p { *hash_bits = 4 }),
            dp_with(&|p| if let Params::Dp { depth, .. } = p { *depth = 3 }),
            dp_with(&|p| if let Params::Dp { lookahead, .. } = p { *lookahead = 0 }),
            dp_with(&|p| if let Params::Dp { dist_cache_size, .. } = p { *dist_cache_size = -1 }),
            dp_with(&|p| if let Params::Dp { iterations, .. } = p { *iterations = 0 }),
            dp_with(&|p| if let Params::Dp { max_candidates, .. } = p { *max_candidates = 0 }),
            dp_with(&|p| if let Params::Dp { max_candidates, .. } = p {
                *max_candidates = ffi::CRUSHLZBITMAP_MAX_DP_CANDS + 1
            }),
            // Regression: crushlzbitmap_scratch_size does not itself bound
            // max_candidates (unlike its crushlzfse sibling), so before
            // Params::validate was added this reached scratch.reserve and
            // asked the allocator for tens of terabytes rather than being
            // rejected. This case must come back near-instantly with
            // InvalidParams, not hang or abort the process trying to
            // allocate.
            dp_with(&|p| if let Params::Dp { max_candidates, .. } = p { *max_candidates = i32::MAX }),
            row(ffi::CRUSHLZBITMAP_MIN_ROW_HASH_BITS - 1, 2, 4, 1, 0, 0),
            row(ffi::CRUSHLZBITMAP_MAX_ROW_HASH_BITS + 1, 2, 4, 1, 0, 0),
            row(16, 0, 4, 1, 0, 0),
            row(16, 3, 4, 1, 0, 0),
            row(16, ffi::CRUSHLZBITMAP_MAX_ROW_DEPTH + 1, 4, 1, 0, 0),
            row(16, 8, 4, 1, 0, 0),
            row(16, 2, -1, 1, 0, 0),
            row(16, 2, 9, 1, 0, 0),
            row(16, 2, 4, -1, 0, 0),
            row(16, 2, 4, 9, 0, 0),
            row(16, 2, 4, 1, 8, 0),
            row(16, 2, 4, 1, ffi::CRUSHLZBITMAP_MAX_ROW_SCAN + 16, 0),
            row(16, 2, 4, 1, 0, 2),
            row(16, 2, 8, 1, 0, 0),
            row(16, 2, 4, 1, 64, 0),
            Params::Fast { hash_bits: ffi::CRUSHLZBITMAP_MIN_FAST_HASH_BITS - 1, windows: 4, dist_cache_size: 2, accept_diff: 2, skip_shift: 4 },
            Params::Fast { hash_bits: ffi::CRUSHLZBITMAP_MAX_FAST_HASH_BITS + 1, windows: 4, dist_cache_size: 2, accept_diff: 2, skip_shift: 4 },
            Params::Fast { hash_bits: 16, windows: 0, dist_cache_size: 2, accept_diff: 2, skip_shift: 4 },
            Params::Fast { hash_bits: 16, windows: 3, dist_cache_size: 2, accept_diff: 2, skip_shift: 4 },
            Params::Fast { hash_bits: 16, windows: ffi::CRUSHLZBITMAP_MAX_FAST_WINDOWS * 2, dist_cache_size: 2, accept_diff: 2, skip_shift: 4 },
            Params::Fast { hash_bits: 16, windows: 4, dist_cache_size: -1, accept_diff: 2, skip_shift: 4 },
            Params::Fast { hash_bits: 16, windows: 4, dist_cache_size: ffi::CRUSHLZBITMAP_MAX_FAST_DIST_CACHE + 1, accept_diff: 2, skip_shift: 4 },
            Params::Fast { hash_bits: 16, windows: 4, dist_cache_size: 2, accept_diff: -1, skip_shift: 4 },
            Params::Fast { hash_bits: 16, windows: 4, dist_cache_size: 2, accept_diff: 8, skip_shift: 4 },
            Params::Fast { hash_bits: 16, windows: 4, dist_cache_size: 2, accept_diff: 2, skip_shift: -1 },
            Params::Fast { hash_bits: 16, windows: 4, dist_cache_size: 2, accept_diff: 2, skip_shift: ffi::CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT + 1 },
        ];
        let mut scratch = Scratch::new();
        for params in bad {
            assert_eq!(compress_with(data, &params).unwrap_err(), Error::InvalidParams, "{params:?} should be rejected");
            assert_eq!(compress_chunk(data, 0, &params, &mut scratch).unwrap_err(), Error::InvalidParams);
        }
    }

    #[test]
    fn error_display_and_level_default() {
        assert_eq!(Level::default(), Level::DEFAULT);
        assert!(Level::MIN < Level::DEFAULT && Level::DEFAULT < Level::MAX);
        for e in [Error::OutputTooSmall { written: 0 }, Error::InvalidInput, Error::InvalidParams, Error::Encode] {
            assert!(!e.to_string().is_empty());
        }
        fn assert_send<T: Send>() {}
        assert_send::<Scratch>();
    }
}
