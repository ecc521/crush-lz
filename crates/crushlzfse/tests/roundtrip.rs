// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Checks this crate's side of the FFI boundary for both codecs: slice
// lengths pass through, every level round-trips through our decoder at
// sizes on both sides of the block boundary, scratch reuse is byte-stable,
// and the C status codes map to the right Error.

/// Compressible but not trivial: words from a small vocabulary joined by
/// pseudo-random punctuation, so every level has real choices to make.
fn sample(n: usize) -> Vec<u8> {
    const WORDS: [&str; 12] = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo",
        "lima",
    ];
    let mut x: u32 = 0x2545_F491;
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out.extend_from_slice(WORDS[(x % 12) as usize].as_bytes());
        out.push(if x & 0x100 != 0 { b' ' } else { b',' });
        if x & 0x7000 == 0 {
            out.push((x >> 20) as u8);
        }
    }
    out.truncate(n);
    out
}

const SIZES: [usize; 7] = [0, 1, 4095, 65535, 65536, 65537, 300_000];

macro_rules! codec_tests {
    ($name:ident, $codec:path) => {
        mod $name {
            use super::{SIZES, sample};
            use $codec as c;
            use c::{Error, Level, Params, Scratch};

            fn levels() -> impl Iterator<Item = Level> {
                (Level::MIN.0..=Level::MAX.0).map(Level)
            }

            fn assert_roundtrip(packed: &[u8], original: &[u8], what: &str) {
                let back = c::decompress(packed).unwrap_or_else(|e| panic!("{what}: decompress failed: {e}"));
                assert!(back == original, "{what}: round-trip mismatch");
                let mut exact = vec![0u8; original.len()];
                let n = c::decompress_into(&mut exact, packed).expect("decompress_into");
                assert_eq!(n, original.len(), "{what}: decompress_into length");
                assert!(exact == original, "{what}: decompress_into mismatch");
            }

            #[test]
            fn decoder_accepts_disjoint_slices_of_one_allocation() {
                // Safe Rust may split one Vec into the compressed input and
                // output slices. Their byte ranges are adjacent but do not
                // overlap, even though C sees one allocation behind both.
                let data = sample(4096);
                let packed = c::compress(&data, Level::DEFAULT).expect("compress");
                let mut storage = vec![0xa5u8; packed.len() + data.len() + 1];
                let (src, dst_and_guard) = storage.split_at_mut(packed.len());
                src.copy_from_slice(&packed);
                let n = c::decompress_into(&mut dst_and_guard[..data.len()], src)
                    .expect("decompress_into shared allocation");
                assert_eq!(n, data.len());
                assert_eq!(&dst_and_guard[..n], data.as_slice());
                assert_eq!(dst_and_guard[data.len()], 0xa5, "destination guard");
                assert_eq!(src, packed.as_slice(), "source was modified");
            }

            #[test]
            fn every_level_roundtrips_every_size() {
                // Every level, whatever its strategy, is bounded to a
                // single fixed 64 KiB block per call, so the bound no longer
                // varies by strategy or level: MAX's bound is what this
                // shared dst needs across the whole level loop below, and
                // any level's would do equally.
                let (bound_params, _) = Params::for_level(Level::MAX);
                let mut scratch = Scratch::new();
                for &size in &SIZES {
                    let data = sample(size);
                    let mut dst = vec![0u8; c::compress_bound(size, &bound_params)];
                    for level in levels() {
                        if size > 65_536 {
                            // Every level accepts at most one 64 KiB piece
                            // per call; anything larger is a clear failure,
                            // never silent chunking or streaming.
                            assert_eq!(
                                c::compress_into(&mut dst, &data, level, &mut scratch),
                                Err(Error::InputTooLarge),
                                "level {level:?} size {size}: must reject >64 KiB input"
                            );
                            continue;
                        }
                        let n = c::compress_into(&mut dst, &data, level, &mut scratch)
                            .unwrap_or_else(|e| panic!("level {level:?} size {size}: {e}"));
                        assert_roundtrip(&dst[..n], &data, &format!("level {level:?} size {size}"));
                    }
                }
            }

            #[test]
            fn vec_variant_matches_into_variant() {
                let data = sample(65_536);
                // MAX's bound is never smaller than any other level's for
                // this size; see every_level_roundtrips_every_size.
                let (bound_params, _) = Params::for_level(Level::MAX);
                let mut scratch = Scratch::new();
                let mut dst = vec![0u8; c::compress_bound(data.len(), &bound_params)];
                for level in [Level::MIN, Level::DEFAULT, Level::MAX] {
                    let n = c::compress_into(&mut dst, &data, level, &mut scratch).expect("compress_into");
                    let owned = c::compress(&data, level).expect("compress");
                    assert_eq!(owned, &dst[..n], "level {level:?}");
                }
            }

            #[test]
            fn too_small_dst_is_output_too_small() {
                let data = sample(20_000);
                let mut scratch = Scratch::new();
                let mut tiny = [0u8; 8];
                assert_eq!(
                    c::compress_into(&mut tiny, &data, Level::DEFAULT, &mut scratch),
                    Err(Error::OutputTooSmall { written: 0 })
                );
                let mut empty = [0u8; 0];
                assert_eq!(
                    c::compress_into(&mut empty, &data, Level::MIN, &mut scratch),
                    Err(Error::OutputTooSmall { written: 0 })
                );
            }

            #[test]
            fn corrupted_input_is_invalid() {
                let data = sample(30_000);
                let packed = c::compress(&data, Level::DEFAULT).expect("compress");
                // Cut before the end-of-stream marker, so the decoder runs out
                // of input rather than reading a valid but shorter stream.
                let truncated = &packed[..packed.len() / 2];
                assert_eq!(c::decompress(truncated), Err(Error::InvalidInput));
                let mut sized = vec![0u8; data.len()];
                assert_eq!(c::decompress_into(&mut sized, truncated), Err(Error::InvalidInput));
            }

            #[test]
            fn decompress_into_reports_short_buffer() {
                let data = sample(30_000);
                let packed = c::compress(&data, Level::DEFAULT).expect("compress");
                let mut short = vec![0u8; data.len() / 2];
                // Not a fixed expected count: how far the decoder gets
                // before running out of room depends on the codec's own
                // internal block structure. What must hold regardless: the
                // reported prefix is genuinely correct output, not garbage.
                match c::decompress_into(&mut short, &packed) {
                    Err(Error::OutputTooSmall { written }) => {
                        assert!(written <= short.len(), "reported more written than the buffer could hold");
                        assert_eq!(
                            short[..written],
                            data[..written],
                            "the reported prefix must be genuinely correct output"
                        );
                    }
                    other => panic!("expected OutputTooSmall, got {other:?}"),
                }
            }

            #[test]
            fn params_for_default_level_roundtrips() {
                let data = sample(65_536);
                let (params, _) = Params::for_level(Level::DEFAULT);
                let via_params = c::compress_with(&data, &params).expect("compress_with");
                let via_level = c::compress(&data, Level::DEFAULT).expect("compress");
                assert_eq!(via_params, via_level, "a level and its own Params must encode identically");
                assert_roundtrip(&via_params, &data, "Params::for_level(DEFAULT)");
                for level in levels() {
                    let a = c::compress(&data, level).expect("compress");
                    let b = c::compress_with(&data, &Params::for_level(level).0).expect("compress_with");
                    assert_eq!(a, b, "level {level:?} differs from its own Params");
                }
            }

            #[test]
            fn higher_levels_never_grow_output() {
                // Consecutive levels are not monotonic on every input (the
                // switch between strategies can lose on some data), but the
                // named anchors are ordered on anything compressible that
                // fits in one block.
                let data = sample(65_536);
                let size = |level| c::compress(&data, level).expect("compress").len();
                let (min, zero, dflt, max) =
                    (size(Level::MIN), size(Level(0)), size(Level::DEFAULT), size(Level::MAX));
                assert!(zero <= min, "level 0 ({zero}) larger than MIN ({min})");
                assert!(dflt <= zero, "DEFAULT ({dflt}) larger than level 0 ({zero})");
                assert!(max <= dflt, "MAX ({max}) larger than DEFAULT ({dflt})");
                assert!(max < data.len() / 2, "MAX ({max}) barely compressed a compressible sample");
            }

            #[test]
            fn scratch_reuse_gives_identical_bytes() {
                let data = sample(65_536);
                // MAX's bound is never smaller than any other level's for
                // this size; see every_level_roundtrips_every_size.
                let (bound_params, _) = Params::for_level(Level::MAX);
                let mut reused = Scratch::new();
                let mut a = vec![0u8; c::compress_bound(data.len(), &bound_params)];
                let mut b = a.clone();
                // Grow it at the top level first, then reuse it lower down.
                let top = c::compress_into(&mut a, &data, Level::MAX, &mut reused).expect("first");
                let again = c::compress_into(&mut b, &data, Level::MAX, &mut reused).expect("second");
                assert_eq!(&a[..top], &b[..again], "same scratch, same input, different bytes");
                for level in [Level::MIN, Level::DEFAULT] {
                    let n = c::compress_into(&mut a, &data, level, &mut reused).expect("reused");
                    let m = c::compress_into(&mut b, &data, level, &mut Scratch::new()).expect("fresh");
                    assert_eq!(&a[..n], &b[..m], "level {level:?}: reused scratch differs from a fresh one");
                }
            }

            #[test]
            fn capabilities_agree_with_levels() {
                let caps = c::capabilities();
                assert_eq!(caps.level_min, Level::MIN.0);
                assert_eq!(caps.level_max, Level::MAX.0);
                assert!(!matches!(Params::for_level(Level::MIN).0, Params::Optimal { .. }));
                assert!(matches!(Params::for_level(Level::MAX).0, Params::Optimal { .. }));
            }

            #[test]
            fn out_of_range_levels_are_clamped() {
                let data = sample(10_000);
                let lo = c::compress(&data, Level(Level::MIN.0 - 100)).expect("below MIN");
                let hi = c::compress(&data, Level(Level::MAX.0 + 100)).expect("above MAX");
                assert_eq!(lo, c::compress(&data, Level::MIN).expect("MIN"));
                assert_eq!(hi, c::compress(&data, Level::MAX).expect("MAX"));
                assert_eq!(Level::default(), Level::DEFAULT);
                // for_level reports what it actually clamped to.
                assert_eq!(Params::for_level(Level(Level::MIN.0 - 100)).1, Level::MIN);
                assert_eq!(Params::for_level(Level(Level::MAX.0 + 100)).1, Level::MAX);
            }

            #[test]
            fn scratch_size_matches_growth() {
                let (params, _) = Params::for_level(Level::MAX);
                assert!(c::scratch_size(&params) > 0);
                assert!(c::compress_bound(0, &params) > 0);
                assert!(c::compress_bound(300_000, &params) > 300_000);
            }
        }
    };
}

codec_tests!(lzfse, crushlzfse);
codec_tests!(lzvn, crushlzfse::lzvn);

#[test]
fn lzfse_out_of_range_params_are_rejected() {
    use crushlzfse::{Error, Level, Params};
    let caps = crushlzfse::capabilities();
    let Params::Optimal { search_depth, .. } = Params::for_level(Level::MAX).0 else { panic!("MAX should be optimal") };
    assert!(search_depth <= caps.search_depth.1);
    let mut bad = Params::for_level(Level::MAX).0;
    if let Params::Optimal { search_depth, .. } = &mut bad {
        *search_depth = caps.search_depth.1 + 1;
    }
    assert_eq!(crushlzfse::compress_with(b"abc", &bad), Err(Error::InvalidParams));
    let mut bad = Params::for_level(Level::DEFAULT).0;
    let Params::Lazy { hash_bits, .. } = &mut bad else { panic!("DEFAULT should be lazy") };
    *hash_bits = caps.lazy_hash_bits.0 - 1;
    assert_eq!(crushlzfse::compress_with(b"abc", &bad), Err(Error::InvalidParams));
    let fast = Params::for_level(Level::MIN).0;
    let Params::Fast { .. } = fast else { panic!("MIN should be fast") };
    for edit in [
        (|p: &mut Params| if let Params::Fast { hash_bits, .. } = p { *hash_bits = 9 }) as fn(&mut Params),
        |p| if let Params::Fast { hash_bits, .. } = p { *hash_bits = 17 },
        |p| if let Params::Fast { min_match, .. } = p { *min_match = 3 },
        |p| if let Params::Fast { min_match, .. } = p { *min_match = 9 },
        |p| if let Params::Fast { skip_shift, .. } = p { *skip_shift = 0 },
        |p| if let Params::Fast { max_step, .. } = p { *max_step = 0 },
        |p| if let Params::Fast { max_step, .. } = p { *max_step = 65 },
    ] {
        let mut bad = fast;
        edit(&mut bad);
        assert_eq!(crushlzfse::compress_with(b"abc", &bad), Err(Error::InvalidParams), "{bad:?}");
    }
    // Every valid mode combination encodes and round-trips; long_table and
    // lazy cap min_match at 6.
    let data = sample(30_000);
    for long_table in [false, true] {
        for lazy in [false, true] {
            for min_match in caps.fast_min_match.0..=caps.fast_min_match.1 {
                let p = Params::Fast { hash_bits: 12, min_match, skip_shift: 4, max_step: 8, long_table, lazy };
                if (long_table || lazy) && min_match > 6 {
                    assert_eq!(crushlzfse::compress_with(&data, &p), Err(Error::InvalidParams), "{p:?}");
                    continue;
                }
                let packed = crushlzfse::compress_with(&data, &p).expect("fast params");
                assert_eq!(crushlzfse::decompress(&packed).expect("decode"), data, "{p:?}");
            }
        }
    }
}

#[test]
fn lzfse_chained_matches_unchained_from_empty_stats() {
    use crushlzfse::{Level, Params, Scratch, Stats};
    let data = sample(65_536);
    let mut scratch = Scratch::new();
    for level in Level::MIN.0..=Level::MAX.0 {
        let params = Params::for_level(Level(level)).0;
        let mut a = vec![0u8; crushlzfse::compress_bound(data.len(), &params)];
        let mut b = a.clone();
        let n = crushlzfse::compress_into_with(&mut a, &data, &params, &mut scratch).expect("unchained");
        let mut stats = Stats::default();
        let m = crushlzfse::compress_into_chained(&mut b, &data, &params, &mut scratch, &mut stats).expect("chained");
        assert_eq!(&a[..n], &b[..m], "level {level}: empty stats changed the output");
        assert!(format!("{stats:?}").contains("seeded: true"), "level {level}: stats not written");
    }
}

#[test]
fn lzfse_chain_roundtrips_and_resets_on_error() {
    use crushlzfse::{Error, Level, Params, Scratch, Stats};
    let data = sample(5 * 65_536 + 1234);
    let mut scratch = Scratch::new();
    for level in Level::MIN.0..=Level::MAX.0 {
        let params = Params::for_level(Level(level)).0;
        let mut dst = vec![0u8; crushlzfse::compress_bound(65_536, &params)];
        let mut stats = Stats::default();
        for chunk in data.chunks(65_536) {
            let n = crushlzfse::compress_into_chained(&mut dst, chunk, &params, &mut scratch, &mut stats).expect("chained");
            assert_eq!(crushlzfse::decompress(&dst[..n]).expect("decode"), chunk, "level {level}");
        }
        assert_eq!(
            crushlzfse::compress_into_chained(&mut dst, &data, &params, &mut scratch, &mut stats),
            Err(Error::InputTooLarge)
        );
        assert!(format!("{stats:?}").contains("seeded: false"), "level {level}: stats kept after an error");
    }
}

/// One chain per `seg` chunks, encoded by hand.
fn chain_by_hand(data: &[u8], params: &crushlzfse::Params, seg: usize) -> Vec<Vec<u8>> {
    let mut scratch = crushlzfse::Scratch::new();
    let mut dst = vec![0u8; crushlzfse::compress_bound(65_536, params)];
    let mut out = Vec::new();
    for segment in data.chunks(seg * 65_536) {
        let mut stats = crushlzfse::Stats::default();
        for chunk in segment.chunks(65_536) {
            let n = crushlzfse::compress_into_chained(&mut dst, chunk, params, &mut scratch, &mut stats).expect("chained");
            out.push(dst[..n].to_vec());
        }
    }
    out
}

#[test]
fn lzfse_compress_chunks_segments_and_threads() {
    use crushlzfse::{Level, Params, compress_chunks};
    let data = sample(19 * 65_536 + 777);
    let params = Params::for_level(Level(6)).0;
    let whole = chain_by_hand(&data, &params, usize::MAX / 65_536);
    let by_default = chain_by_hand(&data, &params, crushlzfse::DEFAULT_SEGMENT_SIZE / 65_536);

    // One thread is one chain; any other count uses the default segment.
    assert_eq!(compress_chunks(&data, &params, 1, None).unwrap(), whole);
    for threads in [0, 2, 3, 7, 64] {
        assert_eq!(compress_chunks(&data, &params, threads, None).unwrap(), by_default, "threads {threads}");
    }
    // An explicit segment holds at every thread count; 0 is one chain.
    assert_eq!(compress_chunks(&data, &params, 1, Some(crushlzfse::DEFAULT_SEGMENT_SIZE)).unwrap(), by_default);
    assert_eq!(compress_chunks(&data, &params, 5, Some(0)).unwrap(), whole);
    // Rounded down to whole chunks, never below one.
    assert_eq!(compress_chunks(&data, &params, 4, Some(3 * 65_536 + 5)).unwrap(), chain_by_hand(&data, &params, 3));
    assert_eq!(compress_chunks(&data, &params, 4, Some(1)).unwrap(), chain_by_hand(&data, &params, 1));

    assert_eq!(whole.len(), data.chunks(65_536).count());
    for (out, chunk) in whole.iter().zip(data.chunks(65_536)) {
        assert_eq!(crushlzfse::decompress(out).expect("decode"), chunk);
    }
    assert!(compress_chunks(&[], &params, 0, None).unwrap().is_empty());
}

#[test]
fn lzfse_compress_chunks_every_level_roundtrips() {
    use crushlzfse::{Level, Params, compress_chunks};
    let data = sample(3 * 65_536 + 100);
    for level in Level::MIN.0..=Level::MAX.0 {
        let params = Params::for_level(Level(level)).0;
        let out = compress_chunks(&data, &params, 2, Some(2 * 65_536)).expect("compress_chunks");
        let back: Vec<u8> = out.iter().flat_map(|c| crushlzfse::decompress(c).expect("decode")).collect();
        assert_eq!(back, data, "level {level}");
    }
}

#[test]
fn lzvn_out_of_range_params_are_rejected() {
    use crushlzfse::lzvn::{self, Error, Level, Params};
    let caps = lzvn::capabilities();
    let mut bad = Params::for_level(Level::MAX).0;
    if let Params::Optimal { pareto_k, .. } = &mut bad {
        *pareto_k = caps.pareto_k.1 + 1;
    }
    assert_eq!(lzvn::compress_with(b"abc", &bad), Err(Error::InvalidParams));
    let mut bad = Params::for_level(Level::DEFAULT).0;
    let Params::Greedy { hash_width, .. } = &mut bad else { panic!("DEFAULT should be greedy") };
    *hash_width = 0;
    assert_eq!(lzvn::compress_with(b"abc", &bad), Err(Error::InvalidParams));
    let mut bad = Params::for_level(Level::MIN).0;
    let Params::Fast { min_match, lazy, .. } = &mut bad else { panic!("MIN should be fast") };
    *lazy = true;
    *min_match = caps.fast_min_match.1;
    assert_eq!(lzvn::compress_with(b"abc", &bad), Err(Error::InvalidParams));
}

#[test]
fn lzvn_output_has_no_lzfse_magic() {
    let data = sample(9_000);
    let packed = crushlzfse::lzvn::compress(&data, crushlzfse::lzvn::Level::DEFAULT).expect("compress");
    assert_ne!(&packed[..3], b"bvx", "raw LZVN must not carry LZFSE framing");
    let framed = crushlzfse::compress(&data, crushlzfse::Level::DEFAULT).expect("compress");
    assert_eq!(&framed[..3], b"bvx", "LZFSE output starts with its magic");
}

#[test]
fn error_is_a_std_error() {
    fn takes(_: &dyn std::error::Error) {}
    takes(&crushlzfse::Error::InvalidInput);
    assert_eq!(crushlzfse::Error::OutputTooSmall { written: 0 }.to_string(), "output buffer too small");
    // One Error type serves both codecs.
    let e: crushlzfse::lzvn::Error = crushlzfse::Error::Encode;
    assert_eq!(e, crushlzfse::Error::Encode);
}
