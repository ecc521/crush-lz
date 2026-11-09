// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Hand-written declarations mirroring crushlzfse.h and crushlzvn.h. The
// surface is small enough that bindgen would cost more than it saves. The
// structs here are `#[repr(C)]` mirrors of the C ones; `abi_tests` below
// checks their size and field offsets against what the C compiler actually
// laid out, because a silent mismatch in a tag+union struct is a memory
// safety bug, not a compile error.

use std::os::raw::{c_int, c_void};

pub(crate) const CRUSHLZFSE_LEVEL_MIN: c_int = -5;
pub(crate) const CRUSHLZFSE_LEVEL_MAX: c_int = 11;
pub(crate) const CRUSHLZFSE_LEVEL_DEFAULT: c_int = 0;
pub(crate) const CRUSHLZFSE_INVALID: c_int = -1;
pub(crate) const CRUSHLZFSE_OUTPUT_TOO_SMALL: c_int = -2;
pub(crate) const CRUSHLZFSE_STRATEGY_LAZY: c_int = 0;
pub(crate) const CRUSHLZFSE_STRATEGY_OPTIMAL: c_int = 1;
pub(crate) const CRUSHLZFSE_STRATEGY_FAST: c_int = 2;
pub(crate) const CRUSHLZFSE_STATS_WORDS: usize = 105;

pub(crate) const CRUSHLZVN_LEVEL_MIN: c_int = -5;
pub(crate) const CRUSHLZVN_LEVEL_MAX: c_int = 10;
pub(crate) const CRUSHLZVN_LEVEL_DEFAULT: c_int = 0;
pub(crate) const CRUSHLZVN_INVALID: c_int = -1;
pub(crate) const CRUSHLZVN_OUTPUT_TOO_SMALL: c_int = -2;
pub(crate) const CRUSHLZVN_STRATEGY_GREEDY: c_int = 0;
pub(crate) const CRUSHLZVN_STRATEGY_OPTIMAL: c_int = 1;
pub(crate) const CRUSHLZVN_STRATEGY_FAST: c_int = 2;

// --- crushlzfse.h -----------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LazyParams {
    pub hash_bits: c_int,
    pub hash_width: c_int,
    pub lookahead: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OptimalParams {
    pub search_depth: c_int,
    pub iterations: c_int,
    pub enable_reparse: c_int,
    pub split_max_blocks: i32,
    pub hash_bits: i32,
    pub store_limit: i32,
    pub tuple_tax: i32,
    pub max_live_buckets: i32,
    pub table_search: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct FastParams {
    pub hash_bits: c_int,
    pub min_match: c_int,
    pub skip_shift: c_int,
    pub max_step: c_int,
    pub long_table: c_int,
    pub lazy: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union ParamsUnion {
    pub lazy: LazyParams,
    pub optimal: OptimalParams,
    pub fast: FastParams,
}

/// Mirrors `crushlzfse_encode_params` (tag + union).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct EncodeParams {
    pub strategy: c_int,
    pub p: ParamsUnion,
}

/// Mirrors `crushlzfse_stats`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawStats {
    pub opaque: [u32; CRUSHLZFSE_STATS_WORDS],
}

/// Mirrors `crushlzfse_capabilities`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawCapabilities {
    pub level_min: c_int,
    pub level_max: c_int,
    pub level_default: c_int,
    pub search_depth_min: c_int,
    pub search_depth_max: c_int,
    pub iterations_min: c_int,
    pub iterations_max: c_int,
    pub enable_reparse_min: c_int,
    pub enable_reparse_max: c_int,
    pub split_max_blocks_min: i32,
    pub split_max_blocks_max: i32,
    pub optimal_hash_bits_min: i32,
    pub optimal_hash_bits_max: i32,
    pub store_limit_min: i32,
    pub store_limit_max: i32,
    pub tuple_tax_min: i32,
    pub tuple_tax_max: i32,
    pub max_live_buckets_min: i32,
    pub max_live_buckets_max: i32,
    pub table_search_min: i32,
    pub table_search_max: i32,
    pub lazy_hash_bits_min: c_int,
    pub lazy_hash_bits_max: c_int,
    pub lazy_hash_width_min: c_int,
    pub lazy_hash_width_max: c_int,
    pub lazy_lookahead_min: c_int,
    pub lazy_lookahead_max: c_int,
    pub fast_hash_bits_min: c_int,
    pub fast_hash_bits_max: c_int,
    pub fast_min_match_min: c_int,
    pub fast_min_match_max: c_int,
    pub fast_skip_shift_min: c_int,
    pub fast_skip_shift_max: c_int,
    pub fast_max_step_min: c_int,
    pub fast_max_step_max: c_int,
    pub fast_long_table_min: c_int,
    pub fast_long_table_max: c_int,
    pub fast_lazy_min: c_int,
    pub fast_lazy_max: c_int,
}

// --- crushlzvn.h ------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LzvnGreedyParams {
    pub hash_bits: i32,
    pub hash_width: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LzvnOptimalParams {
    pub search_depth: i32,
    pub store_limit: i32,
    pub hash_bits: i32,
    pub pareto_k: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union LzvnParamsUnion {
    pub greedy: LzvnGreedyParams,
    pub optimal: LzvnOptimalParams,
    /// Same fields and layout as LZFSE's.
    pub fast: FastParams,
}

/// Mirrors `crushlzvn_encode_params` (tag + union).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LzvnEncodeParams {
    pub strategy: c_int,
    pub p: LzvnParamsUnion,
}

/// Mirrors `crushlzvn_capabilities`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct LzvnRawCapabilities {
    pub level_min: c_int,
    pub level_max: c_int,
    pub level_default: c_int,
    pub greedy_hash_bits_min: i32,
    pub greedy_hash_bits_max: i32,
    pub greedy_hash_width_min: i32,
    pub greedy_hash_width_max: i32,
    pub search_depth_min: i32,
    pub search_depth_max: i32,
    pub store_limit_min: i32,
    pub store_limit_max: i32,
    pub hash_bits_min: i32,
    pub hash_bits_max: i32,
    pub pareto_k_min: i32,
    pub pareto_k_max: i32,
    pub fast_hash_bits_min: c_int,
    pub fast_hash_bits_max: c_int,
    pub fast_min_match_min: c_int,
    pub fast_min_match_max: c_int,
    pub fast_skip_shift_min: c_int,
    pub fast_skip_shift_max: c_int,
    pub fast_max_step_min: c_int,
    pub fast_max_step_max: c_int,
    pub fast_long_table_min: c_int,
    pub fast_long_table_max: c_int,
    pub fast_lazy_min: c_int,
    pub fast_lazy_max: c_int,
}

unsafe extern "C" {
    // crushlzfse.h
    pub(crate) fn crushlzfse_get_capabilities() -> RawCapabilities;
    pub(crate) fn crushlzfse_params_for_level(level: c_int, out: *mut EncodeParams) -> c_int;
    pub(crate) fn crushlzfse_scratch_size(params: *const EncodeParams) -> usize;
    pub(crate) fn crushlzfse_encode_bound(src_size: usize, params: *const EncodeParams) -> usize;
    pub(crate) fn crushlzfse_encode_buffer_advanced(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        scratch: *mut c_void,
        scratch_size: usize,
        params: *const EncodeParams,
    ) -> usize;
    pub(crate) fn crushlzfse_encode_buffer_chained(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        scratch: *mut c_void,
        scratch_size: usize,
        params: *const EncodeParams,
        stats: *mut RawStats,
    ) -> usize;
    pub(crate) fn crushlzfse_decode_buffer(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        out_len: *mut usize,
    ) -> c_int;

    // crushlzvn.h
    pub(crate) fn crushlzvn_get_capabilities() -> LzvnRawCapabilities;
    pub(crate) fn crushlzvn_params_for_level(level: c_int, out: *mut LzvnEncodeParams) -> c_int;
    pub(crate) fn crushlzvn_scratch_size(params: *const LzvnEncodeParams) -> usize;
    pub(crate) fn crushlzvn_encode_bound(src_size: usize, params: *const LzvnEncodeParams) -> usize;
    pub(crate) fn crushlzvn_encode_buffer_advanced(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        scratch: *mut c_void,
        scratch_size: usize,
        params: *const LzvnEncodeParams,
    ) -> usize;
    pub(crate) fn crushlzvn_decode_buffer(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        out_len: *mut usize,
    ) -> c_int;
}

unsafe extern "C" {
    // Not part of the public C API (crushlzfse.h/crushlzvn.h): an internal
    // LZFSE decoder symbol (`lzfse_internal.h`) this crate reuses directly
    // rather than re-deriving its block-header parsing (the magic/size
    // fields and the v1/v2 header shapes) a second time in Rust. That kind
    // of two-implementation drift is exactly what desynced lzbitmap's ABI
    // mirrors four times (see crushlz4's README); reusing the C parser
    // avoids it outright instead of just checking for it after the fact.
    pub(crate) fn lzfse_declared_len(src: *const u8, src_end: *const u8, out_len: *mut usize) -> c_int;
}

/// Asserts the mirrors above against the layout the C compiler produced, as
/// reported by the descriptor functions in `crushlzfse_abi.c`. Slot 0 of
/// each descriptor is `sizeof`; the rest are field offsets in declaration
/// order, so a reorder, an insertion and a truncation are all visible.
#[cfg(test)]
mod abi_tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    unsafe extern "C" {
        fn crushlzfse_abi_params(out: *mut usize, n: usize) -> usize;
        fn crushlzfse_abi_lazy(out: *mut usize, n: usize) -> usize;
        fn crushlzfse_abi_optimal(out: *mut usize, n: usize) -> usize;
        fn crushlzfse_abi_fast(out: *mut usize, n: usize) -> usize;
        fn crushlzfse_abi_caps(out: *mut usize, n: usize) -> usize;
        fn crushlzfse_abi_stats(out: *mut usize, n: usize) -> usize;
        fn crushlzfse_abi_consts(out: *mut c_int, n: usize) -> usize;
        fn crushlzvn_abi_params(out: *mut usize, n: usize) -> usize;
        fn crushlzvn_abi_greedy(out: *mut usize, n: usize) -> usize;
        fn crushlzvn_abi_fast(out: *mut usize, n: usize) -> usize;
        fn crushlzvn_abi_optimal(out: *mut usize, n: usize) -> usize;
        fn crushlzvn_abi_caps(out: *mut usize, n: usize) -> usize;
        fn crushlzvn_abi_consts(out: *mut c_int, n: usize) -> usize;
    }

    fn describe(f: unsafe extern "C" fn(*mut usize, usize) -> usize) -> Vec<usize> {
        let mut v = vec![0usize; 64];
        // SAFETY: `v` has room for 64 entries and the callee is told so; it
        // writes at most that many and returns its true count.
        let n = unsafe { f(v.as_mut_ptr(), v.len()) };
        assert!(n <= v.len(), "ABI descriptor longer than its buffer");
        v.truncate(n);
        v
    }

    fn consts(f: unsafe extern "C" fn(*mut c_int, usize) -> usize) -> Vec<c_int> {
        let mut v = vec![0 as c_int; 32];
        // SAFETY: as in `describe`.
        let n = unsafe { f(v.as_mut_ptr(), v.len()) };
        assert!(n <= v.len(), "ABI descriptor longer than its buffer");
        v.truncate(n);
        v
    }

    #[test]
    fn encode_params_layout_matches_c() {
        let c = describe(crushlzfse_abi_params);
        assert_eq!(size_of::<EncodeParams>(), c[0], "EncodeParams size differs from C");
        assert_eq!(offset_of!(EncodeParams, strategy), c[1]);
        assert_eq!(offset_of!(EncodeParams, p), c[2]);
        assert_eq!(size_of::<ParamsUnion>(), c[3], "ParamsUnion size differs from C's union");
        let biggest = c[4..].iter().copied().max().unwrap();
        assert!(
            size_of::<ParamsUnion>() >= biggest,
            "ParamsUnion is {} bytes but C has a {}-byte variant",
            size_of::<ParamsUnion>(),
            biggest
        );
    }

    #[test]
    fn lazy_params_layout_matches_c() {
        let c = describe(crushlzfse_abi_lazy);
        let want = vec![
            size_of::<LazyParams>(),
            offset_of!(LazyParams, hash_bits),
            offset_of!(LazyParams, hash_width),
            offset_of!(LazyParams, lookahead),
        ];
        assert_eq!(c, want, "lazy size/offsets differ (slot 0 is sizeof)");
    }

    #[test]
    fn optimal_params_layout_matches_c() {
        let c = describe(crushlzfse_abi_optimal);
        let want = vec![
            size_of::<OptimalParams>(),
            offset_of!(OptimalParams, search_depth),
            offset_of!(OptimalParams, iterations),
            offset_of!(OptimalParams, enable_reparse),
            offset_of!(OptimalParams, split_max_blocks),
            offset_of!(OptimalParams, hash_bits),
            offset_of!(OptimalParams, store_limit),
            offset_of!(OptimalParams, tuple_tax),
            offset_of!(OptimalParams, max_live_buckets),
            offset_of!(OptimalParams, table_search),
        ];
        assert_eq!(c, want, "optimal size/offsets differ (slot 0 is sizeof)");
    }

    #[test]
    fn fast_params_layout_matches_c() {
        let c = describe(crushlzfse_abi_fast);
        let want = vec![
            size_of::<FastParams>(),
            offset_of!(FastParams, hash_bits),
            offset_of!(FastParams, min_match),
            offset_of!(FastParams, skip_shift),
            offset_of!(FastParams, max_step),
            offset_of!(FastParams, long_table),
            offset_of!(FastParams, lazy),
        ];
        assert_eq!(c, want, "fast size/offsets differ (slot 0 is sizeof)");
    }

    #[test]
    fn stats_layout_matches_c() {
        let c = describe(crushlzfse_abi_stats);
        let want = vec![size_of::<RawStats>(), offset_of!(RawStats, opaque), CRUSHLZFSE_STATS_WORDS];
        assert_eq!(c, want, "stats size/offset/word count differ (slot 0 is sizeof)");
    }

    #[test]
    fn capabilities_layout_matches_c() {
        let c = describe(crushlzfse_abi_caps);
        let want = vec![
            size_of::<RawCapabilities>(),
            offset_of!(RawCapabilities, level_min),
            offset_of!(RawCapabilities, level_max),
            offset_of!(RawCapabilities, level_default),
            offset_of!(RawCapabilities, search_depth_min),
            offset_of!(RawCapabilities, search_depth_max),
            offset_of!(RawCapabilities, iterations_min),
            offset_of!(RawCapabilities, iterations_max),
            offset_of!(RawCapabilities, enable_reparse_min),
            offset_of!(RawCapabilities, enable_reparse_max),
            offset_of!(RawCapabilities, split_max_blocks_min),
            offset_of!(RawCapabilities, split_max_blocks_max),
            offset_of!(RawCapabilities, optimal_hash_bits_min),
            offset_of!(RawCapabilities, optimal_hash_bits_max),
            offset_of!(RawCapabilities, store_limit_min),
            offset_of!(RawCapabilities, store_limit_max),
            offset_of!(RawCapabilities, tuple_tax_min),
            offset_of!(RawCapabilities, tuple_tax_max),
            offset_of!(RawCapabilities, max_live_buckets_min),
            offset_of!(RawCapabilities, max_live_buckets_max),
            offset_of!(RawCapabilities, table_search_min),
            offset_of!(RawCapabilities, table_search_max),
            offset_of!(RawCapabilities, lazy_hash_bits_min),
            offset_of!(RawCapabilities, lazy_hash_bits_max),
            offset_of!(RawCapabilities, lazy_hash_width_min),
            offset_of!(RawCapabilities, lazy_hash_width_max),
            offset_of!(RawCapabilities, lazy_lookahead_min),
            offset_of!(RawCapabilities, lazy_lookahead_max),
            offset_of!(RawCapabilities, fast_hash_bits_min),
            offset_of!(RawCapabilities, fast_hash_bits_max),
            offset_of!(RawCapabilities, fast_min_match_min),
            offset_of!(RawCapabilities, fast_min_match_max),
            offset_of!(RawCapabilities, fast_skip_shift_min),
            offset_of!(RawCapabilities, fast_skip_shift_max),
            offset_of!(RawCapabilities, fast_max_step_min),
            offset_of!(RawCapabilities, fast_max_step_max),
            offset_of!(RawCapabilities, fast_long_table_min),
            offset_of!(RawCapabilities, fast_long_table_max),
            offset_of!(RawCapabilities, fast_lazy_min),
            offset_of!(RawCapabilities, fast_lazy_max),
        ];
        assert_eq!(c, want, "capabilities size/offsets differ (slot 0 is sizeof)");
    }

    #[test]
    fn constants_match_c() {
        let want = vec![
            CRUSHLZFSE_LEVEL_MIN,
            CRUSHLZFSE_LEVEL_MAX,
            CRUSHLZFSE_LEVEL_DEFAULT,
            CRUSHLZFSE_STRATEGY_LAZY,
            CRUSHLZFSE_STRATEGY_OPTIMAL,
            CRUSHLZFSE_STRATEGY_FAST,
            CRUSHLZFSE_INVALID,
            CRUSHLZFSE_OUTPUT_TOO_SMALL,
        ];
        assert_eq!(consts(crushlzfse_abi_consts), want, "a CRUSHLZFSE_* constant is stale");
    }

    #[test]
    fn lzvn_encode_params_layout_matches_c() {
        let c = describe(crushlzvn_abi_params);
        assert_eq!(size_of::<LzvnEncodeParams>(), c[0], "LzvnEncodeParams size differs from C");
        assert_eq!(offset_of!(LzvnEncodeParams, strategy), c[1]);
        assert_eq!(offset_of!(LzvnEncodeParams, p), c[2]);
        assert_eq!(size_of::<LzvnParamsUnion>(), c[3], "LzvnParamsUnion size differs from C's union");
        let biggest = c[4..].iter().copied().max().unwrap();
        assert!(size_of::<LzvnParamsUnion>() >= biggest, "LzvnParamsUnion smaller than a C variant");
    }

    #[test]
    fn lzvn_fast_params_layout_matches_c() {
        let c = describe(crushlzvn_abi_fast);
        let want = vec![
            size_of::<FastParams>(),
            offset_of!(FastParams, hash_bits),
            offset_of!(FastParams, min_match),
            offset_of!(FastParams, skip_shift),
            offset_of!(FastParams, max_step),
            offset_of!(FastParams, long_table),
            offset_of!(FastParams, lazy),
        ];
        assert_eq!(c, want, "LZVN fast size/offsets differ (slot 0 is sizeof)");
    }

    #[test]
    fn lzvn_greedy_params_layout_matches_c() {
        let c = describe(crushlzvn_abi_greedy);
        let want = vec![
            size_of::<LzvnGreedyParams>(),
            offset_of!(LzvnGreedyParams, hash_bits),
            offset_of!(LzvnGreedyParams, hash_width),
        ];
        assert_eq!(c, want, "LZVN greedy size/offsets differ (slot 0 is sizeof)");
    }

    #[test]
    fn lzvn_optimal_params_layout_matches_c() {
        let c = describe(crushlzvn_abi_optimal);
        let want = vec![
            size_of::<LzvnOptimalParams>(),
            offset_of!(LzvnOptimalParams, search_depth),
            offset_of!(LzvnOptimalParams, store_limit),
            offset_of!(LzvnOptimalParams, hash_bits),
            offset_of!(LzvnOptimalParams, pareto_k),
        ];
        assert_eq!(c, want, "LZVN optimal size/offsets differ (slot 0 is sizeof)");
    }

    #[test]
    fn lzvn_capabilities_layout_matches_c() {
        let c = describe(crushlzvn_abi_caps);
        let want = vec![
            size_of::<LzvnRawCapabilities>(),
            offset_of!(LzvnRawCapabilities, level_min),
            offset_of!(LzvnRawCapabilities, level_max),
            offset_of!(LzvnRawCapabilities, level_default),
            offset_of!(LzvnRawCapabilities, greedy_hash_bits_min),
            offset_of!(LzvnRawCapabilities, greedy_hash_bits_max),
            offset_of!(LzvnRawCapabilities, greedy_hash_width_min),
            offset_of!(LzvnRawCapabilities, greedy_hash_width_max),
            offset_of!(LzvnRawCapabilities, search_depth_min),
            offset_of!(LzvnRawCapabilities, search_depth_max),
            offset_of!(LzvnRawCapabilities, store_limit_min),
            offset_of!(LzvnRawCapabilities, store_limit_max),
            offset_of!(LzvnRawCapabilities, hash_bits_min),
            offset_of!(LzvnRawCapabilities, hash_bits_max),
            offset_of!(LzvnRawCapabilities, pareto_k_min),
            offset_of!(LzvnRawCapabilities, pareto_k_max),
            offset_of!(LzvnRawCapabilities, fast_hash_bits_min),
            offset_of!(LzvnRawCapabilities, fast_hash_bits_max),
            offset_of!(LzvnRawCapabilities, fast_min_match_min),
            offset_of!(LzvnRawCapabilities, fast_min_match_max),
            offset_of!(LzvnRawCapabilities, fast_skip_shift_min),
            offset_of!(LzvnRawCapabilities, fast_skip_shift_max),
            offset_of!(LzvnRawCapabilities, fast_max_step_min),
            offset_of!(LzvnRawCapabilities, fast_max_step_max),
            offset_of!(LzvnRawCapabilities, fast_long_table_min),
            offset_of!(LzvnRawCapabilities, fast_long_table_max),
            offset_of!(LzvnRawCapabilities, fast_lazy_min),
            offset_of!(LzvnRawCapabilities, fast_lazy_max),
        ];
        assert_eq!(c, want, "LZVN capabilities size/offsets differ (slot 0 is sizeof)");
    }

    #[test]
    fn lzvn_constants_match_c() {
        let want = vec![
            CRUSHLZVN_LEVEL_MIN,
            CRUSHLZVN_LEVEL_MAX,
            CRUSHLZVN_LEVEL_DEFAULT,
            CRUSHLZVN_STRATEGY_GREEDY,
            CRUSHLZVN_STRATEGY_OPTIMAL,
            CRUSHLZVN_STRATEGY_FAST,
            CRUSHLZVN_INVALID,
            CRUSHLZVN_OUTPUT_TOO_SMALL,
        ];
        assert_eq!(consts(crushlzvn_abi_consts), want, "a CRUSHLZVN_* constant is stale");
    }
}
