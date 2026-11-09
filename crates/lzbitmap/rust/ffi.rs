// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Raw declarations mirroring crushlzbitmap.h, named exactly as the header
//! names them. The small API uses hand-written mirrors checked against C layouts.
#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_void};

pub(crate) const CRUSHLZBITMAP_LEVEL_MIN: c_int = -5;
pub(crate) const CRUSHLZBITMAP_LEVEL_MAX: c_int = 12;
pub(crate) const CRUSHLZBITMAP_LEVEL_DEFAULT: c_int = 0;

pub(crate) const CRUSHLZBITMAP_INVALID: c_int = -1;
pub(crate) const CRUSHLZBITMAP_OUTPUT_TOO_SMALL: c_int = -2;

/// Mirrors CRUSHLZBITMAP_SCRATCH_ALIGN; asserted against the C side in abi_tests.
pub(crate) const CRUSHLZBITMAP_SCRATCH_ALIGN: usize = 16;

pub(crate) const CRUSHLZBITMAP_CHUNK_SIZE: usize = 1 << 15;
pub(crate) const CRUSHLZBITMAP_MAX_CHUNK_SIZE: usize = 0x800A;
// Only read by the ABI test below now that decompress() sizes exactly
// instead of deriving a growth ceiling from it.
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_LAST_CHUNK_SIZE: usize = 6;

#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_BEAM_WIDTH: c_int = 64;
pub(crate) const CRUSHLZBITMAP_STRATEGY_BEAM: c_int = 4;
pub(crate) const CRUSHLZBITMAP_STRATEGY_DP: c_int = 2;
pub(crate) const CRUSHLZBITMAP_STRATEGY_ROW: c_int = 3;
pub(crate) const CRUSHLZBITMAP_STRATEGY_FAST: c_int = 5;

// The bounds every params field is validated against. C does the
// validating; these are here for the tests that probe it and for the ABI
// check that pins them.
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_ITERATIONS: c_int = 64;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_DP_CANDS: c_int = 255;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MIN_ROW_HASH_BITS: c_int = 8;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_ROW_HASH_BITS: c_int = 16;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_ROW_DEPTH: c_int = 16;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_ROW_SCAN: c_int = 256;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MIN_FAST_HASH_BITS: c_int = 10;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_FAST_HASH_BITS: c_int = 16;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_FAST_WINDOWS: c_int = 8;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_FAST_DIST_CACHE: c_int = 2;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_FAST_ACCEPT_DIFF: c_int = 7;
#[allow(dead_code)]
pub(crate) const CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT: c_int = 11;

/// Mirrors `crushlzbitmap_row_params`; field order is the ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct crushlzbitmap_row_params {
    pub hash_bits: c_int,
    pub depth: c_int,
    pub dist_cache_size: c_int,
    pub accept_diff: c_int,
    pub scan_window: c_int,
    pub lookahead: c_int,
}

/// Mirrors `crushlzbitmap_dp_params`. `row` stays first: the C
/// side relies on it aliasing the union's row arm.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct crushlzbitmap_dp_params {
    pub row: crushlzbitmap_row_params,
    pub max_candidates: c_int,
    pub iterations: c_int,
}

/// Mirrors `crushlzbitmap_beam_params`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct crushlzbitmap_beam_params {
    pub row: crushlzbitmap_row_params,
    pub max_candidates: c_int,
    pub beam_width: c_int,
}

/// Mirrors `crushlzbitmap_fast_params`; field order is the ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct crushlzbitmap_fast_params {
    pub hash_bits: c_int,
    pub windows: c_int,
    pub dist_cache_size: c_int,
    pub accept_diff: c_int,
    pub skip_shift: c_int,
}

/// Mirrors the anonymous union `p` inside `crushlzbitmap_params`.
/// Which arm is valid to read is decided by the enclosing `strategy`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union crushlzbitmap_params_union {
    pub dp: crushlzbitmap_dp_params,
    pub beam: crushlzbitmap_beam_params,
    pub row: crushlzbitmap_row_params,
    pub fast: crushlzbitmap_fast_params,
}

/// Mirrors `crushlzbitmap_params`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct crushlzbitmap_params {
    pub strategy: c_int,
    pub p: crushlzbitmap_params_union,
}

/// Mirrors `crushlzbitmap_capabilities`. Field order and count are
/// asserted against the C side in `abi_tests`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RawCapabilities {
    pub level_min: c_int,
    pub level_max: c_int,
    pub level_default: c_int,
    pub row_hash_bits_min: c_int,
    pub row_hash_bits_max: c_int,
    pub row_depth_min: c_int,
    pub row_depth_max: c_int,
    pub row_lookahead_min: c_int,
    pub row_lookahead_max: c_int,
    pub row_dist_cache_size_min: c_int,
    pub row_dist_cache_size_max: c_int,
    pub row_scan_window_min: c_int,
    pub row_scan_window_max: c_int,
    pub row_accept_diff_min: c_int,
    pub row_accept_diff_max: c_int,
    pub dp_max_candidates_min: c_int,
    pub dp_max_candidates_max: c_int,
    pub dp_iterations_min: c_int,
    pub dp_iterations_max: c_int,
    pub beam_width_min: c_int,
    pub beam_width_max: c_int,
    pub fast_hash_bits_min: c_int,
    pub fast_hash_bits_max: c_int,
    pub fast_windows_min: c_int,
    pub fast_windows_max: c_int,
    pub fast_dist_cache_size_min: c_int,
    pub fast_dist_cache_size_max: c_int,
    pub fast_accept_diff_min: c_int,
    pub fast_accept_diff_max: c_int,
    pub fast_skip_shift_min: c_int,
    pub fast_skip_shift_max: c_int,
}

unsafe extern "C" {
    pub(crate) fn crushlzbitmap_params_for_level(level: c_int, params: *mut crushlzbitmap_params) -> c_int;

    pub(crate) fn crushlzbitmap_default_params(strategy: c_int, params: *mut crushlzbitmap_params) -> c_int;

    pub(crate) fn crushlzbitmap_scratch_size(params: *const crushlzbitmap_params) -> usize;

    pub(crate) fn crushlzbitmap_get_capabilities() -> RawCapabilities;

    pub(crate) fn crushlzbitmap_encode_bound(src_size: usize) -> usize;

    pub(crate) fn crushlzbitmap_encode_buffer_advanced(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        scratch: *mut c_void,
        scratch_size: usize,
        params: *const crushlzbitmap_params,
    ) -> usize;

    pub(crate) fn crushlzbitmap_encode_chunk(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        index: usize,
        scratch: *mut c_void,
        scratch_size: usize,
        params: *const crushlzbitmap_params,
    ) -> usize;

    pub(crate) fn crushlzbitmap_decode_buffer(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        out_len: *mut usize,
    ) -> c_int;
}

/// Asserts the mirrors above against the layouts and constants the C
/// translation unit reports through `csrc/zbm_abi.c`. A misordered or
/// missing field, or an undersized union, is memory-unsafe and not a
/// compile error, which is why these are checked rather than eyeballed.
#[cfg(test)]
mod abi_tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    unsafe extern "C" {
        fn zbm_abi_beam(out: *mut usize, n: usize) -> usize;
        fn zbm_abi_dp(out: *mut usize, n: usize) -> usize;
        fn zbm_abi_row(out: *mut usize, n: usize) -> usize;
        fn zbm_abi_fast(out: *mut usize, n: usize) -> usize;
        fn zbm_abi_params(out: *mut usize, n: usize) -> usize;
        fn zbm_abi_capabilities(out: *mut usize, n: usize) -> usize;
        fn zbm_abi_levels(lo: *mut c_int, hi: *mut c_int, dflt: *mut c_int);
        fn zbm_abi_constants(out: *mut c_int, n: usize) -> usize;
    }

    fn describe(f: unsafe extern "C" fn(*mut usize, usize) -> usize) -> Vec<usize> {
        let mut v = vec![0usize; 32];
        // SAFETY: `v` has room for 32 entries and the callee is told so; it
        // writes at most min(its own count, n) of them and returns its true
        // count.
        let n = unsafe { f(v.as_mut_ptr(), v.len()) };
        assert!(n <= v.len(), "ABI descriptor longer than the buffer given to it");
        v.truncate(n);
        v
    }

    #[test]
    fn beam_params_layout_matches_c() {
        assert_eq!(describe(zbm_abi_beam), vec![
            size_of::<crushlzbitmap_beam_params>(),
            offset_of!(crushlzbitmap_beam_params, row),
            offset_of!(crushlzbitmap_beam_params, max_candidates),
            offset_of!(crushlzbitmap_beam_params, beam_width),
        ]);
    }

    #[test]
    fn dp_params_layout_matches_c() {
        let c = describe(zbm_abi_dp);
        let want = vec![
            size_of::<crushlzbitmap_dp_params>(),
            offset_of!(crushlzbitmap_dp_params, row),
            offset_of!(crushlzbitmap_dp_params, max_candidates),
            offset_of!(crushlzbitmap_dp_params, iterations),
        ];
        assert_eq!(c, want, "crushlzbitmap_dp_params layout differs");
        assert_eq!(offset_of!(crushlzbitmap_dp_params, row), 0, "dp.row must stay first");
    }

    #[test]
    fn row_params_layout_matches_c() {
        let c = describe(zbm_abi_row);
        let want = vec![
            size_of::<crushlzbitmap_row_params>(),
            offset_of!(crushlzbitmap_row_params, hash_bits),
            offset_of!(crushlzbitmap_row_params, depth),
            offset_of!(crushlzbitmap_row_params, dist_cache_size),
            offset_of!(crushlzbitmap_row_params, accept_diff),
            offset_of!(crushlzbitmap_row_params, scan_window),
            offset_of!(crushlzbitmap_row_params, lookahead),
        ];
        assert_eq!(c.len(), want.len(), "crushlzbitmap_row_params has a different field count");
        assert_eq!(c, want, "crushlzbitmap_row_params layout differs");
    }

    #[test]
    fn fast_params_layout_matches_c() {
        let c = describe(zbm_abi_fast);
        let want = vec![
            size_of::<crushlzbitmap_fast_params>(),
            offset_of!(crushlzbitmap_fast_params, hash_bits),
            offset_of!(crushlzbitmap_fast_params, windows),
            offset_of!(crushlzbitmap_fast_params, dist_cache_size),
            offset_of!(crushlzbitmap_fast_params, accept_diff),
            offset_of!(crushlzbitmap_fast_params, skip_shift),
        ];
        assert_eq!(c.len(), want.len(), "crushlzbitmap_fast_params has a different field count");
        assert_eq!(c, want, "crushlzbitmap_fast_params layout differs");
    }

    #[test]
    fn params_union_is_not_undersized() {
        let c = describe(zbm_abi_params);
        let (c_params, c_strategy, c_p, c_union) = (c[0], c[1], c[2], c[3]);
        let c_variants = &c[4..];

        assert_eq!(size_of::<crushlzbitmap_params>(), c_params, "crushlzbitmap_params size differs");
        assert_eq!(offset_of!(crushlzbitmap_params, strategy), c_strategy);
        assert_eq!(offset_of!(crushlzbitmap_params, p), c_p);
        assert_eq!(size_of::<crushlzbitmap_params_union>(), c_union, "union size differs from C's");

        let biggest = c_variants.iter().copied().max().unwrap();
        assert!(
            size_of::<crushlzbitmap_params_union>() >= biggest,
            "the union is {} bytes but C has a {}-byte variant",
            size_of::<crushlzbitmap_params_union>(),
            biggest
        );
        assert_eq!(align_of::<crushlzbitmap_params>(), align_of::<c_int>());
    }

    #[test]
    fn level_constants_match_c() {
        let (mut lo, mut hi, mut dflt) = (0 as c_int, 0 as c_int, 0 as c_int);
        // SAFETY: three valid out-pointers, all written unconditionally.
        unsafe { zbm_abi_levels(&mut lo, &mut hi, &mut dflt) };
        assert_eq!(CRUSHLZBITMAP_LEVEL_MIN, lo, "CRUSHLZBITMAP_LEVEL_MIN is stale");
        assert_eq!(CRUSHLZBITMAP_LEVEL_MAX, hi, "CRUSHLZBITMAP_LEVEL_MAX is stale");
        assert_eq!(CRUSHLZBITMAP_LEVEL_DEFAULT, dflt, "CRUSHLZBITMAP_LEVEL_DEFAULT is stale");
        assert!(lo <= dflt && dflt <= hi);
    }

    #[test]
    fn constants_match_c() {
        let mut v = vec![0 as c_int; 32];
        // SAFETY: as in `describe`, the callee is told the true capacity.
        let n = unsafe { zbm_abi_constants(v.as_mut_ptr(), v.len()) };
        assert!(n <= v.len());
        v.truncate(n);
        let want = vec![
            CRUSHLZBITMAP_INVALID,
            CRUSHLZBITMAP_OUTPUT_TOO_SMALL,
            CRUSHLZBITMAP_CHUNK_SIZE as c_int,
            CRUSHLZBITMAP_MAX_CHUNK_SIZE as c_int,
            CRUSHLZBITMAP_LAST_CHUNK_SIZE as c_int,
            CRUSHLZBITMAP_STRATEGY_BEAM,
            CRUSHLZBITMAP_MAX_BEAM_WIDTH,
            CRUSHLZBITMAP_STRATEGY_DP,
            CRUSHLZBITMAP_STRATEGY_ROW,
            CRUSHLZBITMAP_STRATEGY_FAST,
            CRUSHLZBITMAP_MAX_ITERATIONS,
            CRUSHLZBITMAP_MAX_DP_CANDS,
            CRUSHLZBITMAP_MIN_ROW_HASH_BITS,
            CRUSHLZBITMAP_MAX_ROW_HASH_BITS,
            CRUSHLZBITMAP_MAX_ROW_DEPTH,
            CRUSHLZBITMAP_MAX_ROW_SCAN,
            CRUSHLZBITMAP_MIN_FAST_HASH_BITS,
            CRUSHLZBITMAP_MAX_FAST_HASH_BITS,
            CRUSHLZBITMAP_MAX_FAST_WINDOWS,
            CRUSHLZBITMAP_MAX_FAST_DIST_CACHE,
            CRUSHLZBITMAP_MAX_FAST_ACCEPT_DIFF,
            CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT,
        ];
        assert_eq!(v.len(), want.len(), "the C constant descriptor changed length");
        assert_eq!(v, want, "constants differ from crushlzbitmap.h (header declaration order)");
    }

    #[test]
    fn capabilities_layout_matches_c() {
        let c = describe(zbm_abi_capabilities);
        let want = vec![
            size_of::<RawCapabilities>(),
            offset_of!(RawCapabilities, level_min),
            offset_of!(RawCapabilities, level_max),
            offset_of!(RawCapabilities, level_default),
            offset_of!(RawCapabilities, row_hash_bits_min),
            offset_of!(RawCapabilities, row_hash_bits_max),
            offset_of!(RawCapabilities, row_depth_min),
            offset_of!(RawCapabilities, row_depth_max),
            offset_of!(RawCapabilities, row_lookahead_min),
            offset_of!(RawCapabilities, row_lookahead_max),
            offset_of!(RawCapabilities, row_dist_cache_size_min),
            offset_of!(RawCapabilities, row_dist_cache_size_max),
            offset_of!(RawCapabilities, row_scan_window_min),
            offset_of!(RawCapabilities, row_scan_window_max),
            offset_of!(RawCapabilities, row_accept_diff_min),
            offset_of!(RawCapabilities, row_accept_diff_max),
            offset_of!(RawCapabilities, dp_max_candidates_min),
            offset_of!(RawCapabilities, dp_max_candidates_max),
            offset_of!(RawCapabilities, dp_iterations_min),
            offset_of!(RawCapabilities, dp_iterations_max),
            offset_of!(RawCapabilities, beam_width_min),
            offset_of!(RawCapabilities, beam_width_max),
            offset_of!(RawCapabilities, fast_hash_bits_min),
            offset_of!(RawCapabilities, fast_hash_bits_max),
            offset_of!(RawCapabilities, fast_windows_min),
            offset_of!(RawCapabilities, fast_windows_max),
            offset_of!(RawCapabilities, fast_dist_cache_size_min),
            offset_of!(RawCapabilities, fast_dist_cache_size_max),
            offset_of!(RawCapabilities, fast_accept_diff_min),
            offset_of!(RawCapabilities, fast_accept_diff_max),
            offset_of!(RawCapabilities, fast_skip_shift_min),
            offset_of!(RawCapabilities, fast_skip_shift_max),
        ];
        assert_eq!(c.len(), want.len(), "crushlzbitmap_capabilities gained or lost a field");
        assert_eq!(c, want, "crushlzbitmap_capabilities layout differs from the Rust mirror");
    }

    #[test]
    fn scratch_align_matches_c() {
        // The C side static-asserts its own value against the state's
        // alignment; this pins the Rust mirror to that same number.
        assert_eq!(CRUSHLZBITMAP_SCRATCH_ALIGN, 16);
    }
}
