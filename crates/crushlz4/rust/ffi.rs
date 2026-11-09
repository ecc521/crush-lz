// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Raw declarations mirroring crushlz4.h, named exactly as the header names
//! them. Hand-written: four scalar functions do not justify bindgen.

use std::os::raw::{c_int, c_void};

/// `crushlz4_encode_params::mode`. Not covered by `abi_tests` the way the
/// level range is — there is no descriptor for a pair of #defines — so they
/// are asserted against the ladder instead: every level must resolve to one
/// of these two, which `params::tests` checks by construction.
pub(crate) const CRUSHLZ4_MODE_FAST: c_int = 0;
pub(crate) const CRUSHLZ4_MODE_HC: c_int = 1;

pub(crate) const CRUSHLZ4_LEVEL_MIN: c_int = -5;
pub(crate) const CRUSHLZ4_LEVEL_MAX: c_int = 10;
pub(crate) const CRUSHLZ4_LEVEL_DEFAULT: c_int = 0;

pub(crate) const CRUSHLZ4_INVALID: c_int = -1;
pub(crate) const CRUSHLZ4_OUTPUT_TOO_SMALL: c_int = -2;

/// Input bytes per block; an encoder property, not a decoder limit.
#[allow(dead_code)]
pub(crate) const CRUSHLZ4_BLOCK_SIZE: usize = 0x10000;
/// "bv41", a compressed block header, little-endian as stored.
pub(crate) const CRUSHLZ4_MAGIC_COMPRESSED: u32 = 0x3134_7662;
/// "bv4-", a stored block header, little-endian as stored.
pub(crate) const CRUSHLZ4_MAGIC_STORED: u32 = 0x2D34_7662;
/// "bv4$", the end-of-stream terminator, little-endian as stored.
pub(crate) const CRUSHLZ4_MAGIC_END: u32 = 0x2434_7662;
#[allow(dead_code)]
pub(crate) const CRUSHLZ4_MIN_MATCH: usize = 4;
#[allow(dead_code)]
pub(crate) const CRUSHLZ4_MAX_OFFSET: usize = 65535;

/// Mirrors `crushlz4_encode_params`; field order is the ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct crushlz4_encode_params {
    pub mode: c_int,
    pub acceleration: c_int,
    pub hc_level: c_int,
}

/// Mirrors `crushlz4_capabilities`; returned by value, so the field order is
/// the calling convention too. Field order and count are asserted against the
/// C side in `abi_tests`, which is what keeps the mirror from drifting.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct RawCapabilities {
    pub level_min: c_int,
    pub level_max: c_int,
    pub level_default: c_int,
    pub mode_min: c_int,
    pub mode_max: c_int,
    pub acceleration_min: c_int,
    pub acceleration_max: c_int,
    pub hc_level_min: c_int,
    pub hc_level_max: c_int,
}

unsafe extern "C" {
    pub(crate) fn crushlz4_get_capabilities() -> RawCapabilities;

    pub(crate) fn crushlz4_params_for_level(
        level: c_int,
        out: *mut crushlz4_encode_params,
    ) -> c_int;

    pub(crate) fn crushlz4_scratch_size(params: *const crushlz4_encode_params) -> usize;

    pub(crate) fn crushlz4_encode_bound(src_size: usize) -> usize;

    pub(crate) fn crushlz4_encode_buffer_advanced(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        scratch: *mut c_void,
        scratch_size: usize,
        params: *const crushlz4_encode_params,
    ) -> usize;

    pub(crate) fn crushlz4_decode_buffer(
        dst: *mut c_void,
        dst_size: usize,
        src: *const c_void,
        src_size: usize,
        out_len: *mut usize,
    ) -> c_int;
}

/// Asserts the declarations above against what the C translation unit
/// reports through `csrc/crushlz4_abi.c`: a renumbered status, a moved
/// level, a frame constant the tests assert emitted bytes against, or a
/// field that moved inside one of the two structs the header declares.
#[cfg(test)]
mod abi_tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    unsafe extern "C" {
        fn clz4_abi_scalars(out: *mut usize, n: usize) -> usize;
        fn clz4_abi_errors(out: *mut c_int, n: usize) -> usize;
        fn clz4_abi_levels(lo: *mut c_int, hi: *mut c_int, dflt: *mut c_int);
        fn clz4_abi_format(out: *mut usize, n: usize) -> usize;
        fn clz4_abi_params(out: *mut usize, n: usize) -> usize;
        fn clz4_abi_capabilities(out: *mut usize, n: usize) -> usize;
    }

    fn describe_usize(f: unsafe extern "C" fn(*mut usize, usize) -> usize) -> Vec<usize> {
        let mut v = vec![0usize; 32];
        // SAFETY: `v` has room for 32 entries and the callee is told so; it
        // writes at most min(its own count, n) of them and returns its true
        // count.
        let n = unsafe { f(v.as_mut_ptr(), v.len()) };
        assert!(n <= v.len(), "ABI descriptor longer than the buffer given to it");
        v.truncate(n);
        v
    }

    fn describe_int(f: unsafe extern "C" fn(*mut c_int, usize) -> usize) -> Vec<c_int> {
        let mut v = vec![0 as c_int; 32];
        // SAFETY: as above.
        let n = unsafe { f(v.as_mut_ptr(), v.len()) };
        assert!(n <= v.len(), "ABI descriptor longer than the buffer given to it");
        v.truncate(n);
        v
    }

    #[test]
    fn encode_params_layout_matches_c() {
        let c = describe_usize(clz4_abi_params);
        let want = vec![
            size_of::<crushlz4_encode_params>(),
            offset_of!(crushlz4_encode_params, mode),
            offset_of!(crushlz4_encode_params, acceleration),
            offset_of!(crushlz4_encode_params, hc_level),
        ];
        assert_eq!(c.len(), want.len(), "crushlz4_encode_params gained or lost a field");
        assert_eq!(c, want, "crushlz4_encode_params layout differs from the Rust mirror");
    }

    #[test]
    fn capabilities_layout_matches_c() {
        let c = describe_usize(clz4_abi_capabilities);
        let want = vec![
            size_of::<RawCapabilities>(),
            offset_of!(RawCapabilities, level_min),
            offset_of!(RawCapabilities, level_max),
            offset_of!(RawCapabilities, level_default),
            offset_of!(RawCapabilities, mode_min),
            offset_of!(RawCapabilities, mode_max),
            offset_of!(RawCapabilities, acceleration_min),
            offset_of!(RawCapabilities, acceleration_max),
            offset_of!(RawCapabilities, hc_level_min),
            offset_of!(RawCapabilities, hc_level_max),
        ];
        assert_eq!(c.len(), want.len(), "crushlz4_capabilities gained or lost a field");
        assert_eq!(c, want, "crushlz4_capabilities layout differs from the Rust mirror");
    }

    #[test]
    fn boundary_scalars_match_c() {
        let c = describe_usize(clz4_abi_scalars);
        let want = vec![size_of::<c_int>(), size_of::<usize>(), size_of::<*const u8>(), align_of::<usize>()];
        assert_eq!(c.len(), want.len(), "the C scalar descriptor changed length");
        assert_eq!(c, want, "sizeof(int)/sizeof(size_t)/sizeof(void*)/alignof(size_t) differ");
    }

    #[test]
    fn status_codes_match_c() {
        let c = describe_int(clz4_abi_errors);
        let want = vec![CRUSHLZ4_INVALID, CRUSHLZ4_OUTPUT_TOO_SMALL];
        assert_eq!(c.len(), want.len(), "crushlz4.h declares a different number of status codes");
        assert_eq!(c, want, "status codes differ (header declaration order)");
    }

    #[test]
    fn level_constants_match_c() {
        let (mut lo, mut hi, mut dflt) = (0 as c_int, 0 as c_int, 0 as c_int);
        // SAFETY: three valid out-pointers, all written unconditionally.
        unsafe { clz4_abi_levels(&mut lo, &mut hi, &mut dflt) };
        assert_eq!(CRUSHLZ4_LEVEL_MIN, lo, "CRUSHLZ4_LEVEL_MIN is stale");
        assert_eq!(CRUSHLZ4_LEVEL_MAX, hi, "CRUSHLZ4_LEVEL_MAX is stale");
        assert_eq!(CRUSHLZ4_LEVEL_DEFAULT, dflt, "CRUSHLZ4_LEVEL_DEFAULT is stale");
        assert!(lo <= dflt && dflt <= hi, "the default level is outside the ladder");
    }


    #[test]
    fn capabilities_agree_with_the_ladder() {
        // SAFETY: a pure function with no arguments and no failure mode; the
        // struct comes back by value, which is what the layout test pins.
        let c = unsafe { crushlz4_get_capabilities() };
        assert_eq!(c.level_min, CRUSHLZ4_LEVEL_MIN);
        assert_eq!(c.level_max, CRUSHLZ4_LEVEL_MAX);
        for level in c.level_min..=c.level_max {
            let mut p = crushlz4_encode_params::default();
            // SAFETY: `p` is a valid, fully initialised out-pointer.
            unsafe { crushlz4_params_for_level(level, &mut p) };
            assert!(p.mode >= c.mode_min && p.mode <= c.mode_max,
                    "level {level} asks for a mode the advanced entry point rejects");
            // Only the knob this level's mode reads has to be in range; the
            // other carries that mode's neutral value and is never validated.
            if p.mode == CRUSHLZ4_MODE_FAST {
                assert!(p.acceleration >= c.acceleration_min && p.acceleration <= c.acceleration_max,
                        "level {level} asks for an acceleration the advanced entry point rejects");
            } else {
                assert!(p.hc_level >= c.hc_level_min && p.hc_level <= c.hc_level_max,
                        "level {level} asks for an hc_level the advanced entry point rejects");
            }
        }
    }

    #[test]
    fn format_constants_match_c() {
        let c = describe_usize(clz4_abi_format);
        let want = vec![
            CRUSHLZ4_BLOCK_SIZE,
            CRUSHLZ4_MIN_MATCH,
            CRUSHLZ4_MAX_OFFSET,
            CRUSHLZ4_MAGIC_COMPRESSED as usize,
            CRUSHLZ4_MAGIC_STORED as usize,
            CRUSHLZ4_MAGIC_END as usize,
        ];
        assert_eq!(c.len(), want.len(), "the C format descriptor changed length");
        assert_eq!(c, want, "frame/block constants differ from crushlz4.h");
        assert_eq!(CRUSHLZ4_MAGIC_COMPRESSED.to_le_bytes(), *b"bv41");
        assert_eq!(CRUSHLZ4_MAGIC_STORED.to_le_bytes(), *b"bv4-");
        assert_eq!(CRUSHLZ4_MAGIC_END.to_le_bytes(), *b"bv4$");
    }
}
