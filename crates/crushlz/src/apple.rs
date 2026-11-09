// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Decoding through Apple's `libcompression`, for cross-checking.
//!
//! macOS only. Everywhere else the whole module is absent and `--verify`
//! falls back to our decoder. 

use std::os::raw::{c_uint, c_void};

use crate::Algo;

#[link(name = "compression")]
unsafe extern "C" {
    fn compression_decode_buffer(
        dst_buffer: *mut u8,
        dst_size: usize,
        src_buffer: *const u8,
        src_size: usize,
        scratch_buffer: *mut c_void,
        algorithm: c_uint,
    ) -> usize;

    fn compression_decode_scratch_buffer_size(algorithm: c_uint) -> usize;
}

/// `COMPRESSION_LZFSE`, from `<compression.h>`.
const COMPRESSION_LZFSE: c_uint = 0x801;
/// `COMPRESSION_LZBITMAP`, from `<compression.h>`.
const COMPRESSION_LZBITMAP: c_uint = 0x702;
/// `COMPRESSION_LZVN`. Unlike the two above this is *not* in the public enum;
/// it was dropped from the SDK header while remaining implemented. Using it
/// therefore has to be conditional on the probe in [`lzvn_available`] rather
/// than assumed, since nothing stops a future release from retiring the value
/// or reassigning it.
const COMPRESSION_LZVN: c_uint = 0x900;
/// `COMPRESSION_LZ4`, from `<compression.h>`. In the public enum, so it needs
/// no probe of the kind LZVN does. decmpfs types 15/16 select it as of
/// macOS 27.0.
const COMPRESSION_LZ4: c_uint = 0x100;
/// `COMPRESSION_LZMESH`, algorithm enum `0xE05`.
const COMPRESSION_LZMESH: c_uint = 0xE05;

fn algorithm_for(algo: Algo) -> c_uint {
    match algo {
        Algo::Lzfse => COMPRESSION_LZFSE,
        Algo::Lzvn => COMPRESSION_LZVN,
        Algo::Lzbitmap => COMPRESSION_LZBITMAP,
        Algo::Lz4 => COMPRESSION_LZ4,
        Algo::Lzmesh => COMPRESSION_LZMESH,
    }
}

/// Decode `src` with Apple's decoder, expecting exactly `expected_len` bytes.
///
/// Returns `None` if Apple's decoder refuses the stream or produces a
/// different length. The destination is deliberately one byte larger than
/// expected: `compression_decode_buffer` reports `dst_size` both for an exact
/// fit and for a truncated result, so sizing it exactly would make "too long"
/// indistinguishable from "correct".
pub fn decode(algo: Algo, src: &[u8], expected_len: usize) -> Option<Vec<u8>> {
    let algorithm = algorithm_for(algo);

    // Apple's decoder reads scratch it never initialised on some malformed
    // streams, so with a NULL scratch its answer can depend on whatever the
    // allocator happened to hand back. Supplying a zeroed buffer pins it to
    // one reproducible behaviour. See the call-site comment in
    // harness/fuzz/lzbitmap_decode_diff_vs_apple.c.
    let scratch_size = unsafe { compression_decode_scratch_buffer_size(algorithm) };
    let mut scratch = vec![0u8; scratch_size];
    let scratch_ptr = if scratch_size == 0 {
        std::ptr::null_mut()
    } else {
        scratch.as_mut_ptr() as *mut c_void
    };

    let mut dst = vec![0u8; expected_len + 1];
    let n = unsafe {
        compression_decode_buffer(
            dst.as_mut_ptr(),
            dst.len(),
            src.as_ptr(),
            src.len(),
            scratch_ptr,
            algorithm,
        )
    };

    // 0 is both "failed" and "decoded nothing"; only the latter is a real
    // answer, and only when that is what we expected.
    if n == 0 && expected_len != 0 {
        return None;
    }
    if n != expected_len {
        return None;
    }
    dst.truncate(n);
    Some(dst)
}

/// A 64-byte pattern as Apple's own LZVN encoder emits it, so the probe does
/// not depend on our encoder.
const APPLE_LZVN_SAMPLE: [u8; 34] = [
    0xe0, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x38, 0x10, 0xf0, 0x13, 0xe3, 0x0d, 0x0e, 0x0f, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// Whether `libcompression` on this system decodes raw LZVN. The constant it
/// is asked for is a private one, so this checks rather than assumes.
pub fn lzvn_available() -> bool {
    use std::sync::OnceLock;
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let expected: Vec<u8> = (0..64u8).map(|i| i % 16).collect();
        decode(Algo::Lzvn, &APPLE_LZVN_SAMPLE, expected.len()).is_some_and(|back| back == expected)
    })
}

/// Whether Apple's decoder can be used to check `algo` on this build.
pub fn supports(algo: Algo) -> bool {
    match algo {
        Algo::Lzfse | Algo::Lzbitmap | Algo::Lz4 | Algo::Lzmesh => true,
        Algo::Lzvn => lzvn_available(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each format we claim to check must actually round-trip through Apple's
    /// decoder, or `--verify` is quietly weaker than it reports.
    #[test]
    fn apple_decodes_our_output() {
        // <=65536 bytes: every LZFSE/LZVN level now rejects anything larger
        // per call.
        let data: Vec<u8> = (0..65_536u32).map(|i| (i % 251) as u8).collect();
        for algo in [Algo::Lzfse, Algo::Lzbitmap, Algo::Lzvn, Algo::Lz4, Algo::Lzmesh] {
            if !supports(algo) {
                continue;
            }
            let encoded = crate::encode(algo, &data, 0).expect("encode failed");
            let back = decode(algo, &encoded, data.len());
            assert_eq!(back.as_deref(), Some(&data[..]), "{algo} did not survive Apple's decoder");
        }
    }

    /// The probe has to be decisive rather than merely not crashing: LZFSE and
    /// LZBITMAP are public constants and must always be usable here.
    #[test]
    fn public_constants_are_supported() {
        assert!(supports(Algo::Lzfse));
        assert!(supports(Algo::Lzbitmap));
    }
}
