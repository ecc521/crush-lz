// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use crate::Error;
use crate::ffi;

/// Allocates `n` zeroed bytes, reporting [`Error::OutputTooSmall`] instead
/// of aborting the process when the allocator can't back them.
fn try_zeroed(n: usize) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::OutputTooSmall { written: 0 })?;
    v.resize(n, 0); // capacity is already reserved; this cannot reallocate
    Ok(v)
}

/// Decompresses an LZFSE stream into a new `Vec`.
///
/// Sized from the block headers' declared totals when those walk cleanly to
/// an end-of-stream marker. If that hint is wrong (the declared size is
/// never cross-checked against the real output) or absent, the buffer
/// doubles until the output fits.
///
/// No size cap: a claim bigger than this machine can back is
/// [`Error::OutputTooSmall`], not a crash. Use [`decompress_into`] for a
/// hard limit.
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, Error> {
    if let Some(hint) = declared_len(src) {
        let mut dst = try_zeroed(hint)?;
        match decompress_into(&mut dst, src) {
            Ok(n) => {
                dst.truncate(n);
                return Ok(dst);
            }
            Err(Error::OutputTooSmall { .. }) => {}
            Err(e) => return Err(e),
        }
    }
    grow(src, decompress_into)
}

/// Decompresses an LZFSE stream into `dst`, returning the bytes written.
///
/// `dst` must hold the whole output: a partial fill is reported as
/// [`Error::OutputTooSmall`], a malformed stream as [`Error::InvalidInput`].
pub fn decompress_into(dst: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    let mut out_len = 0usize;
    // SAFETY: both slices are valid for their own lengths, the decoder
    // writes at most dst.len() bytes, and `out_len` is a valid out-pointer.
    let status = unsafe {
        ffi::crushlzfse_decode_buffer(dst.as_mut_ptr().cast(), dst.len(), src.as_ptr().cast(), src.len(), &mut out_len)
    };
    match status {
        0 => Ok(out_len),
        // out_len is the exact position the decoder would resume from given more room.
        ffi::CRUSHLZFSE_OUTPUT_TOO_SMALL => Err(Error::OutputTooSmall { written: out_len }),
        ffi::CRUSHLZFSE_INVALID => Err(Error::InvalidInput),
        // Anything a future library adds is a stream we cannot decode.
        _ => Err(Error::InvalidInput),
    }
}

/// Sums each block's declared decoded size by walking headers only, without
/// touching any literal or match payload. `None` means the blocks didn't
/// walk cleanly to an end-of-stream marker (unknown magic, a length past
/// `src`, or a header that fails validation); [`decompress`] falls back to
/// the decoder itself in that case.
///
/// A block's declared size is never cross-checked against its real output,
/// so the total returned can be arbitrarily wrong. `decompress`'s
/// allocation attempt is what handles a claim too large to back, not this
/// function.
fn declared_len(src: &[u8]) -> Option<usize> {
    let mut out_len = 0usize;
    // SAFETY: `start..end` bounds exactly `src`'s own bytes (`add(len)` on a
    // slice's start pointer is always in-bounds-or-one-past-the-end, valid
    // even for an empty slice), and the C side never reads past `end`.
    // `out_len` is a valid out-pointer.
    let rc = unsafe {
        let start = src.as_ptr();
        let end = start.add(src.len());
        ffi::lzfse_declared_len(start, end, &mut out_len)
    };
    (rc == 0).then_some(out_len)
}

/// Runs `into` against a buffer that doubles on [`Error::OutputTooSmall`],
/// with no ceiling of its own: growth only ever stops at either success
/// or an allocation [`try_zeroed`] can't satisfy. Shared by both codecs'
/// `decompress`.
pub(crate) fn grow(src: &[u8], into: fn(&mut [u8], &[u8]) -> Result<usize, Error>) -> Result<Vec<u8>, Error> {
    let mut cap = src.len().saturating_mul(4).max(65_536);
    loop {
        let mut out = try_zeroed(cap)?;
        match into(&mut out, src) {
            Ok(n) => {
                out.truncate(n);
                return Ok(out);
            }
            Err(Error::OutputTooSmall { written }) => match next_cap(cap) {
                Some(next) => cap = next,
                // Already at usize::MAX and still not enough: nothing left
                // to try. `written` here is whatever this last, largest
                // attempt itself reached, the most information available.
                None => return Err(Error::OutputTooSmall { written }),
            },
            Err(e) => return Err(e),
        }
    }
}

/// The next capacity `grow` tries, or `None` once doubling has saturated at
/// `usize::MAX` and there is nothing bigger left to attempt.
fn next_cap(cap: usize) -> Option<usize> {
    let next = cap.saturating_mul(2);
    (next != cap).then_some(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BLOCK_SIZE, Level, compress};

    fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i / 7) ^ (i * 31)) as u8).collect()
    }

    #[test]
    fn declared_len_matches_the_real_size_at_every_level() {
        // Every size here must fit in the one fixed BLOCK_SIZE compress()
        // allows per call; sizes past it are Error::InputTooLarge, covered
        // in scratch.rs's own tests, not this one.
        for len in [0usize, 1, 1000, 4096, 65536] {
            let data = sample(len);
            for level in [Level::MIN, Level(0), Level::DEFAULT, Level::MAX] {
                let packed = compress(&data, level).unwrap();
                assert_eq!(declared_len(&packed), Some(len), "level {level:?} len {len}");
            }
        }
    }

    #[test]
    fn declared_len_declines_garbage() {
        assert_eq!(declared_len(b"not an lzfse stream"), None);
        assert_eq!(declared_len(&[]), None);
        assert_eq!(declared_len(b"bvx"), None, "too short even for a magic");
    }

    #[test]
    fn declared_len_declines_a_truncated_stream() {
        let packed = compress(&sample(BLOCK_SIZE), Level::MAX).unwrap();
        for cut in [4usize, packed.len() / 2, packed.len() - 1] {
            assert_eq!(declared_len(&packed[..cut]), None, "cut to {cut} bytes");
        }
    }

    /// A compressed block's `n_raw_bytes` sits right after its 4-byte magic
    /// in both v1 and v2, and nothing cross-checks it against the block's
    /// real output (`lzfse_decode_base.c`'s COMPRESSEDV1/V2 case never reads
    /// it). `declared_len` passes it through unclamped; the allocation
    /// attempt downstream is responsible for not crashing on a lie.
    #[test]
    fn declared_len_passes_a_lying_raw_bytes_field_straight_through() {
        // Above LZFSE_ENCODE_LZVN_THRESHOLD, so this is a real v1/v2 block
        // rather than the small-input LZVN fallback.
        let data = sample(4096);
        let mut packed = compress(&data, Level::MAX).unwrap();
        assert!(
            packed.starts_with(b"bvx1") || packed.starts_with(b"bvx2"),
            "expected a compressed block, got {:?}",
            &packed[..4]
        );
        packed[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(declared_len(&packed), Some(u32::MAX as usize));

        // A byte-for-byte copy of a valid v1/v2 block is itself valid, so
        // stacking 5 copies sums past a single block's u32 range, proving
        // the total is accumulated as a size_t rather than truncated.
        assert!(packed.ends_with(b"bvx$"));
        packed.truncate(packed.len() - 4); // drop the terminator, re-added once below
        let mut bomb = Vec::new();
        for _ in 0..5 {
            bomb.extend_from_slice(&packed);
        }
        bomb.extend_from_slice(b"bvx$");
        assert_eq!(declared_len(&bomb), Some(5 * u32::MAX as usize));

        // decompress() must not crash on an unclamped lie either. Uses a
        // moderate overclaim rather than the multi-GiB bomb above, since
        // decompress() actually allocates the hint before decoding.
        packed[4..8].copy_from_slice(&(100 * data.len() as u32).to_le_bytes());
        packed.extend_from_slice(b"bvx$");
        assert_eq!(decompress(&packed).unwrap(), data);
    }

    #[test]
    fn decompress_still_succeeds_when_a_later_block_lies_small() {
        // compress() only emits one block (BLOCK_SIZE caps a single call),
        // so a multi-block stream is spliced by hand from two independently
        // compressed pieces. The first block's n_raw_bytes ends up undersold,
        // so declared_len's sum comes up short and decompress() must recover
        // via the doubling fallback.
        let first = sample(BLOCK_SIZE);
        let second = sample(BLOCK_SIZE / 2);
        let mut packed = compress(&first, Level(8)).unwrap();
        assert!(packed.starts_with(b"bvx1") || packed.starts_with(b"bvx2"));
        assert!(packed.ends_with(b"bvx$"));
        packed.truncate(packed.len() - 4);
        packed.extend_from_slice(&compress(&second, Level(8)).unwrap());

        let real = u32::from_le_bytes(packed[4..8].try_into().unwrap());
        packed[4..8].copy_from_slice(&(real / 2).to_le_bytes());

        let mut data = first;
        data.extend_from_slice(&second);
        assert_eq!(decompress(&packed).unwrap(), data);
    }

    #[test]
    fn try_zeroed_reports_an_impossible_allocation_instead_of_aborting() {
        // Not achievable through any real stream (no format here can
        // claim this much from so little input), so this exercises the
        // allocation guard directly, against a size no real machine has.
        assert_eq!(try_zeroed(usize::MAX / 2).unwrap_err(), Error::OutputTooSmall { written: 0 });
    }

    /// `grow` itself isn't exercised to `usize::MAX` here: an `into` that
    /// never succeeds would really zero each doubling buffer, which takes
    /// tens of seconds once sizes reach the tens of gigabytes. This checks
    /// the termination arithmetic directly instead.
    #[test]
    fn next_cap_terminates_at_the_saturation_point() {
        assert_eq!(next_cap(1), Some(2));
        assert_eq!(next_cap(65_536), Some(131_072));
        assert_eq!(next_cap(1 << 62), Some(1 << 63));
        assert_eq!(next_cap(usize::MAX / 2 + 1), Some(usize::MAX), "doubling this saturates to, but isn't already at, usize::MAX");
        assert_eq!(next_cap(usize::MAX), None, "already at usize::MAX; doubling it changes nothing");
    }
}
