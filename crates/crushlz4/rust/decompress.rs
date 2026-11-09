// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use crate::error::Error;
use crate::ffi;

/// LZ4's worst-case expansion, which bounds the size this crate will
/// allocate from a stream's headers before the decoder has validated them.
const MAX_EXPANSION: usize = 255;

/// Allocates `n` zeroed bytes, reporting [`Error::OutputTooSmall`] instead
/// of aborting the process when the allocator can't back them.
fn try_zeroed(n: usize) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::OutputTooSmall { written: 0 })?;
    v.resize(n, 0); // capacity is already reserved; this cannot reallocate
    Ok(v)
}

/// Decompresses `src` into `dst`, returning the bytes written.
pub fn decompress_into(dst: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    decode(dst.as_mut_ptr().cast(), dst.len(), src)
}

/// Runs the decoder; a null `dst` validates the stream and reports its
/// decoded size without writing. `dst_len` bounds that size either way, so a
/// null-dst probe still needs a real cap (or `usize::MAX` for none).
fn decode(dst: *mut std::os::raw::c_void, dst_len: usize, src: &[u8]) -> Result<usize, Error> {
    let mut out_len = 0usize;
    // SAFETY: `dst` is null or valid for `dst_len` bytes; `src` is valid for
    // its length; `out_len` is a valid out-pointer.
    let rc = unsafe { ffi::crushlz4_decode_buffer(dst, dst_len, src.as_ptr().cast(), src.len(), &mut out_len) };
    match rc {
        0 => Ok(out_len),
        // out_len is set here too: bytes decoded from every block fully
        // completed before the one that didn't fit.
        ffi::CRUSHLZ4_OUTPUT_TOO_SMALL => Err(Error::OutputTooSmall { written: out_len }),
        ffi::CRUSHLZ4_INVALID => Err(Error::InvalidInput),
        _ => Err(Error::InvalidInput),
    }
}

/// Sums the decoded sizes the `bv4` block headers declare, without decoding
/// anything. This is only an allocation hint: the decoder re-checks every
/// size it reads, and `None` (unknown magic, a length past the buffer, or a
/// total beyond [`MAX_EXPANSION`]) just means "ask the decoder instead".
fn declared_len(src: &[u8]) -> Option<usize> {
    let le32 = |at: usize| -> Option<u32> {
        src.get(at..at.checked_add(4)?).map(|b| u32::from_le_bytes(b.try_into().expect("slice of exactly 4 bytes")))
    };
    let ceiling = MAX_EXPANSION.checked_mul(src.len())?;
    let mut at = 0usize;
    let mut total = 0usize;

    loop {
        let magic = le32(at)?;
        if magic == ffi::CRUSHLZ4_MAGIC_END {
            return Some(total);
        }

        let decoded = le32(at.checked_add(4)?)? as usize;
        let advance = if magic == ffi::CRUSHLZ4_MAGIC_STORED {
            8usize.checked_add(decoded)?
        } else if magic == ffi::CRUSHLZ4_MAGIC_COMPRESSED {
            12usize.checked_add(le32(at.checked_add(8)?)? as usize)?
        } else {
            return None;
        };

        total = total.checked_add(decoded)?;
        if total > ceiling {
            return None;
        }
        at = at.checked_add(advance)?;
        if at > src.len() {
            return None;
        }
    }
}

/// Decompresses a whole `bv4` stream into a new buffer. The buffer is sized
/// from the block headers when they walk cleanly, and from the decoder's
/// own size report otherwise, so a lying header costs a second pass rather
/// than a wrong result.
///
/// Deliberately not a growth loop: a real decode attempt at a wrong size is
/// never cheaper than the null-dst [`decoded_len`] probe (it still moves
/// every byte a correctly sized one would, and a short buffer gets none of
/// that back), so a failed hint goes straight to the exact walk instead of
/// guessing a bigger size and retrying.
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

    let out_len = decoded_len(src, usize::MAX)?;
    let mut dst = try_zeroed(out_len)?;
    let n = decompress_into(&mut dst, src)?;
    dst.truncate(n);
    Ok(dst)
}

/// The exact decoded length of `src`, without decoding it, or
/// [`Error::OutputTooSmall`] once it would exceed `max_len`. Pass
/// `usize::MAX` for no cap.
///
/// A match's claimed length costs only bookkeeping here, so a stream of
/// few, long matches is cheap to size. It is not cheap in general, though:
/// every token is still walked one at a time (this path can't use the fast
/// block, which needs a real destination), so a stream of many short
/// literals/matches costs close to a real decode. [`decompress`] only
/// reaches this when the header hint doesn't check out.
pub fn decoded_len(src: &[u8], max_len: usize) -> Result<usize, Error> {
    decode(std::ptr::null_mut(), max_len, src)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Level, compress};

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

    /// Semi-compressible: real streams have both stored and compressed
    /// blocks and a mix of literals and matches.
    fn mixed(len: usize) -> Vec<u8> {
        let noise = pseudo_random(len);
        (0..len).map(|i| if i % 11 == 0 { noise[i] } else { b"crushlz-corpus"[i % 14] }).collect()
    }

    fn le32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    /// Decode via the exact two-call path only, bypassing the header hint;
    /// the differential reference for the fast path.
    fn decompress_exact(src: &[u8]) -> Result<Vec<u8>, Error> {
        let out_len = decoded_len(src, usize::MAX)?;
        let mut dst = vec![0u8; out_len];
        let n = decompress_into(&mut dst, src)?;
        dst.truncate(n);
        Ok(dst)
    }

    #[test]
    fn fast_and_exact_paths_agree() {
        for len in [0usize, 1, 3, 4, 17, 1000, 65_535, 65_536, 65_537, 200_000] {
            for data in [pseudo_random(len), mixed(len), vec![0u8; len]] {
                let stream = compress(&data, Level::DEFAULT).unwrap();
                assert_eq!(
                    decompress(&stream).unwrap(),
                    decompress_exact(&stream).unwrap(),
                    "len {len}: fast and exact paths disagree"
                );
                assert_eq!(decompress(&stream).unwrap(), data, "len {len}: round-trip mismatch");
            }
        }
    }

    #[test]
    fn header_claiming_more_than_the_block_holds_is_rejected() {
        let data = mixed(50_000);
        let stream = compress(&data, Level::DEFAULT).unwrap();
        assert_eq!(le32_at(&stream, 0), ffi::CRUSHLZ4_MAGIC_COMPRESSED, "expected a bv41 first block");

        for inflate in [1u32, 64, 4096] {
            let mut bad = stream.clone();
            let claimed = le32_at(&bad, 4) + inflate;
            bad[4..8].copy_from_slice(&claimed.to_le_bytes());

            match decompress(&bad) {
                Err(Error::InvalidInput) => {}
                Err(other) => panic!("+{inflate}: expected InvalidInput, got {other}"),
                Ok(out) => panic!("+{inflate}: accepted a lying header and returned {} bytes", out.len()),
            }
        }
    }

    #[test]
    fn header_claiming_less_than_the_block_holds_is_rejected() {
        let data = mixed(50_000);
        let stream = compress(&data, Level::DEFAULT).unwrap();
        assert_eq!(le32_at(&stream, 0), ffi::CRUSHLZ4_MAGIC_COMPRESSED);

        let mut bad = stream.clone();
        let claimed = le32_at(&bad, 4) - 1;
        bad[4..8].copy_from_slice(&claimed.to_le_bytes());

        match decompress(&bad) {
            Err(Error::InvalidInput) => {}
            Err(other) => panic!("expected InvalidInput, got {other}"),
            Ok(out) => panic!("accepted an undersized claim, returned {} bytes", out.len()),
        }
    }

    #[test]
    fn output_is_never_zero_padded() {
        for len in [1usize, 100, 65_537, 150_000] {
            let data = mixed(len);
            let stream = compress(&data, Level::DEFAULT).unwrap();
            let out = decompress(&stream).unwrap();
            assert_eq!(out.len(), data.len(), "len {len}: output length is not the input length");
            assert_eq!(out, data, "len {len}: content differs");
        }
    }

    #[test]
    fn absurd_declared_size_does_not_allocate() {
        let mut bomb = Vec::new();
        bomb.extend_from_slice(&ffi::CRUSHLZ4_MAGIC_COMPRESSED.to_le_bytes());
        bomb.extend_from_slice(&u32::MAX.to_le_bytes()); // decoded: 4 GiB
        bomb.extend_from_slice(&4u32.to_le_bytes()); // encoded: 4 bytes
        bomb.extend_from_slice(&[0u8; 4]);
        bomb.extend_from_slice(&ffi::CRUSHLZ4_MAGIC_END.to_le_bytes());

        assert_eq!(declared_len(&bomb), None, "a 4 GiB claim from a 20-byte stream must be declined");
        assert!(decompress(&bomb).is_err(), "the bomb stream must not decode successfully");
    }

    #[test]
    fn many_blocks_cannot_sum_past_the_ceiling() {
        let mut s = Vec::new();
        for _ in 0..64 {
            s.extend_from_slice(&ffi::CRUSHLZ4_MAGIC_COMPRESSED.to_le_bytes());
            s.extend_from_slice(&100_000_000u32.to_le_bytes());
            s.extend_from_slice(&4u32.to_le_bytes());
            s.extend_from_slice(&[0u8; 4]);
        }
        s.extend_from_slice(&ffi::CRUSHLZ4_MAGIC_END.to_le_bytes());

        assert_eq!(declared_len(&s), None, "64 x 100 MB claims from a ~1 KB stream must be declined");
        assert!(decompress(&s).is_err());
    }

    #[test]
    fn truncated_streams_are_rejected() {
        let data = mixed(80_000);
        let stream = compress(&data, Level::DEFAULT).unwrap();
        for cut in [1usize, 5, 13, stream.len() / 2, stream.len() - 4, stream.len() - 1] {
            let bad = &stream[..cut];
            if let Ok(out) = decompress(bad) {
                panic!("truncated stream at {cut} bytes decoded successfully, returning {} bytes", out.len());
            }
        }
    }

    #[test]
    fn garbage_is_rejected_by_both_paths_alike() {
        for len in [4usize, 12, 64, 4096] {
            let junk = pseudo_random(len);
            assert_eq!(
                decompress(&junk).is_err(),
                decompress_exact(&junk).is_err(),
                "len {len}: fast and exact paths disagree on whether garbage is valid"
            );
        }
    }

    #[test]
    fn unknown_magic_declines_the_hint() {
        let mut s = Vec::new();
        s.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        s.extend_from_slice(&1024u32.to_le_bytes());
        s.extend_from_slice(&ffi::CRUSHLZ4_MAGIC_END.to_le_bytes());
        assert_eq!(declared_len(&s), None);
        assert!(decompress(&s).is_err());
    }

    #[test]
    fn block_length_past_the_buffer_declines_the_hint() {
        let mut s = Vec::new();
        s.extend_from_slice(&ffi::CRUSHLZ4_MAGIC_STORED.to_le_bytes());
        s.extend_from_slice(&9_999u32.to_le_bytes()); // claims 9999 stored bytes
        s.extend_from_slice(&[0u8; 16]); // but only 16 are here
        assert_eq!(declared_len(&s), None);
    }

    #[test]
    fn terminator_only_stream_is_empty_not_an_error() {
        let s = ffi::CRUSHLZ4_MAGIC_END.to_le_bytes().to_vec();
        assert_eq!(declared_len(&s), Some(0));
        assert_eq!(decompress(&s).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn try_zeroed_reports_an_impossible_allocation_instead_of_aborting() {
        assert_eq!(try_zeroed(usize::MAX / 2).unwrap_err(), Error::OutputTooSmall { written: 0 });
    }

    #[test]
    fn decompress_into_reports_sizes() {
        let data = mixed(50_000);
        let stream = compress(&data, Level::DEFAULT).unwrap();
        let mut exact = vec![0u8; data.len()];
        assert_eq!(decompress_into(&mut exact, &stream).unwrap(), data.len());
        assert_eq!(exact, data);
        // 50_000 bytes is one whole block (< CRUSHLZ4_BLOCK_SIZE), so a
        // buffer one byte short fails before that block completes at all:
        // no prior block exists to have written anything real.
        let mut short = vec![0u8; data.len() - 1];
        assert_eq!(decompress_into(&mut short, &stream).unwrap_err(), Error::OutputTooSmall { written: 0 });
    }

    #[test]
    fn decoded_len_matches_the_real_size_and_honors_a_cap() {
        let data = mixed(150_000);
        let stream = compress(&data, Level::DEFAULT).unwrap();
        assert_eq!(decoded_len(&stream, usize::MAX).unwrap(), data.len());
        assert_eq!(decoded_len(&stream, data.len()).unwrap(), data.len());
        // 150_000 bytes is three blocks (64 KiB, 64 KiB, 18_928 bytes); one
        // byte short of the true total falls entirely within the last
        // block, so the first two (131_072 bytes) fully complete first.
        assert_eq!(
            decoded_len(&stream, data.len() - 1).unwrap_err(),
            Error::OutputTooSmall { written: 2 * ffi::CRUSHLZ4_BLOCK_SIZE }
        );
        assert_eq!(decoded_len(&stream, 0).unwrap_err(), Error::OutputTooSmall { written: 0 });
    }

    #[test]
    fn decoded_len_of_empty_stream_is_zero_even_capped_at_zero() {
        let stream = compress(&[], Level::DEFAULT).unwrap();
        assert_eq!(decoded_len(&stream, 0).unwrap(), 0);
    }
}
