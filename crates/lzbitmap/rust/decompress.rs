// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use crate::error::Error;
use crate::ffi;

/// Allocates `n` zeroed bytes, reporting [`Error::OutputTooSmall`] instead
/// of aborting the process when the allocator can't back them.
pub(crate) fn try_zeroed(n: usize) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::OutputTooSmall { written: 0 })?;
    v.resize(n, 0); // capacity is already reserved; this cannot reallocate
    Ok(v)
}

/// Decompresses `src` into `dst`, returning the bytes written.
pub fn decompress_into(dst: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    let mut out_len = 0usize;
    // SAFETY: `dst` and `src` are valid for their lengths for the call and
    // `out_len` is a valid out-pointer.
    let rc = unsafe {
        ffi::crushlzbitmap_decode_buffer(dst.as_mut_ptr().cast(), dst.len(), src.as_ptr().cast(), src.len(), &mut out_len)
    };
    match rc {
        0 => Ok(out_len),
        // out_len is set here too: bytes decoded from every chunk fully
        // completed before the one that didn't fit.
        ffi::CRUSHLZBITMAP_OUTPUT_TOO_SMALL => Err(Error::OutputTooSmall { written: out_len }),
        ffi::CRUSHLZBITMAP_INVALID => Err(Error::InvalidInput),
        _ => Err(Error::InvalidInput),
    }
}

/// The exact decoded length of `src`, without decoding any chunk body: each
/// chunk header carries its own decoded length, so this just walks headers
/// and sums them. Fails [`Error::OutputTooSmall`] once the running total
/// would exceed `max_len`; pass `usize::MAX` for no cap.
pub fn decoded_len(src: &[u8], max_len: usize) -> Result<usize, Error> {
    let mut out_len = 0usize;
    // SAFETY: a NULL dst tells the C side to walk chunk headers only, never
    // dereferencing it; `src` is valid for its length and `out_len` is a
    // valid out-pointer.
    let rc = unsafe {
        ffi::crushlzbitmap_decode_buffer(std::ptr::null_mut(), max_len, src.as_ptr().cast(), src.len(), &mut out_len)
    };
    match rc {
        0 => Ok(out_len),
        // out_len is set here too: bytes decoded from every chunk fully
        // completed before the one that didn't fit.
        ffi::CRUSHLZBITMAP_OUTPUT_TOO_SMALL => Err(Error::OutputTooSmall { written: out_len }),
        ffi::CRUSHLZBITMAP_INVALID => Err(Error::InvalidInput),
        _ => Err(Error::InvalidInput),
    }
}

/// Decompresses a whole stream into a new buffer, sized exactly from
/// [`decoded_len`] rather than guessed at.
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, Error> {
    let out_len = decoded_len(src, usize::MAX)?;
    let mut dst = try_zeroed(out_len)?;
    let n = decompress_into(&mut dst, src)?;
    dst.truncate(n);
    Ok(dst)
}
