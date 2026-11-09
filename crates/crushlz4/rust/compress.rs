// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use crate::error::Error;
use crate::ffi;
use crate::params::{Level, Params, scratch_size};
use crate::scratch::Scratch;

/// An output size that always fits any input of `src_len` bytes.
pub fn compress_bound(src_len: usize) -> usize {
    // SAFETY: pure arithmetic over its argument.
    unsafe { ffi::crushlz4_encode_bound(src_len) }
}

/// Compresses `src` at `level` into a new buffer: a complete `bv4` stream
/// that Apple's `COMPRESSION_LZ4` decoder accepts.
pub fn compress(src: &[u8], level: Level) -> Result<Vec<u8>, Error> {
    let mut dst = vec![0u8; compress_bound(src.len())];
    let n = compress_into(&mut dst, src, level, &mut Scratch::new())?;
    dst.truncate(n);
    Ok(dst)
}

/// Compresses `src` at `level` into `dst`, returning the bytes written.
/// `dst` needs [`compress_bound`]`(src.len())` bytes to be certain to fit.
pub fn compress_into(dst: &mut [u8], src: &[u8], level: Level, scratch: &mut Scratch) -> Result<usize, Error> {
    compress_into_with(dst, src, &Params::for_level(level).0, scratch)
}

/// Compresses `src` with explicit params into a new buffer. Params outside
/// what [`capabilities`](crate::capabilities) reports are rejected.
pub fn compress_with(src: &[u8], params: &Params) -> Result<Vec<u8>, Error> {
    let mut dst = vec![0u8; compress_bound(src.len())];
    let n = compress_into_with(&mut dst, src, params, &mut Scratch::new())?;
    dst.truncate(n);
    Ok(dst)
}

/// Compresses `src` with explicit params into `dst`, returning the bytes
/// written.
pub fn compress_into_with(
    dst: &mut [u8],
    src: &[u8],
    params: &Params,
    scratch: &mut Scratch,
) -> Result<usize, Error> {
    // A zero here means the params are out of range; reporting that first
    // keeps a short dst from masking it.
    let need = scratch_size(params);
    if need == 0 {
        return Err(Error::InvalidParams);
    }
    let raw = params.to_raw();
    // Sized from the same params the C side carves it with, so the buffer is
    // large enough by construction; the extent is passed anyway because C
    // checks it for every caller, not just this one.
    let mem = scratch.reserve(need);
    let bytes = scratch.bytes();
    // SAFETY: `dst` and `src` are valid for their lengths for the call; `mem`
    // points at `bytes` bytes that live for the call; `raw` is fully
    // initialised and outlives it.
    let n = unsafe {
        ffi::crushlz4_encode_buffer_advanced(
            dst.as_mut_ptr().cast(),
            dst.len(),
            src.as_ptr().cast(),
            src.len(),
            mem,
            bytes,
            &raw,
        )
    };
    if n > 0 {
        Ok(n)
    } else if dst.len() < compress_bound(src.len()) {
        Err(Error::OutputTooSmall { written: 0 })
    } else {
        Err(Error::Encode)
    }
}
