// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use crate::error::Error;
use crate::ffi;
use crate::params::{Level, Params};
use crate::scratch::Scratch;

/// An output size that always fits any input of `src_len` bytes.
pub fn compress_bound(src_len: usize) -> usize {
    // SAFETY: pure arithmetic over its argument.
    unsafe { ffi::crushlzbitmap_encode_bound(src_len) }
}

/// Maps a zero return from an encoder: a short `dst` is the likely cause
/// when it is under the bound, otherwise `otherwise` names the failure.
fn encode_failure(dst_len: usize, src_len: usize, otherwise: Error) -> Error {
    if dst_len < compress_bound(src_len) { Error::OutputTooSmall { written: 0 } } else { otherwise }
}

/// Compresses `src` at `level` into a new buffer.
pub fn compress(src: &[u8], level: Level) -> Result<Vec<u8>, Error> {
    let mut dst = vec![0u8; compress_bound(src.len())];
    let n = compress_into(&mut dst, src, level, &mut Scratch::new())?;
    dst.truncate(n);
    Ok(dst)
}

/// Compresses `src` at `level` into `dst`, returning the bytes written.
/// `dst` needs [`compress_bound`]`(src.len())` bytes to be certain to fit.
pub fn compress_into(dst: &mut [u8], src: &[u8], level: Level, scratch: &mut Scratch) -> Result<usize, Error> {
    // A level always resolves to valid params, so this cannot report
    // InvalidParams; going through one path keeps the scratch sizing in one
    // place, as crushlzfse does.
    compress_into_with(dst, src, &Params::for_level(level).0, scratch)
}

/// Compresses `src` with explicit [`Params`] into a new buffer.
pub fn compress_with(src: &[u8], params: &Params) -> Result<Vec<u8>, Error> {
    let mut dst = vec![0u8; compress_bound(src.len())];
    let n = compress_into_with(&mut dst, src, params, &mut Scratch::new())?;
    dst.truncate(n);
    Ok(dst)
}

/// Compresses `src` with explicit [`Params`] into `dst`, returning the
/// bytes written.
pub fn compress_into_with(dst: &mut [u8], src: &[u8], params: &Params, scratch: &mut Scratch) -> Result<usize, Error> {
    // Checked before scratch is sized from these params, not just before the
    // encode call: crushlzbitmap_scratch_size does not validate max_candidates
    // itself (unlike its crushlzfse sibling).
    params.validate()?;
    let raw = params.to_raw();
    // Sized from the same params the C side carves it with, including the DP
    // candidate tables, which hand-built params can push past any level's
    // need, so the buffer is large enough by construction. The extent goes
    // across anyway, because C checks it for every caller, not just this one.
    let mem = scratch.reserve(crate::scratch::scratch_size(params));
    let bytes = scratch.bytes();
    // SAFETY: `dst` and `src` are valid for their lengths for the call;
    // `raw` is a fully initialized params struct that outlives it;
    // `mem` points at `bytes` bytes at the alignment the encoder asks for.
    let n = unsafe {
        ffi::crushlzbitmap_encode_buffer_advanced(
            dst.as_mut_ptr().cast(),
            dst.len(),
            src.as_ptr().cast(),
            src.len(),
            mem,
            bytes,
            &raw,
        )
    };
    if n == 0 { Err(encode_failure(dst.len(), src.len(), Error::InvalidParams)) } else { Ok(n) }
}
