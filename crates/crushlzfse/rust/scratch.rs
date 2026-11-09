// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use std::os::raw::c_void;

use crate::ffi;
use crate::params::{BLOCK_SIZE, Level, Params, scratch_size};
use crate::Error;

/// Reusable working memory for the LZFSE encoder.
///
/// Starts empty and grows to [`scratch_size`] of whatever params a compress
/// call uses, then stays that size, so a loop over many buffers allocates
/// once. One `Scratch` per thread is the intended pattern; it is `Send` but
/// a compress call needs it exclusively.
#[derive(Debug, Default)]
pub struct Scratch {
    // u64 rather than u8 so the buffer is 8-byte aligned, which is what the
    // C side's carve-up of the region assumes.
    buf: Vec<u64>,
}

impl Scratch {
    /// An empty scratch; the first compress call sizes it.
    pub fn new() -> Scratch {
        Scratch { buf: Vec::new() }
    }

    /// A pointer to at least `bytes` bytes of scratch, growing if needed.
    pub(crate) fn reserve(&mut self, bytes: usize) -> *mut c_void {
        let words = bytes.div_ceil(8);
        if self.buf.len() < words {
            self.buf.resize(words, 0);
        }
        self.buf.as_mut_ptr().cast()
    }

    /// Usable bytes behind the pointer `reserve` returned.
    pub(crate) fn bytes(&self) -> usize {
        self.buf.len() * 8
    }
}

/// An output size that always fits an encode of `src_len` bytes with
/// `params`. Every strategy shares the one fixed [`BLOCK_SIZE`], so the
/// bound does not actually vary by strategy; pass the same params the
/// encode call itself will use.
pub fn compress_bound(src_len: usize, params: &Params) -> usize {
    let raw = params.to_raw();
    // SAFETY: `raw` is a fully initialized params struct that outlives the call.
    unsafe { ffi::crushlzfse_encode_bound(src_len, &raw) }
}

/// Compresses `src` at `level` into a new `Vec`.
pub fn compress(src: &[u8], level: Level) -> Result<Vec<u8>, Error> {
    compress_with(src, &Params::for_level(level).0)
}

/// Compresses `src` with explicit params into a new `Vec`.
pub fn compress_with(src: &[u8], params: &Params) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; compress_bound(src.len(), params)];
    let n = compress_into_with(&mut out, src, params, &mut Scratch::new())?;
    out.truncate(n);
    Ok(out)
}

/// Compresses `src` at `level` into `dst`, returning the bytes written.
///
/// Fails with [`Error::OutputTooSmall`] when `dst` is shorter than
/// [`compress_bound`] of the input and the stream did not fit.
pub fn compress_into(dst: &mut [u8], src: &[u8], level: Level, scratch: &mut Scratch) -> Result<usize, Error> {
    compress_into_with(dst, src, &Params::for_level(level).0, scratch)
}

/// Compresses `src` with explicit params into `dst`, returning the bytes
/// written.
///
/// Fails with [`Error::InputTooLarge`] when `src` is longer than
/// [`BLOCK_SIZE`], whatever the strategy, rather than reporting a bare
/// [`Error::Encode`] for what is actually a caller-contract mismatch.
pub fn compress_into_with(
    dst: &mut [u8],
    src: &[u8],
    params: &Params,
    scratch: &mut Scratch,
) -> Result<usize, Error> {
    params.validate()?;
    if src.len() > BLOCK_SIZE {
        return Err(Error::InputTooLarge);
    }
    let raw = params.to_raw();
    // Sized from the same params the C side carves it with, so the buffer is
    // large enough by construction; the extent is passed anyway because C
    // checks it for every caller, not just this one.
    let mem = scratch.reserve(scratch_size(params));
    let bytes = scratch.bytes();
    // SAFETY: both slices are valid for their own lengths and the encoder
    // writes at most dst.len() bytes; `mem` points at `bytes` bytes that live
    // for the call; `raw` is fully initialised and outlives the call.
    let n = unsafe {
        ffi::crushlzfse_encode_buffer_advanced(dst.as_mut_ptr().cast(), dst.len(), src.as_ptr().cast(), src.len(), mem, bytes, &raw)
    };
    encode_result(n, dst.len(), src.len(), params)
}

fn encode_result(n: usize, dst_len: usize, src_len: usize, params: &Params) -> Result<usize, Error> {
    if n != 0 {
        Ok(n)
    } else if dst_len < compress_bound(src_len, params) {
        Err(Error::OutputTooSmall { written: 0 })
    } else {
        Err(Error::Encode)
    }
}

/// Symbol statistics carried from one chunk's encode to the next, for
/// [`compress_into_chained`].
///
/// The contents are opaque. [`Stats::default`] is an empty chain: the first
/// chunk encodes exactly as [`compress_into_with`] would.
#[derive(Clone)]
pub struct Stats(ffi::RawStats);

impl Default for Stats {
    fn default() -> Stats {
        Stats(ffi::RawStats { opaque: [0; ffi::CRUSHLZFSE_STATS_WORDS] })
    }
}

impl std::fmt::Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stats").field("seeded", &(self.0.opaque[0] != 0)).finish_non_exhaustive()
    }
}

/// Compresses `src` with explicit params into `dst`, seeded by the chunk
/// before it in the chain, returning the bytes written.
///
/// For a file encoded as a run of [`BLOCK_SIZE`] chunks: pass one `Stats`,
/// starting from [`Stats::default`], to each chunk's call in order. The
/// optimal levels (6 to 11) start their parse from the previous chunk's
/// statistics, which is denser; every level updates `stats`. Each output is
/// still a complete stream any LZFSE decoder reads on its own, but its bytes
/// depend on the chunks before it, so start a new chain wherever chunks may
/// be encoded separately. `stats` is reset on any error, and when the chunk
/// is stored as LZVN or raw, so the next chunk runs unseeded.
///
/// Fails as [`compress_into_with`] does.
pub fn compress_into_chained(
    dst: &mut [u8],
    src: &[u8],
    params: &Params,
    scratch: &mut Scratch,
    stats: &mut Stats,
) -> Result<usize, Error> {
    if let Err(e) = params.validate() {
        *stats = Stats::default();
        return Err(e);
    }
    if src.len() > BLOCK_SIZE {
        *stats = Stats::default();
        return Err(Error::InputTooLarge);
    }
    let raw = params.to_raw();
    let mem = scratch.reserve(scratch_size(params));
    let bytes = scratch.bytes();
    // SAFETY: as in compress_into_with; `stats.0` is a live, exclusively
    // borrowed mirror of crushlzfse_stats, whose contents C accepts whatever
    // they are.
    let n = unsafe {
        ffi::crushlzfse_encode_buffer_chained(
            dst.as_mut_ptr().cast(),
            dst.len(),
            src.as_ptr().cast(),
            src.len(),
            mem,
            bytes,
            &raw,
            &mut stats.0,
        )
    };
    encode_result(n, dst.len(), src.len(), params)
}
