// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::Error;
use crate::ffi;
use crate::params::{Level, Params};
use crate::scratch::Scratch;

/// Input bytes per chunk. A stream for `n` input bytes has
/// `n.div_ceil(CHUNK_SIZE) + 1` chunks, the last being the terminator.
pub const CHUNK_SIZE: usize = ffi::CRUSHLZBITMAP_CHUNK_SIZE;

/// The number of chunks a stream for `src_len` input bytes has.
fn chunk_count(src_len: usize) -> usize {
    src_len.div_ceil(CHUNK_SIZE) + 1
}

/// Emits chunk `index` of the stream for the whole input `src`: the stream
/// header comes with chunk 0 and the terminator is the chunk past the
/// input. Concatenating chunks `0..chunk_count` in order gives exactly what
/// [`compress_with`](crate::compress_with) would.
pub fn compress_chunk(src: &[u8], index: usize, params: &Params, scratch: &mut Scratch) -> Result<Vec<u8>, Error> {
    if index.checked_mul(CHUNK_SIZE).is_none() {
        return Err(Error::Encode);
    }
    // See compress_into_with: crushlzbitmap_scratch_size does not validate
    // max_candidates itself, so this must run before scratch is sized from
    // `params` below, not just before the encode call.
    params.validate()?;
    let raw = params.to_raw();
    let mut dst = vec![0u8; ffi::CRUSHLZBITMAP_MAX_CHUNK_SIZE];
    // Same sizing as compress_into_with: taken from the params the encoder
    // carves with, so a chunk call can never present a buffer that is too
    // small for the level it was handed.
    let mem = scratch.reserve(crate::scratch::scratch_size(params));
    let bytes = scratch.bytes();
    // SAFETY: `dst` is the size the chunk encoder requires and `src` is
    // valid for its length; `raw` outlives the call; `mem` points at `bytes`
    // bytes at the alignment the encoder asks for.
    let n = unsafe {
        ffi::crushlzbitmap_encode_chunk(
            dst.as_mut_ptr().cast(),
            dst.len(),
            src.as_ptr().cast(),
            src.len(),
            index,
            mem,
            bytes,
            &raw,
        )
    };
    if n == 0 {
        return Err(Error::InvalidParams);
    }
    dst.truncate(n);
    Ok(dst)
}

/// Compresses `src` at `level` with its chunks spread across `threads`
/// threads (0 means one per core via
/// [`std::thread::available_parallelism`]), one [`Scratch`] each. The output
/// is byte-identical to [`compress`](crate::compress).
pub fn compress_parallel(src: &[u8], level: Level, threads: usize) -> Result<Vec<u8>, Error> {
    let (params, _) = Params::for_level(level);
    let n_chunks = chunk_count(src.len());
    let threads = if threads == 0 { std::thread::available_parallelism().map_or(1, |n| n.get()) } else { threads };
    let n_threads = threads.min(n_chunks);

    // Chunks are handed out from one counter, so faster cores take more.
    let next = AtomicUsize::new(0);
    let work = || {
        let mut scratch = Scratch::new();
        let mut done = Vec::new();
        loop {
            let idx = next.fetch_add(1, Ordering::Relaxed);
            if idx >= n_chunks {
                break;
            }
            done.push((idx, compress_chunk(src, idx, &params, &mut scratch)));
        }
        done
    };

    let mut chunks: Vec<Option<Result<Vec<u8>, Error>>> = (0..n_chunks).map(|_| None).collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..n_threads).map(|_| scope.spawn(work)).collect();
        for h in handles {
            for (idx, result) in h.join().expect("lzbitmap worker thread panicked") {
                chunks[idx] = Some(result);
            }
        }
    });

    let mut out = Vec::new();
    for slot in chunks {
        out.extend_from_slice(&slot.expect("every chunk index was assigned to a thread")?);
    }
    Ok(out)
}
