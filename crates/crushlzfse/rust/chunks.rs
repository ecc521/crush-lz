// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Error;
use crate::params::{BLOCK_SIZE, Params};
use crate::scratch::{Scratch, Stats, compress_bound, compress_into_chained};

/// The segment [`compress_chunks`] uses with more than one thread when the
/// caller does not choose one.
pub const DEFAULT_SEGMENT_SIZE: usize = 512 * 1024;

/// One segment's chunk streams, in order.
type SegmentOut = Result<Vec<Vec<u8>>, Error>;

/// Compresses `src` as a run of [`BLOCK_SIZE`] chunks, one complete stream
/// per chunk (the last may be shorter), chaining statistics from each chunk
/// to the next as [`compress_into_chained`] does.
///
/// The chain restarts every `segment` bytes, rounded down to whole chunks,
/// and segments run in parallel on `threads` threads (0 means one per core).
/// `segment` of `None` means one chain over the whole input when `threads`
/// is 1, and [`DEFAULT_SEGMENT_SIZE`] otherwise; `Some(0)` is always one
/// chain. The output depends on `params` and the segment size, never on how
/// many threads run, so any `threads` other than 1 gives the same bytes.
/// Longer segments compress better; shorter ones spread a file over more
/// cores.
pub fn compress_chunks(
    src: &[u8],
    params: &Params,
    threads: usize,
    segment: Option<usize>,
) -> Result<Vec<Vec<u8>>, Error> {
    params.validate()?;
    let n_chunks = src.len().div_ceil(BLOCK_SIZE);
    let seg_chunks = match segment {
        None if threads == 1 => n_chunks,
        None => DEFAULT_SEGMENT_SIZE / BLOCK_SIZE,
        Some(0) => n_chunks,
        Some(n) => n / BLOCK_SIZE,
    }
    .max(1);
    let n_segs = n_chunks.div_ceil(seg_chunks);
    let threads = if threads == 0 {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    } else {
        threads
    };
    let workers = threads.min(n_segs).max(1);

    // Segments are handed out from one counter, so faster cores take more.
    let next = AtomicUsize::new(0);
    let work = || {
        let mut scratch = Scratch::new();
        let mut dst = vec![0u8; compress_bound(BLOCK_SIZE, params)];
        let mut done = Vec::new();
        loop {
            let seg = next.fetch_add(1, Ordering::Relaxed);
            if seg >= n_segs {
                break;
            }
            let start = seg * seg_chunks * BLOCK_SIZE;
            let end = (start + seg_chunks * BLOCK_SIZE).min(src.len());
            let mut stats = Stats::default();
            let out = src[start..end]
                .chunks(BLOCK_SIZE)
                .map(|chunk| {
                    let n =
                        compress_into_chained(&mut dst, chunk, params, &mut scratch, &mut stats)?;
                    Ok(dst[..n].to_vec())
                })
                .collect::<Result<Vec<_>, Error>>();
            done.push((seg, out));
        }
        done
    };

    let mut segs: Vec<Option<SegmentOut>> = (0..n_segs).map(|_| None).collect();
    let mut place = |done: Vec<(usize, SegmentOut)>| {
        for (seg, out) in done {
            segs[seg] = Some(out);
        }
    };
    if workers == 1 {
        place(work());
    } else {
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers).map(|_| scope.spawn(work)).collect();
            for h in handles {
                place(h.join().expect("lzfse worker thread panicked"));
            }
        });
    }

    let mut chunks = Vec::with_capacity(n_chunks);
    for seg in segs {
        chunks.extend(seg.expect("every segment was claimed")?);
    }
    Ok(chunks)
}
