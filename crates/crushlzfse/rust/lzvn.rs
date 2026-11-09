// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Raw LZVN, with no LZFSE framing around it.
//!
//! Same items as the crate root, for the LZVN bitstream. The output has no
//! header or magic, so it is not self-describing: whoever stores it has to
//! record that it is LZVN before handing it to [`decompress`].

use std::os::raw::c_void;

pub use crate::Error;
use crate::ffi;

/// An LZVN compression level.
///
/// Higher levels search harder for a denser stream and take longer to do
/// it. The value is passed to the encoder as is; out-of-range levels are
/// clamped to [`Level::MIN`]..=[`Level::MAX`] by the encoder, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Level(pub i32);

impl Level {
    /// The fastest, loosest level.
    pub const MIN: Level = Level(ffi::CRUSHLZVN_LEVEL_MIN);
    /// The slowest, densest level.
    pub const MAX: Level = Level(ffi::CRUSHLZVN_LEVEL_MAX);
    /// The level [`Default`] and the `crushlz` command line use.
    pub const DEFAULT: Level = Level(ffi::CRUSHLZVN_LEVEL_DEFAULT);
}

impl Default for Level {
    fn default() -> Self {
        Level::DEFAULT
    }
}

/// The fixed block size every encode call works over, Greedy or Optimal,
/// matching decmpfs's own chunk size: each output block must be
/// independently decodable in units this size. `compress_into_with` rejects
/// a longer `src` with [`Error::InputTooLarge`] rather than chunking or
/// streaming it.
pub const BLOCK_SIZE: usize = 65536;

/// Explicit LZVN encoder settings, for the cases a [`Level`] does not
/// express.
///
/// Start from [`Params::for_level`] and override the fields you want. Every
/// field is validated against [`capabilities`] before encoding; a value
/// outside its range fails with [`Error::InvalidParams`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Params {
    /// The LZFSE fast strategy's matching ([`crate::Params::Fast`]), used by
    /// the lowest levels: single-probe hash tables and a growing stride over
    /// unmatched input. Same fields and ranges.
    Fast {
        /// Log2 of each hash table's size.
        hash_bits: i32,
        /// Bytes hashed by the main table. At most 6 when `long_table` or
        /// `lazy` is set.
        min_match: i32,
        /// The stride over unmatched input grows by one per
        /// `2^skip_shift` bytes since the last match...
        skip_shift: i32,
        /// ...up to this many bytes.
        max_step: i32,
        /// Adds a second table hashed on 8 bytes, consulted first.
        long_table: bool,
        /// Tries up to two following bytes for a longer match before
        /// taking one.
        lazy: bool,
    },
    /// Single-pass hash-chain matching, used by the lower levels. A call
    /// with more than [`BLOCK_SIZE`] of input fails outright, the same as
    /// [`Params::Optimal`]: every output block must be independently
    /// decodable in one fixed 64 KiB unit, matching decmpfs's own chunk
    /// size.
    Greedy {
        /// Log2 of the hash table size.
        hash_bits: i32,
        /// Candidates kept per hash bucket.
        hash_width: i32,
    },
    /// Pareto-pruned optimal parse over a fixed 64 KiB block, used by the
    /// upper levels. Like [`Params::Greedy`], a call with more than
    /// [`BLOCK_SIZE`] of input fails outright: the caller (decmpfs) never
    /// hands one more than a single already-independent piece.
    Optimal {
        /// Match-tree nodes visited per position.
        search_depth: i32,
        /// Candidates stored per position.
        store_limit: i32,
        /// Log2 of the match tree's root count.
        hash_bits: i32,
        /// Parse states kept per position.
        pareto_k: i32,
    },
}

impl Params {
    /// The settings `level` stands for, and the level actually used: values
    /// outside [`Level::MIN`]`..=`[`Level::MAX`] clamp rather than error.
    pub fn for_level(level: Level) -> (Params, Level) {
        let mut raw = std::mem::MaybeUninit::<ffi::LzvnEncodeParams>::uninit();
        // SAFETY: crushlzvn_params_for_level fully initialises *out for any
        // level, clamping the level itself and returning what it clamped to.
        let (raw, used) = unsafe {
            let used = ffi::crushlzvn_params_for_level(level.0, raw.as_mut_ptr());
            (raw.assume_init(), used)
        };
        (Params::from_raw(raw), Level(used))
    }

    fn to_raw(self) -> ffi::LzvnEncodeParams {
        match self {
            Params::Fast { hash_bits, min_match, skip_shift, max_step, long_table, lazy } => ffi::LzvnEncodeParams {
                strategy: ffi::CRUSHLZVN_STRATEGY_FAST,
                p: ffi::LzvnParamsUnion {
                    fast: ffi::FastParams {
                        hash_bits,
                        min_match,
                        skip_shift,
                        max_step,
                        long_table: i32::from(long_table),
                        lazy: i32::from(lazy),
                    },
                },
            },
            Params::Greedy { hash_bits, hash_width } => ffi::LzvnEncodeParams {
                strategy: ffi::CRUSHLZVN_STRATEGY_GREEDY,
                p: ffi::LzvnParamsUnion { greedy: ffi::LzvnGreedyParams { hash_bits, hash_width } },
            },
            Params::Optimal { search_depth, store_limit, hash_bits, pareto_k } => ffi::LzvnEncodeParams {
                strategy: ffi::CRUSHLZVN_STRATEGY_OPTIMAL,
                p: ffi::LzvnParamsUnion {
                    optimal: ffi::LzvnOptimalParams { search_depth, store_limit, hash_bits, pareto_k },
                },
            },
        }
    }

    fn from_raw(raw: ffi::LzvnEncodeParams) -> Params {
        // SAFETY: the tag was written by crushlzvn_params_for_level, which
        // only ever produces one of the three strategies, and the union arm
        // read below is the one that tag names.
        unsafe {
            if raw.strategy == ffi::CRUSHLZVN_STRATEGY_FAST {
                let f = raw.p.fast;
                Params::Fast {
                    hash_bits: f.hash_bits,
                    min_match: f.min_match,
                    skip_shift: f.skip_shift,
                    max_step: f.max_step,
                    long_table: f.long_table != 0,
                    lazy: f.lazy != 0,
                }
            } else if raw.strategy == ffi::CRUSHLZVN_STRATEGY_GREEDY {
                let g = raw.p.greedy;
                Params::Greedy { hash_bits: g.hash_bits, hash_width: g.hash_width }
            } else {
                let o = raw.p.optimal;
                Params::Optimal {
                    search_depth: o.search_depth,
                    store_limit: o.store_limit,
                    hash_bits: o.hash_bits,
                    pareto_k: o.pareto_k,
                }
            }
        }
    }

    /// The same checks the encoder applies, so a rejected value is reported
    /// as [`Error::InvalidParams`] rather than a bare encode failure.
    fn validate(&self) -> Result<(), Error> {
        let c = capabilities();
        let within = |v: i32, (lo, hi): (i32, i32)| v >= lo && v <= hi;
        let ok = match *self {
            Params::Fast { hash_bits, min_match, skip_shift, max_step, long_table, lazy } => {
                within(hash_bits, c.fast_hash_bits)
                    && within(min_match, c.fast_min_match)
                    && (!(long_table || lazy) || min_match <= crate::params::FAST_MAX_MIN_MATCH_MODES)
                    && within(skip_shift, c.fast_skip_shift)
                    && within(max_step, c.fast_max_step)
            }
            Params::Greedy { hash_bits, hash_width } => {
                within(hash_bits, c.greedy_hash_bits) && within(hash_width, c.greedy_hash_width)
            }
            Params::Optimal { search_depth, store_limit, hash_bits, pareto_k } => {
                within(search_depth, c.search_depth)
                    && within(store_limit, c.store_limit)
                    && within(hash_bits, c.hash_bits)
                    && within(pareto_k, c.pareto_k)
            }
        };
        if ok { Ok(()) } else { Err(Error::InvalidParams) }
    }
}

/// The range every [`Params`] field is checked against in this build, each
/// as a `(min, max)` pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Capabilities {
    pub level_min: i32,
    pub level_max: i32,
    /// The level `Level::DEFAULT` stands for, reported by the library rather
    /// than mirrored from a header constant.
    pub level_default: i32,
    pub greedy_hash_bits: (i32, i32),
    pub greedy_hash_width: (i32, i32),
    pub search_depth: (i32, i32),
    pub store_limit: (i32, i32),
    pub hash_bits: (i32, i32),
    pub pareto_k: (i32, i32),
    pub fast_hash_bits: (i32, i32),
    /// With `long_table` or `lazy` set, the upper bound is 6 instead.
    pub fast_min_match: (i32, i32),
    pub fast_skip_shift: (i32, i32),
    pub fast_max_step: (i32, i32),
}

/// The ranges this build enforces for every [`Params`] field.
pub fn capabilities() -> Capabilities {
    // SAFETY: takes no arguments and returns a plain-data struct by value.
    let c = unsafe { ffi::crushlzvn_get_capabilities() };
    Capabilities {
        level_min: c.level_min,
        level_max: c.level_max,
        level_default: c.level_default,
        greedy_hash_bits: (c.greedy_hash_bits_min, c.greedy_hash_bits_max),
        greedy_hash_width: (c.greedy_hash_width_min, c.greedy_hash_width_max),
        search_depth: (c.search_depth_min, c.search_depth_max),
        store_limit: (c.store_limit_min, c.store_limit_max),
        hash_bits: (c.hash_bits_min, c.hash_bits_max),
        pareto_k: (c.pareto_k_min, c.pareto_k_max),
        fast_hash_bits: (c.fast_hash_bits_min, c.fast_hash_bits_max),
        fast_min_match: (c.fast_min_match_min, c.fast_min_match_max),
        fast_skip_shift: (c.fast_skip_shift_min, c.fast_skip_shift_max),
        fast_max_step: (c.fast_max_step_min, c.fast_max_step_max),
    }
}

/// Working memory, in bytes, an encode with these params uses.
///
/// This is what a [`Scratch`] grows to on the first call with these params.
/// It never scales with the input: every call's scratch is sized for the
/// one fixed 64 KiB block, not whatever `src` is.
pub fn scratch_size(params: &Params) -> usize {
    let raw = params.to_raw();
    // SAFETY: `raw` is fully initialised and outlives the call, which only
    // reads it.
    unsafe { ffi::crushlzvn_scratch_size(&raw) }
}

/// Reusable working memory for the LZVN encoder.
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

    fn reserve(&mut self, bytes: usize) -> *mut c_void {
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
    unsafe { ffi::crushlzvn_encode_bound(src_len, &raw) }
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
/// [`BLOCK_SIZE`], for either strategy, rather than reporting a bare
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
        ffi::crushlzvn_encode_buffer_advanced(dst.as_mut_ptr().cast(), dst.len(), src.as_ptr().cast(), src.len(), mem, bytes, &raw)
    };
    if n != 0 {
        Ok(n)
    } else if dst.len() < compress_bound(src.len(), params) {
        Err(Error::OutputTooSmall { written: 0 })
    } else {
        Err(Error::Encode)
    }
}

/// Decompresses a raw LZVN stream into a new `Vec`.
///
/// The stream carries neither a header nor its decoded size (unlike
/// LZFSE's own [`decompress`](crate::decompress), which can read one from
/// its block headers), so the caller has to know it is LZVN. The buffer
/// starts at a multiple of the input and doubles until the output fits,
/// with no size cap: a size along the way that's more than this machine can
/// back is [`Error::OutputTooSmall`], not a crash. Use [`decompress_into`]
/// instead for a hard limit, or whenever the size is already known.
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, Error> {
    crate::decode::grow(src, decompress_into)
}

/// Decompresses a raw LZVN stream into `dst`, returning the bytes written.
///
/// `dst` must hold the whole output: a partial fill is reported as
/// [`Error::OutputTooSmall`], a malformed stream as [`Error::InvalidInput`].
pub fn decompress_into(dst: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    let mut out_len = 0usize;
    // SAFETY: both slices are valid for their own lengths, the decoder
    // writes at most dst.len() bytes, and `out_len` is a valid out-pointer.
    let status = unsafe {
        ffi::crushlzvn_decode_buffer(dst.as_mut_ptr().cast(), dst.len(), src.as_ptr().cast(), src.len(), &mut out_len)
    };
    match status {
        0 => Ok(out_len),
        // out_len is set here too, byte-exact.
        ffi::CRUSHLZVN_OUTPUT_TOO_SMALL => Err(Error::OutputTooSmall { written: out_len }),
        ffi::CRUSHLZVN_INVALID => Err(Error::InvalidInput),
        // Anything a future library adds is a stream we cannot decode.
        _ => Err(Error::InvalidInput),
    }
}
