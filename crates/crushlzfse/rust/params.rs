// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use crate::Error;
use crate::ffi;

/// An LZFSE compression level.
///
/// Higher levels search harder for a denser stream and take longer to do
/// it. The value is passed to the encoder as is; out-of-range levels are
/// clamped to [`Level::MIN`]..=[`Level::MAX`] by the encoder, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Level(pub i32);

impl Level {
    /// The fastest, loosest level.
    pub const MIN: Level = Level(ffi::CRUSHLZFSE_LEVEL_MIN);
    /// The slowest, densest level.
    pub const MAX: Level = Level(ffi::CRUSHLZFSE_LEVEL_MAX);
    /// The level [`Default`] and the `crushlz` command line use.
    pub const DEFAULT: Level = Level(ffi::CRUSHLZFSE_LEVEL_DEFAULT);
}

impl Default for Level {
    fn default() -> Self {
        Level::DEFAULT
    }
}

/// The fixed block size every encode call works over, whatever the strategy,
/// matching decmpfs's own chunk size: each output block must be
/// independently decodable in units this size. `compress_into_with` rejects
/// a longer `src` with [`Error::InputTooLarge`] rather than chunking or
/// streaming it.
pub const BLOCK_SIZE: usize = 65536;

// The C encoder's ceiling on `Params::Fast::min_match` once `long_table` or
// `lazy` is set; capabilities() reports only the plain range.
pub(crate) const FAST_MAX_MIN_MATCH_MODES: i32 = 6;

/// Explicit encoder settings, for the cases a [`Level`] does not express.
///
/// Start from [`Params::for_level`] and override the fields you want. Every
/// field is validated against [`capabilities`] before encoding; a value
/// outside its range fails with [`Error::InvalidParams`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Params {
    /// Single-probe hash-table matching with a growing stride over
    /// unmatched input, used by the lowest levels. Like the other
    /// strategies, a call with more than [`BLOCK_SIZE`] of input fails
    /// outright.
    Fast {
        /// Log2 of each hash table's size.
        hash_bits: i32,
        /// Bytes hashed by the main table. Candidates are verified on 4
        /// bytes, so this sets what the table can find, not the shortest
        /// match taken. At most 6 when `long_table` or `lazy` is set.
        min_match: i32,
        /// The stride over unmatched input grows by one per
        /// `2^skip_shift` bytes since the last match...
        skip_shift: i32,
        /// ...up to this many bytes.
        max_step: i32,
        /// Adds a second table hashed on 8 bytes, consulted first.
        long_table: bool,
        /// Tries up to two following bytes for a match at least two bytes
        /// longer before taking one. A hit on the last match distance is
        /// taken as is.
        lazy: bool,
    },
    /// Lazy matching on a bucketed hash history, used by the levels around
    /// the default: each match is held while up to `lookahead` following
    /// positions are tried for a better-scoring one. A call with more than
    /// [`BLOCK_SIZE`] of input fails outright, the same as
    /// [`Params::Optimal`]: every output block must be independently
    /// decodable in one fixed 64 KiB unit, matching decmpfs's own chunk
    /// size.
    Lazy {
        /// Log2 of the hash table size.
        hash_bits: i32,
        /// Candidates kept per hash bucket, at most 64.
        hash_width: i32,
        /// Following positions tried for a better match, 0 to 2.
        lookahead: i32,
    },
    /// Cost-modelled optimal parse over a fixed 64 KiB block, used by the
    /// upper levels. Like [`Params::Lazy`], a call with more than
    /// [`BLOCK_SIZE`] of input fails outright: the caller (decmpfs) never
    /// hands one more than a single already-independent piece.
    Optimal {
        /// Match-tree nodes visited per position. Ratio saturates near 32.
        search_depth: i32,
        /// Cost-model refinement passes over each block.
        iterations: i32,
        /// Re-run the parse after the block has been split.
        enable_reparse: bool,
        /// Most blocks the voluntary split may commit a chunk to.
        split_max_blocks: i32,
        /// Log2 of the match tree's root count.
        hash_bits: i32,
        /// Candidates stored per position.
        store_limit: i32,
        /// Flat surcharge on every match edge, in 1/256-bit units; raises
        /// decode speed at a small cost in ratio.
        tuple_tax: i32,
        /// Per-position literal-run states allowed to take a literal step.
        max_live_buckets: i32,
        /// Hill-climb passes over each block's frequency tables, scored by
        /// exact payload and header bits; 0 is off.
        table_search: i32,
    },
}

impl Params {
    /// The settings `level` stands for, and the level actually used: values
    /// outside [`Level::MIN`]`..=`[`Level::MAX`] clamp rather than error.
    pub fn for_level(level: Level) -> (Params, Level) {
        let mut raw = std::mem::MaybeUninit::<ffi::EncodeParams>::uninit();
        // SAFETY: crushlzfse_params_for_level fully initialises *out for
        // any level, clamping the level itself and returning what it
        // clamped to.
        let (raw, used) = unsafe {
            let used = ffi::crushlzfse_params_for_level(level.0, raw.as_mut_ptr());
            (raw.assume_init(), used)
        };
        (Params::from_raw(raw), Level(used))
    }

    pub(crate) fn to_raw(self) -> ffi::EncodeParams {
        match self {
            Params::Fast { hash_bits, min_match, skip_shift, max_step, long_table, lazy } => ffi::EncodeParams {
                strategy: ffi::CRUSHLZFSE_STRATEGY_FAST,
                p: ffi::ParamsUnion {
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
            Params::Lazy { hash_bits, hash_width, lookahead } => ffi::EncodeParams {
                strategy: ffi::CRUSHLZFSE_STRATEGY_LAZY,
                p: ffi::ParamsUnion { lazy: ffi::LazyParams { hash_bits, hash_width, lookahead } },
            },
            Params::Optimal {
                search_depth,
                iterations,
                enable_reparse,
                split_max_blocks,
                hash_bits,
                store_limit,
                tuple_tax,
                max_live_buckets,
                table_search,
            } => ffi::EncodeParams {
                strategy: ffi::CRUSHLZFSE_STRATEGY_OPTIMAL,
                p: ffi::ParamsUnion {
                    optimal: ffi::OptimalParams {
                        search_depth,
                        iterations,
                        enable_reparse: i32::from(enable_reparse),
                        split_max_blocks,
                        hash_bits,
                        store_limit,
                        tuple_tax,
                        max_live_buckets,
                        table_search,
                    },
                },
            },
        }
    }

    fn from_raw(raw: ffi::EncodeParams) -> Params {
        // SAFETY: the tag was written by crushlzfse_params_for_level, which
        // only ever produces one of the three strategies, and the union arm
        // read below is the one that tag names.
        unsafe {
            if raw.strategy == ffi::CRUSHLZFSE_STRATEGY_FAST {
                let f = raw.p.fast;
                Params::Fast {
                    hash_bits: f.hash_bits,
                    min_match: f.min_match,
                    skip_shift: f.skip_shift,
                    max_step: f.max_step,
                    long_table: f.long_table != 0,
                    lazy: f.lazy != 0,
                }
            } else if raw.strategy == ffi::CRUSHLZFSE_STRATEGY_LAZY {
                let l = raw.p.lazy;
                Params::Lazy { hash_bits: l.hash_bits, hash_width: l.hash_width, lookahead: l.lookahead }
            } else {
                let o = raw.p.optimal;
                Params::Optimal {
                    search_depth: o.search_depth,
                    iterations: o.iterations,
                    enable_reparse: o.enable_reparse != 0,
                    split_max_blocks: o.split_max_blocks,
                    hash_bits: o.hash_bits,
                    store_limit: o.store_limit,
                    tuple_tax: o.tuple_tax,
                    max_live_buckets: o.max_live_buckets,
                    table_search: o.table_search,
                }
            }
        }
    }

    /// The same checks the encoder applies, so a rejected value is reported
    /// as [`Error::InvalidParams`] rather than a bare encode failure.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let c = capabilities();
        let within = |v: i32, (lo, hi): (i32, i32)| v >= lo && v <= hi;
        let ok = match *self {
            Params::Fast { hash_bits, min_match, skip_shift, max_step, long_table, lazy } => {
                within(hash_bits, c.fast_hash_bits)
                    && within(min_match, c.fast_min_match)
                    && (!(long_table || lazy) || min_match <= FAST_MAX_MIN_MATCH_MODES)
                    && within(skip_shift, c.fast_skip_shift)
                    && within(max_step, c.fast_max_step)
            }
            Params::Lazy { hash_bits, hash_width, lookahead } => {
                within(hash_bits, c.lazy_hash_bits)
                    && within(hash_width, c.lazy_hash_width)
                    && within(lookahead, c.lazy_lookahead)
            }
            Params::Optimal {
                search_depth,
                iterations,
                enable_reparse: _,
                split_max_blocks,
                hash_bits,
                store_limit,
                tuple_tax,
                max_live_buckets,
                table_search,
            } => {
                within(search_depth, c.search_depth)
                    && within(iterations, c.iterations)
                    && within(split_max_blocks, c.split_max_blocks)
                    && within(hash_bits, c.optimal_hash_bits)
                    && within(store_limit, c.store_limit)
                    && within(tuple_tax, c.tuple_tax)
                    && within(max_live_buckets, c.max_live_buckets)
                    && within(table_search, c.table_search)
            }
        };
        if ok { Ok(()) } else { Err(Error::InvalidParams) }
    }
}

/// The range every [`Params`] field is checked against in this build, each
/// as a `(min, max)` pair.
///
/// Several of the underlying limits are compile-time options of the C
/// library, so query this rather than assuming a range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Capabilities {
    pub level_min: i32,
    pub level_max: i32,
    /// The level `Level::DEFAULT` stands for, reported by the library rather
    /// than mirrored from a header constant.
    pub level_default: i32,
    pub search_depth: (i32, i32),
    pub iterations: (i32, i32),
    pub enable_reparse: (i32, i32),
    pub split_max_blocks: (i32, i32),
    pub optimal_hash_bits: (i32, i32),
    pub store_limit: (i32, i32),
    pub tuple_tax: (i32, i32),
    pub max_live_buckets: (i32, i32),
    pub table_search: (i32, i32),
    pub lazy_hash_bits: (i32, i32),
    pub lazy_hash_width: (i32, i32),
    pub lazy_lookahead: (i32, i32),
    pub fast_hash_bits: (i32, i32),
    /// With `long_table` or `lazy` set, the upper bound is 6 instead.
    pub fast_min_match: (i32, i32),
    pub fast_skip_shift: (i32, i32),
    pub fast_max_step: (i32, i32),
}

/// The ranges this build enforces for every [`Params`] field.
pub fn capabilities() -> Capabilities {
    // SAFETY: takes no arguments and returns a plain-data struct by value.
    let c = unsafe { ffi::crushlzfse_get_capabilities() };
    Capabilities {
        level_min: c.level_min,
        level_max: c.level_max,
        level_default: c.level_default,
        search_depth: (c.search_depth_min, c.search_depth_max),
        iterations: (c.iterations_min, c.iterations_max),
        enable_reparse: (c.enable_reparse_min, c.enable_reparse_max),
        split_max_blocks: (c.split_max_blocks_min, c.split_max_blocks_max),
        optimal_hash_bits: (c.optimal_hash_bits_min, c.optimal_hash_bits_max),
        store_limit: (c.store_limit_min, c.store_limit_max),
        tuple_tax: (c.tuple_tax_min, c.tuple_tax_max),
        max_live_buckets: (c.max_live_buckets_min, c.max_live_buckets_max),
        table_search: (c.table_search_min, c.table_search_max),
        lazy_hash_bits: (c.lazy_hash_bits_min, c.lazy_hash_bits_max),
        lazy_hash_width: (c.lazy_hash_width_min, c.lazy_hash_width_max),
        lazy_lookahead: (c.lazy_lookahead_min, c.lazy_lookahead_max),
        fast_hash_bits: (c.fast_hash_bits_min, c.fast_hash_bits_max),
        fast_min_match: (c.fast_min_match_min, c.fast_min_match_max),
        fast_skip_shift: (c.fast_skip_shift_min, c.fast_skip_shift_max),
        fast_max_step: (c.fast_max_step_min, c.fast_max_step_max),
    }
}

/// Working memory, in bytes, an encode with these params uses.
///
/// This is what a [`Scratch`](crate::Scratch) grows to on the first call
/// with these params. It never scales with the input: every call's scratch
/// is sized for the one fixed 64 KiB block, not whatever `src` is.
pub fn scratch_size(params: &Params) -> usize {
    let raw = params.to_raw();
    // SAFETY: `raw` is fully initialised and outlives the call, which only
    // reads it.
    unsafe { ffi::crushlzfse_scratch_size(&raw) }
}
