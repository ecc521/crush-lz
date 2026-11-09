// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use crate::ffi;

/// A numbered compression level. Negative levels trade ratio for speed and
/// positive levels the reverse; the C side clamps values outside
/// [`Level::MIN`]`..=`[`Level::MAX`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Level(pub i32);

impl Level {
    /// The fastest level.
    pub const MIN: Level = Level(ffi::CRUSHLZBITMAP_LEVEL_MIN);
    /// The densest level.
    pub const MAX: Level = Level(ffi::CRUSHLZBITMAP_LEVEL_MAX);
    /// The level used when none is given.
    pub const DEFAULT: Level = Level(ffi::CRUSHLZBITMAP_LEVEL_DEFAULT);
}

impl Default for Level {
    fn default() -> Self {
        Level::DEFAULT
    }
}

/// Explicit encoder settings, for anything a [`Level`] does not express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Params {
    /// The row tier's candidates, recorded by its lookahead lanes, with the
    /// period sequence chosen by shortest path; the strategy behind level 7.
    /// Levels 8–12 use [`Params::Beam`]. The first six fields are the sourcing,
    /// as in [`Params::Row`].
    Dp {
        /// Log2 of the bucket count, 8 to 16.
        hash_bits: i32,
        /// Entries per bucket: 1, 2, 4, 8 or 16, with
        /// `hash_bits + log2(depth)` at most 18.
        depth: i32,
        /// Recently used periods to retry, 0 to 8.
        dist_cache_size: i32,
        /// Accept the continuing period at this many literals without
        /// searching, 0 to 8.
        accept_diff: i32,
        /// Nearest periods scanned exhaustively on a searched block: a
        /// multiple of 16, 0 to 256.
        scan_window: i32,
        /// Must be 1: the lists are ranked by the lookahead lanes' cost.
        lookahead: i32,
        /// Candidates kept per block for the shortest path, 1 to 255.
        max_candidates: i32,
        /// DP passes, 1 to 64; later passes reuse the previous top-12 table.
        iterations: i32,
    },
    /// Row-seeded beam retaining competitive periods across blocks and pricing bitmap runs.
    Beam {
        /// Log2 of the bucket count, 8 to 16.
        hash_bits: i32,
        /// Entries per bucket: 1, 2, 4, 8 or 16, with
        /// `hash_bits + log2(depth)` at most 18.
        depth: i32,
        /// Recently used periods to retry, 0 to 8.
        dist_cache_size: i32,
        /// Accept the continuing period at this many literals without
        /// searching, 0 to 8.
        accept_diff: i32,
        /// Nearest periods scanned exhaustively on a searched block: a
        /// multiple of 16, 0 to 256.
        scan_window: i32,
        /// Must be 1: the lists are ranked by the lookahead lanes' cost.
        lookahead: i32,
        /// Recorded candidates per block, 1 to 255; surviving beam periods are also retried.
        max_candidates: i32,
        /// Surviving states, a power of two from 1 to 64.
        beam_width: i32,
    },
    /// Full-reach buckets probed at every byte window of the block, an
    /// optional exhaustive scan of the nearest periods, exact bit-cost
    /// scoring; the strategy behind levels -2 to 6.
    Row {
        /// Log2 of the bucket count, 8 to 16.
        hash_bits: i32,
        /// Entries per bucket, all probed: 1, 2, 4, 8 or 16, with
        /// `hash_bits + log2(depth)` at most 18.
        depth: i32,
        /// Recently used periods to retry, 0 to 8; above 4 only with
        /// `lookahead`.
        dist_cache_size: i32,
        /// Accept the continuing period at this many literals without
        /// searching, 0 to 8.
        accept_diff: i32,
        /// Nearest periods scanned exhaustively on a searched block: a
        /// multiple of 16, 0 to 256; above 32 only with `lookahead`.
        scan_window: i32,
        /// 1 to probe the block after each candidate too, preferring
        /// periods that persist.
        lookahead: i32,
    },
    /// Searches only blocks the period in force serves poorly, and indexes
    /// only what it searched; the strategy behind levels -5 to -3.
    Fast {
        /// Log2 of the table size, 10 to 16.
        hash_bits: i32,
        /// Byte windows looked up per searched block, spread evenly over
        /// it: 1, 2, 4 or 8.
        windows: i32,
        /// Recently used periods retried on a searched block, 0 to 2.
        dist_cache_size: i32,
        /// Keep the period in force at this many literals without
        /// searching, 0 to 7.
        accept_diff: i32,
        /// 0 never skips; otherwise after `n` searches in a row that keep
        /// the period, the next `n >> skip_shift` blocks are not searched.
        /// 0 to 11.
        skip_shift: i32,
    },
}

impl Params {
    /// The settings `level` stands for, and the level actually used: values
    /// outside [`Level::MIN`]`..=`[`Level::MAX`] clamp rather than error.
    pub fn for_level(level: Level) -> (Self, Level) {
        let mut raw = std::mem::MaybeUninit::<ffi::crushlzbitmap_params>::uninit();
        // SAFETY: `raw` is valid for writes; the call fully initializes it
        // for any level, since the only failure is a NULL pointer, and
        // returns the level it clamped to.
        let (raw, used) = unsafe {
            let used = ffi::crushlzbitmap_params_for_level(level.0, raw.as_mut_ptr());
            (raw.assume_init(), used)
        };
        (Params::from_raw(raw), Level(used))
    }

    /// The DP strategy's documented defaults.
    pub fn dp_default() -> Self {
        Params::strategy_default(ffi::CRUSHLZBITMAP_STRATEGY_DP)
    }

    /// The beam strategy's documented defaults (level 8).
    pub fn beam_default() -> Self {
        Params::strategy_default(ffi::CRUSHLZBITMAP_STRATEGY_BEAM)
    }

    /// The row strategy's documented defaults.
    pub fn row_default() -> Self {
        Params::strategy_default(ffi::CRUSHLZBITMAP_STRATEGY_ROW)
    }

    /// The fast strategy's documented defaults.
    pub fn fast_default() -> Self {
        Params::strategy_default(ffi::CRUSHLZBITMAP_STRATEGY_FAST)
    }

    fn strategy_default(strategy: i32) -> Self {
        let mut raw = std::mem::MaybeUninit::<ffi::crushlzbitmap_params>::uninit();
        // SAFETY: `raw` is valid for writes and `strategy` is one of the
        // three the C side knows, so the call fully initializes it.
        let raw = unsafe {
            let rc = ffi::crushlzbitmap_default_params(strategy, raw.as_mut_ptr());
            assert_eq!(rc, 0, "crushlzbitmap_default_params rejected a known strategy");
            raw.assume_init()
        };
        Params::from_raw(raw)
    }

    pub(crate) fn to_raw(self) -> ffi::crushlzbitmap_params {
        match self {
            Params::Dp { hash_bits, depth, dist_cache_size, accept_diff, scan_window, lookahead, max_candidates, iterations } => {
                ffi::crushlzbitmap_params {
                    strategy: ffi::CRUSHLZBITMAP_STRATEGY_DP,
                    p: ffi::crushlzbitmap_params_union {
                        dp: ffi::crushlzbitmap_dp_params {
                            row: ffi::crushlzbitmap_row_params {
                                hash_bits,
                                depth,
                                dist_cache_size,
                                accept_diff,
                                scan_window,
                                lookahead,
                            },
                            max_candidates,
                            iterations,
                        },
                    },
                }
            }
            Params::Beam { hash_bits, depth, dist_cache_size, accept_diff, scan_window, lookahead, max_candidates, beam_width } => {
                ffi::crushlzbitmap_params {
                    strategy: ffi::CRUSHLZBITMAP_STRATEGY_BEAM,
                    p: ffi::crushlzbitmap_params_union {
                        beam: ffi::crushlzbitmap_beam_params {
                            row: ffi::crushlzbitmap_row_params {
                                hash_bits,
                                depth,
                                dist_cache_size,
                                accept_diff,
                                scan_window,
                                lookahead,
                            },
                            max_candidates,
                            beam_width,
                        },
                    },
                }
            }
            Params::Row { hash_bits, depth, dist_cache_size, accept_diff, scan_window, lookahead } => {
                ffi::crushlzbitmap_params {
                    strategy: ffi::CRUSHLZBITMAP_STRATEGY_ROW,
                    p: ffi::crushlzbitmap_params_union {
                        row: ffi::crushlzbitmap_row_params {
                            hash_bits,
                            depth,
                            dist_cache_size,
                            accept_diff,
                            scan_window,
                            lookahead,
                        },
                    },
                }
            }
            Params::Fast { hash_bits, windows, dist_cache_size, accept_diff, skip_shift } => {
                // The union's larger arms are zeroed first, so the bytes past
                // the fast arm are defined, as C's default_params leaves them.
                let mut raw = ffi::crushlzbitmap_params {
                    strategy: ffi::CRUSHLZBITMAP_STRATEGY_FAST,
                    p: ffi::crushlzbitmap_params_union {
                        dp: ffi::crushlzbitmap_dp_params {
                            row: ffi::crushlzbitmap_row_params {
                                hash_bits: 0,
                                depth: 0,
                                dist_cache_size: 0,
                                accept_diff: 0,
                                scan_window: 0,
                                lookahead: 0,
                            },
                            max_candidates: 0,
                            iterations: 0,
                        },
                    },
                };
                raw.p.fast = ffi::crushlzbitmap_fast_params {
                    hash_bits,
                    windows,
                    dist_cache_size,
                    accept_diff,
                    skip_shift,
                };
                raw
            }
        }
    }

    fn from_raw(raw: ffi::crushlzbitmap_params) -> Self {
        // SAFETY: `raw.strategy` was set by the C side to the arm it wrote,
        // so that arm is the one read. An unknown tag panics rather than
        // guessing an arm.
        unsafe {
            match raw.strategy {
                ffi::CRUSHLZBITMAP_STRATEGY_DP => Params::Dp {
                    hash_bits: raw.p.dp.row.hash_bits,
                    depth: raw.p.dp.row.depth,
                    dist_cache_size: raw.p.dp.row.dist_cache_size,
                    accept_diff: raw.p.dp.row.accept_diff,
                    scan_window: raw.p.dp.row.scan_window,
                    lookahead: raw.p.dp.row.lookahead,
                    max_candidates: raw.p.dp.max_candidates,
                    iterations: raw.p.dp.iterations,
                },
                ffi::CRUSHLZBITMAP_STRATEGY_BEAM => Params::Beam {
                    hash_bits: raw.p.beam.row.hash_bits,
                    depth: raw.p.beam.row.depth,
                    dist_cache_size: raw.p.beam.row.dist_cache_size,
                    accept_diff: raw.p.beam.row.accept_diff,
                    scan_window: raw.p.beam.row.scan_window,
                    lookahead: raw.p.beam.row.lookahead,
                    max_candidates: raw.p.beam.max_candidates,
                    beam_width: raw.p.beam.beam_width,
                },
                ffi::CRUSHLZBITMAP_STRATEGY_ROW => Params::Row {
                    hash_bits: raw.p.row.hash_bits,
                    depth: raw.p.row.depth,
                    dist_cache_size: raw.p.row.dist_cache_size,
                    accept_diff: raw.p.row.accept_diff,
                    scan_window: raw.p.row.scan_window,
                    lookahead: raw.p.row.lookahead,
                },
                ffi::CRUSHLZBITMAP_STRATEGY_FAST => Params::Fast {
                    hash_bits: raw.p.fast.hash_bits,
                    windows: raw.p.fast.windows,
                    dist_cache_size: raw.p.fast.dist_cache_size,
                    accept_diff: raw.p.fast.accept_diff,
                    skip_shift: raw.p.fast.skip_shift,
                },
                other => panic!("crushlzbitmap returned unknown strategy {other}"),
            }
        }
    }
}

/// The valid range of every [`Params`] field, and the level range. Params
/// outside these are rejected rather than clamped.
///
/// Ranges alone do not capture every rule: `row_depth` must also be a power
/// of two, `hash_bits` times `depth` must not exceed 2^18 table entries,
/// `scan_window` must be a multiple of 16, and `fast_windows` must be a power
/// of two. A params set inside every range here can still be rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub level_min: i32,
    pub level_max: i32,
    /// The level [`Level::DEFAULT`] stands for, reported by the library
    /// rather than mirrored from a header constant.
    pub level_default: i32,
    pub row_hash_bits: (i32, i32),
    pub row_depth: (i32, i32),
    pub row_lookahead: (i32, i32),
    pub row_dist_cache_size: (i32, i32),
    pub row_scan_window: (i32, i32),
    pub row_accept_diff: (i32, i32),
    pub dp_max_candidates: (i32, i32),
    pub dp_iterations: (i32, i32),
    /// Beam width must additionally be a power of two.
    pub beam_width: (i32, i32),
    pub fast_hash_bits: (i32, i32),
    pub fast_windows: (i32, i32),
    pub fast_dist_cache_size: (i32, i32),
    pub fast_accept_diff: (i32, i32),
    pub fast_skip_shift: (i32, i32),
}

/// What the encoder accepts.
pub fn capabilities() -> Capabilities {
    // SAFETY: a pure function with no arguments and no failure mode.
    let c = unsafe { ffi::crushlzbitmap_get_capabilities() };
    Capabilities {
        level_min: c.level_min,
        level_max: c.level_max,
        level_default: c.level_default,
        row_hash_bits: (c.row_hash_bits_min, c.row_hash_bits_max),
        row_depth: (c.row_depth_min, c.row_depth_max),
        row_lookahead: (c.row_lookahead_min, c.row_lookahead_max),
        row_dist_cache_size: (c.row_dist_cache_size_min, c.row_dist_cache_size_max),
        row_scan_window: (c.row_scan_window_min, c.row_scan_window_max),
        row_accept_diff: (c.row_accept_diff_min, c.row_accept_diff_max),
        dp_max_candidates: (c.dp_max_candidates_min, c.dp_max_candidates_max),
        dp_iterations: (c.dp_iterations_min, c.dp_iterations_max),
        beam_width: (c.beam_width_min, c.beam_width_max),
        fast_hash_bits: (c.fast_hash_bits_min, c.fast_hash_bits_max),
        fast_windows: (c.fast_windows_min, c.fast_windows_max),
        fast_dist_cache_size: (c.fast_dist_cache_size_min, c.fast_dist_cache_size_max),
        fast_accept_diff: (c.fast_accept_diff_min, c.fast_accept_diff_max),
        fast_skip_shift: (c.fast_skip_shift_min, c.fast_skip_shift_max),
    }
}

impl Params {
    /// The same range checks the encoder applies, so a caller-built `Params`
    /// with a field out of range is reported as [`Error::InvalidParams`]
    /// before it can size an allocation, rather than only once the encode
    /// call itself validates it. `max_candidates` is otherwise unbounded
    /// above in this crate's public API: `crushlzbitmap_scratch_size` on the
    /// C side sizes its DP tables directly from it without validating first
    /// (unlike crushlzfse's equivalent).
    pub(crate) fn validate(&self) -> Result<(), crate::error::Error> {
        let c = capabilities();
        let within = |v: i32, (lo, hi): (i32, i32)| v >= lo && v <= hi;
        let ok = match *self {
            Params::Dp { hash_bits, depth, dist_cache_size, accept_diff, scan_window, lookahead,
                         max_candidates, iterations } => {
                within(hash_bits, c.row_hash_bits)
                    && within(depth, c.row_depth)
                    && within(dist_cache_size, c.row_dist_cache_size)
                    && within(accept_diff, c.row_accept_diff)
                    && within(scan_window, c.row_scan_window)
                    && within(lookahead, c.row_lookahead)
                    && within(max_candidates, c.dp_max_candidates)
                    && within(iterations, c.dp_iterations)
            }
            Params::Beam { hash_bits, depth, dist_cache_size, accept_diff, scan_window, lookahead,
                         max_candidates, beam_width } => {
                within(hash_bits, c.row_hash_bits)
                    && within(depth, c.row_depth)
                    && within(dist_cache_size, c.row_dist_cache_size)
                    && within(accept_diff, c.row_accept_diff)
                    && within(scan_window, c.row_scan_window)
                    && within(lookahead, c.row_lookahead)
                    && within(max_candidates, c.dp_max_candidates)
                    && within(beam_width, c.beam_width)
                    && (beam_width & (beam_width - 1)) == 0
                    && lookahead == 1
            }
            Params::Row { hash_bits, depth, dist_cache_size, accept_diff, scan_window, lookahead } => {
                within(hash_bits, c.row_hash_bits)
                    && within(depth, c.row_depth)
                    && within(dist_cache_size, c.row_dist_cache_size)
                    && within(accept_diff, c.row_accept_diff)
                    && within(scan_window, c.row_scan_window)
                    && within(lookahead, c.row_lookahead)
            }
            Params::Fast { hash_bits, windows, dist_cache_size, accept_diff, skip_shift } => {
                within(hash_bits, c.fast_hash_bits)
                    && within(windows, c.fast_windows)
                    && within(dist_cache_size, c.fast_dist_cache_size)
                    && within(accept_diff, c.fast_accept_diff)
                    && within(skip_shift, c.fast_skip_shift)
            }
        };
        if ok { Ok(()) } else { Err(crate::error::Error::InvalidParams) }
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    #[test]
    fn capabilities_agree_with_the_level_constants() {
        let c = capabilities();
        assert_eq!(c.level_min, Level::MIN.0);
        assert_eq!(c.level_max, Level::MAX.0);
        assert_eq!(c.level_default, Level::DEFAULT.0);
    }
}
