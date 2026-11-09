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
    pub const MIN: Level = Level(ffi::CRUSHLZ4_LEVEL_MIN);
    /// The densest level.
    pub const MAX: Level = Level(ffi::CRUSHLZ4_LEVEL_MAX);
    /// The level used when none is given.
    pub const DEFAULT: Level = Level(ffi::CRUSHLZ4_LEVEL_DEFAULT);
}

impl Default for Level {
    fn default() -> Self {
        Level::DEFAULT
    }
}

/// Which of upstream LZ4's two encoders a level uses. They write the same
/// bitstream, so a stream gives no clue which one produced it — only the
/// parse differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `LZ4_compress_fast`. One knob, [`Params::acceleration`].
    Fast,
    /// `LZ4_compress_HC`. One knob, [`Params::hc_level`].
    Hc,
}

impl Mode {
    fn from_raw(v: i32) -> Mode {
        if v == ffi::CRUSHLZ4_MODE_HC { Mode::Hc } else { Mode::Fast }
    }

    fn to_raw(self) -> i32 {
        match self {
            Mode::Fast => ffi::CRUSHLZ4_MODE_FAST,
            Mode::Hc => ffi::CRUSHLZ4_MODE_HC,
        }
    }
}

/// Compression settings, resolved from a [`Level`] or supplied directly to
/// [`crate::compress_with`] and [`crate::compress_into_with`].
///
/// Exactly one knob is read, chosen by [`Params::mode`]; the other holds that
/// mode's own neutral value rather than anything meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Which encoder this level uses.
    pub mode: Mode,
    /// [`Mode::Fast`] only. Higher skips more input per miss, so it runs
    /// faster and compresses worse; 1 is upstream's own default.
    pub acceleration: i32,
    /// [`Mode::Hc`] only. 2 to 9 widen a hash chain, 10 to 12 run a
    /// shortest-path parse instead. 1 is accepted and clamps to 2.
    pub hc_level: i32,
}

impl Params {
    pub(crate) fn to_raw(self) -> ffi::crushlz4_encode_params {
        ffi::crushlz4_encode_params {
            mode: self.mode.to_raw(),
            acceleration: self.acceleration,
            hc_level: self.hc_level,
        }
    }

    /// The settings `level` stands for, and the level actually used: values
    /// outside [`Level::MIN`]`..=`[`Level::MAX`] clamp rather than error.
    pub fn for_level(level: Level) -> (Params, Level) {
        let mut raw = ffi::crushlz4_encode_params::default();
        // SAFETY: raw is a valid, fully initialised out-pointer, so the C side
        // writes every field and returns the clamped level, never LEVEL_INVALID.
        let used = unsafe { ffi::crushlz4_params_for_level(level.0, &mut raw) };
        (
            Params {
                mode: Mode::from_raw(raw.mode),
                acceleration: raw.acceleration,
                hc_level: raw.hc_level,
            },
            Level(used),
        )
    }
}

/// Bytes of scratch an encode with `params` needs. Set by
/// [`Params::mode`] alone — the two encoders want very different tables, and
/// neither varies with the knob or with input size.
pub fn scratch_size(params: &Params) -> usize {
    let raw = params.to_raw();
    // SAFETY: `raw` is a fully initialised params struct that outlives the call.
    unsafe { ffi::crushlz4_scratch_size(&raw) }
}

/// The valid range of every [`Params`] field, and the level range. Params
/// outside these are rejected rather than clamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub level_min: i32,
    pub level_max: i32,
    /// The level [`Level::DEFAULT`] stands for, reported by the library
    /// rather than mirrored from a header constant.
    pub level_default: i32,
    pub acceleration: (i32, i32),
    pub hc_level: (i32, i32),
}

/// What the encoder accepts.
pub fn capabilities() -> Capabilities {
    // SAFETY: a pure function with no arguments and no failure mode.
    let c = unsafe { ffi::crushlz4_get_capabilities() };
    Capabilities {
        level_min: c.level_min,
        level_max: c.level_max,
        level_default: c.level_default,
        acceleration: (c.acceleration_min, c.acceleration_max),
        hc_level: (c.hc_level_min, c.hc_level_max),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_agree_with_the_level_constants() {
        let c = capabilities();
        assert_eq!(c.level_min, Level::MIN.0);
        assert_eq!(c.level_max, Level::MAX.0);
        assert_eq!(c.level_default, Level::DEFAULT.0);
        // Every level on the ladder sits inside the accepted ranges, on
        // whichever knob its own mode reads.
        for lv in Level::MIN.0..=Level::MAX.0 {
            let p = Params::for_level(Level(lv)).0;
            match p.mode {
                Mode::Fast => assert!(
                    p.acceleration >= c.acceleration.0 && p.acceleration <= c.acceleration.1,
                    "level {lv}"
                ),
                Mode::Hc => assert!(
                    p.hc_level >= c.hc_level.0 && p.hc_level <= c.hc_level.1,
                    "level {lv}"
                ),
            }
        }
    }

    #[test]
    fn the_two_modes_want_different_scratch() {
        // Not "bigger for denser levels": scratch here is a step at the
        // mode boundary and flat either side of it, which is the property
        // a caller sizing one buffer for several levels depends on.
        let fast = scratch_size(&Params::for_level(Level::MIN).0);
        let hc = scratch_size(&Params::for_level(Level::MAX).0);
        assert!(fast > 0 && hc > fast, "{fast} vs {hc}");
        for lv in Level::MIN.0..=Level::MAX.0 {
            let p = Params::for_level(Level(lv)).0;
            let want = match p.mode {
                Mode::Fast => fast,
                Mode::Hc => hc,
            };
            assert_eq!(scratch_size(&p), want, "level {lv}");
        }
    }

    #[test]
    fn levels_clamp_and_report_what_was_used() {
        let (fast, lv) = Params::for_level(Level(i32::MIN));
        assert_eq!(lv, Level::MIN);
        assert_eq!(fast, Params::for_level(Level::MIN).0);
        let (_, lv) = Params::for_level(Level(i32::MAX));
        assert_eq!(lv, Level::MAX);
        // Every level in MIN..=MAX resolves, and reports itself.
        for lv in Level::MIN.0..=Level::MAX.0 {
            assert_eq!(Params::for_level(Level(lv)).1, Level(lv));
        }
    }

    #[test]
    fn every_level_is_its_own_rung() {
        // A level that resolves to the settings of the one below it is a
        // rung the ladder is not using. Upstream has rungs this ladder
        // skips for exactly that reason (HC 8), so nothing may quietly
        // reintroduce a duplicate.
        let mut prev = Params::for_level(Level::MIN).0;
        for level in (ffi::CRUSHLZ4_LEVEL_MIN + 1)..=ffi::CRUSHLZ4_LEVEL_MAX {
            let (p, used) = Params::for_level(Level(level));
            assert_eq!(used, Level(level));
            assert_ne!(p, prev, "level {level} resolves to the same settings as {}", level - 1);
            prev = p;
        }
    }
}
