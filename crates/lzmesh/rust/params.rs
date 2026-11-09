// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

use crate::ffi;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Level(pub i32);

impl Level {
    pub const MIN: Level = Level(ffi::CRUSHLZMESH_LEVEL_MIN);
    pub const MAX: Level = Level(ffi::CRUSHLZMESH_LEVEL_MAX);
    pub const DEFAULT: Level = Level(ffi::CRUSHLZMESH_LEVEL_DEFAULT);
}

impl Default for Level {
    fn default() -> Self {
        Level::DEFAULT
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Params(pub ffi::crushlzmesh_params);

impl Params {
    pub fn for_level(level: Level) -> Self {
        let mut raw = std::mem::MaybeUninit::uninit();
        let rc = unsafe { ffi::crushlzmesh_params_for_level(level.0, raw.as_mut_ptr()) };
        assert_eq!(rc, ffi::CRUSHLZMESH_STATUS_OK);
        Params(unsafe { raw.assume_init() })
    }
}
