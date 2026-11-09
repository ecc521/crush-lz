// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_void};

pub(crate) const CRUSHLZMESH_LEVEL_MIN: c_int = -5;
pub(crate) const CRUSHLZMESH_LEVEL_MAX: c_int = 10;
pub(crate) const CRUSHLZMESH_LEVEL_DEFAULT: c_int = 0;

pub(crate) const CRUSHLZMESH_STATUS_OK: c_int = 0;
#[allow(dead_code)]
pub(crate) const CRUSHLZMESH_INVALID: c_int = -1;
pub(crate) const CRUSHLZMESH_OUTPUT_TOO_SMALL: c_int = -2;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum crushlzmesh_strategy {
    CRUSHLZMESH_STRAT_FAST = 1,
    CRUSHLZMESH_STRAT_LAZY = 2,
    CRUSHLZMESH_STRAT_OPTIMAL = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct crushlzmesh_params {
    pub strategy: crushlzmesh_strategy,
    pub hash_bits: c_int,
    pub min_match: c_int,
    pub max_depth: c_int,
    pub lookahead: c_int,
    pub search_depth: c_int,
    pub iterations: c_int,
}

unsafe extern "C" {
    pub fn crushlzmesh_encode_bound(src_size: usize) -> usize;
    pub fn crushlzmesh_encode_scratch_buffer_size(params: *const crushlzmesh_params) -> usize;
    pub fn crushlzmesh_decode_scratch_buffer_size() -> usize;

    pub fn crushlzmesh_params_for_level(level: c_int, out: *mut crushlzmesh_params) -> c_int;

    pub fn crushlzmesh_encode_buffer(
        dst: *mut u8,
        dst_size: usize,
        src: *const u8,
        src_size: usize,
        scratch: *mut c_void,
        params: *const crushlzmesh_params,
    ) -> usize;

    pub fn crushlzmesh_decode_buffer(
        dst: *mut u8,
        dst_size: usize,
        src: *const u8,
        src_size: usize,
        decoded_size: *mut usize,
    ) -> c_int;
}
