// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use std::os::raw::c_void;

use crate::params::{Params, scratch_size};

/// Reusable working memory for the LZ4 encoder.
///
/// Starts empty and grows to [`scratch_size`] of whatever params a
/// compress call uses, then stays that size, so a loop over many buffers
/// allocates once. Because the call site sizes it from the same params the
/// encoder carves it with, it is never too small to hold: there is no
/// mismatch for a caller to get wrong. One `Scratch` per thread is the
/// intended pattern.
#[derive(Debug, Default)]
pub struct Scratch {
    // u64 rather than u8 so the buffer is 8-byte aligned, which is what the
    // C side's carve-up of the region assumes. The depth-1 table is read as
    // u64 buckets, so this is the alignment that matters.
    buf: Vec<u64>,
}

impl Scratch {
    /// An empty scratch; the first compress call sizes it.
    pub fn new() -> Scratch {
        Scratch { buf: Vec::new() }
    }

    /// A scratch already large enough for `params`, for a caller that would
    /// rather pay the allocation up front than on the first call.
    pub fn for_params(params: &Params) -> Scratch {
        let mut s = Scratch::new();
        s.reserve(scratch_size(params));
        s
    }

    /// A pointer to at least `bytes` bytes of scratch, growing if needed.
    pub(crate) fn reserve(&mut self, bytes: usize) -> *mut c_void {
        let words = bytes.div_ceil(8);
        if self.buf.len() < words {
            self.buf.resize(words, 0);
        }
        self.buf.as_mut_ptr().cast()
    }

    /// Usable bytes behind the pointer `reserve` returns.
    pub(crate) fn bytes(&self) -> usize {
        self.buf.len() * 8
    }
}
