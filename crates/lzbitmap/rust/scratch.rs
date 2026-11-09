// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use std::os::raw::c_void;

use crate::ffi;
use crate::params::Params;

/// Reusable working memory for the LZBITMAP encoder.
///
/// Starts empty and grows to [`scratch_size`] of whatever params a
/// compress call uses, then stays that size, so a loop over many buffers
/// allocates once. Because the call site sizes it from the same params the
/// encoder carves it with, it is never too small to hold: the DP levels'
/// candidate tables are accounted for by construction rather than by a check
/// the caller can fail. One `Scratch` per thread is the intended pattern.
#[derive(Debug, Default)]
pub struct Scratch {
    /// `u64` elements give the buffer 8-byte alignment from `Vec` itself, and
    /// the extra to `CRUSHLZBITMAP_SCRATCH_ALIGN` is taken by over-allocating
    /// and offsetting, since the state wants 16.
    buf: Vec<u64>,
    /// Offset in bytes from `buf`'s start to the aligned view handed to C.
    off: usize,
}

/// Alignment the encoder requires of scratch, mirroring
/// `CRUSHLZBITMAP_SCRATCH_ALIGN`: its row table is read a bucket at a time
/// with one 16-byte vector load, and 16 keeps a bucket off a cache-line
/// boundary.
const ALIGN: usize = ffi::CRUSHLZBITMAP_SCRATCH_ALIGN;

impl Scratch {
    /// An empty scratch; the first compress call sizes it.
    pub fn new() -> Scratch {
        Scratch { buf: Vec::new(), off: 0 }
    }

    /// A scratch already large enough for `params`, for a caller that would
    /// rather pay the allocation up front than on the first call.
    pub fn for_params(params: &Params) -> Scratch {
        let mut s = Scratch::new();
        s.reserve(scratch_size(params));
        s
    }

    /// A pointer to at least `bytes` bytes of `ALIGN`-aligned scratch,
    /// growing if needed.
    pub(crate) fn reserve(&mut self, bytes: usize) -> *mut c_void {
        // ALIGN bytes of slack so an aligned view always fits.
        let words = (bytes + ALIGN).div_ceil(8);
        if self.buf.len() < words {
            self.buf.resize(words, 0);
        }
        // align_offset's result is in units of u64 (the pointer's own
        // pointee type), not bytes: advance the u64 pointer by it before
        // casting to u8, not after, or this only moves 1/8th as far as it
        // should.
        let off = self.buf.as_ptr().align_offset(ALIGN);
        assert!(off < ALIGN, "cannot align the scratch buffer");
        self.off = off * 8;
        let ptr: *mut c_void = unsafe {
            // SAFETY: `off < ALIGN` and the buffer carries ALIGN bytes of
            // slack beyond `bytes`, so the view is in bounds for `bytes`.
            self.buf.as_mut_ptr().add(off).cast()
        };
        debug_assert_eq!(ptr as usize % ALIGN, 0, "reserve() must return an ALIGN-aligned pointer");
        ptr
    }

    /// Usable bytes behind the pointer `reserve` returned.
    pub(crate) fn bytes(&self) -> usize {
        (self.buf.len() * 8).saturating_sub(self.off)
    }
}

/// Bytes of scratch an encode with `params` needs.
pub fn scratch_size(params: &Params) -> usize {
    let raw = params.to_raw();
    // SAFETY: `raw` is a fully initialized params struct that outlives the call.
    unsafe { ffi::crushlzbitmap_scratch_size(&raw) }
}
