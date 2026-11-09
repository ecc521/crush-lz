// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

use crate::ffi;
use crate::params::Params;

pub fn scratch_size(params: &Params) -> usize {
    unsafe { ffi::crushlzmesh_encode_scratch_buffer_size(&params.0) }
}

#[derive(Default)]
pub struct Scratch {
    buf: Vec<u8>,
}

impl Scratch {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn reserve(&mut self, size: usize) -> *mut std::ffi::c_void {
        if self.buf.len() < size {
            self.buf.resize(size, 0);
        }
        self.buf.as_mut_ptr() as *mut std::ffi::c_void
    }
}
