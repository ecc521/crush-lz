// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

use crate::error::Error;
use crate::ffi;
use crate::params::{Level, Params};
use crate::scratch::Scratch;

pub fn compress_bound(src_len: usize) -> usize {
    unsafe { ffi::crushlzmesh_encode_bound(src_len) }
}

pub fn compress(src: &[u8], level: Level) -> Result<Vec<u8>, Error> {
    let params = Params::for_level(level);
    compress_with(src, &params)
}

pub fn compress_with(src: &[u8], params: &Params) -> Result<Vec<u8>, Error> {
    let mut dst = vec![0u8; compress_bound(src.len())];
    let mut scratch = Scratch::new();
    let n = compress_into_with(&mut dst, src, params, &mut scratch)?;
    dst.truncate(n);
    Ok(dst)
}

pub fn compress_into_with(
    dst: &mut [u8],
    src: &[u8],
    params: &Params,
    scratch: &mut Scratch,
) -> Result<usize, Error> {
    let sc_ptr = scratch.reserve(crate::scratch::scratch_size(params));
    let n = unsafe {
        ffi::crushlzmesh_encode_buffer(
            dst.as_mut_ptr(),
            dst.len(),
            src.as_ptr(),
            src.len(),
            sc_ptr,
            &params.0,
        )
    };
    if n == 0 {
        if dst.len() < compress_bound(src.len()) {
            Err(Error::OutputTooSmall { written: 0 })
        } else {
            Err(Error::InvalidInput)
        }
    } else {
        Ok(n)
    }
}
