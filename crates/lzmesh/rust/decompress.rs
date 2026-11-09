// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

use crate::error::Error;
use crate::ffi;

pub fn decompress_into(dst: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    let mut out_len = 0usize;
    let rc = unsafe {
        ffi::crushlzmesh_decode_buffer(
            dst.as_mut_ptr(),
            dst.len(),
            src.as_ptr(),
            src.len(),
            &mut out_len,
        )
    };
    match rc {
        ffi::CRUSHLZMESH_STATUS_OK => Ok(out_len),
        ffi::CRUSHLZMESH_OUTPUT_TOO_SMALL => Err(Error::OutputTooSmall { written: out_len }),
        _ => Err(Error::InvalidInput),
    }
}

pub fn decoded_len(src: &[u8]) -> Result<usize, Error> {
    let mut pos = 0;
    let mut total_usize = 0usize;
    while pos < src.len() {
        let btype = src[pos];
        pos += 1;
        if btype == 0xFF {
            return Ok(total_usize);
        } else if btype == 0x00 {
            if pos + 4 > src.len() {
                return Err(Error::InvalidInput);
            }
            let usize = u32::from_le_bytes(src[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + usize > src.len() {
                return Err(Error::InvalidInput);
            }
            total_usize += usize;
            pos += usize;
        } else if btype == 0x01 {
            if pos + 8 > src.len() {
                return Err(Error::InvalidInput);
            }
            let usize = u32::from_le_bytes(src[pos..pos + 4].try_into().unwrap()) as usize;
            let s2 = u16::from_le_bytes(src[pos + 6..pos + 8].try_into().unwrap()) as usize;
            pos += 8;
            if pos + s2 + 1 > src.len() {
                return Err(Error::InvalidInput);
            }
            total_usize += usize;
            pos += s2 + 1; // skip payload + trailing 0x00 flag
        } else {
            return Err(Error::InvalidInput);
        }
    }
    Ok(total_usize)
}

pub fn decompress(src: &[u8]) -> Result<Vec<u8>, Error> {
    let out_len = decoded_len(src)?;
    let mut dst = vec![0u8; out_len];
    let n = decompress_into(&mut dst, src)?;
    dst.truncate(n);
    Ok(dst)
}
