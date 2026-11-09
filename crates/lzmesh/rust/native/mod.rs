// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Pure-Rust LZMESH codec, ported from csrc/crushlzmesh.c. No `unsafe`.

// Hot loops index several parallel tables by one counter.
#![allow(clippy::needless_range_loop, clippy::too_many_arguments)]

mod block;
mod decode;
mod fast;
mod huff;
mod optimal;

use crate::error::Error;
use crate::ffi::crushlzmesh_strategy as Strategy;
use crate::params::Params;

/// Prices are in 1/16 bit.
pub(crate) const PRICE_SHIFT: u32 = 4;

/// A parsed sequence: `lits` literals, then a match (len 0 for a trailing
/// literal-only run).
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct Seq {
    pub(crate) lits: u32,
    pub(crate) len: u32,
    pub(crate) dist: u32,
}

/// Length of the common prefix of src[a..] and src[b..], with b < end <= len
/// and a < b.
#[inline(always)]
pub(crate) fn match_len(src: &[u8], a: usize, b: usize, end: usize) -> usize {
    let s = b;
    let (mut a, mut b) = (a, b);
    while end - b >= 8 {
        let x = ld64(src, a) ^ ld64(src, b);
        if x != 0 {
            return b - s + (x.trailing_zeros() >> 3) as usize;
        }
        a += 8;
        b += 8;
    }
    while b < end && src[a] == src[b] {
        a += 1;
        b += 1;
    }
    b - s
}

#[inline(always)]
pub(crate) fn ld16(s: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(s[i..i + 2].try_into().unwrap())
}

#[inline(always)]
pub(crate) fn ld32(s: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(s[i..i + 4].try_into().unwrap())
}

#[inline(always)]
pub(crate) fn ld64(s: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(s[i..i + 8].try_into().unwrap())
}

/// Decompresses `src` into `dst`, returning the bytes written.
pub fn decompress_into(dst: &mut [u8], src: &[u8]) -> Result<usize, Error> {
    match decode::decode(dst, src) {
        (Ok(()), n) => Ok(n),
        (Err(decode::Fail::TooSmall), n) => Err(Error::OutputTooSmall { written: n }),
        (Err(decode::Fail::Invalid), _) => Err(Error::InvalidInput),
    }
}

/// Worst-case compressed size for `n` input bytes.
pub fn compress_bound(n: usize) -> usize {
    n + 64
}

/// Compresses `src` with `params`.
pub fn compress_with(src: &[u8], params: &Params) -> Result<Vec<u8>, Error> {
    let mut dst = vec![0u8; compress_bound(src.len())];
    let n = compress_into_with(&mut dst, src, params)?;
    dst.truncate(n);
    Ok(dst)
}

/// Compresses `src` into `dst`, returning the bytes written.
pub fn compress_into_with(dst: &mut [u8], src: &[u8], params: &Params) -> Result<usize, Error> {
    let p = &params.0;
    let fail = |dst: &[u8]| if dst.len() < compress_bound(src.len()) { Error::OutputTooSmall { written: 0 } } else { Error::InvalidInput };
    let n = src.len();
    let mut o = block::Out { dst, pos: 0, raw_start: 0, raw_end: 0 };
    if !(16..=0xFFFF_FFF0).contains(&n) {
        o.raw_end = n;
        if !o.flush_raw(src) || o.pos >= o.dst.len() {
            return Err(fail(o.dst));
        }
        o.dst[o.pos] = 0xFF;
        return Ok(o.pos + 1);
    }
    let hb = (if p.hash_bits != 0 { p.hash_bits } else { 16 }).clamp(10, 22) as u32;
    let optimal = p.strategy == Strategy::CRUSHLZMESH_STRAT_OPTIMAL;
    let depth = (if optimal { p.search_depth } else { p.max_depth }).clamp(1, 1024) as u32;
    let nice = if p.lookahead > 8 { p.lookahead.min(4096) as u32 } else { 128 };
    let iterations = p.iterations.clamp(1, 8) as u32;

    let mut seqs = Vec::new();
    if optimal {
        let mf = optimal::Mf::new(n, hb, depth, nice);
        optimal::Parser::new(src, mf, iterations, nice).parse(&mut seqs);
    } else {
        fast::parse_fast(src, hb, p.strategy == Strategy::CRUSHLZMESH_STRAT_LAZY, depth, &mut seqs);
    }
    let mut bufs = block::EncBufs::new();
    if !block::pack_blocks(&mut o, src, &mut seqs, &mut bufs) || o.pos >= o.dst.len() {
        return Err(fail(o.dst));
    }
    o.dst[o.pos] = 0xFF;
    Ok(o.pos + 1)
}
