// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! LZMESH decoder. Payload: [raw/RLE streams][8 lanes][lane-size trailer]
//! [9-byte footer]; see docs/lzmesh-format-notes.md.

use super::huff::{MAX_CODE, TABLE_SIZE, build_dtable};
use super::{ld16, ld32, ld64};

const LANES: usize = 8;
const MAX_STREAM: usize = 65535;
const R32_MASK: usize = !31;

#[inline(always)]
fn r32(x: usize) -> usize {
    (x + 31) & R32_MASK
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Fail {
    Invalid,
    TooSmall,
}

type R<T = ()> = Result<T, Fail>;

/// One LSB-first lane over the payload. Past `end` it reads zeros.
#[derive(Clone, Copy, Default)]
struct Lane {
    p: usize,
    end: usize,
    bits: u64,
    n: u32,
}

impl Lane {
    fn new(start: usize, end: usize) -> Lane {
        Lane { p: start, end, bits: 0, n: 0 }
    }

    /// Keeps at least 56 bits buffered.
    #[inline(always)]
    fn refill(&mut self, pl: &[u8]) {
        if self.end - self.p >= 8 {
            self.bits |= ld64(pl, self.p) << self.n;
            self.p += ((63 - self.n) >> 3) as usize;
            self.n |= 56;
        } else {
            self.refill_slow(pl);
        }
    }

    #[inline(never)]
    fn refill_slow(&mut self, pl: &[u8]) {
        while self.n <= 56 {
            if self.p < self.end {
                self.bits |= (pl[self.p] as u64) << self.n;
                self.p += 1;
            }
            self.n += 8;
        }
    }

    #[inline(always)]
    fn read(&mut self, k: u32) -> u32 {
        let v = (self.bits & ((1u64 << k) - 1)) as u32;
        self.bits >>= k;
        self.n = self.n.wrapping_sub(k);
        v
    }

    /// One symbol from a table of `mask + 1` entries, or None for an unused code.
    #[inline(always)]
    fn sym(&mut self, table: &[u16], mask: u64) -> Option<u8> {
        let e = table[(self.bits & mask) as usize];
        let len = (e >> 8) as u32;
        if len == 0 {
            return None;
        }
        self.bits >>= len;
        self.n = self.n.wrapping_sub(len);
        Some(e as u8)
    }
}

/// Reads a Huffman table from the lanes into `table`.
fn read_table(lanes: &mut [Lane; LANES], pl: &[u8], table: &mut [u16; TABLE_SIZE]) -> R {
    let h = &mut lanes[0];
    let mut cl = [0u8; 11];
    h.refill(pl);
    for c in &mut cl {
        *c = h.read(3) as u8;
    }
    h.refill(pl);
    let cls = h.read(32);

    let mut ctable = [0u16; 1 << 7];
    if !build_dtable(&mut ctable, 7, &cl) {
        return Err(Fail::Invalid);
    }
    let mut lens = [0u8; 256];
    let mut j = 0usize;
    for hi in 0..16 {
        let c = (cls >> (2 * hi)) & 3;
        for half in 0..2 {
            if c & (if half == 1 { 2 } else { 1 }) == 0 {
                continue;
            }
            for lo in 0..8 {
                let l = &mut lanes[j & 7];
                j += 1;
                l.refill(pl);
                match l.sym(&ctable, 127) {
                    Some(v) if v as usize <= MAX_CODE => lens[hi * 16 + half * 8 + lo] = v,
                    _ => return Err(Fail::Invalid),
                }
            }
        }
    }
    if build_dtable(table, MAX_CODE, &lens) { Ok(()) } else { Err(Fail::Invalid) }
}

/// Symbols 8t + k for t < rounds, for the four lanes k0..k0 + 3. One refill
/// covers four codes of up to 10 bits. Returns true if a code was unused.
fn decode_lanes4(lanes: &mut [Lane; LANES], k0: usize, pl: &[u8], table: &[u16; TABLE_SIZE], out: &mut [u8], rounds: usize) -> bool {
    let [a, b, c, d] = lanes.get_disjoint_mut([k0, k0 + 1, k0 + 2, k0 + 3]).unwrap();
    // Lane state in locals so the stores to `out` cannot be assumed to alias it.
    let (mut la, mut lb, mut lc, mut ld) = (*a, *b, *c, *d);
    let mut bad = false;
    let mask = (TABLE_SIZE - 1) as u64;
    macro_rules! sym {
        ($l:ident, $dst:expr) => {{
            let e = table[($l.bits & mask) as usize];
            let len = (e >> 8) as u32;
            bad |= len == 0;
            $dst = e as u8;
            $l.bits >>= len;
            $l.n = $l.n.wrapping_sub(len);
        }};
    }
    for blk in out[..8 * rounds].as_chunks_mut::<32>().0 {
        la.refill(pl);
        lb.refill(pl);
        lc.refill(pl);
        ld.refill(pl);
        for r in 0..4 {
            sym!(la, blk[8 * r + k0]);
            sym!(lb, blk[8 * r + k0 + 1]);
            sym!(lc, blk[8 * r + k0 + 2]);
            sym!(ld, blk[8 * r + k0 + 3]);
        }
    }
    (*a, *b, *c, *d) = (la, lb, lc, ld);
    bad
}

fn read_coded(lanes: &mut [Lane; LANES], pl: &[u8], out: &mut [u8], n: usize) -> R {
    let mut table = [0u16; TABLE_SIZE];
    read_table(lanes, pl, &mut table)?;
    // Lanes are independent, so each group of four decodes its share of the
    // first 8 * rounds symbols on its own.
    let rounds = (n / LANES) & !3;
    if rounds != 0 {
        let bad = decode_lanes4(lanes, 0, pl, &table, out, rounds) | decode_lanes4(lanes, 4, pl, &table, out, rounds);
        if bad {
            return Err(Fail::Invalid);
        }
    }
    let mut k = 0;
    for slot in &mut out[rounds * LANES..n] {
        let l = &mut lanes[k];
        l.refill(pl);
        *slot = l.sym(&table, (TABLE_SIZE - 1) as u64).ok_or(Fail::Invalid)?;
        k = (k + 1) & 7;
    }
    Ok(())
}

/// Per-call buffers for the decoded streams.
pub(crate) struct Bufs {
    lits: Vec<u8>,  // MAX_STREAM + 16: 16-byte copies may read past the end
    ops: Vec<u8>,
    ex: Vec<u8>,
    dists: Vec<u8>,
    dvals: Vec<u32>, // one spare slot for speculative reads
}

impl Bufs {
    fn new() -> Bufs {
        Bufs {
            lits: vec![0; MAX_STREAM + 16],
            ops: vec![0; MAX_STREAM],
            ex: vec![0; MAX_STREAM],
            dists: vec![0; MAX_STREAM],
            dvals: vec![0; MAX_STREAM + 1],
        }
    }
}

#[inline(always)]
fn read_extra(ex: &[u8], p: &mut usize, end: usize) -> R<u32> {
    if *p >= end {
        return Err(Fail::Invalid);
    }
    let b = ex[*p];
    *p += 1;
    if b != 0xFF {
        return Ok(b as u32);
    }
    if end - *p < 4 {
        return Err(Fail::Invalid);
    }
    let v = ld32(ex, *p);
    *p += 4;
    Ok(v)
}

#[allow(clippy::too_many_arguments)]
fn decode_compressed_block(
    dst: &mut [u8],
    dst_start: usize,
    usize_: usize,
    pl: &[u8],
    s1: usize,
    s2: usize,
    nd_hi: usize,
    reps: &mut [u32; 4],
    bufs: &mut Bufs,
) -> R {
    if s2 < 9 || s1 < 9 {
        return Err(Fail::Invalid);
    }
    let e = s2 - 9;
    let r = s1 - 9;
    if r > e {
        return Err(Fail::Invalid);
    }
    let f = &pl[e..e + 9];
    let modes = ld16(f, 0) as u32;
    let mut counts = [ld16(f, 6) as usize, ld16(f, 2) as usize, ld16(f, 4) as usize, 0];
    let mut m = [0u32; 4];
    for (i, mi) in m.iter_mut().enumerate() {
        *mi = (modes >> (3 * i)) & 7;
        if *mi > 2 {
            return Err(Fail::Invalid);
        }
    }

    let mut lanes = [Lane::default(); LANES];
    let have_lanes = r < e;
    if have_lanes {
        let w = (pl[e - 1] >> 3) as u32;
        let tlen = 4usize.max((7 * w as usize + 5).div_ceil(8));
        if e < r + tlen {
            return Err(Fail::Invalid);
        }
        let st = e - tlen;
        let mut t = Lane::new(st, e);
        let mut pos = r;
        for (k, lane) in lanes.iter_mut().enumerate() {
            let sz = if k < 7 {
                t.refill(pl);
                t.read(w) as usize
            } else {
                st - pos
            };
            if sz > st - pos {
                return Err(Fail::Invalid);
            }
            // Sizes only place each lane's start: as Apple's decoder accepts, a
            // lane that reads past its end continues into the bytes after it.
            *lane = Lane::new(pos, e);
            pos += sz;
        }
    }

    let mut raw = 0usize;
    for i in 0..4 {
        if i == 3 {
            let nd = bufs.ops[..counts[1]].iter().filter(|&&op| op & 63 >= 32).count();
            // The low byte of the count ends the payload; the high byte follows it.
            if nd != (f[8] as usize | nd_hi << 8) {
                return Err(Fail::Invalid);
            }
            counts[3] = nd;
        }
        let n = counts[i];
        let buf: &mut [u8] = match i {
            0 => &mut bufs.lits,
            1 => &mut bufs.ops,
            2 => &mut bufs.ex,
            _ => &mut bufs.dists,
        };
        match m[i] {
            0 => {
                if r - raw < n {
                    return Err(Fail::Invalid);
                }
                buf[..n].copy_from_slice(&pl[raw..raw + n]);
                raw += n;
            }
            1 => {
                if raw >= r {
                    return Err(Fail::Invalid);
                }
                buf[..n].fill(pl[raw]);
                raw += 1;
            }
            _ => {
                if !have_lanes {
                    return Err(Fail::Invalid);
                }
                read_coded(&mut lanes, pl, buf, n)?;
            }
        }
    }
    if raw != r {
        return Err(Fail::Invalid);
    }

    // Far-distance bits follow the coded streams; distance j uses lane j % 8.
    let nd = counts[3];
    for j in 0..nd {
        let b = bufs.dists[j] as u32;
        let k = b >> 3;
        let mut d = (b & 7) as u64 + 1;
        if k != 0 {
            if !have_lanes {
                return Err(Fail::Invalid);
            }
            let l = &mut lanes[j & 7];
            l.refill(pl);
            let a = (1u64 << k) | l.read(k) as u64;
            // Apple keeps the low 32 bits; the match checks the result.
            d = ((((a - 1) << 3) | (b & 7) as u64) + 1) & 0xFFFF_FFFF;
        }
        bufs.dvals[j] = d as u32;
    }

    execute(dst, dst_start, usize_, counts, reps, bufs)
}

/// Runs the ops. The block size truncates the final match. Fast paths copy
/// in 16-byte chunks and may write up to 32 bytes past the current position,
/// but never past the end of `dst`.
fn execute(dst: &mut [u8], dst_start: usize, usize_: usize, counts: [usize; 4], reps: &mut [u32; 4], bufs: &Bufs) -> R {
    let lits = &bufs.lits[..];
    let ops = &bufs.ops[..counts[1]];
    let exb = &bufs.ex[..];
    let dvals = &bufs.dvals[..];
    let mut o = dst_start;
    let oend = o + usize_;
    let wend = dst.len().saturating_sub(32);
    let mut lit = 0usize;
    let lit_end = counts[0];
    let mut ex = 0usize;
    let ex_end = counts[2];
    let mut dv = 0usize;
    let dv_end = counts[3];
    let lit_cap = r32(counts[0]);
    let mut opi = 0usize;
    let mut first_bonus = (dst_start == 0) as usize;
    let [mut r0, mut r1, mut r2, mut r3] = *reps;

    while opi < ops.len() && o < oend {
        let op = ops[opi] as usize;
        opi += 1;
        let lc = op >> 6;
        let mc = op & 63;
        let mut nl = lc;
        if lc == 3 {
            nl = 3 + read_extra(exb, &mut ex, ex_end)? as usize;
        }
        nl += first_bonus;
        first_bonus = 0;
        // Only the literals actually written must exist; the block's size can
        // cut the final run short, but not past r32(lits) + the current op
        // index, which Apple's decoder rejects.
        if lit + nl > lit_cap + (opi - 1) {
            return Err(Fail::Invalid);
        }
        let take = nl.min(oend - o);
        if lit_end - lit < take {
            return Err(Fail::Invalid);
        }
        if take <= 16 && o <= wend {
            dst[o..o + 16].copy_from_slice(&lits[lit..lit + 16]);
        } else if o + take <= wend {
            let mut i = 0;
            while i < take {
                dst[o + i..o + i + 16].copy_from_slice(&lits[lit + i..lit + i + 16]);
                i += 16;
            }
        } else {
            dst[o..o + take].copy_from_slice(&lits[lit..lit + take]);
        }
        lit += take;
        o += take;

        // Rep and new-distance matches share the arithmetic: a new distance is
        // read speculatively (dvals has a spare slot) and moves the reps like
        // slot 3.
        let isnew = mc >= 32;
        let rv = if mc & 16 != 0 { if mc & 8 != 0 { r3 } else { r2 } } else if mc & 8 != 0 { r1 } else { r0 };
        let d = if isnew { dvals[dv] } else { rv };
        let r = if isnew { 3 } else { mc >> 3 };
        let mut ml = if isnew { mc - 30 } else { (mc & 7) + 2 };
        if if isnew { mc == 63 } else { mc & 7 == 7 } {
            ml = (if isnew { 33 } else { 9 }) + read_extra(exb, &mut ex, ex_end)? as usize;
        }
        if isnew {
            if dv >= dv_end {
                return Err(Fail::Invalid);
            }
            dv += 1;
        }
        // Move to front.
        r3 = if r >= 3 { r2 } else { r3 };
        r2 = if r >= 2 { r1 } else { r2 };
        r1 = if r >= 1 { r0 } else { r1 };
        r0 = d;
        if o >= oend {
            break;
        }
        let d = d as usize;
        // A distance that wrapped to 0 is rejected, but only when a match
        // byte is written, as Apple does.
        if d == 0 || d > o {
            return Err(Fail::Invalid);
        }
        let m = o - d;
        if o + ml <= wend {
            if d >= 16 {
                // Sequential 16-byte copies stay correct for d >= 16.
                dst.copy_within(m..m + 16, o);
                dst.copy_within(m + 16..m + 32, o + 16);
                let mut i = 32;
                while i < ml {
                    dst.copy_within(m + i..m + i + 16, o + i);
                    i += 16;
                }
            } else if d >= 8 {
                let mut i = 0;
                while i < ml {
                    dst.copy_within(m + i..m + i + 8, o + i);
                    i += 8;
                }
            } else {
                // Spread the period to at least 8 bytes, then copy 8 at a time.
                const INC: [usize; 8] = [0, 1, 2, 1, 0, 4, 4, 4];
                const DEC: [isize; 8] = [0, 0, 0, -1, -4, 1, 2, 3];
                for k in 0..4 {
                    dst[o + k] = dst[m + k];
                }
                let s = m + INC[d];
                dst.copy_within(s..s + 4, o + 4);
                let s = s.wrapping_sub(DEC[d] as usize);
                let mut i = 8;
                while i < ml {
                    dst.copy_within(s + i - 8..s + i, o + i);
                    i += 8;
                }
            }
            o = (o + ml).min(oend);
        } else {
            let ml = ml.min(oend - o);
            for i in 0..ml {
                dst[o + i] = dst[m + i];
            }
            o += ml;
        }
    }
    *reps = [r0, r1, r2, r3];
    // Apple's decoder also rejects blocks with unused stream elements.
    if o != oend || opi != ops.len() || lit != lit_end || ex != ex_end || dv != dv_end {
        return Err(Fail::Invalid);
    }
    Ok(())
}

/// Decodes a whole stream into `dst`. Returns (status, bytes of completed blocks).
pub(crate) fn decode(dst: &mut [u8], src: &[u8]) -> (R, usize) {
    let mut sp = 0usize;
    let mut dp = 0usize;
    let mut reps = [1u32; 4];
    let mut bufs: Option<Box<Bufs>> = None;
    while sp < src.len() {
        let btype = src[sp];
        sp += 1;
        match btype {
            0xFF => return (Ok(()), dp),
            0x00 => {
                if src.len() - sp < 4 {
                    break;
                }
                let us = ld32(src, sp) as usize;
                sp += 4;
                if src.len() - sp < us {
                    break;
                }
                if dst.len() - dp < us {
                    return (Err(Fail::TooSmall), dp);
                }
                dst[dp..dp + us].copy_from_slice(&src[sp..sp + us]);
                dp += us;
                sp += us;
            }
            0x01 => {
                if src.len() - sp < 8 {
                    break;
                }
                let us = ld32(src, sp) as usize;
                let s1 = ld16(src, sp + 4) as usize;
                let s2 = ld16(src, sp + 6) as usize;
                sp += 8;
                if src.len() - sp < s2 + 1 || s2 >= us {
                    break;
                }
                if dst.len() - dp < us {
                    return (Err(Fail::TooSmall), dp);
                }
                let b = bufs.get_or_insert_with(|| Box::new(Bufs::new()));
                let pl = &src[sp..sp + s2];
                if decode_compressed_block(dst, dp, us, pl, s1, s2, src[sp + s2] as usize, &mut reps, b).is_err() {
                    break;
                }
                dp += us;
                sp += s2 + 1;
            }
            _ => break,
        }
    }
    (Err(Fail::Invalid), dp)
}
