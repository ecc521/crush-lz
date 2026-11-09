// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Greedy and lazy parse for the fast levels.
//!
//! Match finding is split in two. An indexing pass hashes every position into
//! the tables (hash8, hash4 or hash4 rows, and a small hash3 for near
//! matches) and records what it found in a ring of slots, with no
//! data-dependent branches. The parse then reads slots instead of probing
//! tables, so lazy look-ahead is cheap.
//!
//! Deeper levels replace the single hash4 entry with rows: each bucket keeps
//! its last R positions and an 8-bit tag of each one's hash, so the search
//! verifies independent loads instead of walking a chain.

use super::block::bitlen32;
use super::{PRICE_SHIFT, Seq, ld32, ld64, match_len};

const H3_BITS: u32 = 14;
const H3_DIST: usize = 4096;
const RING: usize = 1024;
const GOLD32: u32 = 2654435761;

/// Cost estimates in 1/16 bit.
struct Cost {
    lit: i32,
    rep_op: i32,
    new_op: i32,
    dsym: i32,
    ext: i32,
}

#[derive(Clone, Copy, Default)]
struct Cand {
    len: u32,
    dist: u32,
    gain: i32,
}

#[inline(always)]
fn fast_gain(c: &Cost, len: u32, d: u32, rep: bool) -> i32 {
    let g = (len as i32).wrapping_mul(c.lit);
    if rep {
        return g - c.rep_op - if len > 8 { c.ext } else { 0 };
    }
    let a = ((d - 1) >> 3) + 1;
    g - c.new_op - c.dsym - (((bitlen32(a) - 1) << PRICE_SHIFT) as i32) - if len > 32 { c.ext } else { 0 }
}

/// The previous occupants of a position's hash8, hash4 and hash3 entries.
#[derive(Clone, Copy, Default)]
struct Slot {
    c8: u32,
    c4: u32,
    c3: u32,
}

/// hash4 rows of R positions plus tags, for deeper searches.
struct Rows {
    pos: Vec<u32>,
    tag: Vec<u8>,
    head: Vec<u8>,
    rlog: u32,
    rbits: u32,
}

struct Fast<'a> {
    src: &'a [u8],
    n: usize,
    lim: usize,    // positions with 8 readable bytes
    filled: usize, // positions below this are indexed
    h4: Vec<u32>,
    h3: Vec<u32>,
    h8: Vec<u32>,
    prev: Option<Vec<u32>>, // hash4 chain, for depths 2 to 8
    rows: Option<Rows>,
    depth: u32,
    hb: u32,
    c: Cost,
    ring: Box<[Slot; RING]>,
}

/// Length of the match between a and b given x = load64(a) ^ load64(b).
#[inline(always)]
fn xor_len(src: &[u8], a: usize, b: usize, x: u64) -> u32 {
    if x != 0 {
        return x.trailing_zeros() >> 3;
    }
    8 + match_len(src, a + 8, b + 8, src.len()) as u32
}

impl Fast<'_> {
    /// Indexes positions [a, b), all below lim. Tables start zeroed, so an
    /// empty entry names position 0, still a real position to compare with.
    fn index(&mut self, a: usize, b: usize) {
        let src = self.src;
        let sh8 = 64 - self.hb;
        let sh4 = 32 - self.hb;
        if let Some(prev) = self.prev.as_mut() {
            for i in a..b {
                let v = ld32(src, i);
                let s4 = &mut self.h4[(v.wrapping_mul(GOLD32) >> sh4) as usize];
                prev[i] = *s4;
                *s4 = i as u32;
            }
        } else if let Some(r) = self.rows.as_mut() {
            let rmask = (1u32 << r.rlog) - 1;
            let rsh = 32 - r.rbits;
            for i in a..b {
                let h = ld32(src, i).wrapping_mul(GOLD32);
                let row = (h >> rsh) as usize;
                let slot = (r.head[row] as u32 + 1) & rmask;
                r.head[row] = slot as u8;
                let at = (row << r.rlog) + slot as usize;
                r.pos[at] = i as u32;
                r.tag[at] = (h >> (rsh - 8)) as u8;
            }
        }
        let has_prev = self.prev.is_some();
        let has_rows = self.rows.is_some();
        for i in a..b {
            let x = ld64(src, i);
            let v = x as u32;
            let i8 = (x.wrapping_mul(0x9E37_79B1_85EB_CA87) >> sh8) as usize;
            let i3 = ((v & 0xFF_FFFF).wrapping_mul(GOLD32) >> (32 - H3_BITS)) as usize;
            let mut e = Slot { c8: self.h8[i8], c3: self.h3[i3], c4: 0 };
            self.h8[i8] = i as u32;
            self.h3[i3] = i as u32;
            if has_prev {
                e.c4 = self.prev.as_ref().unwrap()[i];
            } else if !has_rows {
                let s4 = &mut self.h4[(v.wrapping_mul(GOLD32) >> sh4) as usize];
                e.c4 = *s4;
                *s4 = i as u32;
            }
            self.ring[i & (RING - 1)] = e;
        }
    }

    /// Makes sure position i (below lim) is indexed. Indexing runs ahead in
    /// half rings, so the slots of the last RING / 2 positions stay valid.
    /// With rows it runs ahead less, as later positions push older ones out.
    #[inline(always)]
    fn slot(&mut self, i: usize) -> Slot {
        while self.filled <= i {
            let step = if self.rows.is_some() { 64 } else { RING / 2 };
            let b = (self.filled + step).min(self.lim);
            self.index(self.filled, b);
            self.filled = b;
        }
        self.ring[i & (RING - 1)]
    }

    /// Best match at i among the reps and the indexed candidates. Needs 8
    /// readable bytes at i.
    fn best(&mut self, i: usize, r: &[u32; 4]) -> Cand {
        let e = self.slot(i);
        let src = self.src;
        let n = self.n;
        let mut b = Cand::default();
        let x8 = ld64(src, i);
        let rem = n - i;
        // A hash candidate is only extended if it could be longer than the best.
        macro_rules! may_beat {
            ($c:expr) => {
                (b.len as usize) < rem && src[$c as usize + b.len as usize] == src[i + b.len as usize]
            };
        }
        for &d in r {
            if d as usize > i {
                continue;
            }
            let x = ld64(src, i - d as usize) ^ x8;
            if x & 0xFFFF != 0 {
                continue;
            }
            let l = xor_len(src, i - d as usize, i, x);
            let g = fast_gain(&self.c, l, d, true);
            if g > b.gain {
                b = Cand { len: l, dist: d, gain: g };
            }
        }
        let c8 = e.c8;
        let c4 = if self.rows.is_some() { u32::MAX } else { e.c4 };
        let c3 = e.c3;
        if (c8 as usize) < i && ld64(src, c8 as usize) == x8 && may_beat!(c8) {
            let l = 8 + match_len(src, c8 as usize + 8, i + 8, n) as u32;
            let d = (i - c8 as usize) as u32;
            let g = fast_gain(&self.c, l, d, false);
            if g > b.gain {
                b = Cand { len: l, dist: d, gain: g };
            }
        }
        if let Some(prev) = &self.prev {
            let mut c = c4;
            let mut dd = 0;
            while dd < self.depth && (c as usize) < i {
                let x = ld64(src, c as usize) ^ x8;
                if x as u32 == 0 && may_beat!(c) {
                    let l = xor_len(src, c as usize, i, x);
                    let d = (i - c as usize) as u32;
                    let g = fast_gain(&self.c, l, d, false);
                    if g > b.gain {
                        b = Cand { len: l, dist: d, gain: g };
                    }
                }
                dd += 1;
                c = prev[c as usize];
            }
        } else if let Some(rw) = &self.rows {
            let rlog = rw.rlog;
            let rr = 1u32 << rlog;
            let rsh = 32 - rw.rbits;
            let h = (x8 as u32).wrapping_mul(GOLD32);
            let row = (h >> rsh) as usize;
            let rp = &rw.pos[row << rlog..(row << rlog) + rr as usize];
            let rt = &rw.tag[row << rlog..(row << rlog) + rr as usize];
            let want = 0x0101_0101_0101_0101u64.wrapping_mul((h >> (rsh - 8)) as u8 as u64);
            let mut m = 0u64;
            for k in (0..rr as usize).step_by(8) {
                // Exact zero-byte test, then gather the high bits into a byte.
                let z = ld64(rt, k) ^ want;
                let t = !(((z & 0x7F7F_7F7F_7F7F_7F7F).wrapping_add(0x7F7F_7F7F_7F7F_7F7F)) | z | 0x7F7F_7F7F_7F7F_7F7F);
                m |= ((t >> 7).wrapping_mul(0x0102_0408_1020_4080) >> 56) << k;
            }
            // Newest first: rotate the row's head to the top bit (entry j
            // moves to bit (j + R - 1 - hd) mod R).
            let hd = rw.head[row] as u32;
            let rmask = if rr == 64 { u64::MAX } else { (1u64 << rr) - 1 };
            m = ((m << (rr - 1 - hd)) | if hd + 1 < rr { m >> (hd + 1) } else { 0 }) & rmask;
            let mut dd = 0;
            while m != 0 && dd < self.depth {
                let top = 63 - m.leading_zeros();
                m &= !(1u64 << top);
                let c = rp[((top + hd + 1) & (rr - 1)) as usize];
                if c as usize >= i {
                    continue; // indexed ahead of the parse
                }
                dd += 1;
                let x = ld64(src, c as usize) ^ x8;
                if x as u32 != 0 || !may_beat!(c) {
                    continue;
                }
                let l = xor_len(src, c as usize, i, x);
                let d = (i - c as usize) as u32;
                let g = fast_gain(&self.c, l, d, false);
                if g > b.gain {
                    b = Cand { len: l, dist: d, gain: g };
                }
            }
        } else if (c4 as usize) < i && c4 as usize != i - b.dist as usize {
            let x = ld64(src, c4 as usize) ^ x8;
            if x as u32 == 0 && may_beat!(c4) {
                let l = xor_len(src, c4 as usize, i, x);
                let d = (i - c4 as usize) as u32;
                let g = fast_gain(&self.c, l, d, false);
                if g > b.gain {
                    b = Cand { len: l, dist: d, gain: g };
                }
            }
        }
        if b.len < 4 && (c3 as usize) < i && c3 != c4 && i - (c3 as usize) < H3_DIST {
            let x = ld64(src, c3 as usize) ^ x8;
            if x & 0xFF_FFFF == 0 {
                let l = xor_len(src, c3 as usize, i, x);
                let d = (i - c3 as usize) as u32;
                let g = fast_gain(&self.c, l, d, false);
                if g > b.gain {
                    b = Cand { len: l, dist: d, gain: g };
                }
            }
        }
        b
    }
}

/// Greedy or lazy parse driven by estimated bit savings. `src.len() >= 16`.
pub(crate) fn parse_fast(src: &[u8], hb: u32, lazy: bool, depth: u32, out: &mut Vec<Seq>) {
    let n = src.len();
    let mut prev = None;
    let mut rows = None;
    if depth > 1 && depth <= 8 {
        prev = Some(vec![0u32; n]);
    } else if depth > 8 {
        // Rows of R >= depth positions, twice as many entries in all as the
        // hash4 table would have.
        let mut rlog = 4;
        while (1u32 << rlog) < depth && rlog < 6 {
            rlog += 1;
        }
        let rbits = hb + 1 - rlog;
        let ne = 1usize << (rbits + rlog);
        rows = Some(Rows { pos: vec![0; ne], tag: vec![0; ne + 8], head: vec![0; 1 << rbits], rlog, rbits });
    }
    let mut f = Fast {
        src,
        n,
        lim: n - 7,
        filled: 0,
        h4: vec![0; 1 << hb],
        h3: vec![0; 1 << H3_BITS],
        h8: vec![0; 1 << hb],
        prev,
        rows,
        depth,
        hb,
        c: Cost {
            lit: 6 << PRICE_SHIFT,
            rep_op: 6 << PRICE_SHIFT,
            new_op: 7 << PRICE_SHIFT,
            dsym: 5 << PRICE_SHIFT,
            ext: 6 << PRICE_SHIFT,
        },
        ring: Box::new([Slot::default(); RING]),
    };

    let mut r = [1u32; 4];
    let (mut i, mut anchor, mut miss) = (1usize, 0usize, 0usize);
    while i + 8 <= n {
        let mut m = f.best(i, &r);
        if m.gain <= 0 {
            miss += 1;
            i += 1 + (miss >> 6);
            continue;
        }
        miss = 0;
        let mut mi = i;
        if lazy {
            while mi + 9 <= n && m.len < 64 {
                let m2 = f.best(mi + 1, &r);
                if m2.gain <= m.gain + f.c.lit {
                    break;
                }
                m = m2;
                mi += 1;
            }
        }
        let end = (mi + m.len as usize).min(n);
        out.push(Seq { lits: (mi - anchor) as u32, len: (end - mi) as u32, dist: m.dist });
        let slot = r.iter().position(|&x| x == m.dist).unwrap_or(3);
        for k in (1..=slot).rev() {
            r[k] = r[k - 1];
        }
        r[0] = m.dist;
        i = end;
        anchor = end;
    }
    if anchor < n || out.is_empty() {
        out.push(Seq { lits: (n - anchor) as u32, len: 0, dist: 0 });
    }
}
