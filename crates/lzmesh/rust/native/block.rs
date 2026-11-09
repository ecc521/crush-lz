// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Block assembly: streams from parsed sequences, entropy plans, the block
//! writer and the packer that splits sequences into blocks.

use super::huff::{MAX_CODE, huff_codes, huff_lengths};
use super::Seq;

const LANES: usize = 8;
pub(crate) const MAX_STREAM: usize = 65535;
const PAYLOAD_MAX: usize = 65535;
const SCRATCH_MAX: usize = 62944;
const MODE_RAW: u32 = 0;
const MODE_RLE: u32 = 1;
const MODE_HUFF: u32 = 2;

#[inline(always)]
fn r32(x: usize) -> usize {
    (x + 31) & !31
}

#[inline(always)]
pub(crate) fn bitlen32(v: u32) -> u32 {
    32 - v.leading_zeros()
}

/// Distance byte k << 3 | low plus k raw bits holding a - 2^k.
#[inline(always)]
pub(crate) fn dist_code(d: u32) -> (u32, u32, u32) {
    let x = d.wrapping_sub(1);
    let a = (x >> 3) + 1;
    let k = bitlen32(a) - 1;
    ((k << 3) | (x & 7), a - (1 << k), k)
}

/// LSB-first bit writer over its own buffer. Each put stores 8 bytes, so the
/// buffer has 8 bytes of slack past `end`; a put that would overrun even that
/// marks the writer as overflowed instead.
pub(crate) struct Bw {
    buf: Vec<u8>,
    p: usize,
    end: usize,
    acc: u64,
    n: u32,
    over: bool,
}

impl Bw {
    pub(crate) fn new(cap: usize) -> Bw {
        Bw { buf: vec![0; cap + 16], p: 0, end: cap, acc: 0, n: 0, over: false }
    }

    fn reset(&mut self) {
        self.p = 0;
        self.acc = 0;
        self.n = 0;
        self.over = false;
    }

    /// Writes k <= 32 bits.
    #[inline(always)]
    pub(crate) fn put(&mut self, v: u64, k: u32) {
        let acc = self.acc | v << self.n;
        let n = self.n + k;
        match self.buf.get_mut(self.p..self.p + 8) {
            Some(w) => w.copy_from_slice(&acc.to_le_bytes()),
            None => {
                self.over = true;
                return;
            }
        }
        self.p += (n >> 3) as usize;
        self.acc = acc >> (n & !7);
        self.n = n & 7;
    }

    /// Pads to a byte boundary. Returns false if the writer ran past its end.
    pub(crate) fn flush(&mut self) -> bool {
        if self.n != 0 {
            self.put(0, 8 - self.n);
        }
        !self.over && self.p <= self.end
    }

    fn bytes(&self) -> &[u8] {
        &self.buf[..self.p]
    }
}

/// Table layout: 11 3-bit code-length-code lengths, 16 2-bit half masks,
/// then each participating symbol's length spread over the lanes.
#[derive(Clone, Copy, Default)]
struct TablePlan {
    cllen: [u8; 11],
    clcode: [u16; 11],
    halves: u32,
    bits: usize,
}

fn plan_table(lens: &[u8; 256]) -> TablePlan {
    let mut t = TablePlan::default();
    let mut clfreq = [0u32; 11];
    for h in 0..32 {
        let g = &lens[h * 8..h * 8 + 8];
        if g.iter().all(|&l| l == 0) {
            continue;
        }
        t.halves |= 1 << h;
        for &l in g {
            clfreq[l as usize] += 1;
        }
    }
    let used = clfreq.iter().filter(|&&f| f != 0).count();
    let last = clfreq.iter().rposition(|&f| f != 0).unwrap_or(0);
    if used < 2 {
        clfreq[if last == 0 { 1 } else { 0 }] = 1;
    }
    huff_lengths(&clfreq, 7, &mut t.cllen);
    huff_codes(&t.cllen, &mut t.clcode);
    t.bits = 33 + 32;
    for h in 0..32 {
        if t.halves >> h & 1 != 0 {
            for &l in &lens[h * 8..h * 8 + 8] {
                t.bits += t.cllen[l as usize] as usize;
            }
        }
    }
    t
}

fn write_table(lanes: &mut [Bw], lens: &[u8; 256], t: &TablePlan) {
    for &l in &t.cllen {
        lanes[0].put(l as u64, 3);
    }
    for hi in 0..16 {
        lanes[0].put(((t.halves >> (2 * hi)) & 3) as u64, 2);
    }
    let mut j = 0;
    for h in 0..32 {
        if t.halves >> h & 1 == 0 {
            continue;
        }
        for &v in &lens[h * 8..h * 8 + 8] {
            lanes[j & 7].put(t.clcode[v as usize] as u64, t.cllen[v as usize] as u32);
            j += 1;
        }
    }
}

struct StreamPlan {
    mode: u32,
    lens: [u8; 256],
    codes: [u16; 256],
    plan: TablePlan,
}

fn plan_stream(data: &[u8]) -> StreamPlan {
    let mut sp = StreamPlan { mode: MODE_RAW, lens: [0; 256], codes: [0; 256], plan: TablePlan::default() };
    let n = data.len();
    let mut freq = [0u32; 256];
    let mut f4 = [[0u32; 256]; 3];
    // Four counters per symbol so runs of one byte do not serialize on a store.
    let (ch, rem) = data.as_chunks::<4>();
    for c in ch {
        freq[c[0] as usize] += 1;
        f4[0][c[1] as usize] += 1;
        f4[1][c[2] as usize] += 1;
        f4[2][c[3] as usize] += 1;
    }
    for &b in rem {
        freq[b as usize] += 1;
    }
    for k in 0..256 {
        freq[k] += f4[0][k] + f4[1][k] + f4[2][k];
    }
    let distinct = freq.iter().filter(|&&f| f != 0).count();
    if n == 0 {
        return sp;
    }
    if distinct == 1 {
        sp.mode = MODE_RLE;
        return sp;
    }
    huff_lengths(&freq, MAX_CODE, &mut sp.lens);
    huff_codes(&sp.lens, &mut sp.codes);
    sp.plan = plan_table(&sp.lens);
    let mut bits = sp.plan.bits;
    for s in 0..256 {
        bits += freq[s] as usize * sp.lens[s] as usize;
    }
    sp.mode = if bits.div_ceil(8) + 8 < n { MODE_HUFF } else { MODE_RAW };
    sp
}

/// Encoder work buffers, reused across blocks.
pub(crate) struct EncBufs {
    lits: Vec<u8>,
    ops: Vec<u8>,
    ex: Vec<u8>,
    dists: Vec<u8>,
    far: Vec<u32>,
    lanes: Vec<Bw>,
}

impl EncBufs {
    pub(crate) fn new() -> EncBufs {
        EncBufs {
            lits: vec![0; MAX_STREAM + 32],
            ops: vec![0; MAX_STREAM],
            ex: vec![0; MAX_STREAM],
            dists: vec![0; MAX_STREAM],
            far: vec![0; MAX_STREAM],
            lanes: (0..LANES).map(|_| Bw::new(PAYLOAD_MAX)).collect(),
        }
    }
}

/// One block's streams, as built by build_streams.
#[derive(Clone, Copy, Default)]
pub(crate) struct Block {
    take: usize,
    usize: usize,
    nl: usize,
    no: usize,
    ne: usize,
    nd: usize,
    far: bool,
    reps: [u32; 4],
}

#[inline(always)]
fn push_extra(ex: &mut [u8], ne: &mut usize, v: u32) {
    if v < 255 {
        ex[*ne] = v as u8;
        *ne += 1;
    } else {
        ex[*ne] = 0xFF;
        ex[*ne + 1..*ne + 5].copy_from_slice(&v.to_le_bytes());
        *ne += 5;
    }
}

/// Builds the streams for the longest prefix of `q` that fits the decoder's
/// budget: Apple's decoder rejects blocks whose stream sizes exceed it (see
/// the format notes).
/// `src` starts at the block's first byte.
fn build_streams(src: &[u8], q: &[Seq], stream_start: bool, reps: [u32; 4], b: &mut EncBufs) -> Block {
    let (mut nl, mut no, mut ne, mut nd, mut us) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut farbits = 0u32;
    let [mut r0, mut r1, mut r2, mut r3] = reps;
    let mut p = 0usize;
    let mut i = 0;
    while i < q.len() {
        let t = q[i];
        let (lits, l, d) = (t.lits, t.len, t.dist);
        let enc = lits - (stream_start && i == 0) as u32;
        let mut e2 = ne + if enc < 3 { 0 } else if enc - 3 < 255 { 1 } else { 5 };
        let mut d2 = nd;
        let mut slot: i32 = 4;
        if l != 0 {
            slot = if r0 == d { 0 } else if r1 == d { 1 } else if r2 == d { 2 } else if r3 == d { 3 } else { -1 };
            if slot >= 0 {
                if l > 8 {
                    e2 += if l - 9 < 255 { 1 } else { 5 };
                }
            } else {
                if l > 32 {
                    e2 += if l - 33 < 255 { 1 } else { 5 };
                }
                d2 += 1;
            }
        }
        let lits = lits as usize;
        let cost = r32(nl + lits) + r32(no + 1) + r32(e2) + r32(d2) + r32(4 * d2);
        if cost > SCRATCH_MAX || nl + lits > MAX_STREAM {
            break;
        }
        b.lits[nl..nl + lits].copy_from_slice(&src[p..p + lits]);
        nl += lits;
        p += lits;
        let lc = enc.min(3);
        if lc == 3 {
            push_extra(&mut b.ex, &mut ne, enc - 3);
        }
        let mut mc = 0u32;
        if slot == 4 {
            // literal-only seq
        } else if slot >= 0 {
            if l <= 8 {
                mc = (slot as u32) << 3 | (l - 2);
            } else {
                mc = (slot as u32) << 3 | 7;
                push_extra(&mut b.ex, &mut ne, l - 9);
            }
            if slot >= 3 {
                r3 = r2;
            }
            if slot >= 2 {
                r2 = r1;
            }
            if slot >= 1 {
                r1 = r0;
            }
            r0 = d;
        } else {
            if l <= 32 {
                mc = l + 30;
            } else {
                mc = 63;
                push_extra(&mut b.ex, &mut ne, l - 33);
            }
            let (code, v, kb) = dist_code(d);
            b.dists[nd] = code as u8;
            b.far[nd] = v;
            nd += 1;
            farbits |= kb;
            r3 = r2;
            r2 = r1;
            r1 = r0;
            r0 = d;
        }
        b.ops[no] = (lc << 6 | mc) as u8;
        no += 1;
        p += l as usize;
        us += lits + l as usize;
        i += 1;
    }
    Block { take: i, usize: us, nl, no, ne, nd, far: farbits != 0, reps: [r0, r1, r2, r3] }
}

#[derive(PartialEq, Eq)]
enum Why {
    TooBig,
    Raw,
}

/// Writes one compressed block into `out`. Returns its size, or why not.
fn write_block(out: &mut [u8], k: &Block, b: &mut EncBufs) -> Result<usize, Why> {
    let (nl, no, ne, nd, usize_) = (k.nl, k.no, k.ne, k.nd, k.usize);
    let counts = [nl, no, ne, nd];
    let sp: [StreamPlan; 4] = [plan_stream(&b.lits[..nl]), plan_stream(&b.ops[..no]), plan_stream(&b.ex[..ne]), plan_stream(&b.dists[..nd])];
    let mut need_lanes = k.far;
    let mut raw_len = 0;
    for i in 0..4 {
        need_lanes |= sp[i].mode == MODE_HUFF;
        raw_len += match sp[i].mode {
            MODE_RAW => counts[i],
            MODE_RLE => 1,
            _ => 0,
        };
    }
    if raw_len + 9 + 15 > usize_ {
        return Err(Why::Raw);
    }
    let room = out.len().saturating_sub(10).min(PAYLOAD_MAX);
    if raw_len + 9 > room {
        return Err(Why::TooBig);
    }
    let (head, pl) = out.split_at_mut(9);
    let mut pos = 0;
    for i in 0..4 {
        let data: &[u8] = match i {
            0 => &b.lits[..nl],
            1 => &b.ops[..no],
            2 => &b.ex[..ne],
            _ => &b.dists[..nd],
        };
        match sp[i].mode {
            MODE_RAW => {
                pl[pos..pos + data.len()].copy_from_slice(data);
                pos += data.len();
            }
            MODE_RLE => {
                pl[pos] = data[0];
                pos += 1;
            }
            _ => {}
        }
    }
    let r = pos;
    if need_lanes {
        let EncBufs { lits, ops, ex, dists, far, lanes } = b;
        for l in lanes.iter_mut() {
            l.reset();
        }
        for i in 0..4 {
            if sp[i].mode != MODE_HUFF {
                continue;
            }
            write_table(lanes, &sp[i].lens, &sp[i].plan);
            let mut ce = [0u32; 256];
            for c in 0..256 {
                ce[c] = sp[i].codes[c] as u32 | (sp[i].lens[c] as u32) << 16;
            }
            let d: &[u8] = match i {
                0 => &lits[..nl],
                1 => &ops[..no],
                2 => &ex[..ne],
                _ => &dists[..nd],
            };
            let (ch, rem) = d.as_chunks::<LANES>();
            for c in ch {
                for (l, &s) in c.iter().enumerate() {
                    let e = ce[s as usize];
                    lanes[l].put((e & 0xFFFF) as u64, e >> 16);
                }
            }
            for (l, &s) in rem.iter().enumerate() {
                let e = ce[s as usize];
                lanes[l].put((e & 0xFFFF) as u64, e >> 16);
            }
        }
        if k.far {
            for j in 0..nd {
                lanes[j & 7].put(far[j] as u64, (dists[j] >> 3) as u32);
            }
        }
        let mut sizes = [0usize; LANES];
        let (mut total, mut maxsz) = (0, 0);
        for l in 0..LANES {
            // A non-empty lane ends with a 1 bit before the zero padding.
            if lanes[l].p != 0 || lanes[l].n != 0 {
                lanes[l].put(1, 1);
            }
            if !lanes[l].flush() {
                return Err(Why::TooBig);
            }
            sizes[l] = lanes[l].p;
            total += sizes[l];
            if l < 7 {
                maxsz = maxsz.max(sizes[l]);
            }
        }
        let w = bitlen32(maxsz as u32).max(1);
        let tlen = 4usize.max((7 * w as usize + 5).div_ceil(8));
        if r + total + tlen + 9 > room {
            return Err(Why::TooBig);
        }
        for l in lanes.iter() {
            pl[pos..pos + l.p].copy_from_slice(l.bytes());
            pos += l.p;
        }
        let mut tw = Bw::new(24);
        for &sz in &sizes[..7] {
            tw.put(sz as u64, w);
        }
        tw.flush();
        pl[pos..pos + tlen].copy_from_slice(&tw.buf[..tlen]);
        pl[pos + tlen - 1] |= (w << 3) as u8;
        pos += tlen;
    }
    let modes = sp[0].mode | sp[1].mode << 3 | sp[2].mode << 6 | sp[3].mode << 9;
    let f = &mut pl[pos..pos + 9];
    f[0..2].copy_from_slice(&(modes as u16).to_le_bytes());
    f[2..4].copy_from_slice(&(no as u16).to_le_bytes());
    f[4..6].copy_from_slice(&(ne as u16).to_le_bytes());
    f[6..8].copy_from_slice(&(nl as u16).to_le_bytes());
    f[8] = nd as u8;
    pos += 9;
    // Keep compressed blocks at least 5 bytes under raw so the bound holds.
    if pos + 10 + 5 > usize_ {
        return Err(Why::Raw);
    }
    head[0] = 0x01;
    head[1..5].copy_from_slice(&(usize_ as u32).to_le_bytes());
    head[5..7].copy_from_slice(&((r + 9) as u16).to_le_bytes());
    head[7..9].copy_from_slice(&(pos as u16).to_le_bytes());
    pl[pos] = (nd >> 8) as u8;
    Ok(pos + 10)
}

/// Output cursor with a pending raw run [raw_start, raw_end) of the input.
pub(crate) struct Out<'a> {
    pub(crate) dst: &'a mut [u8],
    pub(crate) pos: usize,
    pub(crate) raw_start: usize,
    pub(crate) raw_end: usize,
}

impl Out<'_> {
    pub(crate) fn flush_raw(&mut self, src: &[u8]) -> bool {
        let len = self.raw_end - self.raw_start;
        if len == 0 {
            return true;
        }
        if len > 0xFFFF_FFFF || self.dst.len() - self.pos < len + 5 {
            return false;
        }
        let p = self.pos;
        self.dst[p] = 0x00;
        self.dst[p + 1..p + 5].copy_from_slice(&(len as u32).to_le_bytes());
        self.dst[p + 5..p + 5 + len].copy_from_slice(&src[self.raw_start..self.raw_end]);
        self.pos += len + 5;
        self.raw_start = self.raw_end;
        true
    }
}

/// Writes block `k` where it will land once the pending raw run is flushed,
/// and flushes that run only if the block is kept, so a raw run is split only
/// by a block that is smaller than raw. Returns false only when the output
/// cannot hold the raw run.
fn try_block(o: &mut Out, src: &[u8], k: &Block, b: &mut EncBufs, min_room: usize) -> Result<bool, Why> {
    let pending = o.raw_end - o.raw_start;
    let reserve = if pending != 0 { pending + 5 } else { 0 };
    if pending > 0xFFFF_FFFF || o.dst.len() - o.pos < reserve {
        return Ok(false);
    }
    let at = o.pos + reserve;
    if o.dst.len() - at <= min_room {
        return Err(Why::TooBig);
    }
    let w = write_block(&mut o.dst[at..], k, b)?;
    let flushed = o.flush_raw(src);
    debug_assert!(flushed && o.pos == at);
    o.pos += w;
    Ok(true)
}

/// Packs seqs into blocks of at most 64 KiB payload, each as many seqs as fit
/// the decoder's scratch budget. Anything that does not compress below raw
/// joins the pending raw run.
pub(crate) fn pack_blocks(o: &mut Out, src: &[u8], q: &mut [Seq], b: &mut EncBufs) -> bool {
    let mut reps = [1u32; 4];
    let mut inp = 0usize;
    let mut si = 0usize;
    while si < q.len() {
        let mut k = build_streams(&src[inp..], &q[si..], inp == 0, reps, b);
        if k.take == 0 {
            // One huge literal run: emit a literal-only piece of it.
            let piece = [Seq { lits: 32768, len: 0, dist: 0 }];
            k = build_streams(&src[inp..], &piece, inp == 0, reps, b);
            match try_block(o, src, &k, b, 16) {
                Ok(false) => return false,
                Ok(true) => {
                    o.raw_start = inp + 32768;
                    o.raw_end = inp + 32768;
                }
                Err(_) => o.raw_end += 32768,
            }
            inp += 32768;
            q[si].lits -= 32768;
            continue;
        }
        loop {
            match try_block(o, src, &k, b, 0) {
                Ok(false) => return false,
                Ok(true) => {
                    reps = k.reps;
                    o.raw_start = inp + k.usize;
                    o.raw_end = inp + k.usize;
                    break;
                }
                Err(Why::TooBig) if k.take > 1 => {
                    k = build_streams(&src[inp..], &q[si..si + k.take / 2], inp == 0, reps, b);
                }
                Err(_) => {
                    // Raw: the matches in a raw block no longer update the
                    // reps; later blocks re-derive rep slots by distance.
                    o.raw_end += k.usize;
                    break;
                }
            }
        }
        inp += k.usize;
        si += k.take;
    }
    o.flush_raw(src)
}
