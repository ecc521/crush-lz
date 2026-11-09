// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Optimal parse over a binary-tree match finder, re-priced over passes.

use super::block::dist_code;
use super::huff::{MAX_CODE, huff_lengths};
use super::{PRICE_SHIFT, Seq, ld16, ld32, match_len};

const NO_POS: u32 = u32::MAX;
const INF: u32 = u32::MAX;
const HASH3_BITS: u32 = 14;
pub(crate) const MAX_CAND: usize = 12;
const GOLD32: u32 = 2654435761;

#[derive(Clone, Copy, Default)]
pub(crate) struct Match {
    len: u32,
    dist: u32,
}

/// Binary tree match finder (as in LZMA's BT4) with a small 3-byte hash for
/// close short matches.
pub(crate) struct Mf {
    head: Vec<u32>,
    head3: Vec<u32>,
    son: Vec<u32>, // two children per window position
    wmask: u32,
    hbits: u32,
    depth: u32,
    nice: u32,
}

impl Mf {
    pub(crate) fn new(n: usize, hbits: u32, depth: u32, nice: u32) -> Mf {
        let mut w = 1u32 << 16;
        while (w as usize) < n && w < 1 << 24 {
            w <<= 1;
        }
        Mf {
            head: vec![NO_POS; 1 << hbits],
            head3: vec![NO_POS; 1 << HASH3_BITS],
            son: vec![0; 2 * w as usize],
            wmask: w - 1,
            hbits,
            depth,
            nice,
        }
    }

    #[inline(always)]
    fn hash4(&self, src: &[u8], p: usize) -> usize {
        (ld32(src, p).wrapping_mul(GOLD32) >> (32 - self.hbits)) as usize
    }

    #[inline(always)]
    fn hash3(src: &[u8], p: usize) -> usize {
        ((ld32(src, p) & 0xFF_FFFF).wrapping_mul(GOLD32) >> (32 - HASH3_BITS)) as usize
    }

    /// Collects matches at `pos` with strictly increasing length, then inserts pos.
    fn find(&mut self, src: &[u8], pos: usize, end: usize, out: &mut [Match]) -> usize {
        if end - pos < 4 {
            return 0;
        }
        let mut n = 0;
        let mut best = 2;
        let h3 = Self::hash3(src, pos);
        let c3 = self.head3[h3];
        self.head3[h3] = pos as u32;
        if c3 != NO_POS && pos - (c3 as usize) < 4096 {
            let l = match_len(src, c3 as usize, pos, end);
            if l > best {
                best = l;
                out[n] = Match { len: l as u32, dist: (pos - c3 as usize) as u32 };
                n += 1;
            }
        }
        self.bt_find(src, pos, end, Some(out), n, best)
    }

    fn insert(&mut self, src: &[u8], pos: usize, end: usize) {
        if end - pos < 4 {
            return;
        }
        self.head3[Self::hash3(src, pos)] = pos as u32;
        self.bt_find(src, pos, end, None, 0, 0);
    }

    /// Walks and re-roots the tree at pos (every call inserts pos). The tree
    /// compares up to the end of the input, matches are reported up to `end`.
    fn bt_find(&mut self, src: &[u8], pos: usize, end: usize, mut out: Option<&mut [Match]>, mut n: usize, mut best: usize) -> usize {
        let h = self.hash4(src, pos);
        let mut cur = self.head[h];
        self.head[h] = pos as u32;
        let wm = self.wmask;
        let son = &mut self.son[..];
        // Indices of the two open child links.
        let mut ptr0 = 2 * (pos & wm as usize) + 1;
        let mut ptr1 = 2 * (pos & wm as usize);
        let limit = (self.nice as usize).min(src.len() - pos);
        let (mut len0, mut len1) = (0usize, 0usize);
        let mut d = self.depth;
        loop {
            if cur == NO_POS || d == 0 || pos - cur as usize > wm as usize {
                son[ptr0] = NO_POS;
                son[ptr1] = NO_POS;
                break;
            }
            let pair = 2 * (cur & wm) as usize;
            let pb = cur as usize;
            let mut len = len0.min(len1);
            if src[pb + len] == src[pos + len] {
                len += match_len(src, pb + len, pos + len, pos + limit);
                let mut full = len.min(end - pos);
                if full > best
                    && let Some(o) = out.as_deref_mut()
                {
                    best = full;
                    if len == limit && full == len {
                        full += match_len(src, pb + len, pos + len, end);
                    }
                    if n < o.len() {
                        n += 1;
                    }
                    o[n - 1] = Match { len: full as u32, dist: (pos - cur as usize) as u32 };
                }
                if len == limit {
                    son[ptr1] = son[pair];
                    son[ptr0] = son[pair + 1];
                    break;
                }
            }
            if src[pb + len] < src[pos + len] {
                son[ptr1] = cur;
                ptr1 = pair + 1;
                cur = son[ptr1];
                len1 = len;
            } else {
                son[ptr0] = cur;
                ptr0 = pair;
                cur = son[ptr0];
                len0 = len;
            }
            d -= 1;
        }
        n
    }
}

/// Symbol prices in 1/16 bit.
#[derive(Clone)]
pub(crate) struct Prices {
    lit: [u16; 256],
    op: [u16; 256],
    ex: [u16; 256],
    dist: [u16; 256],
}

impl Default for Prices {
    fn default() -> Prices {
        Prices { lit: [0; 256], op: [0; 256], ex: [0; 256], dist: [0; 256] }
    }
}

fn prices_from_freq(out: &mut [u16; 256], freq: &[u32; 256], unseen_bits: u32) {
    let used = freq.iter().filter(|&&f| f != 0).count();
    if used < 2 {
        for s in 0..256 {
            out[s] = ((if freq[s] != 0 { 1 } else { unseen_bits }) << PRICE_SHIFT) as u16;
        }
        return;
    }
    let mut lens = [0u8; 256];
    huff_lengths(freq, MAX_CODE, &mut lens);
    for s in 0..256 {
        out[s] = ((if lens[s] != 0 { lens[s] as u32 } else { unseen_bits }) << PRICE_SHIFT) as u16;
    }
}

#[inline(always)]
fn price_extra(pr: &Prices, v: u32) -> u32 {
    if v < 255 { pr.ex[v as usize] as u32 } else { pr.ex[255] as u32 + (32 << PRICE_SHIFT) }
}

/// How a node's reps follow from its predecessor's: 0..3 that rep slot moved
/// to the front, or one of these.
const RC_NEW: u32 = 4;
const RC_LIT: u32 = 5;

/// A parse node; its price lives in a separate array.
#[derive(Clone, Copy, Default)]
struct Node {
    litlen: u32,
    prev: u32,
    len: u32,
    dist: u32,
    rc: u32,
    reps: [u32; 4], // set when the node is visited
}

pub(crate) struct Parser<'a> {
    src: &'a [u8],
    pub(crate) mf: Mf,
    pr: Prices,
    iterations: u32,
    nice: u32,
    nodes: Vec<Node>,
    price: Vec<u32>,
    best: Vec<Seq>,
    cand: Vec<Match>,
    ncand: Vec<u8>,
    chunk: usize,
}

#[inline(always)]
fn relax(nd: &mut [Node], price: &mut [u32], t: usize, p: u32, from: u32, len: u32, dist: u32, rc: u32) {
    if p < price[t] {
        price[t] = p;
        let to = &mut nd[t];
        to.litlen = 0;
        to.prev = from;
        to.len = len;
        to.dist = dist;
        to.rc = rc;
    }
}

/// Bit k set where base + lp[k] < price[k], for k < 8.
#[inline(always)]
fn less8(base: u32, lp: &[u32], price: &[u32]) -> u32 {
    let lp: &[u32; 8] = lp[..8].try_into().unwrap();
    let pr: &[u32; 8] = price[..8].try_into().unwrap();
    let mut m = 0;
    for k in 0..8 {
        m |= ((base.wrapping_add(lp[k]) < pr[k]) as u32) << k;
    }
    m
}

/// Relaxes nodes i + l for l in [a, b] with prices base + lp[l]. Few of these
/// win, so eight lengths are compared at once and only winners are written.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn relax_run(nd: &mut [Node], price: &mut [u32], i: usize, a: usize, b: usize, base: u32, lp: &[u32; 65], dist: u32, rc: u32) {
    let mut l = a;
    while l + 8 <= b + 1 {
        let mut m = less8(base, &lp[l..], &price[i + l..]);
        while m != 0 {
            let k = m.trailing_zeros() as usize;
            m &= m - 1;
            relax(nd, price, i + l + k, base.wrapping_add(lp[l + k]), i as u32, (l + k) as u32, dist, rc);
        }
        l += 8;
    }
    while l <= b {
        relax(nd, price, i + l, base.wrapping_add(lp[l]), i as u32, l as u32, dist, rc);
        l += 1;
    }
}

/// Derives node t's reps from its predecessor, which has been visited.
#[inline(always)]
fn node_reps(nd: &mut [Node], t: usize) {
    let to = nd[t];
    let pr = nd[to.prev as usize].reps;
    if to.rc == RC_LIT {
        nd[t].reps = pr;
        return;
    }
    // A new distance (even one equal to a rep) shifts the reps like slot 3.
    let r = if to.rc == RC_NEW { 3 } else { to.rc as usize };
    let mut nr = [to.dist, 0, 0, 0];
    let mut q = 1;
    for (k, &v) in pr.iter().enumerate() {
        if q == 4 {
            break;
        }
        if k == r {
            continue;
        }
        nr[q] = v;
        q += 1;
    }
    nd[t].reps = nr;
}

impl<'a> Parser<'a> {
    pub(crate) fn new(src: &'a [u8], mf: Mf, iterations: u32, nice: u32) -> Parser<'a> {
        let chunk = 1usize << 16;
        Parser {
            src,
            mf,
            pr: Prices::default(),
            iterations,
            nice,
            nodes: vec![Node::default(); chunk + 1],
            price: vec![0; chunk + 1],
            best: Vec::with_capacity(chunk + 1),
            cand: vec![Match::default(); MAX_CAND * chunk],
            ncand: vec![0; chunk],
            chunk,
        }
    }

    /// Optimal parse of [s, e) starting with `ll` pending literals and `reps`.
    /// Appends sequences for every match; returns the pending literal count.
    fn dp_chunk(&mut self, s: usize, e: usize, ll: u32, reps: &mut [u32; 4], out: &mut Vec<Seq>) -> usize {
        let src = self.src;
        let pr = &self.pr;
        let n = e - s;
        let nd = &mut self.nodes[..];
        let price = &mut self.price[..];
        let nice = self.nice as usize;
        // Op plus length-extra price of each match length up to 64, by literal
        // code: for each rep slot, and for new distances.
        let mut rep_lp = [[[0u32; 65]; 4]; 4];
        let mut new_lp = [[0u32; 65]; 4];
        for lc in 0..4 {
            let opp = &pr.op[lc << 6..];
            for l in 2..=64usize {
                for r in 0..4 {
                    rep_lp[lc][r][l] = if l <= 8 { opp[r << 3 | (l - 2)] as u32 } else { opp[r << 3 | 7] as u32 + price_extra(pr, l as u32 - 9) };
                }
                new_lp[lc][l] = if l <= 32 { opp[l + 30] as u32 } else { opp[63] as u32 + price_extra(pr, l as u32 - 33) };
            }
        }
        price[0] = 0;
        nd[0].litlen = ll;
        nd[0].len = 0;
        nd[0].reps = *reps;
        price[1..=n].fill(INF);
        let mut reach = 0usize; // nodes past this have not been relaxed

        let mut i = 0usize;
        while i < n {
            if i != 0 {
                node_reps(nd, i);
            }
            let cur = nd[i];
            let pos = s + i;
            // literal
            let lp = price[i].wrapping_add(pr.lit[src[pos] as usize] as u32);
            if lp < price[i + 1] {
                price[i + 1] = lp;
                let nx = &mut nd[i + 1];
                nx.litlen = cur.litlen + 1;
                nx.prev = i as u32;
                nx.len = 0;
                nx.rc = RC_LIT;
            }
            let avail = n - i;
            reach = reach.max(i + 1);
            if avail < 2 {
                i += 1;
                continue;
            }
            let ll_i = cur.litlen;
            let lc = ll_i.min(3) as usize;
            // Op symbols for this literal count, and the base price of any match here.
            let opp = &pr.op[lc << 6..];
            let base_price = price[i].wrapping_add(if ll_i < 3 { 0 } else { price_extra(pr, ll_i - 3) });
            let here2 = ld16(src, pos);
            let (mut best_len, mut best_dist) = (0usize, 0u32);
            // repeat distances; slots holding the same distance as an earlier
            // slot are skipped.
            let cr = cur.reps;
            let dup = ((cr[1] == cr[0]) as u32) << 1
                | ((cr[2] == cr[0] || cr[2] == cr[1]) as u32) << 2
                | ((cr[3] == cr[0] || cr[3] == cr[1] || cr[3] == cr[2]) as u32) << 3;
            for r in 0..4 {
                let d = cr[r] as usize;
                if d > pos || (dup >> r & 1) != 0 || ld16(src, pos - d) != here2 {
                    continue;
                }
                let l = match_len(src, pos - d, pos, e);
                if l < 2 {
                    continue;
                }
                reach = reach.max(i + l);
                if l >= nice {
                    best_len = l;
                    best_dist = d as u32;
                }
                let lmax = l.min(64);
                relax_run(nd, price, i, 2, lmax, base_price, &rep_lp[lc][r], d as u32, r as u32);
                if l > lmax {
                    let p = base_price.wrapping_add(opp[r << 3 | 7] as u32).wrapping_add(price_extra(pr, l as u32 - 9));
                    relax(nd, price, i + l, p, i as u32, l as u32, d as u32, r as u32);
                }
            }
            // new distances
            let nc = self.ncand[i] as usize;
            let cm = &self.cand[i * MAX_CAND..i * MAX_CAND + nc];
            let mut prevl = 2usize;
            let lpt = &new_lp[lc];
            for c in cm {
                let l = (c.len as usize).min(avail);
                let d = c.dist;
                if l <= prevl {
                    continue;
                }
                let (b, _, k) = dist_code(d);
                let bp = base_price.wrapping_add(pr.dist[b as usize] as u32).wrapping_add(k << PRICE_SHIFT);
                if l >= nice && l > best_len {
                    best_len = l;
                    best_dist = d;
                }
                let lmax = l.min(64);
                relax_run(nd, price, i, prevl + 1, lmax, bp, lpt, d, RC_NEW);
                // A length past 64 is only tried when the previous candidate
                // was at most 64 bytes long (this keeps the established parse).
                if l > lmax && prevl <= lmax {
                    let p = bp.wrapping_add(opp[63] as u32).wrapping_add(price_extra(pr, l as u32 - 33));
                    relax(nd, price, i + l, p, i as u32, l as u32, d, RC_NEW);
                }
                reach = reach.max(i + l);
                prevl = l;
            }
            if best_len != 0 {
                // Long match: commit to it and restart the parse after it.
                let slot = cur.reps.iter().position(|&x| x == best_dist);
                let j = i + best_len;
                price[j] = price[i];
                let to = &mut nd[j];
                to.litlen = 0;
                to.prev = i as u32;
                to.len = best_len as u32;
                to.dist = best_dist;
                to.rc = slot.map_or(RC_NEW, |q| q as u32);
                // Invalidate everything between so the backtrack goes through it.
                for t in j + 1..=reach {
                    price[t] = INF;
                }
                reach = j;
                price[i + 1..j].fill(INF);
                price[j] = 0;
                i = j;
                continue;
            }
            i += 1;
        }
        if n != 0 {
            node_reps(nd, n);
        }

        // Backtrack from n: literals between matches accumulate into the
        // following seq.
        let mut cnt = 0;
        let mut t = n;
        while t > 0 {
            if nd[t].len != 0 {
                cnt += 1;
            }
            t = nd[t].prev as usize;
        }
        let first = out.len();
        out.resize(first + cnt, Seq::default());
        let mut k = out.len();
        let mut pending = 0u32;
        let mut lits_after = 0u32;
        let mut t = n;
        while t > 0 {
            let pv = nd[t].prev as usize;
            if nd[t].len != 0 {
                k -= 1;
                out[k].len = nd[t].len;
                out[k].dist = nd[t].dist;
                if k + 1 < out.len() {
                    out[k + 1].lits = lits_after;
                } else {
                    pending = lits_after;
                }
                lits_after = 0;
            } else {
                lits_after += 1;
            }
            t = pv;
        }
        if cnt != 0 {
            out[first].lits = lits_after + ll;
        } else {
            pending = lits_after + ll;
        }
        *reps = nd[n].reps;
        pending as usize
    }

    /// Prices for the first chunk, from a greedy parse over its candidates:
    /// the longest new match or a rep0 match at each position, whichever is
    /// longer.
    fn seed_prices(&mut self, s: usize, e: usize, reps: [u32; 4]) {
        let src = self.src;
        let q = &mut self.best;
        q.clear();
        let mut anchor = s;
        let mut r0 = reps[0];
        let mut i = s;
        while i + 4 <= e {
            let (mut l, mut d) = (0usize, 0u32);
            if r0 as usize <= i {
                l = match_len(src, i - r0 as usize, i, e);
                d = r0;
            }
            let nc = self.ncand[i - s] as usize;
            if nc != 0 {
                let cm = self.cand[(i - s) * MAX_CAND + nc - 1];
                let cl = (cm.len as usize).min(e - i);
                if cl > l {
                    l = cl;
                    d = cm.dist;
                }
            }
            if l < 2 {
                i += 1;
                continue;
            }
            q.push(Seq { lits: (i - anchor) as u32, len: l as u32, dist: d });
            r0 = d;
            i += l;
            anchor = i;
        }
        q.push(Seq { lits: (e - anchor) as u32, len: 0, dist: 0 });
        seq_stats(src, s, q, reps, &mut self.pr);
    }

    pub(crate) fn parse(&mut self, out: &mut Vec<Seq>) {
        let src = self.src;
        let n = src.len();
        let mut reps = [1u32; 4];
        let mut ll = 0u32;
        let mut have_prices = false;
        // Re-pricing a chunk against its own statistics only pays when the
        // chunk is coded as a block of its own, so larger inputs take one pass
        // per chunk, priced from the chunk before.
        let iters = if n <= self.chunk { self.iterations } else { 1 };
        let nice = self.nice as usize;
        let mut s = 0;
        while s < n {
            let e = n.min(s + self.chunk);
            let mut i = s;
            while i < e {
                let at = (i - s) * MAX_CAND;
                let c = self.mf.find(src, i, e, &mut self.cand[at..at + MAX_CAND]);
                self.ncand[i - s] = c as u8;
                // The parse commits to matches of nice length, so skip
                // searching inside them.
                if c != 0 && self.cand[at + c - 1].len as usize >= nice {
                    let j = e.min(i + self.cand[at + c - 1].len as usize);
                    i += 1;
                    while i < j {
                        self.mf.insert(src, i, e);
                        self.ncand[i - s] = 0;
                        i += 1;
                    }
                    continue;
                }
                i += 1;
            }
            if !have_prices {
                self.seed_prices(s, e, reps);
                have_prices = true;
            }
            let r0 = reps;
            let mark = out.len();
            let mut pending;
            // Re-pricing does not always converge, so keep the cheapest pass.
            let mut best_cost = u64::MAX;
            let (mut best_n, mut best_pending) = (0usize, 0usize);
            let mut best_reps = [0u32; 4];
            for _ in 0..iters {
                out.truncate(mark);
                reps = r0;
                pending = self.dp_chunk(s, e, ll, &mut reps, out);
                // The first seq's literals start ll bytes before s.
                let cost = seq_stats(src, s - ll as usize, &out[mark..], r0, &mut self.pr);
                if cost < best_cost {
                    best_cost = cost;
                    best_n = out.len() - mark;
                    best_pending = pending;
                    best_reps = reps;
                    if iters > 1 && best_n != 0 {
                        self.best.clear();
                        self.best.extend_from_slice(&out[mark..]);
                    }
                }
            }
            if iters > 1 {
                out.truncate(mark);
                out.extend_from_slice(&self.best[..best_n]);
                pending = best_pending;
                reps = best_reps;
            } else {
                pending = best_pending;
            }
            ll = pending as u32;
            s = e;
        }
        if ll != 0 || out.is_empty() {
            out.push(Seq { lits: ll, len: 0, dist: 0 });
        }
    }
}

/// Symbol statistics of `q` as the block writer would emit them. Sets prices
/// from them and returns the estimated coded size in 1/16 bit.
fn seq_stats(src: &[u8], mut pos: usize, q: &[Seq], reps_in: [u32; 4], pr: &mut Prices) -> u64 {
    let (mut fl, mut fo, mut fe, mut fd) = ([0u32; 256], [0u32; 256], [0u32; 256], [0u32; 256]);
    let mut far = 0u64;
    let mut r = reps_in;
    for t in q {
        for &b in &src[pos..pos + t.lits as usize] {
            fl[b as usize] += 1;
        }
        pos += t.lits as usize;
        let ll = t.lits;
        let lc = ll.min(3);
        if lc == 3 {
            fe[(ll - 3).min(255) as usize] += 1;
        }
        let mut mc = 0u32;
        if t.len != 0 {
            let (d, l) = (t.dist, t.len);
            match r.iter().position(|&x| x == d) {
                Some(slot) => {
                    mc = (slot as u32) << 3 | if l <= 8 { l - 2 } else { 7 };
                    if l > 8 {
                        fe[(l - 9).min(255) as usize] += 1;
                    }
                    for k in (1..=slot).rev() {
                        r[k] = r[k - 1];
                    }
                }
                None => {
                    mc = if l <= 32 { l + 30 } else { 63 };
                    if l > 32 {
                        fe[(l - 33).min(255) as usize] += 1;
                    }
                    let (b, _, k) = dist_code(d);
                    fd[b as usize] += 1;
                    far += k as u64;
                    r[3] = r[2];
                    r[2] = r[1];
                    r[1] = r[0];
                }
            }
            r[0] = d;
            pos += l as usize;
        }
        fo[(lc << 6 | mc) as usize] += 1;
    }
    prices_from_freq(&mut pr.lit, &fl, 11);
    prices_from_freq(&mut pr.op, &fo, 11);
    prices_from_freq(&mut pr.ex, &fe, 10);
    prices_from_freq(&mut pr.dist, &fd, 10);
    let mut cost = far << PRICE_SHIFT;
    for k in 0..256 {
        cost += fl[k] as u64 * pr.lit[k] as u64 + fo[k] as u64 * pr.op[k] as u64 + fe[k] as u64 * pr.ex[k] as u64 + fd[k] as u64 * pr.dist[k] as u64;
    }
    cost
}
