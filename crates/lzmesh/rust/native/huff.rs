// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! Canonical Huffman: length-limited code lengths, codes and decode tables.

/// Longest symbol code.
pub(crate) const MAX_CODE: usize = 10;
/// Decode table size for symbol codes.
pub(crate) const TABLE_SIZE: usize = 1 << MAX_CODE;

#[inline]
pub(crate) fn bitrev(v: u32, n: u32) -> u32 {
    if n == 0 { 0 } else { v.reverse_bits() >> (32 - n) }
}

/// Length-limited code lengths by package-merge; unused symbols get 0.
/// `lens.len()` is the symbol count; `limit` is at most [`MAX_CODE`].
pub(crate) fn huff_lengths(freq: &[u32], limit: usize, lens: &mut [u8]) {
    const QMAX: usize = 512;
    let nsym = lens.len();
    let mut idx = [0usize; 256];
    let mut n = 0;
    lens.fill(0);
    for s in 0..nsym {
        if freq[s] != 0 {
            idx[n] = s;
            n += 1;
        }
    }
    if n == 0 {
        return;
    }
    if n == 1 {
        lens[idx[0]] = 1;
        return;
    }
    // Stable sort by frequency (ties stay in symbol order): LSD radix sort
    // over the bytes the largest frequency needs.
    let maxf = idx[..n].iter().map(|&s| freq[s]).max().unwrap();
    let mut tmp = [0usize; 256];
    let mut sh = 0;
    while sh < 32 && (maxf >> sh) != 0 {
        let mut cnt = [0usize; 257];
        for &s in &idx[..n] {
            cnt[((freq[s] >> sh) & 0xFF) as usize + 1] += 1;
        }
        for b in 0..256 {
            cnt[b + 1] += cnt[b];
        }
        for &s in &idx[..n] {
            let c = &mut cnt[((freq[s] >> sh) & 0xFF) as usize];
            tmp[*c] = s;
            *c += 1;
        }
        idx[..n].copy_from_slice(&tmp[..n]);
        sh += 8;
    }
    let mut wq = [[0u64; QMAX]; 2];
    let mut leaf = [[0u8; QMAX]; MAX_CODE];
    let mut qn = [0usize; MAX_CODE];
    // Level limit-1 is the deepest and holds only leaves.
    let mut cur = 0;
    for i in 0..n {
        wq[cur][i] = freq[idx[i]] as u64;
        leaf[limit - 1][i] = 1;
    }
    qn[limit - 1] = n;
    for lev in (0..limit - 1).rev() {
        let np = qn[lev + 1] / 2;
        let nxt = cur ^ 1;
        let (mut a, mut b, mut k) = (0, 0, 0);
        while (a < n || b < np) && k < QMAX {
            let pw = if b < np { wq[cur][2 * b] + wq[cur][2 * b + 1] } else { 0 };
            if b >= np || (a < n && freq[idx[a]] as u64 <= pw) {
                wq[nxt][k] = freq[idx[a]] as u64;
                a += 1;
                leaf[lev][k] = 1;
            } else {
                wq[nxt][k] = pw;
                b += 1;
                leaf[lev][k] = 0;
            }
            k += 1;
        }
        qn[lev] = k;
        cur = nxt;
    }
    let mut t = 2 * n - 2;
    let mut lev = 0;
    while lev < limit && t != 0 {
        let x: usize = leaf[lev][..t.min(qn[lev])].iter().map(|&b| b as usize).sum();
        for &s in &idx[..x] {
            lens[s] += 1;
        }
        t = 2 * (t - x);
        lev += 1;
    }
}

fn next_codes(lens: &[u8], table_bits: usize) -> [u32; MAX_CODE + 2] {
    let mut count = [0u32; MAX_CODE + 1];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; MAX_CODE + 2];
    let mut code = 0u32;
    for len in 1..=table_bits {
        code = (code + count[len - 1]) << 1;
        next[len] = code;
    }
    next
}

/// Bit-reversed canonical codes, ready for LSB-first writing.
pub(crate) fn huff_codes(lens: &[u8], rcodes: &mut [u16]) {
    let mut next = next_codes(lens, MAX_CODE);
    for (s, &l) in lens.iter().enumerate() {
        rcodes[s] = if l != 0 {
            let c = next[l as usize];
            next[l as usize] += 1;
            bitrev(c, l as u32) as u16
        } else {
            0
        };
    }
}

/// Decode table: entry = symbol | length << 8, length 0 marks an unused code.
/// Codes are canonical (by length, then symbol) and stored bit-reversed.
/// Returns false for an oversubscribed or too-long code.
pub(crate) fn build_dtable(table: &mut [u16], table_bits: usize, lens: &[u8]) -> bool {
    if lens.iter().any(|&l| l as usize > table_bits) {
        return false;
    }
    let mut count = [0u32; MAX_CODE + 1];
    for &l in lens {
        count[l as usize] += 1;
    }
    let kraft: u32 = (1..=table_bits).map(|len| count[len] << (table_bits - len)).sum();
    if kraft > 1 << table_bits {
        return false;
    }
    let mut next = next_codes(lens, table_bits);
    let size = 1usize << table_bits;
    let table = &mut table[..size];
    table.fill(0);
    for (s, &l) in lens.iter().enumerate() {
        if l == 0 {
            continue;
        }
        let len = l as usize;
        let rc = bitrev(next[len], len as u32) as usize;
        next[len] += 1;
        let e = (s | len << 8) as u16;
        for slot in table[rc..].iter_mut().step_by(1 << len) {
            *slot = e;
        }
    }
    true
}
