// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Match probes for the fast strategies of LZFSE (levels -5 to -1) and LZVN.
// Tables hold 16-bit positions, since a call never exceeds 64 KiB, and are
// written without a check: every entry, zeroed or stale, names an earlier
// position of the block, which the compare then accepts or rejects on its
// bytes. Requires lzfse_internal.h.

#ifndef FAST_MATCH_H
#define FAST_MATCH_H

#include <stdint.h>

// Parameter ranges, shared by both codecs' validation and capabilities.
#define CRUSHLZFSE_FAST_MIN_HASH_BITS 10
#define CRUSHLZFSE_FAST_MAX_HASH_BITS 16
#define CRUSHLZFSE_FAST_MIN_MIN_MATCH 4
#define CRUSHLZFSE_FAST_MAX_MIN_MATCH 8
// The ceiling on min_match once long_table or lazy is set.
#define CRUSHLZFSE_FAST_MAX_MIN_MATCH_MODES 6
#define CRUSHLZFSE_FAST_MIN_SKIP_SHIFT 1
#define CRUSHLZFSE_FAST_MAX_SKIP_SHIFT 31
#define CRUSHLZFSE_FAST_MIN_MAX_STEP 1
#define CRUSHLZFSE_FAST_MAX_MAX_STEP 64

static inline int crushlzfse_fast_params_valid(int hb, int mm, int ss, int ms, int lt, int lazy) {
  int mm_max = (lt || lazy) ? CRUSHLZFSE_FAST_MAX_MIN_MATCH_MODES : CRUSHLZFSE_FAST_MAX_MIN_MATCH;
  return hb >= CRUSHLZFSE_FAST_MIN_HASH_BITS && hb <= CRUSHLZFSE_FAST_MAX_HASH_BITS &&
         mm >= CRUSHLZFSE_FAST_MIN_MIN_MATCH && mm <= mm_max &&
         ss >= CRUSHLZFSE_FAST_MIN_SKIP_SHIFT && ss <= CRUSHLZFSE_FAST_MAX_SKIP_SHIFT &&
         ms >= CRUSHLZFSE_FAST_MIN_MAX_STEP && ms <= CRUSHLZFSE_FAST_MAX_MAX_STEP &&
         (lt == 0 || lt == 1) && (lazy == 0 || lazy == 1);
}

// min_match bytes from the low end of v, multiplicatively hashed. prime is
// CRUSHLZFSE_FAST_PRIME, passed in so the caller can hold it in a register:
// arm64 otherwise rebuilds the 64-bit constant, four instructions, at every
// use.
#define CRUSHLZFSE_FAST_PRIME 0xCF1BBCDCB7A56463ULL
#if defined(LZFSE_PROOF)
LZFSE_NOINLINE
#else
LZFSE_INLINE
#endif
uint32_t crushlzfse_fast_hash(uint64_t v, int min_match, int hash_bits, uint64_t prime)
#if defined(LZFSE_PROOF)
LZFSE_REQUIRES(min_match >= CRUSHLZFSE_FAST_MIN_MIN_MATCH && min_match <= CRUSHLZFSE_FAST_MAX_MIN_MATCH)
LZFSE_REQUIRES(hash_bits >= CRUSHLZFSE_FAST_MIN_HASH_BITS && hash_bits <= CRUSHLZFSE_FAST_MAX_HASH_BITS)
LZFSE_ASSIGNS()
LZFSE_ENSURES(__CPROVER_return_value < (1u << hash_bits))
#endif
{
  if (min_match == 4) return ((uint32_t)v * 2654435761U) >> (32 - hash_bits);
  return (uint32_t)(((v << (64 - 8 * min_match)) * prime) >> (64 - hash_bits));
}

// Indexes two positions inside a match that started at mpos and ends at end.
LZFSE_INLINE void crushlzfse_fast_index_match(const uint8_t *src, lzfse_offset mpos, lzfse_offset end,
                                              int min_match, int hash_bits, uint64_t prime, uint16_t *table,
                                              uint16_t *ltable, int long_table) {
  uint64_t a = load8(src + mpos + 2);
  uint64_t b = load8(src + end - 2);
  table[crushlzfse_fast_hash(a, min_match, hash_bits, prime)] = (uint16_t)(mpos + 2);
  table[crushlzfse_fast_hash(b, min_match, hash_bits, prime)] = (uint16_t)(end - 2);
  if (long_table) {
    ltable[crushlzfse_fast_hash(a, 8, hash_bits, prime)] = (uint16_t)(mpos + 2);
    ltable[crushlzfse_fast_hash(load8(src + end - 1), 8, hash_bits, prime)] = (uint16_t)(end - 1);
  }
}

#if defined(LZFSE_PROOF)
LZFSE_NOINLINE
#else
LZFSE_INLINE
#endif
uint32_t crushlzfse_fast_best(const uint8_t *src, lzfse_offset pos, lzfse_offset src_end,
                                           int min_match, int hash_bits, uint64_t prime, uint16_t *table,
                                           uint16_t *ltable, int long_table, lzfse_offset *ref) {
  uint64_t v = load8(src + pos);
  uint32_t max_length = (uint32_t)(src_end - pos - 8);
  uint32_t h = crushlzfse_fast_hash(v, min_match, hash_bits, prime);
  lzfse_offset c = table[h];
  table[h] = (uint16_t)pos;
  uint32_t best = 0;
  lzfse_offset cl = -1;
  if (long_table) {
    uint32_t hl = crushlzfse_fast_hash(v, 8, hash_bits, prime);
    cl = ltable[hl];
    ltable[hl] = (uint16_t)pos;
    if (load8(src + cl) == v) {
      best = match_extend(src + cl, src + pos, 8, max_length);
      *ref = cl;
    }
  }
  if (c != cl && load4(src + c) == (uint32_t)v) {
    uint32_t len = match_extend(src + c, src + pos, 4, max_length);
    if (len > best) { best = len; *ref = c; }
  }
  return best;
}


// Looks for a match at ip or ip + 1 and extends it back over the pending
// literals from anchor. Returns its length with *mpos and *mref set, or 0.
// Probed positions are indexed either way. rep is the last distance, 0
// before the first match. The modes are the fast strategy's, described in
// lzfse_encode_base.c.
LZFSE_INLINE uint32_t crushlzfse_fast_find(const uint8_t *src, lzfse_offset src_end, lzfse_offset ilimit,
                                           lzfse_offset ip, lzfse_offset anchor, uint32_t rep, int min_match,
                                           int hash_bits, uint64_t prime, uint16_t *table, uint16_t *ltable,
                                           int long_table, int lazy, lzfse_offset *mpos_out,
                                           lzfse_offset *mref_out) {
  lzfse_offset mpos, mref = 0;
  uint32_t len;
  if (lazy) {
    // rep <= the previous match's position < ip, so ip + 1 - rep >= 1.
    if (rep != 0 && load4(src + ip + 1) == load4(src + ip + 1 - rep)) {
      uint64_t v = load8(src + ip);
      table[crushlzfse_fast_hash(v, min_match, hash_bits, prime)] = (uint16_t)ip;
      if (long_table) ltable[crushlzfse_fast_hash(v, 8, hash_bits, prime)] = (uint16_t)ip;
      mpos = ip + 1;
      mref = mpos - rep;
      len = match_extend(src + mref, src + mpos, 4, (uint32_t)(src_end - mpos - 8));
    } else {
      len = crushlzfse_fast_best(src, ip, src_end, min_match, hash_bits, prime, table, ltable, long_table, &mref);
      if (len == 0) return 0;
      mpos = ip;
      // At most two steps, so a run of ever longer candidates costs a
      // bounded number of extensions per match.
      for (int step = 0; step < 2 && mpos + 1 < ilimit; step++) {
        lzfse_offset r1 = 0;
        uint32_t l1 = crushlzfse_fast_best(src, mpos + 1, src_end, min_match, hash_bits, prime, table, ltable,
                                           long_table, &r1);
        if (l1 <= len + 1) break;
        mpos++; mref = r1; len = l1;
      }
    }
  } else if (long_table) {
    uint64_t v0 = load8(src + ip);
    uint32_t h = crushlzfse_fast_hash(v0, min_match, hash_bits, prime);
    uint32_t hl = crushlzfse_fast_hash(v0, 8, hash_bits, prime);
    lzfse_offset c = table[h], cl = ltable[hl];
    table[h] = (uint16_t)ip;
    ltable[hl] = (uint16_t)ip;
    uint32_t known = 4;
    if (rep != 0 && load4(src + ip + 1) == load4(src + ip + 1 - rep)) {
      mpos = ip + 1; mref = mpos - rep;
    } else if (load8(src + cl) == v0) {
      mpos = ip; mref = cl; known = 8;
    } else if (load4(src + c) == (uint32_t)v0) {
      uint64_t v1 = load8(src + ip + 1);
      uint32_t hl1 = crushlzfse_fast_hash(v1, 8, hash_bits, prime);
      lzfse_offset cl1 = ltable[hl1];
      ltable[hl1] = (uint16_t)(ip + 1);
      if (load8(src + cl1) == v1) { mpos = ip + 1; mref = cl1; known = 8; }
      else { mpos = ip; mref = c; }
    } else {
      return 0;
    }
    len = match_extend(src + mref, src + mpos, known, (uint32_t)(src_end - mpos - 8));
  } else {
    uint64_t v0 = load8(src + ip);
    uint64_t v1 = load8(src + ip + 1);
    uint32_t h0 = crushlzfse_fast_hash(v0, min_match, hash_bits, prime);
    uint32_t h1 = crushlzfse_fast_hash(v1, min_match, hash_bits, prime);
    lzfse_offset c0 = table[h0];
    table[h0] = (uint16_t)ip;
    lzfse_offset c1 = table[h1];
    table[h1] = (uint16_t)(ip + 1);
    if (rep != 0 && load4(src + ip + 1) == load4(src + ip + 1 - rep)) {
      mpos = ip + 1; mref = mpos - rep;
    } else if (load4(src + c0) == (uint32_t)v0) {
      mpos = ip; mref = c0;
    } else if (load4(src + c1) == (uint32_t)v1) {
      // c1 may be ip, written just above when h0 == h1: still an earlier
      // position than ip + 1.
      mpos = ip + 1; mref = c1;
    } else {
      return 0;
    }
    len = match_extend(src + mref, src + mpos, 4, (uint32_t)(src_end - mpos - 8));
  }
  while (mpos > anchor && mref > 0 && src[mpos - 1] == src[mref - 1]) { mpos--; mref--; len++; }
  *mpos_out = mpos;
  *mref_out = mref;
  return len;
}

#endif // FAST_MATCH_H
