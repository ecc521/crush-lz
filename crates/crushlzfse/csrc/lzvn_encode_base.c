/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
    in the documentation and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
// Modifications copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0 AND BSD-3-Clause


// LZVN low-level encoder

#include "lzvn_encode_base.h"
#include "lzvn_zopt.h"
#include "bt_match.h"
#include "fast_match.h"

#if defined(_MSC_VER) && !defined(__clang__)
#  define restrict __restrict
#endif

/*! Copy at least nbytes by 8-byte blocks (may overrun); no overlap. */
LZVN_INLINE unsigned char *lzvn_copy64(unsigned char *restrict dst,
                                       const unsigned char *restrict src,
                                       size_t nbytes)
#ifdef LZVN_PROOF
LZVN_REQUIRES(nbytes <= PROOF_MAX_OBJECT - 8)
LZVN_REQUIRES(__CPROVER_r_ok(src, nbytes + 7))
LZVN_REQUIRES(__CPROVER_w_ok(dst, nbytes + 7))
LZVN_REQUIRES(!__CPROVER_same_object(src, dst))
LZVN_ASSIGNS(__CPROVER_object_upto(dst, nbytes + 7))
LZVN_ENSURES(__CPROVER_return_value == dst + nbytes)
#endif
{
#if defined(LZVN_PROOF) && defined(LZVN_FAST_COPY)
  __CPROVER_assert(__CPROVER_r_ok(src, nbytes + 7), "copy64 src read");
  __CPROVER_assert(__CPROVER_w_ok(dst, nbytes + 7), "copy64 dst write");
  return dst + nbytes;
#else
  for (size_t i = 0; i < nbytes; i += 8)
#ifdef LZVN_PROOF
    LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst, nbytes + 7))
    LZVN_LOOP_INVARIANT(i <= nbytes + 7 && i % 8 == 0)
    LZVN_LOOP_DECREASES(nbytes + 7 - i)
    memcpy(dst + i, src + i, 8);
#else
    store8(dst + i, load8(src + i));
#endif
  return dst + nbytes;
#endif
}

/*! Copy exactly nbytes; unlike lzvn_copy64, never reads or writes past
 * nbytes in either buffer, since callers use it (in emit_literal, for the
 * stream's very last literal run) right up against the true end of src. */
LZVN_INLINE unsigned char *lzvn_copy8(unsigned char *restrict dst,
                                      const unsigned char *restrict src,
                                      size_t nbytes)
#ifdef LZVN_PROOF
LZVN_REQUIRES(__CPROVER_r_ok(src, nbytes))
LZVN_REQUIRES(__CPROVER_w_ok(dst, nbytes))
LZVN_REQUIRES(!__CPROVER_same_object(src, dst))
LZVN_ASSIGNS(__CPROVER_object_upto(dst, nbytes))
LZVN_ENSURES(__CPROVER_return_value == dst + nbytes)
#endif
{
#if defined(LZVN_PROOF) && defined(LZVN_COPY_SUMMARY)
  /* Full-range copy summary for emitter composition. The actual scalar
   * copy loops are verified separately by lzvn_copy8, without this flag. */
  memcpy(dst, src, nbytes);
  return dst + nbytes;
#elif defined(LZVN_PROOF) && defined(LZVN_FAST_COPY)
  __CPROVER_assert(__CPROVER_r_ok(src, nbytes), "copy8 src read");
  __CPROVER_assert(__CPROVER_w_ok(dst, nbytes), "copy8 dst write");
  return dst + nbytes;
#else
  size_t i = 0;
#if defined(LZFSE_MATCH_EXTEND_SSE2) // __m128i available; same gate as match_extend's fast path
  for (; i + 16 <= nbytes; i += 16)
    _mm_storeu_si128((__m128i *)(void *)(dst + i),
                     _mm_loadu_si128((const __m128i *)(const void *)(src + i)));
#endif
  for (; i + 8 <= nbytes; i += 8)
#ifdef LZVN_PROOF
    LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst, nbytes))
    LZVN_LOOP_INVARIANT(i <= nbytes)
    LZVN_LOOP_DECREASES(nbytes - i)
    memcpy(dst + i, src + i, 8);
#else
    store8(dst + i, load8(src + i));
#endif
  for (; i < nbytes; i++)
#ifdef LZVN_PROOF
    LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst, nbytes))
    LZVN_LOOP_INVARIANT(i <= nbytes)
    LZVN_LOOP_DECREASES(nbytes - i)
#endif
    dst[i] = src[i];
  return dst + nbytes;
#endif
}

/*! Emit the final literal (L,0,0). Returns q1 if output is full, in which
 * case the output is partially invalid. */
LZVN_INLINE unsigned char *emit_literal(const unsigned char *p,
                                        unsigned char *q, unsigned char *q1,
                                        size_t L)
#ifdef LZVN_PROOF
LZVN_REQUIRES(__CPROVER_same_object(q, q1))
LZVN_REQUIRES(LZVN_OFFSET(q) <= LZVN_OFFSET(q1))
LZVN_REQUIRES(__CPROVER_w_ok(q, (size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q))))
LZVN_REQUIRES(__CPROVER_r_ok(p, L))
LZVN_REQUIRES(!__CPROVER_same_object(p, q))
LZVN_ASSIGNS(__CPROVER_object_upto(q, (size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q))))
LZVN_ENSURES(__CPROVER_return_value == q1 ||
             (__CPROVER_same_object(__CPROVER_return_value, q1) &&
              (L == 0 ? __CPROVER_return_value == q : LZVN_OFFSET(__CPROVER_return_value) > LZVN_OFFSET(q)) &&
              LZVN_OFFSET(__CPROVER_return_value) <= LZVN_OFFSET(q1)))
#endif
{
  size_t x;
#ifdef LZVN_EXACT_EMIT
  unsigned char *const output_base=q;
  const unsigned char *const source_base=p;
  const size_t original_length=L;
#endif
  while (L > 15)
#ifdef LZVN_EXACT_EMIT
    LZVN_LOOP_ASSIGNS(L,x,q,p,__CPROVER_object_upto(output_base,(size_t)(q1-output_base)))
    LZVN_LOOP_INVARIANT(L<=original_length)
    LZVN_LOOP_INVARIANT(p==source_base+(original_length-L))
    LZVN_LOOP_INVARIANT(__CPROVER_same_object(q,output_base))
    LZVN_LOOP_INVARIANT(LZVN_OFFSET(q)>=LZVN_OFFSET(output_base) && LZVN_OFFSET(q)<=LZVN_OFFSET(q1))
    LZVN_LOOP_DECREASES(L)
#endif
  {
    x = L < 271 ? L : 271;
#if defined(LZVN_PROOF) && !defined(LZVN_EXACT_EMIT)
    if ((size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q)) < x + 10)
#else
    if ((size_t)(q1 - q) <= x + 10)
#endif
      goto OUT_FULL;
    store2(q, 0xE0 + ((x - 16) << 8));
    q += 2;
    L -= x;
    q = lzvn_copy8(q, p, x);
    p += x;
  }
  if (L > 0) {
#if defined(LZVN_PROOF) && !defined(LZVN_EXACT_EMIT)
    if ((size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q)) < L + 10)
#else
    if ((size_t)(q1 - q) <= L + 10)
#endif
      goto OUT_FULL;
    LZVN_EMIT_BYTE(q, 0xE0 + L); // 1110LLLL
    q = lzvn_copy8(q, p, L);
  }
  return q;

OUT_FULL:
  return q1;
}

// ===============================================================
// CrushLZVN cost model. LZVN has no entropy coder, so every op's byte cost
// is an exact function of (L, M, D, D_prev); these mirror emit() and
// emit_literal() byte for byte and must be kept in step with them.

/*! Bytes for a final literal-only run of length L (no embedded tail).
 * Exposed (not static) so crushlzvn.c's encode_bound and its literal-only
 * fallback share this one definition instead of two formulas that could
 * drift apart. */
#if !defined(CRUSHLZVN_DISPATCH_PROOF)
int32_t lzvn_literal_final_cost(int32_t L) {
  int32_t cost = 0;
  int32_t full = L / 271, rem = L % 271;
  cost += L + 2 * full;
  cost += rem > 15 ? 2 : rem > 0 ? 1 : 0;
  return cost;
}
#endif

/*! Bytes for peeling a literal run of length L down to the 0-3 byte tail a
 * following match embeds for free; writes that tail to *tail_out. */
static inline int32_t lzvn_literal_prefix_cost(int32_t L, int32_t *tail_out) {
  if (__builtin_expect(L < 271, 1)) {
    if (L <= 3) {
      *tail_out = L;
      return 0;
    }
    *tail_out = 0;
    return (L <= 15) ? (1 + L) : (2 + L);
  }
  int32_t full = L / 271, rem = L % 271;
  int32_t cost = 273 * full;
  if (rem > 15) {
    cost += 2 + rem;
    rem = 0;
  } else if (rem > 3) {
    cost += 1 + rem;
    rem = 0;
  }
  *tail_out = rem;
  return cost;
}

/*! Bytes for a match op with embedded tail L (0-3), length M (>=3),
 * distance D and previous distance D_prev (0 if none). */
static inline int32_t lzvn_match_op_cost(int32_t L, int32_t M, int32_t D,
                                         int32_t D_prev) {
  if (M <= 4) return (D == D_prev ? 1 : ((D < 1536) ? 2 : 3)) + L;
  if (__builtin_expect(D == D_prev, 0)) {
    int32_t inline_cap = 10 - 2 * L;
    if (inline_cap > M) inline_cap = M;
    int32_t M_rem = M - inline_cap;
    int32_t cost = 1 + L;
    if (__builtin_expect(M_rem < 271, 1)) {
      cost += (M_rem > 15) ? 2 : (M_rem > 0 ? 1 : 0);
    } else {
      int32_t full = M_rem / 271, rem = M_rem % 271;
      cost += 2 * full;
      cost += rem > 15 ? 2 : rem > 0 ? 1 : 0;
    }
    return cost;
  }
  if (D < 1536) {
    int32_t inline_cap = 10 - 2 * L;
    if (inline_cap > M) inline_cap = M;
    int32_t M_rem = M - inline_cap;
    int32_t cost = 2 + L;
    if (__builtin_expect(M_rem < 271, 1)) {
      cost += (M_rem > 15) ? 2 : (M_rem > 0 ? 1 : 0);
    } else {
      int32_t full = M_rem / 271, rem = M_rem % 271;
      cost += 2 * full;
      cost += rem > 15 ? 2 : rem > 0 ? 1 : 0;
    }
    return cost;
  }
  if (D < 16384 && M <= 34) return 3 + L;
  int32_t inline_cap = 10 - 2 * L;
  if (inline_cap > M) inline_cap = M;
  int32_t M_rem = M - inline_cap;
  int32_t cost = 3 + L;
  if (__builtin_expect(M_rem < 271, 1)) {
    cost += (M_rem > 15) ? 2 : (M_rem > 0 ? 1 : 0);
  } else {
    int32_t full = M_rem / 271, rem = M_rem % 271;
    cost += 2 * full;
    cost += rem > 15 ? 2 : rem > 0 ? 1 : 0;
  }
  return cost;
}

/*! Emit (L,M,D), M>=3. Reads at most L+4 bytes from p. Returns q1 if output
 * is full, in which case the output is partially invalid. */
LZVN_INLINE unsigned char *emit(const unsigned char *p, unsigned char *q,
                                unsigned char *q1, size_t L, size_t M,
                                size_t D, size_t D_prev)
#ifdef LZVN_PROOF
LZVN_REQUIRES(__CPROVER_same_object(q, q1))
LZVN_REQUIRES(LZVN_OFFSET(q) <= LZVN_OFFSET(q1))
LZVN_REQUIRES(__CPROVER_w_ok(q, (size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q))))
LZVN_REQUIRES(L <= PROOF_MAX_OBJECT - 8)
LZVN_REQUIRES(__CPROVER_r_ok(p, L + 8))
LZVN_REQUIRES(!__CPROVER_same_object(p, q))
LZVN_REQUIRES(M >= 3)
LZVN_REQUIRES(D >= 1 && D <= LZVN_ENCODE_MAX_DISTANCE)
LZVN_ASSIGNS(__CPROVER_object_upto(q, (size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q))))
LZVN_ENSURES(__CPROVER_return_value == q1 ||
             (__CPROVER_same_object(__CPROVER_return_value, q1) &&
              LZVN_OFFSET(__CPROVER_return_value) > LZVN_OFFSET(q) &&
              LZVN_OFFSET(__CPROVER_return_value) <= LZVN_OFFSET(q1)))
#endif
{
  size_t x;
  while (L > 15) {
    x = L < 271 ? L : 271;
#if defined(LZVN_PROOF) && !defined(LZVN_EXACT_EMIT)
    if ((size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q)) < x + 10)
#else
    if ((size_t)(q1 - q) <= x + 10)
#endif
      goto OUT_FULL;
    store2(q, 0xE0 + ((x - 16) << 8));
    q += 2;
    L -= x;
    q = lzvn_copy64(q, p, x);
    p += x;
  }
  if (L > 3) {
#if defined(LZVN_PROOF) && !defined(LZVN_EXACT_EMIT)
    if ((size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q)) < L + 10)
#else
    if ((size_t)(q1 - q) <= L + 10)
#endif
      goto OUT_FULL;
    LZVN_EMIT_BYTE(q, 0xE0 + L); // 1110LLLL
    q = lzvn_copy64(q, p, L);
    p += L;
    L = 0;
  }
  x = M <= 10 - 2 * L ? M : 10 - 2 * L; // x = min(10-2*L,M)
  M -= x;
  x -= 3; // M = (x+3) + M'    max value for x is 7-2*L

  uint32_t literal = load4(p);

#if defined(LZVN_PROOF) && !defined(LZVN_EXACT_EMIT)
  if ((size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q)) < 8)
#else
  if ((size_t)(q1 - q) <= 8)
#endif
    goto OUT_FULL;

  if (D == D_prev) {
    if (L == 0) {
      LZVN_EMIT_BYTE(q, 0xF0 + (x + 3)); // XM!
    } else {
      LZVN_EMIT_BYTE(q, (L << 6) + (x << 3) + 6); //  LLxxx110
    }
    store4(q, literal);
    q += L;
  } else if (D < 2048 - 2 * 256) {
    // Short dist    D>>8 in 0..5
    LZVN_EMIT_BYTE(q, (D >> 8) + (L << 6) + (x << 3)); // LLxxxDDD
    LZVN_EMIT_BYTE(q, D & 0xFF);
    store4(q, literal);
    q += L;
  } else if (D >= (1 << 14) || M == 0 || (x + 3) + M > 34) {
    // Long dist
    LZVN_EMIT_BYTE(q, (L << 6) + (x << 3) + 7);
    store2(q, D);
    q += 2;
    store4(q, literal);
    q += L;
  } else {
    // Medium distance
    x += M;
    M = 0;
    LZVN_EMIT_BYTE(q, 0xA0 + (x >> 2) + (L << 3));
    store2(q, D << 2 | (x & 3));
    q += 2;
    store4(q, literal);
    q += L;
  }

  while (M > 15) {
#if defined(LZVN_PROOF) && !defined(LZVN_EXACT_EMIT)
    if ((size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q)) < 2)
#else
    if ((size_t)(q1 - q) <= 2)
#endif
      goto OUT_FULL;
    x = M < 271 ? M : 271;
    store2(q, 0xf0 + ((x - 16) << 8));
    q += 2;
    M -= x;
  }
  if (M > 0) {
#if defined(LZVN_PROOF) && !defined(LZVN_EXACT_EMIT)
    if ((size_t)(LZVN_OFFSET(q1) - LZVN_OFFSET(q)) < 1)
#else
    if ((size_t)(q1 - q) <= 1)
#endif
      goto OUT_FULL;
    LZVN_EMIT_BYTE(q, 0xF0 + M); // M = 0..15
  }

  return q;

OUT_FULL:
  return q1;
}

static inline int32_t offset_to_s32(lzvn_offset x) { return (int32_t)x; }

// Unsigned: positions reach LZVN_ENCODE_MAX_SRC_SIZE, and any slot value
// then reads as a candidate at or after src_begin (0).
static inline lzvn_offset offset_from_u32(int32_t x) { return (lzvn_offset)(uint32_t)x; }

// Hash and matching

/*! hash3i with a runtime output width. */
static inline uint32_t lzvn_zopt_hash3(uint32_t x, int32_t hash_bits) {
  x &= 0xffffff; // truncate to 24-bit input, same as hash3i
  uint32_t h = (x * (1 + (1 << 6) + (1 << 12))) >> 12;
  return h & ((1u << hash_bits) - 1);
}

static inline lzvn_offset trailing_zero_bytes(uint32_t x) {
  return (x == 0) ? 4 : (__builtin_ctzl(x) >> 3);
}

/*! Matching bytes [0,4] between src+i and src+j; reads 4 bytes from each. */
static inline lzvn_offset nmatch4(const unsigned char *src, lzvn_offset i,
                                  lzvn_offset j) {
  uint32_t vi = load4(src + i);
  uint32_t vj = load4(src + j);
  return trailing_zero_bytes(vi ^ vj);
}

// match_extend's widened reads can land past max_length, so callers subtract
// this from the readable length before passing max_length, rather than only
// checking that the margin exists.
#define LZVN_ZOPT_MATCH_EXTEND_MARGIN 16

/*! Try to expand (m_begin, m0_begin) into a match of length >= 3 at distance
 * <= LZVN_ENCODE_MAX_DISTANCE; returns 1 and fills *match, else 0. */
static inline int __attribute__((unused)) lzvn_find_match(const unsigned char *src,
                                                          lzvn_offset src_begin,
                                                          lzvn_offset src_end, lzvn_offset l_begin,
                                                          lzvn_offset m0_begin, lzvn_offset m_begin,
                                                          lzvn_match_info *match) {
  lzvn_offset n = nmatch4(src, m_begin, m0_begin);
  if (n < 3)
    return 0; // no match

  lzvn_offset D = m_begin - m0_begin; // actual distance
  if (D <= 0 || D > LZVN_ENCODE_MAX_DISTANCE)
    return 0; // distance out of range

  lzvn_offset m_end = m_begin + n;
  if (n == 4) {
    lzvn_offset max_len = src_end - m_begin - LZVN_ZOPT_MATCH_EXTEND_MARGIN;
    if (max_len > 4) {
      m_end = m_begin + (lzvn_offset)match_extend(src + m_begin, src + m0_begin, 4, (uint32_t)max_len);
    } else {
      while (n == 4 && m_end + 4 < src_end) {
        n = nmatch4(src, m_end, m_end - D);
        m_end += n;
      }
    }
  }

  // Expand backwards over literal
  while (m0_begin > src_begin && m_begin > l_begin &&
         src[m_begin - 1] == src[m0_begin - 1]) {
    m0_begin--;
    m_begin--;
  }

  lzvn_offset M = m_end - m_begin; // match length
  match->m_begin = m_begin;
  match->m_end = m_end;
  match->K = M - ((D < 0x600) ? 2 : 3);
  match->M = M;
  match->D = D;

  return 1; // OK
}

/*! lzvn_find_match when n bytes (n <= 4) are already known to match. */
#ifdef LZVN_PROOF
static __attribute__((noinline))
#else
static inline
#endif
int lzvn_find_matchN(const unsigned char *src, lzvn_offset src_begin,
                     lzvn_offset src_end, lzvn_offset l_begin,
                     lzvn_offset m0_begin, lzvn_offset m_begin,
                     lzvn_offset n, lzvn_match_info *match)
#ifdef LZVN_PROOF
LZVN_REQUIRES(0 <= src_begin && src_begin <= l_begin && l_begin <= m_begin)
LZVN_REQUIRES(src_end <= (lzvn_offset)LZVN_ENCODE_MAX_SRC_SIZE)
LZVN_REQUIRES(src_begin <= m0_begin && m0_begin <= 0x10000000000LL)
LZVN_REQUIRES(0 <= n && n <= 4 && m_begin <= src_end && m_begin + n <= src_end)
LZVN_REQUIRES(__CPROVER_r_ok(src, (size_t)src_end))
LZVN_REQUIRES(__CPROVER_w_ok(match, sizeof *match))
LZVN_ASSIGNS(*match)
LZVN_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == 1)
LZVN_ENSURES(__CPROVER_return_value == 0 ||
             (match->m_begin >= l_begin && match->m_begin <= m_begin &&
              0 <= match->m_end && match->m_end <= src_end &&
              match->M == match->m_end - match->m_begin && match->M >= 3 &&
              match->D == m_begin - m0_begin &&
              match->D >= 1 && match->D <= LZVN_ENCODE_MAX_DISTANCE &&
              match->m_begin - match->D >= src_begin))
#endif
{
  if (n < 3)
    return 0; // no match

  lzvn_offset D = m_begin - m0_begin; // actual distance
  if (D <= 0 || D > LZVN_ENCODE_MAX_DISTANCE)
    return 0; // distance out of range

  lzvn_offset m_end = m_begin + n;
  if (n == 4) {
    lzvn_offset max_len = src_end - m_begin - LZVN_ZOPT_MATCH_EXTEND_MARGIN;
    if (max_len > 4) {
      m_end = m_begin + (lzvn_offset)match_extend(src + m_begin, src + m0_begin, 4, (uint32_t)max_len);
    } else {
      while (n == 4 && m_end + 4 < src_end)
#ifdef LZVN_PROOF
        LZVN_LOOP_ASSIGNS(n, m_end)
        LZVN_LOOP_INVARIANT(0 <= n && n <= 4 && m_end >= m_begin + 3 && m_end <= src_end)
        LZVN_LOOP_DECREASES(2 * (src_end - m_end) + (n == 4))
#endif
      {
        n = nmatch4(src, m_end, m_end - D);
        m_end += n;
      }
    }
  }

  // Expand backwards over literal
  while (m0_begin > src_begin && m_begin > l_begin &&
         src[m_begin - 1] == src[m0_begin - 1])
#ifdef LZVN_PROOF
    LZVN_LOOP_ASSIGNS(m0_begin, m_begin)
    LZVN_LOOP_INVARIANT(src_begin <= m0_begin && l_begin <= m_begin &&
                        m_begin <= LZVN_LOOP_ENTRY(m_begin) &&
                        m_begin - m0_begin == D && m_begin < m_end)
    LZVN_LOOP_DECREASES(m_begin - l_begin)
#endif
  {
    m0_begin--;
    m_begin--;
  }

  lzvn_offset M = m_end - m_begin; // match length
  match->m_begin = m_begin;
  match->m_end = m_end;
  match->K = M - ((D < 0x600) ? 2 : 3);
  match->M = M;
  match->D = D;

  return 1; // OK
}

// Encoder backend

/*! Emit a match; returns bytes written, 0 if dst is full. */
LZVN_INLINE lzvn_offset lzvn_emit_match(lzvn_encoder_state *state,
                                        lzvn_match_info match)
#ifdef LZVN_PROOF
LZVN_REQUIRES(__CPROVER_rw_ok(state, sizeof *state))
LZVN_REQUIRES(__CPROVER_same_object(state->dst, state->dst_end))
LZVN_REQUIRES(LZVN_OFFSET(state->dst) <= LZVN_OFFSET(state->dst_end))
LZVN_REQUIRES(__CPROVER_w_ok(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_REQUIRES(match.m_begin >= state->src_literal)
LZVN_REQUIRES(match.M >= 3)
LZVN_REQUIRES(match.D >= 1 && match.D <= LZVN_ENCODE_MAX_DISTANCE)
LZVN_REQUIRES(__CPROVER_r_ok(state->src + state->src_literal, (size_t)(match.m_begin - state->src_literal) + 8))
LZVN_REQUIRES(!__CPROVER_same_object(state->src, state->dst))
LZVN_ASSIGNS(state->dst, state->d_prev, state->src_literal,
             __CPROVER_object_upto(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_ENSURES(__CPROVER_same_object(state->dst, LZVN_OLD(state->dst)))
LZVN_ENSURES(LZVN_OFFSET(state->dst) <= LZVN_OFFSET(state->dst_end))
LZVN_ENSURES(__CPROVER_w_ok(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_ENSURES((__CPROVER_return_value == 0 &&
              state->dst == LZVN_OLD(state->dst) &&
              state->src_literal == LZVN_OLD(state->src_literal) &&
              state->d_prev == LZVN_OLD(state->d_prev)) ||
             (__CPROVER_return_value > 0 &&
              LZVN_OFFSET(state->dst) == LZVN_OFFSET(LZVN_OLD(state->dst)) + (size_t)__CPROVER_return_value &&
              state->src_literal == match.m_end &&
              state->d_prev == match.D))
#endif
{
  size_t L = (size_t)(match.m_begin - state->src_literal); // literal count
  size_t M = (size_t)match.M;                              // match length
  size_t D = (size_t)match.D;                              // match distance
  size_t D_prev = (size_t)state->d_prev; // previously emitted match distance
  unsigned char *dst = emit(state->src + state->src_literal, state->dst,
                            state->dst_end, L, M, D, D_prev);
  if (dst >= state->dst_end) {
    return 0; // FULL
  }

  lzvn_offset dst_used = dst - state->dst;
  state->d_prev = match.D;
  state->dst = dst;
  state->src_literal = match.m_end;
  return dst_used;
}

/*! Emit an n-byte literal; returns bytes written, 0 if dst is full. */
LZVN_INLINE lzvn_offset lzvn_emit_literal(lzvn_encoder_state *state,
                                          lzvn_offset n)
#ifdef LZVN_PROOF
LZVN_REQUIRES(__CPROVER_rw_ok(state, sizeof *state))
LZVN_REQUIRES(__CPROVER_same_object(state->dst, state->dst_end))
LZVN_REQUIRES(LZVN_OFFSET(state->dst) <= LZVN_OFFSET(state->dst_end))
LZVN_REQUIRES(__CPROVER_w_ok(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_REQUIRES(__CPROVER_r_ok(state->src + state->src_literal, (size_t)n))
LZVN_REQUIRES(!__CPROVER_same_object(state->src, state->dst))
LZVN_ASSIGNS(state->dst, state->src_literal,
             __CPROVER_object_upto(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_ENSURES(__CPROVER_same_object(state->dst, LZVN_OLD(state->dst)))
LZVN_ENSURES(LZVN_OFFSET(state->dst) <= LZVN_OFFSET(state->dst_end))
LZVN_ENSURES(__CPROVER_w_ok(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_ENSURES((__CPROVER_return_value == 0 &&
              state->dst == LZVN_OLD(state->dst) &&
              state->src_literal == LZVN_OLD(state->src_literal)) ||
             (__CPROVER_return_value > 0 &&
              LZVN_OFFSET(state->dst) == LZVN_OFFSET(LZVN_OLD(state->dst)) + (size_t)__CPROVER_return_value &&
              state->src_literal == LZVN_OLD(state->src_literal) + n))
#endif
{
  size_t L = (size_t)n;
  unsigned char *dst = emit_literal(state->src + state->src_literal, state->dst,
                                    state->dst_end, L);
  if (dst >= state->dst_end)
    return 0; // FULL

  lzvn_offset dst_used = dst - state->dst;
  state->dst = dst;
  state->src_literal += n;
  return dst_used;
}

/*! Emit end-of-stream; returns 8, or 0 if dst is full. */
LZVN_INLINE lzvn_offset lzvn_emit_end_of_stream(lzvn_encoder_state *state)
#ifdef LZVN_PROOF
LZVN_REQUIRES(__CPROVER_rw_ok(state, sizeof *state))
LZVN_REQUIRES(__CPROVER_same_object(state->dst, state->dst_end))
LZVN_REQUIRES(LZVN_OFFSET(state->dst) <= LZVN_OFFSET(state->dst_end))
LZVN_REQUIRES(__CPROVER_w_ok(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_ASSIGNS(state->dst, __CPROVER_object_upto(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_ENSURES(__CPROVER_same_object(state->dst, LZVN_OLD(state->dst)))
LZVN_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == 8)
LZVN_ENSURES(LZVN_OFFSET(state->dst) <= LZVN_OFFSET(state->dst_end))
LZVN_ENSURES(LZVN_OFFSET(state->dst) == LZVN_OFFSET(LZVN_OLD(state->dst)) + (size_t)__CPROVER_return_value)
LZVN_ENSURES(__CPROVER_w_ok(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
#endif
{
#if defined(LZVN_PROOF) && !defined(LZVN_EXACT_EMIT)
  if ((size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst)) < 8)
#else
  if ((size_t)(state->dst_end - state->dst) < 8)
#endif
    return 0; // FULL

  store8(state->dst, 0x06); // end-of-stream command
  state->dst += 8;
  return 8; // dst_used
}

// ===============================================================
// CrushLZVN greedy encoder: lzvn_encode with runtime hash_bits/hash_width.
// The history table is a ring buffer per bucket. The search must walk slots
// most-recently-written first: UPDATE's tie-break (m_end > best.m_end + 1)
// depends on that order to match a shift-based table. hash_width=4 is
// bit-identical to lzvn_encode.
//
// Forced-inline body, instantiated per literal hash_width below so the two
// `% hash_width` moduli fold to masks.
#ifdef LZVN_PROOF
// A match found at or after the current literal start, within the source,
// reaching back to a valid history position; or no match (M == 0).
#define LZVN_MATCH_OK(m)                                                       \
  (((m).M == 0 && (m).m_end == 0) ||                                           \
   (0 <= (m).m_begin && (m).m_begin <= state->src_current &&                   \
    0 <= (m).m_end && (m).m_end <= state->src_end &&                           \
    (m).M >= 3 && (m).D >= 1 && (m).D <= LZVN_ENCODE_MAX_DISTANCE &&           \
    (m).m_end - (m).m_begin == (m).M && state->src_literal <= (m).m_begin &&   \
    (m).m_begin - (m).D >= state->src_begin))
// What every position of the greedy loop preserves.
#define LZVN_GREEDY_STATE_OK                                                   \
  (state->src_begin <= state->src_literal &&                                   \
   state->src_literal <= state->src_end && LZVN_MATCH_OK(state->pending) &&    \
   (state->d_prev == 0 ||                                                      \
    (state->d_prev >= 1 && state->d_prev <= LZVN_ENCODE_MAX_DISTANCE &&        \
     state->d_prev <= state->src_current - state->src_begin)) &&               \
   __CPROVER_same_object(state->dst, state->dst_end) &&                        \
   LZVN_OFFSET(state->dst) <= LZVN_OFFSET(state->dst_end) &&                   \
   __CPROVER_w_ok(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
#endif

// One source position of the greedy loop: probe the bucket, resolve against
// the pending match, emit what is settled, record the position. Returns 1 if
// the destination filled (the table is then not updated), else 0.
#ifdef LZVN_PROOF
static __attribute__((noinline))
#else
LZFSE_INLINE
#endif
int lzvn_greedy_wide_step(lzvn_encoder_state *state, int32_t hash_bits,
                          int32_t hash_width, int32_t *hist_pos,
                          uint32_t *hist_value, uint16_t *hist_cursor,
                          lzvn_offset sentinel_pos, uint32_t sentinel_val)
#ifdef LZVN_PROOF
LZVN_REQUIRES(__CPROVER_rw_ok(state, sizeof *state))
LZVN_REQUIRES(__CPROVER_same_object(state->dst, state->dst_end))
LZVN_REQUIRES(!__CPROVER_same_object(state->src, state->dst))
LZVN_REQUIRES(__CPROVER_r_ok(state->src, (size_t)state->src_end))
LZVN_REQUIRES(hash_bits >= 10 && hash_bits <= 16)
LZVN_REQUIRES(hash_width >= 1 && hash_width <= 64)
LZVN_REQUIRES(__CPROVER_rw_ok(hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos))
LZVN_REQUIRES(__CPROVER_rw_ok(hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZVN_REQUIRES(__CPROVER_rw_ok(hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
/* These are the separation premises of the native greedy-loop ACSL proof.
 * The three table slices may share one scratch allocation, and the LZFSE
 * fallback may place output immediately after that allocation's table slice. */
LZVN_REQUIRES(!__CPROVER_same_object(state, state->src) &&
              !__CPROVER_same_object(state, state->dst) &&
              !__CPROVER_same_object(state, hist_pos) &&
              !__CPROVER_same_object(state, hist_value) &&
              !__CPROVER_same_object(state, hist_cursor))
LZVN_REQUIRES(!__CPROVER_same_object(state->src, hist_pos) &&
              !__CPROVER_same_object(state->src, hist_value) &&
              !__CPROVER_same_object(state->src, hist_cursor))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(state->dst,
              (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst)),
              hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(state->dst,
              (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst)),
              hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(state->dst,
              (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst)),
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(hist_pos,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos,
              hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(hist_pos,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(hist_value,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(8 <= state->src_end && state->src_end <= (lzvn_offset)LZVN_ENCODE_MAX_SRC_SIZE &&
              state->src_begin == 0 && state->src_begin <= state->src_current &&
              state->src_current < state->src_current_end &&
              state->src_current_end <= state->src_end - 8)
LZVN_REQUIRES(LZVN_GREEDY_STATE_OK)
LZVN_REQUIRES(sentinel_pos >= state->src_begin && sentinel_pos <= state->src_end - 4)
LZVN_ASSIGNS(state->src_literal, state->dst, state->pending, state->d_prev,
             __CPROVER_object_upto(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))),
             __CPROVER_object_upto(hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos),
             __CPROVER_object_upto(hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value),
             __CPROVER_object_upto(hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == 1)
LZVN_ENSURES(LZVN_GREEDY_STATE_OK)
LZVN_ENSURES(__CPROVER_same_object(state->dst, LZVN_OLD(state->dst)) &&
             LZVN_OFFSET(state->dst) >= LZVN_OFFSET(LZVN_OLD(state->dst)))
LZVN_ENSURES(state->src_literal >= LZVN_OLD(state->src_literal))
#endif
{
  const lzvn_match_info NO_MATCH = {0};

  uint32_t vi = load4(state->src + state->src_current);
  uint32_t h = lzvn_zopt_hash3(vi, hash_bits);

  int32_t *bucket_pos = hist_pos + (size_t)h * (size_t)hash_width;
  uint32_t *bucket_val = hist_value + (size_t)h * (size_t)hash_width;
  // hist_cursor packs (slots ever written, next write slot) as two bytes,
  // which is why hash_width must be <= 255.
  uint32_t meta = hist_cursor[h];
  uint32_t fill = meta >> 8;
  /* PROOF GUARD: % hash_width. Believed unnecessary: the cursor is only ever
     stored already reduced. It keeps the step contract independent of table
     contents, and is a mask in the power-of-two instances. */
  uint32_t cursor = (meta & 0xFFu) % (uint32_t)hash_width;

  if (state->src_current >= state->src_literal) {
    lzvn_match_info incoming = NO_MATCH;

    // Newest slot first, bounded by fill; the sentinel probe covers the rest.
    for (uint32_t k = 0; k < fill; k++)
#ifdef LZVN_PROOF
      LZVN_LOOP_ASSIGNS(k, incoming)
      LZVN_LOOP_INVARIANT(k <= fill && LZVN_MATCH_OK(incoming))
      LZVN_LOOP_DECREASES(fill - k)
#endif
    {
      int32_t slot = (int32_t)((cursor + (uint32_t)hash_width - 1u - k) % (uint32_t)hash_width);
      uint32_t diff = bucket_val[slot] ^ vi;
      if ((diff & 0x00FFFFFF) != 0)
        continue;
      lzvn_offset nk = (diff == 0) ? 4 : 3;
      if (nk == 3 && (1 + (state->src_current - state->src_literal)) < incoming.K)
        continue;
      lzvn_offset ik = offset_from_u32(bucket_pos[slot]);
      lzvn_match_info m1;
      if (lzvn_find_matchN(state->src, state->src_begin, state->src_end,
                           state->src_literal, ik, state->src_current, nk, &m1)) {
        if (m1.K > incoming.K || (m1.K == incoming.K && m1.m_end > incoming.m_end + 1))
          incoming = m1;
      }
    }
    // Stands in for every unwritten slot, after the real entries. One probe
    // equals (hash_width - fill) identical ones because UPDATE's tie-break is
    // false for a candidate against itself.
    if (fill < (uint32_t)hash_width) {
      uint32_t diff = sentinel_val ^ vi;
      if ((diff & 0x00FFFFFF) == 0) {
        lzvn_offset nk = (diff == 0) ? 4 : 3;
        lzvn_match_info m1;
        if (lzvn_find_matchN(state->src, state->src_begin, state->src_end,
                             state->src_literal, sentinel_pos, state->src_current, nk, &m1)) {
          if (m1.K > incoming.K || (m1.K == incoming.K && m1.m_end > incoming.m_end + 1))
            incoming = m1;
        }
      }
    }

    if (state->d_prev != 0) {
      uint32_t diff_prev = load4(state->src + state->src_current - state->d_prev) ^ vi;
      if ((diff_prev & 0x00FFFFFF) == 0) {
        lzvn_offset nk = (diff_prev == 0) ? 4 : 3;
        lzvn_match_info m1;
        if (lzvn_find_matchN(state->src, state->src_begin, state->src_end,
                             state->src_literal, state->src_current - state->d_prev,
                             state->src_current, nk, &m1)) {
          m1.K = m1.M - 1; // fix K for D_prev, same as lzvn_encode
          if (m1.K > incoming.K || (m1.K == incoming.K && m1.m_end > incoming.m_end + 1))
            incoming = m1;
        }
      }
    }

    if (incoming.M == 0) {
      if (state->src_current - state->src_literal >= LZVN_ENCODE_MAX_LITERAL_BACKLOG) {
        if (state->pending.M != 0) {
          if (lzvn_emit_match(state, state->pending) == 0) return 1;
          state->pending = NO_MATCH;
        } else {
          if (lzvn_emit_literal(state, 271) == 0) return 1;
        }
      }
    } else if (state->pending.M == 0) {
      state->pending = incoming;
    } else {
      if (state->pending.m_end <= incoming.m_begin) {
        if (lzvn_emit_match(state, state->pending) == 0) return 1;
        state->pending = incoming;
      } else {
        if (incoming.K > state->pending.K)
          state->pending = incoming;
        if (lzvn_emit_match(state, state->pending) == 0) return 1;
        state->pending = NO_MATCH;
      }
    }
  }

  bucket_pos[cursor] = offset_to_s32(state->src_current);
  bucket_val[cursor] = vi;
  cursor = (cursor + 1u) % (uint32_t)hash_width;
  if (fill < (uint32_t)hash_width)
    fill++;
  hist_cursor[h] = (uint16_t)((fill << 8) | cursor);
  return 0;
}

LZFSE_INLINE void lzvn_encode_greedy_wide_hw(lzvn_encoder_state *state, int32_t hash_bits,
                                              int32_t hash_width, int32_t *hist_pos,
                                              uint32_t *hist_value, uint16_t *hist_cursor) {
  // Sentinel every unwritten slot reads as; probed once per bucket.
  lzvn_offset sentinel_pos = -LZVN_ENCODE_MAX_DISTANCE;
  if (sentinel_pos < state->src_begin)
    sentinel_pos = state->src_begin;
  const uint32_t sentinel_val = load4(state->src + sentinel_pos);

  for (; state->src_current < state->src_current_end; state->src_current++)
#ifdef LZVN_PROOF
    LZVN_LOOP_ASSIGNS(state->src_current, state->src_literal, state->dst, state->pending, state->d_prev,
                      __CPROVER_object_upto(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))),
                      __CPROVER_object_upto(hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos),
                      __CPROVER_object_upto(hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value),
                      __CPROVER_object_upto(hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
    LZVN_LOOP_INVARIANT(state->src_begin <= state->src_current && state->src_current <= state->src_current_end)
    LZVN_LOOP_INVARIANT(LZVN_GREEDY_STATE_OK)
    LZVN_LOOP_INVARIANT(state->src_literal >= LZVN_LOOP_ENTRY(state->src_literal))
    LZVN_LOOP_INVARIANT(__CPROVER_same_object(state->dst, LZVN_LOOP_ENTRY(state->dst)) &&
                        LZVN_OFFSET(state->dst) >= LZVN_OFFSET(LZVN_LOOP_ENTRY(state->dst)))
    LZVN_LOOP_DECREASES(state->src_current_end - state->src_current)
#endif
  {
    if (lzvn_greedy_wide_step(state, hash_bits, hash_width, hist_pos, hist_value, hist_cursor,
                              sentinel_pos, sentinel_val))
      return;
  }
}

// One wrapper per level-table width, each its own inlining of the body.
#define LZVN_GREEDY_WIDE_INSTANCE(HW)                                                                     \
  static void lzvn_encode_greedy_wide_hw##HW(lzvn_encoder_state *state, int32_t hash_bits,                \
                                              int32_t *hist_pos, uint32_t *hist_value,                     \
                                              uint16_t *hist_cursor) {                                     \
    lzvn_encode_greedy_wide_hw(state, hash_bits, HW, hist_pos, hist_value, hist_cursor);                   \
  }
LZVN_GREEDY_WIDE_INSTANCE(1)
LZVN_GREEDY_WIDE_INSTANCE(2)
LZVN_GREEDY_WIDE_INSTANCE(4)
LZVN_GREEDY_WIDE_INSTANCE(8)
LZVN_GREEDY_WIDE_INSTANCE(16)
LZVN_GREEDY_WIDE_INSTANCE(32)
LZVN_GREEDY_WIDE_INSTANCE(64)
#undef LZVN_GREEDY_WIDE_INSTANCE

// default keeps arbitrary hash_width working (crushlzvn_sweep passes widths
// that are not powers of two).
void lzvn_encode_greedy_wide(lzvn_encoder_state *state, int32_t hash_bits,
                             int32_t hash_width, int32_t *hist_pos,
                             uint32_t *hist_value, uint16_t *hist_cursor)
#ifdef LZVN_PROOF
LZVN_REQUIRES(__CPROVER_rw_ok(state, sizeof *state))
LZVN_REQUIRES(__CPROVER_same_object(state->dst, state->dst_end))
LZVN_REQUIRES(LZVN_OFFSET(state->dst) <= LZVN_OFFSET(state->dst_end))
LZVN_REQUIRES(__CPROVER_w_ok(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_REQUIRES(__CPROVER_r_ok(state->src, (size_t)state->src_end))
LZVN_REQUIRES(!__CPROVER_same_object(state->src, state->dst))
LZVN_REQUIRES(hash_bits >= 10 && hash_bits <= 16)
LZVN_REQUIRES(hash_width >= 1 && hash_width <= 64)
LZVN_REQUIRES(__CPROVER_rw_ok(hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos))
LZVN_REQUIRES(__CPROVER_rw_ok(hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZVN_REQUIRES(__CPROVER_rw_ok(hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(!__CPROVER_same_object(state, state->src) &&
              !__CPROVER_same_object(state, state->dst) &&
              !__CPROVER_same_object(state, hist_pos) &&
              !__CPROVER_same_object(state, hist_value) &&
              !__CPROVER_same_object(state, hist_cursor))
LZVN_REQUIRES(!__CPROVER_same_object(state->src, hist_pos) &&
              !__CPROVER_same_object(state->src, hist_value) &&
              !__CPROVER_same_object(state->src, hist_cursor))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(state->dst,
              (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst)),
              hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(state->dst,
              (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst)),
              hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(state->dst,
              (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst)),
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(hist_pos,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos,
              hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(hist_pos,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(hist_value,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(8 <= state->src_end && state->src_end <= (lzvn_offset)LZVN_ENCODE_MAX_SRC_SIZE &&
              state->src_begin == 0 && state->src_begin <= state->src_current &&
              state->src_current <= state->src_current_end &&
              state->src_current_end <= state->src_end - 8)
LZVN_REQUIRES(LZVN_GREEDY_STATE_OK)
LZVN_ASSIGNS(state->dst, state->src_literal, state->src_current, state->pending, state->d_prev,
             __CPROVER_object_upto(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))),
             __CPROVER_object_upto(hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos),
             __CPROVER_object_upto(hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value),
             __CPROVER_object_upto(hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_ENSURES(__CPROVER_same_object(state->dst, LZVN_OLD(state->dst)))
LZVN_ENSURES(LZVN_OFFSET(state->dst) >= LZVN_OFFSET(LZVN_OLD(state->dst)) &&
             LZVN_OFFSET(state->dst) <= LZVN_OFFSET(state->dst_end))
LZVN_ENSURES(__CPROVER_w_ok(state->dst, (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst))))
LZVN_ENSURES(state->src_literal >= LZVN_OLD(state->src_literal) &&
             state->src_literal <= state->src_end)
#endif
{
#if defined(LZVN_PROOF) && !defined(LZVN_NATIVE_GREEDY_DISPATCH)
  // The width-specialised instances are this body with a literal width.
  lzvn_encode_greedy_wide_hw(state, hash_bits, hash_width, hist_pos, hist_value, hist_cursor);
  return;
#endif
  switch (hash_width) {
  case 1:  lzvn_encode_greedy_wide_hw1(state, hash_bits, hist_pos, hist_value, hist_cursor); return;
  case 2:  lzvn_encode_greedy_wide_hw2(state, hash_bits, hist_pos, hist_value, hist_cursor); return;
  case 4:  lzvn_encode_greedy_wide_hw4(state, hash_bits, hist_pos, hist_value, hist_cursor); return;
  case 8:  lzvn_encode_greedy_wide_hw8(state, hash_bits, hist_pos, hist_value, hist_cursor); return;
  case 16: lzvn_encode_greedy_wide_hw16(state, hash_bits, hist_pos, hist_value, hist_cursor); return;
  case 32: lzvn_encode_greedy_wide_hw32(state, hash_bits, hist_pos, hist_value, hist_cursor); return;
  case 64: lzvn_encode_greedy_wide_hw64(state, hash_bits, hist_pos, hist_value, hist_cursor); return;
  default: lzvn_encode_greedy_wide_hw(state, hash_bits, hash_width, hist_pos, hist_value, hist_cursor); return;
  }
}

void lzvn_encode_greedy_init_table(int32_t hash_bits, uint16_t *hist_cursor)
#ifdef LZVN_PROOF
LZVN_REQUIRES(hash_bits >= 0 && hash_bits <= 16)
LZVN_REQUIRES(__CPROVER_w_ok(hist_cursor, ((size_t)1 << hash_bits) * sizeof(uint16_t)))
LZVN_ASSIGNS(__CPROVER_object_upto(hist_cursor, ((size_t)1 << hash_bits) * sizeof(uint16_t)))
#endif
{
  memset(hist_cursor, 0, ((size_t)1 << hash_bits) * sizeof(uint16_t));
}

// ===============================================================
// CrushLZVN fast encoder: the LZFSE fast strategy's match search
// (fast_match.h) writing LZVN ops. LZVN also sends a repeated distance in
// the cheapest op, so the probe one byte ahead on the last distance carries
// over unchanged. Tables are cleared by the caller.

LZFSE_INLINE lzvn_offset lzvn_fast_skip_step(lzvn_offset ip, lzvn_offset anchor,
                                              int skip_shift, int probed,
                                              lzvn_offset max_stride) {
  lzvn_offset step = probed + ((ip - anchor) >> skip_shift);
  return step < max_stride ? step : max_stride;
}

#if !defined(LZVN_PROOF) && !defined(_MSC_VER)
// Forced inline (as on main) so each LZVN_FAST_INSTANCE folds its constants.
static inline __attribute__((always_inline)) size_t lzvn_encode_fast_impl(unsigned char *dst, size_t dst_size, const unsigned char *src,
                                          size_t src_size, int hash_bits, int min_match, int skip_shift,
                                          int max_step, int long_table, int lazy, uint16_t *table,
                                          uint16_t *ltable);
#endif
LZVN_INLINE size_t lzvn_encode_fast_impl(unsigned char *dst, size_t dst_size, const unsigned char *src,
                                          size_t src_size, int hash_bits, int min_match, int skip_shift,
                                          int max_step, int long_table, int lazy, uint16_t *table,
                                          uint16_t *ltable)
#ifdef LZVN_PROOF
LZVN_REQUIRES(src != NULL && __CPROVER_r_ok(src, src_size))
LZVN_REQUIRES(dst != NULL && __CPROVER_w_ok(dst, dst_size))
LZVN_REQUIRES(!__CPROVER_same_object(src, dst))
LZVN_REQUIRES(hash_bits >= 10 && hash_bits <= 16)
LZVN_REQUIRES(min_match >= 4 && min_match <= (long_table || lazy ? 6 : 8))
LZVN_REQUIRES(skip_shift >= 1 && skip_shift <= 31)
LZVN_REQUIRES(max_step >= 1 && max_step <= 64)
LZVN_REQUIRES(long_table == 0 || long_table == 1)
LZVN_REQUIRES(lazy == 0 || lazy == 1)
LZVN_REQUIRES(__CPROVER_rw_ok(table, ((size_t)1 << hash_bits) * sizeof *table))
LZVN_REQUIRES(!long_table || (ltable != NULL && __CPROVER_rw_ok(ltable, ((size_t)1 << hash_bits) * sizeof *ltable)))
LZVN_ASSIGNS(__CPROVER_object_upto(dst, dst_size),
             __CPROVER_object_whole(table))
LZVN_ASSIGNS(long_table != 0 && ltable != NULL: __CPROVER_object_whole(ltable))
LZVN_ENSURES(__CPROVER_return_value <= dst_size)
#endif
{
  if (dst_size < LZVN_ENCODE_MIN_DST_SIZE || src_size > LZVN_ZOPT_BLOCK_SIZE)
    return 0;
  unsigned char *q = dst;
  unsigned char *const q1 = dst + dst_size - 8; // room for end-of-stream
  const lzvn_offset src_end = (lzvn_offset)src_size;
  // Keeps every load8 below, and emit's literal over-read, in bounds.
  const lzvn_offset ilimit = src_end - 16;
  // The stride never drops below the positions a probe covers.
  const int probed = (lazy || long_table) ? 1 : 2;
  const lzvn_offset max_stride = max_step > probed ? max_step : probed;
  uint64_t prime = CRUSHLZFSE_FAST_PRIME;
#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(prime)); // opaque, so it stays in a register
#endif
  lzvn_offset anchor = 0, ip = 1;
  uint32_t rep = 0; // 0 until the first match: never a valid distance
  while (ip < ilimit) {
    lzvn_offset mpos, mref;
    uint32_t len = crushlzfse_fast_find(src, src_end, ilimit, ip, anchor, rep, min_match, hash_bits, prime,
                                        table, ltable, long_table, lazy, &mpos, &mref);
    if (len == 0) {
      ip += lzvn_fast_skip_step(ip, anchor, skip_shift, probed, max_stride);
      continue;
    }
    uint32_t d = (uint32_t)(mpos - mref);
    q = emit(src + anchor, q, q1, (size_t)(mpos - anchor), len, d, rep);
    if (q >= q1)
      return 0;
    rep = d;
    anchor = mpos + len;
    if (anchor < ilimit)
      crushlzfse_fast_index_match(src, mpos, anchor, min_match, hash_bits, prime, table, ltable, long_table);
    ip = anchor;
  }
  q = emit_literal(src + anchor, q, q1, (size_t)(src_end - anchor));
  if (q >= q1)
    return 0;
  store8(q, 0x06); // end-of-stream command
  return (size_t)(q + 8 - dst);
}

// One instantiation per hashed length and mode, as for LZFSE.
#define LZVN_FAST_INSTANCE(MM, LONG, LAZY)                                                              \
  static size_t lzvn_encode_fast_##MM##_##LONG##_##LAZY(unsigned char *dst, size_t dst_size,             \
                                                         const unsigned char *src, size_t src_size,       \
                                                         int hb, int ss, int ms, uint16_t *t,             \
                                                         uint16_t *lt) {                                  \
    return lzvn_encode_fast_impl(dst, dst_size, src, src_size, hb, MM, ss, ms, LONG, LAZY, t, lt);         \
  }
LZVN_FAST_INSTANCE(4, 0, 0)
LZVN_FAST_INSTANCE(5, 0, 0)
LZVN_FAST_INSTANCE(6, 0, 0)
LZVN_FAST_INSTANCE(7, 0, 0)
LZVN_FAST_INSTANCE(8, 0, 0)
LZVN_FAST_INSTANCE(4, 1, 0)
LZVN_FAST_INSTANCE(5, 1, 0)
LZVN_FAST_INSTANCE(6, 1, 0)
LZVN_FAST_INSTANCE(4, 0, 1)
LZVN_FAST_INSTANCE(5, 0, 1)
LZVN_FAST_INSTANCE(6, 0, 1)
LZVN_FAST_INSTANCE(4, 1, 1)
LZVN_FAST_INSTANCE(5, 1, 1)
LZVN_FAST_INSTANCE(6, 1, 1)
#undef LZVN_FAST_INSTANCE

size_t lzvn_encode_fast_buffer(void *dst_v, size_t dst_size, const void *src_v, size_t src_size,
                               int hash_bits, int min_match, int skip_shift, int max_step, int long_table,
                               int lazy, uint16_t *table, uint16_t *ltable)
#ifdef LZVN_PROOF
LZVN_REQUIRES(src_v != NULL && __CPROVER_r_ok(src_v, src_size))
LZVN_REQUIRES(dst_v != NULL && __CPROVER_w_ok(dst_v, dst_size))
LZVN_REQUIRES(!__CPROVER_same_object(src_v, dst_v))
LZVN_REQUIRES(hash_bits >= 10 && hash_bits <= 16)
LZVN_REQUIRES(min_match >= 4 && min_match <= (long_table || lazy ? 6 : 8))
LZVN_REQUIRES(skip_shift >= 1 && skip_shift <= 31)
LZVN_REQUIRES(max_step >= 1 && max_step <= 64)
LZVN_REQUIRES(long_table == 0 || long_table == 1)
LZVN_REQUIRES(lazy == 0 || lazy == 1)
LZVN_REQUIRES(__CPROVER_rw_ok(table, ((size_t)1 << hash_bits) * sizeof *table))
LZVN_REQUIRES(!long_table || (ltable != NULL && __CPROVER_rw_ok(ltable, ((size_t)1 << hash_bits) * sizeof *ltable)))
LZVN_ASSIGNS(__CPROVER_object_upto(dst_v, dst_size),
             __CPROVER_object_whole(table))
LZVN_ASSIGNS(long_table != 0 && ltable != NULL: __CPROVER_object_whole(ltable))
LZVN_ENSURES(__CPROVER_return_value <= dst_size)
#endif
{
  unsigned char *d = dst_v;
  const unsigned char *s = src_v;
  int hb = hash_bits, ss = skip_shift, ms = max_step;
  if (!long_table && !lazy) {
    switch (min_match) {
    case 4: return lzvn_encode_fast_4_0_0(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    case 5: return lzvn_encode_fast_5_0_0(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    case 6: return lzvn_encode_fast_6_0_0(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    case 7: return lzvn_encode_fast_7_0_0(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    default: return lzvn_encode_fast_8_0_0(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    }
  }
  if (long_table && !lazy) {
    switch (min_match) {
    case 4: return lzvn_encode_fast_4_1_0(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    case 5: return lzvn_encode_fast_5_1_0(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    default: return lzvn_encode_fast_6_1_0(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    }
  }
  if (!long_table) {
    switch (min_match) {
    case 4: return lzvn_encode_fast_4_0_1(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    case 5: return lzvn_encode_fast_5_0_1(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    default: return lzvn_encode_fast_6_0_1(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
    }
  }
  switch (min_match) {
  case 4: return lzvn_encode_fast_4_1_1(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
  case 5: return lzvn_encode_fast_5_1_1(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
  default: return lzvn_encode_fast_6_1_1(d, dst_size, s, src_size, hb, ss, ms, table, ltable);
  }
}

// ===============================================================
// CrushLZVN optimal-parse encoder: candidate search, Pareto DP, commit.

/*! Builds the candidate menu for [0, end_pos) into z->cand_*: each position
 * keeps the longest cand_capacity of the increasing run its tree walk
 * returns (bt_match.h). A farther distance never costs less in LZVN, so a
 * shorter match farther away is never worth keeping. The scan stops 4 bytes
 * short of src_end for the hash load; positions past that get no
 * candidates. A call is exactly one block, with no bytes before it. */
#if defined(LZVN_OPTIMAL_PROOF)
static __attribute__((noinline)) void lzvn_zopt_build_candidates(lzvn_zopt_scratch *z,
                                                                 const unsigned char *src,
                                                                 lzvn_offset src_end, int32_t end_pos)
LZVN_REQUIRES(z != NULL && __CPROVER_rw_ok(z, sizeof *z))
LZVN_REQUIRES(src != NULL && __CPROVER_r_ok(src, (size_t)src_end))
LZVN_REQUIRES(end_pos >= 0 && end_pos <= LZVN_ZOPT_BLOCK_SIZE)
LZVN_ASSIGNS(__CPROVER_object_whole(z))
LZVN_ENSURES(z->max_tuples == __CPROVER_old(z->max_tuples))
LZVN_ENSURES(z->tup_M == __CPROVER_old(z->tup_M))
LZVN_ENSURES(z->tup_L == __CPROVER_old(z->tup_L))
LZVN_ENSURES(z->tup_D == __CPROVER_old(z->tup_D))
#else
static void lzvn_zopt_build_candidates(lzvn_zopt_scratch *z,
                                       const unsigned char *src,
                                       lzvn_offset src_end, int32_t end_pos)
#endif
{
  const int32_t cstride = z->cand_capacity;
  const uint32_t root_bits = bt_root_bits((uint32_t)z->hash_bits, (size_t)end_pos);
  memset(z->bt_head, 0xFF, ((size_t)1 << root_bits) * sizeof(*z->bt_head));
  // end_pos <= LZVN_ZOPT_BLOCK_SIZE, which is what cand_count is carved for.
  memset(z->cand_count, 0, (size_t)end_pos * sizeof(*z->cand_count));

  int32_t scan_end = end_pos;
  if ((lzvn_offset)scan_end + 4 > src_end) scan_end = (int32_t)(src_end - 4);
  if (scan_end < 0) scan_end = 0;

  int32_t skip_until = 0, skip_end = 0, skip_dist = 0;
  int32_t ml[BT_MAX_MATCHES], md[BT_MAX_MATCHES];
  for (int32_t i = 0; i < scan_end; i++) {
    int32_t *out_len = z->cand_len + (size_t)i * cstride;
    int32_t *out_dist = z->cand_dist + (size_t)i * cstride;
    // Lengths past end_pos are unusable; compares stop short of match_extend's
    // margin.
    int32_t real_room = end_pos - i;
    lzvn_offset ext_room = src_end - i - LZVN_ZOPT_MATCH_EXTEND_MARGIN;
    if (i < skip_until) {
      int32_t l = skip_end - i;
      if (l > real_room) l = real_room;
      out_len[0] = l;
      out_dist[0] = skip_dist;
      z->cand_count[i] = 1;
      continue;
    }
    uint32_t limit = ext_room > 0 ? (uint32_t)ext_room : 0;
    uint32_t longest;
    int32_t longest_dist;
    int n = bt_insert_find(src, i, limit, z->search_depth, LZVN_ENCODE_MAX_DISTANCE,
                           LZVN_ZOPT_MIN_MATCH_LEN, (uint32_t)real_room, z->bt_son,
                           z->bt_head + bt_hash3(src + i, root_bits), ml, md, &longest,
                           &longest_dist);
    int first = n > cstride ? n - cstride : 0;
    int32_t cnt = 0;
    for (int k = first; k < n; k++, cnt++) {
      out_len[cnt] = ml[k];
      out_dist[cnt] = md[k];
    }
    z->cand_count[i] = (uint16_t)cnt;
    if (longest >= LZVN_ZOPT_BT_SKIP_LEN) {
      skip_end = i + (int32_t)longest;
      skip_until = skip_end - LZVN_ZOPT_BT_SKIP_KEEP;
      skip_dist = longest_dist;
    }
  }
}

// ===============================================================
// Optimal-parse DP: a bounded Pareto front of (cost, run_len, last_dist)
// states per position (layout and rationale in lzvn_zopt_pareto.h). Costs
// are exact bytes, so one forward pass is exact for the given menu. Each
// state prices its pending literal run as if a match header will embed it;
// a run dangling at end_pos is undercosted by at most 4 bytes, which the
// entry point corrects.
//
// A candidate of length L is relaxed at every length in
// [L - LZVN_ZOPT_SUBLEN_WINDOW, L], floored at LZVN_ZOPT_MIN_MATCH_LEN for
// the hash menu and at LZVN_ZOPT_MIN_REPEAT_MATCH_LEN for the repeat probe
// when tail==0.

// Insert a state into position pos's front. Returns its slot, or -1 if an
// equal-key state was already cheaper-or-equal or the front is full of
// cheaper states. A self-referencing run_start_slot (passed as -1) must be
// patched by the caller once the slot is known.
static int32_t lzvn_pareto_insert(lzvn_pareto_scratch *p, int32_t pos,
                                  int32_t cost, int32_t run_len,
                                  int32_t last_dist, int32_t via_len,
                                  int32_t via_dist, int32_t src_slot,
                                  int32_t run_start_pos,
                                  int32_t run_start_slot) {
  int32_t k_cap = p->k_cap;
  int32_t cnt = p->count[pos];
  lzvn_pareto_slot *slots = p->slots + (size_t)pos * (size_t)k_cap;

  for (int32_t s = 0; s < cnt; s++) {
    if (slots[s].last_dist == last_dist && slots[s].run_len == run_len) {
      if (cost < slots[s].cost) {
        slots[s].cost = cost;
        slots[s].run_len = run_len;
        slots[s].via_len = via_len;
        slots[s].via_dist = via_dist;
        slots[s].src_slot = src_slot;
        slots[s].run_start_pos = run_start_pos;
        slots[s].run_start_slot = run_start_slot;
        if (cnt == k_cap) {
          int32_t wc = slots[0].cost;
          for (int32_t w = 1; w < k_cap; w++) if (slots[w].cost > wc) wc = slots[w].cost;
          p->worst_cost[pos] = wc;
        }
        return s;
      }
      return -1; // same (last_dist,run_len), existing state already cheaper-or-equal
    }
  }

  if (cnt < k_cap) {
    int32_t s = cnt;
    p->count[pos] = cnt + 1;
    slots[s].cost = cost;
    slots[s].run_len = run_len;
    slots[s].last_dist = last_dist;
    slots[s].via_len = via_len;
    slots[s].via_dist = via_dist;
    slots[s].src_slot = src_slot;
    slots[s].run_start_pos = run_start_pos;
    slots[s].run_start_slot = run_start_slot;
    if (cnt + 1 == k_cap) {
      int32_t wc = slots[0].cost;
      for (int32_t w = 1; w < k_cap; w++) if (slots[w].cost > wc) wc = slots[w].cost;
      p->worst_cost[pos] = wc;
    }
    return s;
  }

  int32_t worst = 0;
  int32_t worst_cost = slots[0].cost;
  for (int32_t s = 1; s < cnt; s++) {
    int32_t c = slots[s].cost;
    if (c > worst_cost) {
      worst = s;
      worst_cost = c;
    }
  }
  if (cost < worst_cost) {
    slots[worst].cost = cost;
    slots[worst].run_len = run_len;
    slots[worst].last_dist = last_dist;
    slots[worst].via_len = via_len;
    slots[worst].via_dist = via_dist;
    slots[worst].src_slot = src_slot;
    slots[worst].run_start_pos = run_start_pos;
    slots[worst].run_start_slot = run_start_slot;
    int32_t wc = slots[0].cost;
    for (int32_t w = 1; w < k_cap; w++) if (slots[w].cost > wc) wc = slots[w].cost;
    p->worst_cost[pos] = wc;
    return worst;
  }
  return -1;
}

// Repeat-match ends already measured in this DP pass, by distance. For a
// fixed distance a match ends at the first p with src[p] != src[p - d], the
// same p for every start before it, so one measurement serves every later
// position inside the run. A measurement stops after LZVN_ZOPT_REP_EXTEND_CAP
// bytes: the states carry many distances, and measuring each one's run in
// full is O(n^2) on input that keeps them all matching (a Fibonacci word).
// A capped end is re-measured once less than half of it is left, so a long
// run still costs about two compares per byte.
#ifndef LZVN_ZOPT_REP_EXTEND_CAP
#define LZVN_ZOPT_REP_EXTEND_CAP 1024
#endif
#define LZVN_REP_CACHE_BITS 4
typedef struct {
  int32_t dist[1 << LZVN_REP_CACHE_BITS];
  uint8_t capped[1 << LZVN_REP_CACHE_BITS];
  lzvn_offset end[1 << LZVN_REP_CACHE_BITS];
} lzvn_rep_cache;

// Length of the repeat match at i, at most max_len, given that its first
// four bytes match. Past LZVN_ZOPT_REP_EXTEND_CAP it may come up short of
// the longest; the tree's candidates still carry the full length.
static inline uint32_t lzvn_rep_extend(lzvn_rep_cache *c, const unsigned char *src,
                                       lzvn_offset i, int32_t dist, uint32_t max_len) {
  uint32_t slot = ((uint32_t)dist * 2654435761u) >> (32 - LZVN_REP_CACHE_BITS);
  if (c->dist[slot] == dist && c->end[slot] > i) {
    lzvn_offset left = c->end[slot] - i;
    if (!c->capped[slot] || left >= LZVN_ZOPT_REP_EXTEND_CAP / 2) return (uint32_t)left;
  }
  uint32_t cap = max_len < LZVN_ZOPT_REP_EXTEND_CAP ? max_len : LZVN_ZOPT_REP_EXTEND_CAP;
  uint32_t ext = match_extend(src + i, src + i - dist, 4, cap);
  c->dist[slot] = dist;
  c->capped[slot] = ext == cap && cap < max_len;
  c->end[slot] = i + (lzvn_offset)ext;
  return ext;
}

// Relax a match edge from (i, src_slot) into every landing position in the
// sub-length window, down to min_len.
static void lzvn_pareto_relax_match(lzvn_pareto_scratch *p, int32_t i,
                                    int32_t end_pos, int32_t base_cost,
                                    int32_t tail, int32_t last_dist,
                                    int32_t src_slot, int32_t length,
                                    int32_t dist, int32_t min_len) {
  int32_t m_lo = length - LZVN_ZOPT_SUBLEN_WINDOW;
  if (m_lo < min_len)
    m_lo = min_len;
  for (int32_t m = m_lo; m <= length; m++) {
    int32_t j = i + m;
    if (j > end_pos)
      break; // longer m only moves further past the window
    int32_t cost = base_cost + lzvn_match_op_cost(tail, m, dist, last_dist);
    if (cost >= p->worst_cost[j])
      continue;
    int32_t idx = lzvn_pareto_insert(p, j, cost, 0, dist, m, dist, src_slot,
                                     j, -1);
    if (idx >= 0)
      p->slots[(size_t)j * (size_t)p->k_cap + (size_t)idx].run_start_slot =
          idx; // self-reference: run_len==0 here
  }
}

// Runs the DP over [start_pos, end_pos) on the built candidate menu; the
// result lands in z->tup_*/n_tuples for lzvn_zopt_commit. Returns 0 on
// tuple-count overflow.
#define DEFINE_PARETO_RUN_DP(K_CAP) \
static int lzvn_pareto_run_dp_k##K_CAP(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p, \
                                       const unsigned char *src, \
                                       lzvn_offset src_end, int32_t start_pos, \
                                       int32_t end_pos) { \
  int32_t cstride = z->cand_capacity; \
  size_t n_pos = (size_t)(end_pos - start_pos) + 1; \
  memset(p->count + start_pos, 0, n_pos * sizeof(*p->count)); \
  for (int32_t pos = start_pos; pos <= end_pos; pos++) p->worst_cost[pos] = INT32_MAX; \
  p->count[start_pos] = 1; \
  lzvn_pareto_slot *s_start = p->slots + (size_t)start_pos * (size_t)K_CAP; \
  s_start[0].cost = 0; \
  s_start[0].run_len = 0; \
  s_start[0].last_dist = 0; \
  s_start[0].via_len = 0; \
  s_start[0].via_dist = 0; \
  s_start[0].src_slot = -1; \
  s_start[0].run_start_pos = start_pos; \
  s_start[0].run_start_slot = 0; \
  lzvn_rep_cache rep_cache; \
  memset(rep_cache.dist, 0, sizeof(rep_cache.dist)); \
  for (int32_t i = start_pos; i < end_pos; i++) { \
    int32_t n_states = p->count[i]; \
    if (n_states == 0) continue; \
    lzvn_pareto_slot *s_curr = p->slots + (size_t)i * (size_t)K_CAP; \
    int32_t tails[K_CAP]; \
    int32_t costs[K_CAP]; \
    int32_t last_dists[K_CAP]; \
    uint16_t vi16 = load2(src + i); \
    for (int32_t s_idx = 0; s_idx < n_states; s_idx++) { \
      costs[s_idx] = s_curr[s_idx].cost; \
      int32_t st_run_len = s_curr[s_idx].run_len; \
      last_dists[s_idx] = s_curr[s_idx].last_dist; \
      int32_t delta; \
      if (__builtin_expect(st_run_len < 270, 1)) { \
        if (st_run_len < 3) { delta = 0; tails[s_idx] = st_run_len; } \
        else if (st_run_len == 3) { delta = 5; tails[s_idx] = 3; } \
        else if (st_run_len == 15) { delta = 2; tails[s_idx] = 0; } \
        else { delta = 1; tails[s_idx] = 0; } \
      } else { \
        int32_t dummy_tail; \
        delta = lzvn_literal_prefix_cost(st_run_len + 1, &dummy_tail) - \
                lzvn_literal_prefix_cost(st_run_len, &tails[s_idx]); \
      } \
      int32_t new_run_len = st_run_len + 1; \
      int32_t new_cost = costs[s_idx] + delta; \
      { \
        int32_t pos = i + 1; \
        if (new_cost < p->worst_cost[pos]) { \
          lzvn_pareto_slot *s_next = p->slots + (size_t)pos * (size_t)K_CAP; \
          int32_t cnt = p->count[pos]; \
          int updated = 0; \
          for (int32_t s = 0; s < cnt; s++) { \
            if (s_next[s].last_dist == last_dists[s_idx] && s_next[s].run_len == new_run_len) { \
              if (new_cost < s_next[s].cost) { \
                s_next[s].cost = new_cost; \
                s_next[s].run_len = new_run_len; \
                s_next[s].via_len = 0; \
                s_next[s].via_dist = 0; \
                s_next[s].src_slot = -1; \
                s_next[s].run_start_pos = s_curr[s_idx].run_start_pos; \
                s_next[s].run_start_slot = s_curr[s_idx].run_start_slot; \
                if (cnt == K_CAP) { \
                  int32_t wc = s_next[0].cost; \
                  for (int32_t w = 1; w < K_CAP; w++) if (s_next[w].cost > wc) wc = s_next[w].cost; \
                  p->worst_cost[pos] = wc; \
                } \
              } \
              updated = 1; \
              break; \
            } \
          } \
          if (!updated) { \
            if (cnt < K_CAP) { \
              p->count[pos] = cnt + 1; \
              s_next[cnt].cost = new_cost; \
              s_next[cnt].run_len = new_run_len; \
              s_next[cnt].last_dist = last_dists[s_idx]; \
              s_next[cnt].via_len = 0; \
              s_next[cnt].via_dist = 0; \
              s_next[cnt].src_slot = -1; \
              s_next[cnt].run_start_pos = s_curr[s_idx].run_start_pos; \
              s_next[cnt].run_start_slot = s_curr[s_idx].run_start_slot; \
              if (cnt + 1 == K_CAP) { \
                int32_t wc = s_next[0].cost; \
                for (int32_t w = 1; w < K_CAP; w++) if (s_next[w].cost > wc) wc = s_next[w].cost; \
                p->worst_cost[pos] = wc; \
              } \
            } else { \
              int32_t worst = 0, worst_cost = s_next[0].cost; \
              for (int32_t s = 1; s < cnt; s++) { \
                int32_t c = s_next[s].cost; \
                if (c > worst_cost) { worst = s; worst_cost = c; } \
              } \
              if (new_cost < worst_cost) { \
                s_next[worst].cost = new_cost; \
                s_next[worst].run_len = new_run_len; \
                s_next[worst].last_dist = last_dists[s_idx]; \
                s_next[worst].via_len = 0; \
                s_next[worst].via_dist = 0; \
                s_next[worst].src_slot = -1; \
                s_next[worst].run_start_pos = s_curr[s_idx].run_start_pos; \
                s_next[worst].run_start_slot = s_curr[s_idx].run_start_slot; \
                int32_t wc = s_next[0].cost; \
                for (int32_t w = 1; w < K_CAP; w++) if (s_next[w].cost > wc) wc = s_next[w].cost; \
                p->worst_cost[pos] = wc; \
              } \
            } \
          } \
        } \
      } \
      if (last_dists[s_idx] > 0 && (lzvn_offset)i - last_dists[s_idx] >= 0) { \
        lzvn_offset m0 = (lzvn_offset)i - last_dists[s_idx]; \
        if (load2(src + m0) == vi16) { \
          int32_t repeat_min = (tails[s_idx] == 0) ? LZVN_ZOPT_MIN_REPEAT_MATCH_LEN : LZVN_ZOPT_MIN_MATCH_LEN; \
          lzvn_offset n = nmatch4(src, i, m0); \
          if (n >= (lzvn_offset)repeat_min) { \
            lzvn_offset m_end = (lzvn_offset)i + n; \
            if (n == 4) { \
              lzvn_offset max_len = end_pos - i; \
              if (max_len > 4 && src_end - ((lzvn_offset)i + 4) >= LZVN_ZOPT_MATCH_EXTEND_MARGIN) { \
                uint32_t ext = lzvn_rep_extend(&rep_cache, src, i, last_dists[s_idx], (uint32_t)max_len); \
                m_end = (lzvn_offset)i + (lzvn_offset)ext; \
              } \
            } \
            int32_t M = (int32_t)(m_end - i); \
            if (M >= repeat_min) { \
              int32_t m_lo = M - LZVN_ZOPT_SUBLEN_WINDOW; \
              if (m_lo < repeat_min) m_lo = repeat_min; \
              for (int32_t m = m_lo; m <= M; m++) { \
                int32_t j = i + m; \
                if (j > end_pos) break; \
                int32_t r_cost = costs[s_idx] + lzvn_match_op_cost(tails[s_idx], m, last_dists[s_idx], last_dists[s_idx]); \
                if (r_cost >= p->worst_cost[j]) continue; \
                lzvn_pareto_slot *s_j = p->slots + (size_t)j * (size_t)K_CAP; \
                int32_t j_cnt = p->count[j]; \
                int updated = 0; \
                for (int32_t s = 0; s < j_cnt; s++) { \
                  if (s_j[s].last_dist == last_dists[s_idx] && s_j[s].run_len == 0) { \
                    if (r_cost < s_j[s].cost) { \
                      s_j[s].cost = r_cost; \
                      s_j[s].via_len = m; \
                      s_j[s].via_dist = last_dists[s_idx]; \
                      s_j[s].src_slot = s_idx; \
                      s_j[s].run_start_pos = j; \
                      s_j[s].run_start_slot = (int32_t)s; \
                      if (j_cnt == K_CAP) { \
                        int32_t wc = s_j[0].cost; \
                        for (int32_t w = 1; w < K_CAP; w++) if (s_j[w].cost > wc) wc = s_j[w].cost; \
                        p->worst_cost[j] = wc; \
                      } \
                    } \
                    updated = 1; \
                    break; \
                  } \
                } \
                if (!updated) { \
                  if (j_cnt < K_CAP) { \
                    p->count[j] = j_cnt + 1; \
                    s_j[j_cnt].cost = r_cost; \
                    s_j[j_cnt].run_len = 0; \
                    s_j[j_cnt].last_dist = last_dists[s_idx]; \
                    s_j[j_cnt].via_len = m; \
                    s_j[j_cnt].via_dist = last_dists[s_idx]; \
                    s_j[j_cnt].src_slot = s_idx; \
                    s_j[j_cnt].run_start_pos = j; \
                    s_j[j_cnt].run_start_slot = j_cnt; \
                    if (j_cnt + 1 == K_CAP) { \
                      int32_t wc = s_j[0].cost; \
                      for (int32_t w = 1; w < K_CAP; w++) if (s_j[w].cost > wc) wc = s_j[w].cost; \
                      p->worst_cost[j] = wc; \
                    } \
                  } else { \
                    int32_t worst = 0, worst_cost = s_j[0].cost; \
                    for (int32_t s = 1; s < j_cnt; s++) { \
                      int32_t c = s_j[s].cost; \
                      if (c > worst_cost) { worst = s; worst_cost = c; } \
                    } \
                    if (r_cost < worst_cost) { \
                      s_j[worst].cost = r_cost; \
                      s_j[worst].run_len = 0; \
                      s_j[worst].last_dist = last_dists[s_idx]; \
                      s_j[worst].via_len = m; \
                      s_j[worst].via_dist = last_dists[s_idx]; \
                      s_j[worst].src_slot = s_idx; \
                      s_j[worst].run_start_pos = j; \
                      s_j[worst].run_start_slot = worst; \
                      int32_t wc = s_j[0].cost; \
                      for (int32_t w = 1; w < K_CAP; w++) if (s_j[w].cost > wc) wc = s_j[w].cost; \
                      p->worst_cost[j] = wc; \
                    } \
                  } \
                } \
              } \
            } \
          } \
        } \
      } \
    } \
    uint16_t cnt = z->cand_count[i]; \
    const int32_t *lens = z->cand_len + (size_t)i * cstride; \
    const int32_t *dists = z->cand_dist + (size_t)i * cstride; \
    for (uint16_t k = 0; k < cnt; k++) { \
      int32_t length = lens[k]; \
      int32_t dist = dists[k]; \
      int32_t m_lo = length - LZVN_ZOPT_SUBLEN_WINDOW; \
      if (m_lo < LZVN_ZOPT_MIN_MATCH_LEN) m_lo = LZVN_ZOPT_MIN_MATCH_LEN; \
      for (int32_t m = m_lo; m <= length; m++) { \
        int32_t j = i + m; \
        if (j > end_pos) break; \
        int32_t best_s = 0; \
        int32_t best_cost = costs[0] + lzvn_match_op_cost(tails[0], m, dist, last_dists[0]); \
        for (int32_t s = 1; s < n_states; s++) { \
          int32_t c = costs[s] + lzvn_match_op_cost(tails[s], m, dist, last_dists[s]); \
          if (c < best_cost) { best_cost = c; best_s = s; } \
        } \
        if (best_cost >= p->worst_cost[j]) continue; \
        lzvn_pareto_slot *s_j = p->slots + (size_t)j * (size_t)K_CAP; \
        int32_t j_cnt = p->count[j]; \
        int updated = 0; \
        for (int32_t s = 0; s < j_cnt; s++) { \
          if (s_j[s].last_dist == dist && s_j[s].run_len == 0) { \
            if (best_cost < s_j[s].cost) { \
              s_j[s].cost = best_cost; \
              s_j[s].via_len = m; \
              s_j[s].via_dist = dist; \
              s_j[s].src_slot = best_s; \
              s_j[s].run_start_pos = j; \
              s_j[s].run_start_slot = (int32_t)s; \
              if (j_cnt == K_CAP) { \
                int32_t wc = s_j[0].cost; \
                for (int32_t w = 1; w < K_CAP; w++) if (s_j[w].cost > wc) wc = s_j[w].cost; \
                p->worst_cost[j] = wc; \
              } \
            } \
            updated = 1; \
            break; \
          } \
        } \
        if (!updated) { \
          if (j_cnt < K_CAP) { \
            p->count[j] = j_cnt + 1; \
            s_j[j_cnt].cost = best_cost; \
            s_j[j_cnt].run_len = 0; \
            s_j[j_cnt].last_dist = dist; \
            s_j[j_cnt].via_len = m; \
            s_j[j_cnt].via_dist = dist; \
            s_j[j_cnt].src_slot = best_s; \
            s_j[j_cnt].run_start_pos = j; \
            s_j[j_cnt].run_start_slot = j_cnt; \
            if (j_cnt + 1 == K_CAP) { \
              int32_t wc = s_j[0].cost; \
              for (int32_t w = 1; w < K_CAP; w++) if (s_j[w].cost > wc) wc = s_j[w].cost; \
              p->worst_cost[j] = wc; \
            } \
          } else { \
            int32_t worst = 0, worst_cost = s_j[0].cost; \
            for (int32_t s = 1; s < j_cnt; s++) { \
              int32_t c = s_j[s].cost; \
              if (c > worst_cost) { worst = s; worst_cost = c; } \
            } \
            if (best_cost < worst_cost) { \
              s_j[worst].cost = best_cost; \
              s_j[worst].run_len = 0; \
              s_j[worst].last_dist = dist; \
              s_j[worst].via_len = m; \
              s_j[worst].via_dist = dist; \
              s_j[worst].src_slot = best_s; \
              s_j[worst].run_start_pos = j; \
              s_j[worst].run_start_slot = worst; \
              int32_t wc = s_j[0].cost; \
              for (int32_t w = 1; w < K_CAP; w++) if (s_j[w].cost > wc) wc = s_j[w].cost; \
              p->worst_cost[j] = wc; \
            } \
          } \
        } \
      } \
    } \
  } \
  int32_t pf_count = p->count[end_pos]; \
  if (pf_count == 0) return 0; \
  lzvn_pareto_slot *s_end = p->slots + (size_t)end_pos * (size_t)K_CAP; \
  int32_t best_slot = 0; \
  for (int32_t s = 1; s < pf_count; s++) \
    if (s_end[s].cost < s_end[best_slot].cost) \
      best_slot = s; \
  int32_t n_rev = 0, cursor = end_pos, slot = best_slot; \
  while (cursor > start_pos) { \
    if (n_rev >= z->max_tuples) return 0; \
    lzvn_pareto_slot *s_cur = p->slots + (size_t)cursor * (size_t)K_CAP + (size_t)slot; \
    int32_t via_len = s_cur->via_len; \
    if (via_len > 0) { \
      int32_t dist = s_cur->via_dist; \
      int32_t source = cursor - via_len; \
      int32_t src_slot_idx = s_cur->src_slot; \
      lzvn_pareto_slot *s_src = p->slots + (size_t)source * (size_t)K_CAP + (size_t)src_slot_idx; \
      int32_t lit_run = s_src->run_len; \
      z->rev_len[n_rev] = via_len; \
      z->rev_dist[n_rev] = dist; \
      z->rev_lit_run[n_rev] = lit_run; \
      n_rev++; \
      cursor = s_src->run_start_pos; \
      slot = s_src->run_start_slot; \
    } else { \
      int32_t lit_run = s_cur->run_len; \
      if (lit_run <= 0) break; \
      z->rev_len[n_rev] = 0; \
      z->rev_dist[n_rev] = 0; \
      z->rev_lit_run[n_rev] = lit_run; \
      n_rev++; \
      cursor = s_cur->run_start_pos; \
      slot = s_cur->run_start_slot; \
    } \
  } \
  for (int32_t t = 0; t < n_rev; t++) { \
    int32_t src_idx = n_rev - 1 - t; \
    z->tup_L[t] = (uint32_t)z->rev_lit_run[src_idx]; \
    z->tup_M[t] = (uint32_t)z->rev_len[src_idx]; \
    z->tup_D[t] = (uint32_t)z->rev_dist[src_idx]; \
  } \
  z->n_tuples = n_rev; \
  return 1; \
}

DEFINE_PARETO_RUN_DP(2)
DEFINE_PARETO_RUN_DP(4)
DEFINE_PARETO_RUN_DP(6)

// Generic fallback for arbitrary k_cap
static int lzvn_pareto_run_dp_generic(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                                      const unsigned char *src,
                                      lzvn_offset src_end, int32_t start_pos,
                                      int32_t end_pos) {
  int32_t cstride = z->cand_capacity;
  int32_t k_cap = p->k_cap;

  size_t n_pos = (size_t)(end_pos - start_pos) + 1;
  memset(p->count + start_pos, 0, n_pos * sizeof(*p->count));
  for (int32_t pos = start_pos; pos <= end_pos; pos++) p->worst_cost[pos] = INT32_MAX;

  p->count[start_pos] = 1;
  lzvn_pareto_slot *s_start = p->slots + (size_t)start_pos * (size_t)k_cap;
  s_start[0].cost = 0;
  s_start[0].run_len = 0;
  s_start[0].last_dist = 0;
  s_start[0].via_len = 0;
  s_start[0].via_dist = 0;
  s_start[0].src_slot = -1;
  s_start[0].run_start_pos = start_pos;
  s_start[0].run_start_slot = 0;

  lzvn_rep_cache rep_cache;
  memset(rep_cache.dist, 0, sizeof(rep_cache.dist));
  for (int32_t i = start_pos; i < end_pos; i++) {
    int32_t n_states = p->count[i];
    if (n_states == 0)
      continue;
    lzvn_pareto_slot *s_curr = p->slots + (size_t)i * (size_t)k_cap;
    uint16_t vi16 = load2(src + i);

    for (int32_t s_idx = 0; s_idx < n_states; s_idx++) {
      int32_t st_cost = s_curr[s_idx].cost;
      int32_t st_run_len = s_curr[s_idx].run_len;
      int32_t st_last_dist = s_curr[s_idx].last_dist;

      int32_t dummy_tail;
      int32_t new_run_len = st_run_len + 1;
      int32_t delta = lzvn_literal_prefix_cost(new_run_len, &dummy_tail) -
                      lzvn_literal_prefix_cost(st_run_len, &dummy_tail);
      int32_t new_cost = st_cost + delta;
      lzvn_pareto_insert(p, i + 1, new_cost, new_run_len, st_last_dist, 0,
                         0, -1, s_curr[s_idx].run_start_pos,
                         s_curr[s_idx].run_start_slot);

      int32_t tail;
      lzvn_literal_prefix_cost(st_run_len, &tail);

      if (st_last_dist > 0 && (lzvn_offset)i - st_last_dist >= 0) {
        lzvn_offset m0 = (lzvn_offset)i - st_last_dist;
        if (load2(src + m0) == vi16) {
          int32_t repeat_min = (tail == 0) ? LZVN_ZOPT_MIN_REPEAT_MATCH_LEN
                                            : LZVN_ZOPT_MIN_MATCH_LEN;
          lzvn_offset n = nmatch4(src, i, m0);
          if (n >= (lzvn_offset)repeat_min) {
            lzvn_offset m_end = (lzvn_offset)i + n;
            if (n == 4) {
              lzvn_offset max_len = end_pos - i;
              if (max_len > 4 &&
                  src_end - ((lzvn_offset)i + 4) >= LZVN_ZOPT_MATCH_EXTEND_MARGIN) {
                uint32_t ext = lzvn_rep_extend(&rep_cache, src, i, st_last_dist, (uint32_t)max_len);
                m_end = (lzvn_offset)i + (lzvn_offset)ext;
              }
            }
            int32_t M = (int32_t)(m_end - i);
            if (M >= repeat_min)
              lzvn_pareto_relax_match(p, i, end_pos, st_cost, tail, st_last_dist,
                                      s_idx, M, (int32_t)st_last_dist, repeat_min);
          }
        }
      }
    }

    uint16_t cnt = z->cand_count[i];
    const int32_t *lens = z->cand_len + (size_t)i * cstride;
    const int32_t *dists = z->cand_dist + (size_t)i * cstride;
    for (uint16_t k = 0; k < cnt; k++) {
      int32_t length = lens[k];
      int32_t dist = dists[k];
      int32_t m_lo = length - LZVN_ZOPT_SUBLEN_WINDOW;
      if (m_lo < LZVN_ZOPT_MIN_MATCH_LEN)
        m_lo = LZVN_ZOPT_MIN_MATCH_LEN;
      for (int32_t m = m_lo; m <= length; m++) {
        int32_t j = i + m;
        if (j > end_pos)
          break;
        int32_t best_s = 0;
        int32_t best_cost = INT32_MAX;
        for (int32_t s = 0; s < n_states; s++) {
          int32_t tail;
          lzvn_literal_prefix_cost(s_curr[s].run_len, &tail);
          int32_t c = s_curr[s].cost + lzvn_match_op_cost(tail, m, dist, s_curr[s].last_dist);
          if (c < best_cost) {
            best_cost = c;
            best_s = s;
          }
        }
        if (best_cost >= p->worst_cost[j])
          continue;
        int32_t idx = lzvn_pareto_insert(p, j, best_cost, 0, dist, m, dist, best_s, j, -1);
        if (idx >= 0)
          p->slots[(size_t)j * (size_t)k_cap + (size_t)idx].run_start_slot = idx;
      }
    }
  }

  int32_t pf_count = p->count[end_pos];
  if (pf_count == 0)
    return 0;
  lzvn_pareto_slot *s_end = p->slots + (size_t)end_pos * (size_t)k_cap;
  int32_t best_slot = 0;
  for (int32_t s = 1; s < pf_count; s++)
    if (s_end[s].cost < s_end[best_slot].cost)
      best_slot = s;

  int32_t n_rev = 0;
  int32_t cursor = end_pos;
  int32_t slot = best_slot;
  while (cursor > start_pos) {
    if (n_rev >= z->max_tuples)
      return 0;
    lzvn_pareto_slot *s_cur = p->slots + (size_t)cursor * (size_t)k_cap + (size_t)slot;
    int32_t via_len = s_cur->via_len;
    if (via_len > 0) {
      int32_t dist = s_cur->via_dist;
      int32_t source = cursor - via_len;
      int32_t src_slot_idx = s_cur->src_slot;
      lzvn_pareto_slot *s_src = p->slots + (size_t)source * (size_t)k_cap + (size_t)src_slot_idx;
      int32_t lit_run = s_src->run_len;
      z->rev_len[n_rev] = via_len;
      z->rev_dist[n_rev] = dist;
      z->rev_lit_run[n_rev] = lit_run;
      n_rev++;
      cursor = s_src->run_start_pos;
      slot = s_src->run_start_slot;
    } else {
      int32_t lit_run = s_cur->run_len;
      if (lit_run <= 0)
        break;
      z->rev_len[n_rev] = 0;
      z->rev_dist[n_rev] = 0;
      z->rev_lit_run[n_rev] = lit_run;
      n_rev++;
      cursor = s_cur->run_start_pos;
      slot = s_cur->run_start_slot;
    }
  }

  for (int32_t t = 0; t < n_rev; t++) {
    int32_t src_idx = n_rev - 1 - t;
    z->tup_L[t] = (uint32_t)z->rev_lit_run[src_idx];
    z->tup_M[t] = (uint32_t)z->rev_len[src_idx];
    z->tup_D[t] = (uint32_t)z->rev_dist[src_idx];
  }
  z->n_tuples = n_rev;
  return 1;
}

// Runs the DP over [start_pos, end_pos) on the built candidate menu; the
// result lands in z->tup_*/n_tuples for lzvn_zopt_commit. Returns 0 on
// tuple-count overflow.
#if defined(LZVN_OPTIMAL_PROOF)
static __attribute__((noinline)) int lzvn_pareto_run_dp(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                                                        const unsigned char *src,
                                                        lzvn_offset src_end, int32_t start_pos,
                                                        int32_t end_pos)
LZVN_REQUIRES(z != NULL && __CPROVER_rw_ok(z, sizeof *z))
LZVN_REQUIRES(p != NULL && __CPROVER_rw_ok(p, sizeof *p))
LZVN_REQUIRES(src_end >= 0 && src != NULL && __CPROVER_r_ok(src, (size_t)src_end))
LZVN_REQUIRES(0 <= start_pos && start_pos <= end_pos &&
              end_pos <= LZVN_ZOPT_BLOCK_SIZE && end_pos <= src_end)
LZVN_REQUIRES(LZVN_PARETO_STORAGE_OK(z, p, end_pos))
LZVN_ASSIGNS(z->n_tuples,
             __CPROVER_object_upto(p->count, ((size_t)end_pos + 1) * sizeof *p->count),
             __CPROVER_object_upto(p->worst_cost, ((size_t)end_pos + 1) * sizeof *p->worst_cost),
             __CPROVER_object_upto(p->slots, ((size_t)end_pos + 1) * (size_t)p->k_cap * sizeof *p->slots),
             __CPROVER_object_upto(z->tup_M, (size_t)z->max_tuples * sizeof *z->tup_M),
             __CPROVER_object_upto(z->tup_L, (size_t)z->max_tuples * sizeof *z->tup_L),
             __CPROVER_object_upto(z->tup_D, (size_t)z->max_tuples * sizeof *z->tup_D))
LZVN_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == 1)
LZVN_ENSURES(z->tup_M == __CPROVER_old(z->tup_M))
LZVN_ENSURES(z->tup_L == __CPROVER_old(z->tup_L))
LZVN_ENSURES(z->tup_D == __CPROVER_old(z->tup_D))
LZVN_ENSURES(z->max_tuples == __CPROVER_old(z->max_tuples))
LZVN_ENSURES(__CPROVER_return_value == 1 ==> (z->n_tuples >= 0 && z->n_tuples <= z->max_tuples))
LZVN_ENSURES(__CPROVER_return_value == 1 ==> (z->n_tuples == 0 || z->tup_L[z->n_tuples - 1] <= LZVN_ZOPT_BLOCK_SIZE))
#else
static int lzvn_pareto_run_dp(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                              const unsigned char *src,
                              lzvn_offset src_end, int32_t start_pos,
                              int32_t end_pos)
#endif
{
  int res;
  switch (p->k_cap) {
  case 2: res = lzvn_pareto_run_dp_k2(z, p, src, src_end, start_pos, end_pos); break;
  case 4: res = lzvn_pareto_run_dp_k4(z, p, src, src_end, start_pos, end_pos); break;
  case 6: res = lzvn_pareto_run_dp_k6(z, p, src, src_end, start_pos, end_pos); break;
  default: res = lzvn_pareto_run_dp_generic(z, p, src, src_end, start_pos, end_pos); break;
  }
  return res;
}

// Cheapest state at end_pos, before the dangling-final-run correction.
#if defined(LZVN_OPTIMAL_PROOF)
static __attribute__((noinline)) int32_t lzvn_pareto_total_cost(lzvn_pareto_scratch *p, int32_t end_pos)
LZVN_REQUIRES(p != NULL && __CPROVER_rw_ok(p, sizeof *p))
LZVN_ASSIGNS()
LZVN_ENSURES(__CPROVER_return_value >= 0 && __CPROVER_return_value <= 1000000)
#else
static int32_t lzvn_pareto_total_cost(lzvn_pareto_scratch *p, int32_t end_pos)
#endif
{
  int32_t cnt = p->count[end_pos];
  lzvn_pareto_slot *s_end = p->slots + (size_t)end_pos * (size_t)p->k_cap;
  int32_t best = INT32_MAX;
  for (int32_t s = 0; s < cnt; s++)
    if (s_end[s].cost < best)
      best = s_end[s].cost;
  return best;
}

/*! Commits the tuple sequence through emit()/emit_literal(). Returns bytes
 * written, or 0 if dst is too small. */
#if defined(LZVN_OPTIMAL_PROOF)
static __attribute__((noinline)) size_t lzvn_zopt_commit(const unsigned char *src, unsigned char *dst,
                                                         size_t dst_size, const lzvn_zopt_scratch *z,
                                                         int32_t start_pos)
LZVN_REQUIRES(src != NULL)
LZVN_REQUIRES(dst != NULL && __CPROVER_w_ok(dst, dst_size))
LZVN_REQUIRES(!__CPROVER_same_object(src, dst))
LZVN_REQUIRES(z != NULL && __CPROVER_r_ok(z, sizeof *z))
LZVN_ASSIGNS(__CPROVER_object_upto(dst, dst_size))
LZVN_ENSURES(__CPROVER_return_value <= dst_size)
#else
static size_t lzvn_zopt_commit(const unsigned char *src, unsigned char *dst,
                               size_t dst_size, const lzvn_zopt_scratch *z,
                               int32_t start_pos)
#endif
{
  if (dst_size < 8)
    return 0;
  unsigned char *q = dst;
  unsigned char *q1 = dst + dst_size - 8; // reserve 8 bytes for end-of-stream
  int32_t cursor = start_pos;
  size_t d_prev = 0;

  for (int32_t t = 0; t < z->n_tuples; t++) {
    uint32_t L = z->tup_L[t], M = z->tup_M[t], D = z->tup_D[t];
    if (M == 0) {
      q = emit_literal(src + cursor, q, q1, L);
    } else {
      q = emit(src + cursor, q, q1, L, M, D, d_prev);
      d_prev = D;
    }
    if (q >= q1)
      return 0; // OUT_FULL
    cursor += (int32_t)(L + M);
  }

  q1 = dst + dst_size; // restore full range for the end-of-stream marker
  if (q + 8 > q1)
    return 0;
  store8(q, 0x06);
  q += 8;
  return (size_t)(q - dst);
}

// Entry point for the optimal levels; contract in lzvn_encode_base.h.
size_t lzvn_encode_optimal_buffer_pareto(void *dst, size_t dst_size,
                                         const void *src, size_t src_size,
                                         lzvn_zopt_scratch *z,
                                         lzvn_pareto_scratch *p) {
  if (src_size > (size_t)LZVN_ZOPT_BLOCK_SIZE)
    return 0;
  int32_t n = (int32_t)src_size;
  const unsigned char *s = (const unsigned char *)src;
  lzvn_offset padded_end = (lzvn_offset)src_size + LZVN_ZOPT_SRC_PADDING;

  lzvn_zopt_build_candidates(z, s, padded_end, n);
  if (!lzvn_pareto_run_dp(z, p, s, padded_end, 0, n))
    return 0; // tuple-count overflow, caller should fail over to another strategy

  // The DP's cost plus the final-run correction must equal the committed
  // size, or the cost model and the writers disagree.
  int32_t expected = lzvn_pareto_total_cost(p, n);
  if (z->n_tuples > 0 && z->tup_M[z->n_tuples - 1] == 0) {
    int32_t L = (int32_t)z->tup_L[z->n_tuples - 1];
    int32_t tail;
    expected += lzvn_literal_final_cost(L) - lzvn_literal_prefix_cost(L, &tail);
  }

  size_t committed = lzvn_zopt_commit(s, (unsigned char *)dst, dst_size, z, 0);
  if (committed == 0)
    return 0;
  if ((int32_t)(committed - 8) != expected)
    return 0; // internal inconsistency, fail safe
  return committed;
}

// API entry points

// Whole-buffer wrapper around lzvn_encode_greedy_wide.
size_t lzvn_encode_greedy_wide_buffer(void *__restrict dst, size_t dst_size,
                                      const void *__restrict src, size_t src_size,
                                      int32_t hash_bits, int32_t hash_width,
                                      int32_t *hist_pos, uint32_t *hist_value,
                                      uint16_t *hist_cursor)
#ifdef LZVN_PROOF
LZVN_REQUIRES(src != NULL && __CPROVER_r_ok(src, src_size))
LZVN_REQUIRES(dst != NULL && __CPROVER_w_ok(dst, dst_size))
LZVN_REQUIRES(!__CPROVER_same_object(src, dst))
LZVN_REQUIRES(hash_bits >= 10 && hash_bits <= 16)
LZVN_REQUIRES(hash_width >= 1 && hash_width <= 64)
LZVN_REQUIRES(__CPROVER_rw_ok(hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos))
LZVN_REQUIRES(__CPROVER_rw_ok(hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZVN_REQUIRES(__CPROVER_rw_ok(hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(!__CPROVER_same_object(src, hist_pos) &&
              !__CPROVER_same_object(src, hist_value) &&
              !__CPROVER_same_object(src, hist_cursor))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(dst, dst_size,
              hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(dst, dst_size,
              hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(dst, dst_size,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(hist_pos,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos,
              hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(hist_pos,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(hist_value,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_ASSIGNS(__CPROVER_object_upto(dst, dst_size),
             __CPROVER_object_upto(hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos),
             __CPROVER_object_upto(hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value),
             __CPROVER_object_upto(hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZVN_ENSURES(__CPROVER_return_value <= dst_size)
#endif
{
  if (dst_size < LZVN_ENCODE_MIN_DST_SIZE)
    return 0;
  if (src_size > LZVN_ENCODE_MAX_SRC_SIZE)
    return 0; // positions are 32-bit; the caller splits larger inputs

  lzvn_encoder_state state;
  memset(&state, 0, sizeof(state));
  state.src = src;
  state.src_begin = 0;
  state.src_end = (lzvn_offset)src_size;
  state.src_literal = 0;
  state.src_current = 0;
  state.dst = dst;
  state.dst_begin = dst;
  state.dst_end = (unsigned char *)dst + dst_size - 8;

  if (src_size >= LZVN_ENCODE_MIN_SRC_SIZE) {
    state.src_current_end = (lzvn_offset)src_size - LZVN_ENCODE_MIN_MARGIN;
    lzvn_encode_greedy_init_table(hash_bits, hist_cursor);
    lzvn_encode_greedy_wide(&state, hash_bits, hash_width, hist_pos, hist_value, hist_cursor);
  }

  lzvn_emit_literal(&state, state.src_end - state.src_literal);
  state.dst_end = (unsigned char *)dst + dst_size;
  lzvn_emit_end_of_stream(&state);

  if (state.src_literal != state.src_end)
    return 0;

#ifdef LZVN_PROOF
  return (size_t)(LZVN_OFFSET(state.dst) - LZVN_OFFSET(state.dst_begin));
#else
  return (size_t)(state.dst - state.dst_begin);
#endif
}

/*! Whole-buffer encode as pure literals, no match search at all: exactly
 * lzvn_literal_final_cost(src_size) + 8 bytes on success, 0 if dst is too
 * small. crushlzvn.c falls back to this whenever a real parse would cost
 * more, which is what makes its encode_bound() provable rather than an
 * empirical margin. See the cost model comment above. */
size_t lzvn_encode_literal_only_buffer(void *__restrict dst, size_t dst_size,
                                       const void *__restrict src, size_t src_size)
#ifdef LZVN_PROOF
LZVN_REQUIRES(src == NULL || __CPROVER_r_ok(src, src_size))
LZVN_REQUIRES(dst == NULL || __CPROVER_w_ok(dst, dst_size))
LZVN_REQUIRES(src == NULL || dst == NULL || !__CPROVER_same_object(src, dst))
LZVN_ASSIGNS(dst != NULL: __CPROVER_object_upto(dst, dst_size))
LZVN_ENSURES(__CPROVER_return_value <= dst_size)
#endif
{
  if (!dst || !src)
    return 0;
  unsigned char *q = (unsigned char *)dst;
  if (dst_size < 8)
    return 0;
  // Reserve the trailing 8 bytes for the end-of-stream op, as
  // lzvn_encode_greedy_wide_buffer does, so emit_literal's own "+10" margin
  // check can't approve a write that leaves no room for it.
  unsigned char *end = emit_literal((const unsigned char *)src, q, q + dst_size - 8, src_size);
  if (end >= q + dst_size - 8)
    return 0; // FULL
  store8(end, 0x06); // end-of-stream command
  end += 8;
  return (size_t)(end - q);
}
