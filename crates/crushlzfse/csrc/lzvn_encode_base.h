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

#ifndef LZVN_ENCODE_BASE_H
#define LZVN_ENCODE_BASE_H

#include "lzfse_internal.h"
#include "lzvn_zopt.h"
#include "lzvn_zopt_pareto.h"

#if defined(LZVN_PROOF) || defined(CRUSHLZVN_DISPATCH_PROOF)
/* Storage and nonalias geometry used by the Pareto DP replacement contract.
 * The real scratch initializers carve these regions from one allocation. */
#define LZVN_PARETO_STORAGE_OK(z, p, n) ( \
  (z)->max_tuples > 0 && 1 <= (p)->k_cap && (p)->k_cap <= LZVN_PARETO_MAX_K && \
  __CPROVER_rw_ok((z)->tup_L, ((size_t)(z)->max_tuples * sizeof *(z)->tup_L)) && \
  __CPROVER_rw_ok((z)->tup_M, ((size_t)(z)->max_tuples * sizeof *(z)->tup_M)) && \
  __CPROVER_rw_ok((z)->tup_D, ((size_t)(z)->max_tuples * sizeof *(z)->tup_D)) && \
  __CPROVER_rw_ok((p)->count, (((size_t)(n) + 1) * sizeof *(p)->count)) && \
  __CPROVER_rw_ok((p)->worst_cost, (((size_t)(n) + 1) * sizeof *(p)->worst_cost)) && \
  __CPROVER_rw_ok((p)->slots, (((size_t)(n) + 1) * (size_t)(p)->k_cap * sizeof *(p)->slots)) && \
  LZVN_PROOF_RANGES_DISJOINT(z, sizeof *(z), p, sizeof *(p)) && \
  LZVN_PROOF_RANGES_DISJOINT(z, sizeof *(z), (z)->tup_L, ((size_t)(z)->max_tuples * sizeof *(z)->tup_L)) && \
  LZVN_PROOF_RANGES_DISJOINT(z, sizeof *(z), (z)->tup_M, ((size_t)(z)->max_tuples * sizeof *(z)->tup_M)) && \
  LZVN_PROOF_RANGES_DISJOINT(z, sizeof *(z), (z)->tup_D, ((size_t)(z)->max_tuples * sizeof *(z)->tup_D)) && \
  LZVN_PROOF_RANGES_DISJOINT(z, sizeof *(z), (p)->count, (((size_t)(n) + 1) * sizeof *(p)->count)) && \
  LZVN_PROOF_RANGES_DISJOINT(z, sizeof *(z), (p)->worst_cost, (((size_t)(n) + 1) * sizeof *(p)->worst_cost)) && \
  LZVN_PROOF_RANGES_DISJOINT(z, sizeof *(z), (p)->slots, (((size_t)(n) + 1) * (size_t)(p)->k_cap * sizeof *(p)->slots)) && \
  LZVN_PROOF_RANGES_DISJOINT(p, sizeof *(p), (z)->tup_L, ((size_t)(z)->max_tuples * sizeof *(z)->tup_L)) && \
  LZVN_PROOF_RANGES_DISJOINT(p, sizeof *(p), (z)->tup_M, ((size_t)(z)->max_tuples * sizeof *(z)->tup_M)) && \
  LZVN_PROOF_RANGES_DISJOINT(p, sizeof *(p), (z)->tup_D, ((size_t)(z)->max_tuples * sizeof *(z)->tup_D)) && \
  LZVN_PROOF_RANGES_DISJOINT(p, sizeof *(p), (p)->count, (((size_t)(n) + 1) * sizeof *(p)->count)) && \
  LZVN_PROOF_RANGES_DISJOINT(p, sizeof *(p), (p)->worst_cost, (((size_t)(n) + 1) * sizeof *(p)->worst_cost)) && \
  LZVN_PROOF_RANGES_DISJOINT(p, sizeof *(p), (p)->slots, (((size_t)(n) + 1) * (size_t)(p)->k_cap * sizeof *(p)->slots)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_L, ((size_t)(z)->max_tuples * sizeof *(z)->tup_L), (z)->tup_M, ((size_t)(z)->max_tuples * sizeof *(z)->tup_M)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_L, ((size_t)(z)->max_tuples * sizeof *(z)->tup_L), (z)->tup_D, ((size_t)(z)->max_tuples * sizeof *(z)->tup_D)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_L, ((size_t)(z)->max_tuples * sizeof *(z)->tup_L), (p)->count, (((size_t)(n) + 1) * sizeof *(p)->count)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_L, ((size_t)(z)->max_tuples * sizeof *(z)->tup_L), (p)->worst_cost, (((size_t)(n) + 1) * sizeof *(p)->worst_cost)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_L, ((size_t)(z)->max_tuples * sizeof *(z)->tup_L), (p)->slots, (((size_t)(n) + 1) * (size_t)(p)->k_cap * sizeof *(p)->slots)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_M, ((size_t)(z)->max_tuples * sizeof *(z)->tup_M), (z)->tup_D, ((size_t)(z)->max_tuples * sizeof *(z)->tup_D)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_M, ((size_t)(z)->max_tuples * sizeof *(z)->tup_M), (p)->count, (((size_t)(n) + 1) * sizeof *(p)->count)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_M, ((size_t)(z)->max_tuples * sizeof *(z)->tup_M), (p)->worst_cost, (((size_t)(n) + 1) * sizeof *(p)->worst_cost)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_M, ((size_t)(z)->max_tuples * sizeof *(z)->tup_M), (p)->slots, (((size_t)(n) + 1) * (size_t)(p)->k_cap * sizeof *(p)->slots)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_D, ((size_t)(z)->max_tuples * sizeof *(z)->tup_D), (p)->count, (((size_t)(n) + 1) * sizeof *(p)->count)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_D, ((size_t)(z)->max_tuples * sizeof *(z)->tup_D), (p)->worst_cost, (((size_t)(n) + 1) * sizeof *(p)->worst_cost)) && \
  LZVN_PROOF_RANGES_DISJOINT((z)->tup_D, ((size_t)(z)->max_tuples * sizeof *(z)->tup_D), (p)->slots, (((size_t)(n) + 1) * (size_t)(p)->k_cap * sizeof *(p)->slots)) && \
  LZVN_PROOF_RANGES_DISJOINT((p)->count, (((size_t)(n) + 1) * sizeof *(p)->count), (p)->worst_cost, (((size_t)(n) + 1) * sizeof *(p)->worst_cost)) && \
  LZVN_PROOF_RANGES_DISJOINT((p)->count, (((size_t)(n) + 1) * sizeof *(p)->count), (p)->slots, (((size_t)(n) + 1) * (size_t)(p)->k_cap * sizeof *(p)->slots)) && \
  LZVN_PROOF_RANGES_DISJOINT((p)->worst_cost, (((size_t)(n) + 1) * sizeof *(p)->worst_cost), (p)->slots, (((size_t)(n) + 1) * (size_t)(p)->k_cap * sizeof *(p)->slots)) )
#endif

#if defined(LZVN_PROOF) || defined(CRUSHLZVN_DISPATCH_PROOF)
#ifndef LZVN_REQUIRES
#define LZVN_REQUIRES(x)        __CPROVER_requires(x)
#define LZVN_ENSURES(x)         __CPROVER_ensures(x)
#define LZVN_ASSIGNS(...)       __CPROVER_assigns(__VA_ARGS__)
#define LZVN_LOOP_ASSIGNS(...)  __CPROVER_assigns(__VA_ARGS__)
#define LZVN_LOOP_INVARIANT(x)  __CPROVER_loop_invariant(x)
#define LZVN_LOOP_DECREASES(x)  __CPROVER_decreases(x)
#define LZVN_LOOP_ENTRY(x)      __CPROVER_loop_entry(x)
#define LZVN_OLD(x)             __CPROVER_old(x)
#define LZVN_OFFSET(p)          __CPROVER_POINTER_OFFSET(p)
#define LZVN_PROOF_RANGES_DISJOINT(a, a_size, b, b_size) \
  ((a_size) == 0 || (b_size) == 0 || \
   !__CPROVER_same_object((a), (b)) || \
   (LZVN_OFFSET(a) <= LZVN_OFFSET(b) \
      ? (a_size) <= (size_t)(LZVN_OFFSET(b) - LZVN_OFFSET(a)) \
      : (b_size) <= (size_t)(LZVN_OFFSET(a) - LZVN_OFFSET(b))))
#define LZVN_INLINE             static __attribute__((noinline))
#endif
#else
#ifndef LZVN_REQUIRES
#define LZVN_REQUIRES(x)
#define LZVN_ENSURES(x)
#define LZVN_ASSIGNS(...)
#define LZVN_LOOP_ASSIGNS(...)
#define LZVN_LOOP_INVARIANT(x)
#define LZVN_LOOP_DECREASES(x)
/* Production keeps main's plain `static inline` for the emitter and copy
 * helpers: the compiler keeps emit()/emit_literal() out of line in the
 * greedy and fast loops, which is measurably faster than forcing them in.
 * (Proof builds make them noinline so their contracts can replace them.) */
#define LZVN_INLINE             static inline
#endif
#endif

#if defined(LZVN_PROOF) && defined(LZVN_FAST_COPY)
#define LZVN_EMIT_BYTE(dst, b) do { __CPROVER_assert(__CPROVER_w_ok((dst), 1), "emit byte write"); (dst)++; } while (0)
#else
#define LZVN_EMIT_BYTE(dst, b) (*(dst)++ = (b))
#endif

// Types and constants

#define LZVN_ENCODE_MAX_DISTANCE                                               \
  0xffff // max match distance we can represent with LZVN encoding, MUST be
         // 0xFFFF
#define LZVN_ENCODE_MIN_MARGIN                                                 \
  8 // min number of bytes required between current and end during encoding,
    // MUST be >= 8
#define LZVN_ENCODE_MAX_LITERAL_BACKLOG                                        \
  400 // if the number of pending literals exceeds this size, emit a long
      // literal, MUST be >= 271

typedef struct {
  lzvn_offset m_begin; // beginning of match, current position
  lzvn_offset m_end; // end of match, this is where the next literal would begin
                     // if we emit the entire match
  lzvn_offset M;     // match length M: m_end - m_begin
  lzvn_offset D;     // match distance D
  lzvn_offset K;     // match gain: M - distance storage (L not included)
} lzvn_match_info;

// Encoder state

typedef struct {
  const unsigned char *src;
  // src[i] is valid for src_begin <= i < src_end; src_begin may be negative.
  lzvn_offset src_begin;
  lzvn_offset src_end;
  lzvn_offset src_current;
  // Must have src_current_end + 8 <= src_end.
  lzvn_offset src_current_end;
  // May be before or after src_current.
  lzvn_offset src_literal;

  unsigned char *dst;
  unsigned char *dst_begin;
  unsigned char *dst_end;

  lzvn_match_info pending;

  lzvn_offset d_prev;

} lzvn_encoder_state;

/*! Greedy LZVN encode over a runtime hash_bits/hash_width table. At width=4
 * this is the same candidates-per-bucket, same tie-breaks as Apple's
 * original open-source LZVN encoder (the reference this project ported from
 * and later dropped in favor of this generalization), just with a
 * round-robin insert in place of its shift-rotate, which measures faster at
 * any hash_bits. Note Apple's current shipped libcompression is not always
 * byte-identical to that open-source reference; hash_bits and hash_width are
 * this crate's own level table's tuning knobs. hist_pos/hist_value hold
 * (1<<hash_bits)*hash_width entries each and hist_cursor (1<<hash_bits),
 * all caller-owned and reset via lzvn_encode_greedy_init_table first.
 * hash_width must be in [1, 255]: hist_cursor packs two per-bucket bytes. */
void lzvn_encode_greedy_wide(lzvn_encoder_state *state, int32_t hash_bits,
                             int32_t hash_width, int32_t *hist_pos,
                             uint32_t *hist_value, uint16_t *hist_cursor);

/*! Resets the history table; call once per encode before
 * lzvn_encode_greedy_wide. Only hist_cursor is written. */
void lzvn_encode_greedy_init_table(int32_t hash_bits, uint16_t *hist_cursor);

/*! Whole-buffer wrapper around lzvn_encode_greedy_wide. Returns bytes
 * written, or 0 if dst is too small. Table sizing as for
 * lzvn_encode_greedy_wide. */
#if !defined(CRUSHLZVN_DISPATCH_PROOF)
size_t lzvn_encode_greedy_wide_buffer(void *__restrict dst, size_t dst_size,
                                      const void *__restrict src, size_t src_size,
                                      int32_t hash_bits, int32_t hash_width,
                                      int32_t *hist_pos, uint32_t *hist_value,
                                      uint16_t *hist_cursor);
#endif

/*! Whole-buffer fast encode (fast_match.h), with the LZFSE fast strategy's
 * parameters and limits. table holds 2^hash_bits entries, ltable as many
 * when long_table is set; both must be zeroed. src_size is at most
 * LZVN_ZOPT_BLOCK_SIZE. Returns bytes written, or 0 if dst is too small. */
size_t lzvn_encode_fast_buffer(void *dst, size_t dst_size, const void *src, size_t src_size,
                               int hash_bits, int min_match, int skip_shift, int max_step, int long_table,
                               int lazy, uint16_t *table, uint16_t *ltable)
#if defined(CRUSHLZVN_DISPATCH_PROOF)
LZVN_REQUIRES(src != NULL && __CPROVER_r_ok(src, src_size))
LZVN_REQUIRES(dst != NULL && __CPROVER_w_ok(dst, dst_size))
LZVN_REQUIRES(!__CPROVER_same_object(src, dst))
LZVN_REQUIRES(__CPROVER_rw_ok(table, ((size_t)1 << hash_bits) * sizeof *table))
LZVN_REQUIRES(!long_table || (ltable != NULL && __CPROVER_rw_ok(ltable, ((size_t)1 << hash_bits) * sizeof *ltable)))
LZVN_ASSIGNS(__CPROVER_object_upto(dst, dst_size),
             __CPROVER_object_whole(table))
LZVN_ASSIGNS(long_table != 0 && ltable != NULL: __CPROVER_object_whole(ltable))
LZVN_ENSURES(__CPROVER_return_value <= dst_size)
#endif
;

/*! Bytes for a final literal-only run of length L, matching what
 * lzvn_encode_literal_only_buffer actually writes (its own cost, without
 * the 8-byte end-of-stream op). */
#if defined(CRUSHLZVN_DISPATCH_PROOF)
static inline int32_t lzvn_literal_final_cost(int32_t L) {
  int32_t cost = 0;
  int32_t full = L / 271, rem = L % 271;
  cost += L + 2 * full;
  cost += rem > 15 ? 2 : rem > 0 ? 1 : 0;
  return cost;
}
#else
int32_t lzvn_literal_final_cost(int32_t L);
#endif

/*! Whole-buffer encode as pure literals: no match search, so its cost is
 * exactly lzvn_literal_final_cost(src_size) + 8, an upper bound crushlzvn.c
 * can fall back to whenever a real parse would exceed it. Returns bytes
 * written, or 0 if dst is too small. */
size_t lzvn_encode_literal_only_buffer(void *__restrict dst, size_t dst_size,
                                       const void *__restrict src, size_t src_size)
#if defined(CRUSHLZVN_DISPATCH_PROOF)
LZVN_REQUIRES(src == NULL || __CPROVER_r_ok(src, src_size))
LZVN_REQUIRES(dst == NULL || __CPROVER_w_ok(dst, dst_size))
LZVN_REQUIRES(src == NULL || dst == NULL || !__CPROVER_same_object(src, dst))
LZVN_ASSIGNS(dst != NULL: __CPROVER_object_upto(dst, dst_size))
LZVN_ENSURES(__CPROVER_return_value <= dst_size)
#endif
;

// Readable bytes lzvn_encode_optimal_buffer_pareto requires past
// src[src_size); crushlzvn.c copies src into a padded region to satisfy it.
#define LZVN_ZOPT_SRC_PADDING 32

/*! Optimal-parse encode of src[0..src_size) into dst. `z` and `p` must be
 * sized for LZVN_ZOPT_BLOCK_SIZE (the only block size, fixed), and `z` must
 * have search_depth set; src_size must not exceed LZVN_ZOPT_BLOCK_SIZE.
 * Requires LZVN_ZOPT_SRC_PADDING readable bytes past src[src_size). Returns
 * bytes written (including the 8-byte end-of-stream op), or 0 on failure:
 * dst too small, src_size over LZVN_ZOPT_BLOCK_SIZE, or tuple-count
 * overflow. */
size_t lzvn_encode_optimal_buffer_pareto(void *dst, size_t dst_size,
                                         const void *src, size_t src_size,
                                         lzvn_zopt_scratch *z,
                                         lzvn_pareto_scratch *p)
#if defined(CRUSHLZVN_DISPATCH_PROOF) || defined(LZVN_OPTIMAL_PROOF)
LZVN_REQUIRES(src != NULL && __CPROVER_r_ok(src, src_size + LZVN_ZOPT_SRC_PADDING))
LZVN_REQUIRES(dst != NULL && __CPROVER_w_ok(dst, dst_size))
LZVN_REQUIRES(!__CPROVER_same_object(src, dst))
LZVN_REQUIRES(z != NULL && __CPROVER_rw_ok(z, sizeof *z))
LZVN_REQUIRES(p != NULL && __CPROVER_rw_ok(p, sizeof *p))
LZVN_REQUIRES(!__CPROVER_same_object(dst, z))
LZVN_REQUIRES(!__CPROVER_same_object(dst, p))
LZVN_REQUIRES(!__CPROVER_same_object(src, z) || (const uint8_t *)src >= (const uint8_t *)z + sizeof(*z) || (const uint8_t *)src + src_size + LZVN_ZOPT_SRC_PADDING <= (const uint8_t *)z)
LZVN_REQUIRES(!__CPROVER_same_object(src, p) || (const uint8_t *)src >= (const uint8_t *)p + sizeof(*p) || (const uint8_t *)src + src_size + LZVN_ZOPT_SRC_PADDING <= (const uint8_t *)p)
LZVN_REQUIRES(!__CPROVER_same_object(z, p) || (const uint8_t *)z >= (const uint8_t *)p + sizeof(*p) || (const uint8_t *)z + sizeof(*z) <= (const uint8_t *)p)
LZVN_REQUIRES(z->max_tuples > 0)
LZVN_REQUIRES(z->tup_M != NULL && __CPROVER_rw_ok(z->tup_M, (size_t)z->max_tuples * sizeof *z->tup_M))
LZVN_REQUIRES(z->tup_L != NULL && __CPROVER_rw_ok(z->tup_L, (size_t)z->max_tuples * sizeof *z->tup_L))
LZVN_REQUIRES(src_size > (size_t)LZVN_ZOPT_BLOCK_SIZE ||
              LZVN_PARETO_STORAGE_OK(z, p, src_size))
// Unenforced: the body also writes the regions carved after *z and *p.
LZVN_ASSIGNS(__CPROVER_object_upto(dst, dst_size),
             __CPROVER_object_whole(z),
             __CPROVER_object_whole(p))
LZVN_ENSURES(__CPROVER_return_value <= dst_size)
LZVN_ENSURES(src_size > (size_t)LZVN_ZOPT_BLOCK_SIZE ==> __CPROVER_return_value == 0)
#endif
;

#endif // LZVN_ENCODE_BASE_H
