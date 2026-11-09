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


// LZVN low-level decoder

#ifndef LZVN_DECODE_BASE_H
#define LZVN_DECODE_BASE_H

#include "lzfse_internal.h"

typedef struct {
  const unsigned char *src;
  const unsigned char *src_end;

  unsigned char *dst;
  unsigned char *dst_begin;
  unsigned char *dst_end;

  // Distance of the last match, or 0.
  lzvn_offset d_prev;

  int end_of_stream;

  // Set when destination room ran out mid-literal or mid-match, so src/dst
  // stopped partway through an op rather than cleanly on an op boundary.
  // Not a resumable position: a caller wanting more output re-decodes from
  // the start with a larger destination, same as every caller here does.
  int truncated_mid_op;

} lzvn_decoder_state;

/*! Decode source to destination, updating state (src, dst, d_prev). Does not
 *  resume a call truncated by running out of source or destination room:
 *  src/dst mark how far it got, not a position a second call can continue
 *  from mid-op. */
/* The single lzvn_decode contract. lzvn_decode_threaded enforces it on the
 * shipping computed-goto body, lzvn_decode on the portable switch; every
 * caller target replaces the call with it. */
#if defined(LZVN_PROOF) || defined(LZFSE_PROOF)
#define LZVN_DECODE_OFF(p) __CPROVER_POINTER_OFFSET(p)
#ifndef LZVN_PROOF_RANGES_DISJOINT
#define LZVN_PROOF_RANGES_DISJOINT(a, a_size, b, b_size) \
  ((a_size) == 0 || (b_size) == 0 || \
   !__CPROVER_same_object((a), (b)) || \
   (__CPROVER_POINTER_OFFSET(a) <= __CPROVER_POINTER_OFFSET(b) \
      ? (size_t)(a_size) <= (size_t)(__CPROVER_POINTER_OFFSET(b) - __CPROVER_POINTER_OFFSET(a)) \
      : (size_t)(b_size) <= (size_t)(__CPROVER_POINTER_OFFSET(a) - __CPROVER_POINTER_OFFSET(b))))
#endif
#define LZVN_DECODE_CONTRACT                                                   \
  __CPROVER_requires(__CPROVER_rw_ok(state, sizeof *state))                    \
  __CPROVER_requires(LZVN_DECODE_OFF(state->src) <=                            \
                     LZVN_DECODE_OFF(state->src_end))                          \
  __CPROVER_requires(__CPROVER_r_ok(state->src,                                \
      (size_t)(LZVN_DECODE_OFF(state->src_end) - LZVN_DECODE_OFF(state->src)))) \
  __CPROVER_requires(LZVN_DECODE_OFF(state->dst_begin) <=                      \
                         LZVN_DECODE_OFF(state->dst) &&                        \
                     LZVN_DECODE_OFF(state->dst) <=                            \
                         LZVN_DECODE_OFF(state->dst_end))                      \
  __CPROVER_requires(__CPROVER_rw_ok(state->dst_begin,                         \
      (size_t)(LZVN_DECODE_OFF(state->dst_end) -                               \
               LZVN_DECODE_OFF(state->dst_begin))))                            \
  __CPROVER_requires(__CPROVER_same_object(state->dst_begin, state->dst_end))  \
  __CPROVER_requires(__CPROVER_same_object(state->dst_begin, state->dst))      \
  __CPROVER_requires(__CPROVER_same_object(state->src, state->src_end))        \
  __CPROVER_requires(LZVN_PROOF_RANGES_DISJOINT(state->src,                   \
      (size_t)(LZVN_DECODE_OFF(state->src_end) - LZVN_DECODE_OFF(state->src)), \
      state->dst_begin,                                                         \
      (size_t)(LZVN_DECODE_OFF(state->dst_end) - LZVN_DECODE_OFF(state->dst_begin)))) \
  __CPROVER_requires(!__CPROVER_same_object(state, state->dst_begin))          \
  __CPROVER_requires(!__CPROVER_same_object(state, state->src))                \
  __CPROVER_requires(state->d_prev >= 0 && (size_t)state->d_prev <=           \
                     (size_t)(LZVN_DECODE_OFF(state->dst) -                    \
                         LZVN_DECODE_OFF(state->dst_begin)))                   \
  __CPROVER_requires(state->end_of_stream == 0 || state->end_of_stream == 1)   \
  __CPROVER_requires(state->truncated_mid_op == 0 ||                           \
                     state->truncated_mid_op == 1)                             \
  __CPROVER_assigns(state->src, state->dst, state->d_prev,                     \
      state->end_of_stream, state->truncated_mid_op,                           \
      __CPROVER_object_upto(state->dst_begin,                                  \
          (size_t)(LZVN_DECODE_OFF(state->dst_end) -                           \
                   LZVN_DECODE_OFF(state->dst_begin))))                        \
  __CPROVER_ensures(__CPROVER_same_object(state->src, state->src_end))         \
  __CPROVER_ensures(LZVN_DECODE_OFF(state->src) >=                             \
                    LZVN_DECODE_OFF(__CPROVER_old(state->src)))                \
  __CPROVER_ensures(LZVN_DECODE_OFF(state->src) <=                             \
                    LZVN_DECODE_OFF(state->src_end))                           \
  __CPROVER_ensures(__CPROVER_same_object(state->dst, state->dst_begin))       \
  __CPROVER_ensures(LZVN_DECODE_OFF(state->dst) >=                             \
                    LZVN_DECODE_OFF(__CPROVER_old(state->dst)))                \
  __CPROVER_ensures(LZVN_DECODE_OFF(state->dst) <=                             \
                    LZVN_DECODE_OFF(state->dst_end))                           \
  __CPROVER_ensures(state->dst_begin == __CPROVER_old(state->dst_begin))       \
  __CPROVER_ensures(state->dst_end == __CPROVER_old(state->dst_end))           \
  __CPROVER_ensures(state->src_end == __CPROVER_old(state->src_end))           \
  __CPROVER_ensures(state->d_prev >= 0 && (size_t)state->d_prev <=            \
                    (size_t)(LZVN_DECODE_OFF(state->dst) -                     \
                        LZVN_DECODE_OFF(state->dst_begin)))                    \
  __CPROVER_ensures(state->end_of_stream == 0 || state->end_of_stream == 1)    \
  __CPROVER_ensures(state->truncated_mid_op == 0 ||                            \
                    state->truncated_mid_op == 1)
#endif
#if defined(LZFSE_PROOF) && !defined(LZVN_PROOF)
void lzvn_decode(lzvn_decoder_state *state) LZVN_DECODE_CONTRACT;
#else
void lzvn_decode(lzvn_decoder_state *state);
#endif

#endif // LZVN_DECODE_BASE_H
