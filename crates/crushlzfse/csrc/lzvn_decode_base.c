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

#include "lzvn_decode_base.h"

#if !defined(HAVE_LABELS_AS_VALUES)
#  if defined(__GNUC__) || defined(__clang__)
#    define HAVE_LABELS_AS_VALUES 1
#  else
#    define HAVE_LABELS_AS_VALUES 0
#  endif
#endif

// Source and destination are each a (pointer, length) pair advanced together.
#define PTR_LEN_INC(_pointer, _length, _increment)                             \
  (_pointer += _increment, _length -= _increment)

// Commit positions at the start of an instruction.
#define UPDATE_GOOD                                                            \
  (state->src = src_ptr, state->dst = dst_ptr, state->d_prev = D)

#ifdef LZVN_PROOF
#define LZVN_REQUIRES(x)        __CPROVER_requires(x)
#define LZVN_ENSURES(x)         __CPROVER_ensures(x)
#define LZVN_ASSIGNS(...)       __CPROVER_assigns(__VA_ARGS__)
#define LZVN_LOOP_ASSIGNS(...)  __CPROVER_assigns(__VA_ARGS__)
#define LZVN_LOOP_INVARIANT(x)  __CPROVER_loop_invariant(x)
#define LZVN_LOOP_DECREASES(x)  __CPROVER_decreases(x)
#define LZVN_LOOP_ENTRY(x)      __CPROVER_loop_entry(x)
#define LZVN_OLD(x)             __CPROVER_old(x)
#define LZVN_OFFSET(p)          __CPROVER_POINTER_OFFSET(p)
#define LZVN_INLINE             static __attribute__((noinline))
#else
#define LZVN_REQUIRES(x)
#define LZVN_ENSURES(x)
#define LZVN_ASSIGNS(...)
#define LZVN_LOOP_ASSIGNS(...)
#define LZVN_LOOP_INVARIANT(x)
#define LZVN_LOOP_DECREASES(x)
#define LZVN_INLINE             static inline __attribute__((always_inline))
#endif

LZVN_INLINE
int lzvn_copy_match(unsigned char *dst_ptr, size_t dst_len, size_t D, size_t M, size_t *out_written)
#ifdef LZVN_PROOF
LZVN_REQUIRES(D >= 1)
LZVN_REQUIRES(LZVN_OFFSET(dst_ptr) >= D)
LZVN_REQUIRES(__CPROVER_r_ok(dst_ptr - D, D))
LZVN_REQUIRES(__CPROVER_w_ok(dst_ptr, dst_len))
LZVN_REQUIRES(__CPROVER_w_ok(out_written, sizeof *out_written))
LZVN_REQUIRES(!__CPROVER_same_object(out_written, dst_ptr))
LZVN_ASSIGNS(*out_written, __CPROVER_object_upto(dst_ptr, dst_len))
LZVN_ENSURES(__CPROVER_return_value == (M > dst_len ? 1 : 0))
LZVN_ENSURES(*out_written == (M > dst_len ? dst_len : M))
LZVN_ENSURES(*out_written <= M && *out_written <= dst_len)
#endif
{
  //  Copy semantics are byte-by-byte in increasing order: D < M replicates the
  //  last D bytes (D == 1 splats one byte), so wide copies must respect D.
  //  This is main's fast-path test. M <= 271 (the largest per-op match) keeps
  //  M + 7 from wrapping for an arbitrary M; every caller's M is a constant
  //  range within it, so the compiler drops that comparison.
  if (__builtin_expect(M <= 271 && dst_len >= M + 7 && D >= 8, 1)) {
    //  D >= 8 means 8-byte chunks never read bytes not yet written; the
    //  overshoot fits the dst_len >= M + 7 margin.
    for (size_t i = 0; i < M; i += 8)
#ifdef LZVN_PROOF
      LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst_ptr, dst_len))
      LZVN_LOOP_INVARIANT(i <= M + 7 && i % 8 == 0)
      LZVN_LOOP_DECREASES(M + 7 - i)
#endif
      memcpy(dst_ptr + i, dst_ptr + i - D, 8);
    *out_written = M;
    return 0;
  } else if (M <= dst_len) {
    const unsigned char *sp = dst_ptr - D;
    for (size_t i = 0; i < M; ++i)
#ifdef LZVN_PROOF
      LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst_ptr, dst_len))
      LZVN_LOOP_INVARIANT(i <= M)
      LZVN_LOOP_DECREASES(M - i)
#endif
      dst_ptr[i] = sp[i];
    *out_written = M;
    return 0;
  } else {
    const unsigned char *sp = dst_ptr - D;
    for (size_t i = 0; i < dst_len; ++i)
#ifdef LZVN_PROOF
      LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst_ptr, dst_len))
      LZVN_LOOP_INVARIANT(i <= dst_len)
      LZVN_LOOP_DECREASES(dst_len - i)
#endif
      dst_ptr[i] = sp[i];
    *out_written = dst_len;
    return 1;
  }
}

LZVN_INLINE
int lzvn_copy_literal(unsigned char *dst_ptr, size_t dst_len,
                      const unsigned char *src_ptr, size_t src_len,
                      size_t L, size_t *out_written)
#ifdef LZVN_PROOF
LZVN_REQUIRES(L <= src_len)
LZVN_REQUIRES(__CPROVER_r_ok(src_ptr, src_len))
LZVN_REQUIRES(__CPROVER_w_ok(dst_ptr, dst_len))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(src_ptr, src_len, dst_ptr, dst_len))
LZVN_REQUIRES(__CPROVER_w_ok(out_written, sizeof *out_written))
LZVN_REQUIRES(!__CPROVER_same_object(out_written, dst_ptr))
LZVN_REQUIRES(!__CPROVER_same_object(out_written, src_ptr))
LZVN_ASSIGNS(*out_written, __CPROVER_object_upto(dst_ptr, dst_len))
LZVN_ENSURES(__CPROVER_return_value == (L > dst_len ? 1 : 0))
LZVN_ENSURES(*out_written == (L > dst_len ? dst_len : L))
LZVN_ENSURES(*out_written <= L && *out_written <= dst_len)
#endif
{
  //  Main's fast-path test. L <= src_len (a precondition), and src_len
  //  bounds an object, so L + 7 cannot wrap.
  if (dst_len >= L + 7 && src_len >= L + 7) {
    for (size_t i = 0; i < L; i += 8)
#ifdef LZVN_PROOF
      LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst_ptr, dst_len))
      LZVN_LOOP_INVARIANT(i <= L + 7 && i % 8 == 0)
      LZVN_LOOP_DECREASES(L + 7 - i)
#endif
      memcpy(dst_ptr + i, src_ptr + i, 8);
    *out_written = L;
    return 0;
  } else if (L <= dst_len) {
    for (size_t i = 0; i < L; ++i)
#ifdef LZVN_PROOF
      LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst_ptr, dst_len))
      LZVN_LOOP_INVARIANT(i <= L)
      LZVN_LOOP_DECREASES(L - i)
#endif
      dst_ptr[i] = src_ptr[i];
    *out_written = L;
    return 0;
  } else {
    for (size_t i = 0; i < dst_len; ++i)
#ifdef LZVN_PROOF
      LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst_ptr, dst_len))
      LZVN_LOOP_INVARIANT(i <= dst_len)
      LZVN_LOOP_DECREASES(dst_len - i)
#endif
      dst_ptr[i] = src_ptr[i];
    *out_written = dst_len;
    return 1;
  }
}

LZVN_INLINE
int lzvn_copy_literal_short(unsigned char *dst_ptr, size_t dst_len,
                      const unsigned char *src_ptr, size_t src_len,
                      size_t L, size_t *out_written)
#ifdef LZVN_PROOF
LZVN_REQUIRES(L <= 3 && L <= src_len)
LZVN_REQUIRES(__CPROVER_r_ok(src_ptr, src_len))
LZVN_REQUIRES(__CPROVER_w_ok(dst_ptr, dst_len))
LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(src_ptr, src_len, dst_ptr, dst_len))
LZVN_REQUIRES(__CPROVER_w_ok(out_written, sizeof *out_written))
LZVN_REQUIRES(!__CPROVER_same_object(out_written, dst_ptr))
LZVN_REQUIRES(!__CPROVER_same_object(out_written, src_ptr))
LZVN_ASSIGNS(*out_written, __CPROVER_object_upto(dst_ptr, dst_len))
LZVN_ENSURES(__CPROVER_return_value == (L > dst_len ? 1 : 0))
LZVN_ENSURES(*out_written == (L > dst_len ? dst_len : L))
LZVN_ENSURES(*out_written <= L && *out_written <= dst_len)
#endif
{
  //  L is 0-3 for the literal of a literal+match op, so a 4-byte copy
  //  covers it when both buffers have room.
  if (__builtin_expect(dst_len >= 4 && src_len >= 4, 1)) {
    memcpy(dst_ptr, src_ptr, 4);
    *out_written = L;
    return 0;
  } else if (L <= dst_len) {
    for (size_t i = 0; i < L; ++i)
#ifdef LZVN_PROOF
      LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst_ptr, dst_len))
      LZVN_LOOP_INVARIANT(i <= L)
      LZVN_LOOP_DECREASES(L - i)
#endif
      dst_ptr[i] = src_ptr[i];
    *out_written = L;
    return 0;
  } else {
    for (size_t i = 0; i < dst_len; ++i)
#ifdef LZVN_PROOF
      LZVN_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst_ptr, dst_len))
      LZVN_LOOP_INVARIANT(i <= dst_len)
      LZVN_LOOP_DECREASES(dst_len - i)
#endif
      dst_ptr[i] = src_ptr[i];
    *out_written = dst_len;
    return 1;
  }
}

void lzvn_decode(lzvn_decoder_state *state)
#ifdef LZVN_PROOF
LZVN_DECODE_CONTRACT
#endif
{
#if HAVE_LABELS_AS_VALUES
  static const void *opc_tbl[256] = {
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&eos,   &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&nop,   &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&nop,   &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&udef,  &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,
      &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d,
      &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d,
      &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d,
      &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d, &&med_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&sml_d, &&pre_d, &&lrg_d,
      &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,
      &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,  &&udef,
      &&lrg_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l,
      &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l, &&sml_l,
      &&lrg_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m,
      &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m, &&sml_m};
#else
  enum lzvn_opc_class {
    LZVN_OPC_SML_D = 0,
    LZVN_OPC_MED_D,
    LZVN_OPC_LRG_D,
    LZVN_OPC_PRE_D,
    LZVN_OPC_SML_M,
    LZVN_OPC_LRG_M,
    LZVN_OPC_SML_L,
    LZVN_OPC_LRG_L,
    LZVN_OPC_EOS,
    LZVN_OPC_NOP,
    LZVN_OPC_UDEF
  };

  static const unsigned char opc_class[256] = {
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_EOS,   LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_NOP,   LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_NOP,   LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_UDEF,  LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_UDEF,  LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_UDEF,  LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_UDEF,  LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_UDEF,  LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,
    LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D,
    LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D,
    LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D,
    LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D, LZVN_OPC_MED_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_SML_D, LZVN_OPC_PRE_D, LZVN_OPC_LRG_D,
    LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,
    LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,  LZVN_OPC_UDEF,
    LZVN_OPC_LRG_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L,
    LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L, LZVN_OPC_SML_L,
    LZVN_OPC_LRG_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M,
    LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M, LZVN_OPC_SML_M
  };
#endif
  size_t src_len = state->src_end - state->src;
  size_t dst_len = state->dst_end - state->dst;
  if (src_len == 0 || dst_len == 0)
    return; // empty buffer

#if !HAVE_LABELS_AS_VALUES
  const unsigned char *const src = state->src;
  unsigned char *const dst = state->dst_begin;
  const size_t slen = (size_t)(state->src_end - src);
  const size_t dcap = (size_t)(state->dst_end - dst);

  size_t sp = 0;
  size_t dp = (size_t)(state->dst - dst);
  size_t D = state->d_prev;
  size_t new_d = D;
  size_t M;
  size_t L;
  size_t opc_len;
  size_t l_written = 0;
  size_t m_written = 0;
  _Bool eos = 0;
  _Bool truncated_mid_op = 0;

  unsigned char opc = src[0];

  for (;;)
#ifdef LZVN_PROOF
  LZVN_LOOP_ASSIGNS(sp, dp, D, new_d, M, L, opc_len, opc,
                    l_written, m_written, eos, truncated_mid_op,
                    __CPROVER_object_upto(dst, dcap))
  LZVN_LOOP_INVARIANT(sp < slen && dp <= dcap && D <= dp &&
                      sp >= LZVN_LOOP_ENTRY(sp) && dp >= LZVN_LOOP_ENTRY(dp) &&
                      opc == src[sp] && !eos && !truncated_mid_op)
  LZVN_LOOP_DECREASES(slen - sp)
#endif
  {
    opc_len = 0;
    L = 0;
    M = 0;
    new_d = D;
    switch (opc_class[opc]) {
    case LZVN_OPC_SML_D:
      opc_len = 2;
      L = (size_t)extract(opc, 6, 2);
      M = (size_t)extract(opc, 3, 3) + 3;
      if (slen - sp <= opc_len + L) goto loop_done;
      new_d = (size_t)extract(opc, 0, 3) << 8 | src[sp + 1];
      break;

    case LZVN_OPC_MED_D: {
      opc_len = 3;
      L = (size_t)extract(opc, 3, 2);
      if (slen - sp <= opc_len + L) goto loop_done;
      uint16_t opc23 = load2(&src[sp + 1]);
      M = (size_t)((extract(opc, 0, 3) << 2 | extract(opc23, 0, 2)) + 3);
      new_d = (size_t)extract(opc23, 2, 14);
      break;
    }

    case LZVN_OPC_LRG_D:
      opc_len = 3;
      L = (size_t)extract(opc, 6, 2);
      M = (size_t)extract(opc, 3, 3) + 3;
      if (slen - sp <= opc_len + L) goto loop_done;
      new_d = load2(&src[sp + 1]);
      break;

    case LZVN_OPC_PRE_D:
      opc_len = 1;
      L = (size_t)extract(opc, 6, 2);
      M = (size_t)extract(opc, 3, 3) + 3;
      if (slen - sp <= opc_len + L) goto loop_done;
      break;

    case LZVN_OPC_SML_M:
      opc_len = 1;
      if (slen - sp <= opc_len) goto loop_done;
      M = (size_t)extract(opc, 0, 4);
      break;

    case LZVN_OPC_LRG_M:
      opc_len = 2;
      if (slen - sp <= opc_len) goto loop_done;
      M = src[sp + 1] + 16;
      break;

    case LZVN_OPC_SML_L:
      opc_len = 1;
      L = (size_t)extract(opc, 0, 4);
      if (slen - sp <= opc_len + L) goto loop_done;
      break;

    case LZVN_OPC_LRG_L:
      opc_len = 2;
      if (slen - sp <= 2) goto loop_done;
      L = src[sp + 1] + 16;
      if (slen - sp <= opc_len + L) goto loop_done;
      break;

    case LZVN_OPC_NOP:
      opc_len = 1;
      if (slen - sp <= opc_len) goto loop_done;
      break;

    case LZVN_OPC_EOS:
      opc_len = 8;
      if (slen - sp < opc_len) goto loop_done;
      sp += opc_len;
      eos = 1;
      goto loop_done;

    default:
      goto loop_done;
    }

    sp += opc_len;
    if (L > 0) {
      if (lzvn_copy_literal(dst + dp, dcap - dp, src + sp, slen - sp, L, &l_written)) {
        sp += l_written;
        dp += l_written;
        truncated_mid_op = 1;
        goto loop_done;
      }
      dp += L;
      sp += L;
    }
    if (M > 0) {
      if (new_d > dp || new_d == 0)
        goto loop_done;
      D = new_d;
      if (lzvn_copy_match(dst + dp, dcap - dp, D, M, &m_written)) {
        dp += m_written;
        truncated_mid_op = 1;
        goto loop_done;
      }
      dp += M;
    }
    if (sp == slen)
      goto loop_done;
    opc = src[sp];
    continue;
  }

loop_done:
  state->src = src + sp;
  state->dst = dst + dp;
  state->d_prev = D;
  if (eos)
    state->end_of_stream = 1;
  if (truncated_mid_op)
    state->truncated_mid_op = 1;
#else
  const unsigned char *src_ptr = state->src;
  unsigned char *dst_ptr = state->dst;
  size_t D = state->d_prev;
  size_t M;
  size_t L;
  size_t opc_len;
  size_t l_written = 0;
  size_t m_written = 0;
  unsigned char opc = src_ptr[0];
#ifdef LZVN_THREADED_PROOF
  /* Normalize only the three computed-goto backedges to this loop head.
   * The same computed-goto table and production label bodies execute. No
   * handler, byte operation, bound check or state update is substituted. */
  for (;;)
    LZVN_LOOP_ASSIGNS(src_ptr, dst_ptr, src_len, dst_len, D, M, L,
                      opc_len, opc, l_written, m_written,
                      state->src, state->dst, state->d_prev,
                      state->end_of_stream, state->truncated_mid_op,
                      __CPROVER_object_upto(state->dst_begin,
                        (size_t)(LZVN_OFFSET(state->dst_end) - LZVN_OFFSET(state->dst_begin))))
    LZVN_LOOP_INVARIANT(__CPROVER_same_object(src_ptr, state->src_end) &&
                        __CPROVER_same_object(dst_ptr, state->dst_begin))
    LZVN_LOOP_INVARIANT(LZVN_OFFSET(src_ptr) >= LZVN_OFFSET(LZVN_LOOP_ENTRY(src_ptr)) &&
                        LZVN_OFFSET(src_ptr) < LZVN_OFFSET(state->src_end))
    LZVN_LOOP_INVARIANT(LZVN_OFFSET(dst_ptr) >= LZVN_OFFSET(LZVN_LOOP_ENTRY(dst_ptr)) &&
                        LZVN_OFFSET(dst_ptr) <= LZVN_OFFSET(state->dst_end))
    LZVN_LOOP_INVARIANT(src_len == (size_t)(state->src_end - src_ptr) &&
                        dst_len == (size_t)(state->dst_end - dst_ptr))
    LZVN_LOOP_INVARIANT(D <= (size_t)(dst_ptr - state->dst_begin) && opc == src_ptr[0])
    LZVN_LOOP_INVARIANT(__CPROVER_same_object(state->src, src_ptr) &&
                        LZVN_OFFSET(state->src) >= LZVN_OFFSET(LZVN_LOOP_ENTRY(src_ptr)) &&
                        LZVN_OFFSET(state->src) <= LZVN_OFFSET(src_ptr))
    LZVN_LOOP_INVARIANT(__CPROVER_same_object(state->dst, dst_ptr) &&
                        LZVN_OFFSET(state->dst) >= LZVN_OFFSET(LZVN_LOOP_ENTRY(dst_ptr)) &&
                        LZVN_OFFSET(state->dst) <= LZVN_OFFSET(dst_ptr))
    LZVN_LOOP_INVARIANT(state->d_prev <= (size_t)(state->dst - state->dst_begin))
    LZVN_LOOP_INVARIANT(state->end_of_stream == 0 || state->end_of_stream == 1)
    LZVN_LOOP_INVARIANT(state->truncated_mid_op == 0 || state->truncated_mid_op == 1)
    LZVN_LOOP_DECREASES(src_len)
  {
#endif
  goto *opc_tbl[opc];
//  sml_d, med_d, lrg_d and pre_d each carry a literal and a match: each label
//  decodes its header, checks the source holds the op plus one byte of the
//  next, and jumps to the shared copy.
sml_d:
  UPDATE_GOOD;
  //  LLMMMDDD DDDDDDDD LITERAL
  opc_len = 2;
  L = (size_t)extract(opc, 6, 2);
  M = (size_t)extract(opc, 3, 3) + 3;
  if (src_len <= opc_len + L)
    return; // source truncated
  D = (size_t)extract(opc, 0, 3) << 8 | src_ptr[1];
  goto copy_literal_and_match;

med_d:
  UPDATE_GOOD;
  //  101LLMMM DDDDDDMM DDDDDDDD LITERAL
  opc_len = 3;
  L = (size_t)extract(opc, 3, 2);
  if (src_len <= opc_len + L)
    return; // source truncated
  uint16_t opc23 = load2(&src_ptr[1]);
  M = (size_t)((extract(opc, 0, 3) << 2 | extract(opc23, 0, 2)) + 3);
  D = (size_t)extract(opc23, 2, 14);
  goto copy_literal_and_match;

lrg_d:
  UPDATE_GOOD;
  //  LLMMM111 DDDDDDDD DDDDDDDD LITERAL, distances up to 65535
  opc_len = 3;
  L = (size_t)extract(opc, 6, 2);
  M = (size_t)extract(opc, 3, 3) + 3;
  if (src_len <= opc_len + L)
    return; // source truncated
  D = load2(&src_ptr[1]);
  goto copy_literal_and_match;

pre_d:
  UPDATE_GOOD;
  //  LLMMM110 LITERAL, distance repeated from the previous match
  opc_len = 1;
  L = (size_t)extract(opc, 6, 2);
  M = (size_t)extract(opc, 3, 3) + 3;
  if (src_len <= opc_len + L)
    return; // source truncated
  goto copy_literal_and_match;

copy_literal_and_match:
  PTR_LEN_INC(src_ptr, src_len, opc_len);
  if (lzvn_copy_literal_short(dst_ptr, dst_len, src_ptr, src_len, L, &l_written)) {
    state->src = src_ptr + l_written;
    state->dst = dst_ptr + l_written;
    state->truncated_mid_op = 1;
    return; // destination truncated
  }
  PTR_LEN_INC(dst_ptr, dst_len, L);
  PTR_LEN_INC(src_ptr, src_len, L);
  if (D > (size_t)(dst_ptr - state->dst_begin) || D == 0)
    goto invalid_match_distance;
  goto copy_match_body;

// Match-only opcodes: sml_m and lrg_m reuse the previous distance.
sml_m:
  UPDATE_GOOD;
  //  1111MMMM
  opc_len = 1;
  if (src_len <= opc_len)
    return; // source truncated
  M = (size_t)extract(opc, 0, 4);
  PTR_LEN_INC(src_ptr, src_len, opc_len);
  goto copy_match;

lrg_m:
  UPDATE_GOOD;
  //  11110000 MMMMMMMM, M biased by 16: [16, 271]
  opc_len = 2;
  if (src_len <= opc_len)
    return; // source truncated
  M = src_ptr[1] + 16;
  PTR_LEN_INC(src_ptr, src_len, opc_len);
  goto copy_match;

copy_match:
  //  D <= dst_ptr - dst_begin holds throughout (state contract and every
  //  update above), so a match-only op need only reject D == 0: no match
  //  has set a distance yet.
  if (D == 0)
    goto invalid_match_distance;
copy_match_body:
  if (lzvn_copy_match(dst_ptr, dst_len, D, M, &m_written)) {
    state->src = src_ptr;
    state->dst = dst_ptr + m_written;
    state->truncated_mid_op = 1;
    return; // destination truncated
  }
  PTR_LEN_INC(dst_ptr, dst_len, M);
  opc = src_ptr[0];
#ifdef LZVN_THREADED_PROOF
  continue;
#elif HAVE_LABELS_AS_VALUES
  goto *opc_tbl[opc];
#else
  continue;
#endif

// Literal-only opcodes; D is preserved across them.
sml_l:
  UPDATE_GOOD;
  //  1110LLLL LITERAL
  opc_len = 1;
  L = (size_t)extract(opc, 0, 4);
  goto copy_literal;

lrg_l:
  UPDATE_GOOD;
  //  11100000 LLLLLLLL LITERAL, L biased by 16: [16, 271]
  opc_len = 2;
  if (src_len <= 2)
    return; // source truncated
  L = src_ptr[1] + 16;
  goto copy_literal;

copy_literal:
  if (src_len <= opc_len + L)
    return; // source truncated
  PTR_LEN_INC(src_ptr, src_len, opc_len);
  if (lzvn_copy_literal(dst_ptr, dst_len, src_ptr, src_len, L, &l_written)) {
    state->src = src_ptr + l_written;
    state->dst = dst_ptr + l_written;
    state->truncated_mid_op = 1;
    return; // destination truncated
  }
  PTR_LEN_INC(dst_ptr, dst_len, L);
  PTR_LEN_INC(src_ptr, src_len, L);
  opc = src_ptr[0];
#ifdef LZVN_THREADED_PROOF
  continue;
#elif HAVE_LABELS_AS_VALUES
  goto *opc_tbl[opc];
#else
  continue;
#endif

// Other opcodes
nop:
  UPDATE_GOOD;
  opc_len = 1;
  if (src_len <= opc_len)
    return; // source truncated
  PTR_LEN_INC(src_ptr, src_len, opc_len);
  opc = src_ptr[0];
#ifdef LZVN_THREADED_PROOF
  continue;
#elif HAVE_LABELS_AS_VALUES
  goto *opc_tbl[opc];
#else
  continue;
#endif

eos:
  opc_len = 8;
  if (src_len < opc_len)
    return; // source truncated (here we don't need an extra byte for next op
            // code)
  PTR_LEN_INC(src_ptr, src_len, opc_len);
  state->end_of_stream = 1;
  UPDATE_GOOD;
  return; // end-of-stream

// Return on error
udef:
invalid_match_distance:

  return; // we already updated state
#ifdef LZVN_THREADED_PROOF
  }
#endif
#endif
}

// API entry points

/*! Decodes a complete LZVN bitstream into dst; stops when dst fills, src is
 * exhausted, or end-of-stream is decoded. Returns bytes written. */
size_t lzvn_decode_buffer(void *__restrict dst, size_t dst_size,
                          const void *__restrict src, size_t src_size)
#ifdef LZVN_PROOF
LZVN_REQUIRES(src == NULL || __CPROVER_r_ok(src, src_size))
LZVN_REQUIRES(dst == NULL || __CPROVER_w_ok(dst, dst_size))
LZVN_REQUIRES(src == NULL || dst == NULL || LZVN_PROOF_RANGES_DISJOINT(src, src_size, dst, dst_size))
LZVN_ASSIGNS(dst != NULL: __CPROVER_object_upto(dst, dst_size))
LZVN_ENSURES(__CPROVER_return_value <= dst_size)
#endif
{
  if (dst == NULL || src == NULL || dst_size == 0 || src_size == 0)
    return 0;

  lzvn_decoder_state state;
  memset(&state, 0, sizeof(state));
  state.src = (const unsigned char *)src;
  state.src_end = (const unsigned char *)src + src_size;
  state.dst_begin = (unsigned char *)dst;
  state.dst = (unsigned char *)dst;
  state.dst_end = (unsigned char *)dst + dst_size;

  lzvn_decode(&state);

  return (size_t)(state.dst - (unsigned char *)dst);
}
