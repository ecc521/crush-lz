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


//  The decoder's two hot loops, the literal FSE loop and the LMD loop.
//  lzfse_decode_base.c includes this file once per instruction-set variant,
//  so there is no include guard and every name is spelled through
//  LZFSE_HOT(). The includer defines LZFSE_HOT_SUFFIX (appended to each
//  name) and LZFSE_HOT_ATTR (function attributes, where a target(...) goes)
//  before including, and undefines them after. Everything called from here
//  is static inline, so a variant's target features reach the inlined body.

#if !defined(LZFSE_HOT_SUFFIX) || !defined(LZFSE_HOT_ATTR_DEFINED)
#error "lzfse_decode_hot.h is a template; define LZFSE_HOT_SUFFIX/LZFSE_HOT_ATTR first"
#endif

#define LZFSE_HOT_CAT_(a, b) a##b
#define LZFSE_HOT_CAT(a, b) LZFSE_HOT_CAT_(a, b)
#define LZFSE_HOT(name) LZFSE_HOT_CAT(name, LZFSE_HOT_SUFFIX)

/*! @abstract Decode the block's literal array into bs->literals, advancing
 *  s->src past the literal payload. Returns 0, or -1 on a malformed stream. */
static LZFSE_HOT_ATTR int
LZFSE_HOT(lzfse_decode_literals)(lzfse_decoder_state *s,
                                 const lzfse_compressed_block_header_v1 *header1,
                                 lzfse_compressed_block_decoder_state *bs) {
  fse_in_stream in;
  //  Not s->src_begin (the whole frame): a block's own header is its
  //  legitimate lookback, not an unrelated earlier (or, for a resumed
  //  decode, preceding) block's — the same bound lzfse_decode_lmd's
  //  src_start relies on. A strictness choice, not a memory-safety one —
  //  both bounds stay inside the caller's buffer, and the reference decoder
  //  this project derives from (still shipping in Apple's libcompression)
  //  uses the looser src_begin bound here too. The accumulator holds at
  //  most 63 bits of lookahead, so the lowest byte this reads is 8 bytes
  //  before the payload, which is always this block's own header.
  const uint8_t *buf_start = s->src - 8;
  s->src += header1->n_literal_payload_bytes; // skip literal payload
  const uint8_t *buf = s->src; // read bits backwards from the end
  if (fse_in_init(&in, header1->literal_bits, &buf, buf_start) != 0)
    return -1;

  uint32_t state0 = header1->literal_state[0];
  uint32_t state1 = header1->literal_state[1];
  uint32_t state2 = header1->literal_state[2];
  uint32_t state3 = header1->literal_state[3];

  //  buf_start sits at least 8 bytes into this block's header, so the
  //  lookahead load below buf never leaves the input.
  uint64_t next = FSE_LOOKAHEAD_REFILL ? load8(buf - 8) : 0;
  uint8_t *lp = bs->literals;
  uint8_t *const lp_end = lp + header1->n_literals;
  const int32_t *const ltab = bs->literal_decoder;
#if FSE_IOSTREAM_64 && !defined(LZFSE_REDUCED_PROOF)
  //  Each flush moves buf down by at most 8 bytes, so with 8*G bytes of
  //  payload below it G groups need no bound check; the checked loop below
  //  finishes the rest.
  {
    size_t safe_groups = (size_t)(buf - buf_start) / 8;
    // Clamp the byte span before forming a pointer into the literal array.
    // A large encoded payload can otherwise put that pointer far beyond it.
    size_t safe_bytes = 4 * safe_groups;
    size_t literal_bytes = (size_t)(lp_end - lp);
    if (safe_bytes > literal_bytes)
      safe_bytes = literal_bytes;
    uint8_t *lp_safe = lp + safe_bytes;
    for (; lp < lp_safe; lp += 4) {
#if FSE_LOOKAHEAD_REFILL
      fse_in_flush_next(&in, &buf, buf_start, &next);
#else
      fse_in_flush64_unchecked(&in, &buf);
#endif
      uint32_t w = fse_decode_u32(&state0, ltab, &in);
      w |= (uint32_t)fse_decode_u32(&state1, ltab, &in) << 8;
      w |= (uint32_t)fse_decode_u32(&state2, ltab, &in) << 16;
      w |= (uint32_t)fse_decode_u32(&state3, ltab, &in) << 24;
      store4(lp, w);
    }
  }
#endif
  //  Four literals per step. A block whose n_literals is not a multiple of
  //  four writes up to three more, inside the copy margin.
  for (; lp < lp_end; lp += 4)
#ifdef LZFSE_REDUCED_PROOF
    LZFSE_LOOP_ASSIGNS(lp, in, buf, next, state0, state1, state2, state3,
                       __CPROVER_object_upto(bs->literals, sizeof bs->literals))
    LZFSE_LOOP_INVARIANT(__CPROVER_same_object(lp, bs->literals) &&
                         LZFSE_OFFSET(lp) >= LZFSE_OFFSET(bs->literals) &&
                         LZFSE_OFFSET(lp) <= LZFSE_OFFSET(lp_end) &&
                         ((LZFSE_OFFSET(lp) - LZFSE_OFFSET(bs->literals)) & 3) == 0 &&
                         __CPROVER_same_object(buf, buf_start) &&
                         LZFSE_OFFSET(buf) >= LZFSE_OFFSET(buf_start) &&
                         LZFSE_OFFSET(buf) <= LZFSE_OFFSET(s->src) &&
                         in.accum_nbits >= 0 && in.accum_nbits < 64)
    LZFSE_LOOP_DECREASES(LZFSE_OFFSET(lp_end) - LZFSE_OFFSET(lp))
#endif
  {
#ifdef LZFSE_REDUCED_PROOF
    if (lp + 4 > lp_end)
      return -1;
#endif
#if FSE_IOSTREAM_64
    if (fse_in_flush_next(&in, &buf, buf_start, &next) != 0)
      return -1; // [57, 64] bits
    uint32_t w = fse_decode_u32(&state0, ltab, &in);           // 10b max
    w |= (uint32_t)fse_decode_u32(&state1, ltab, &in) << 8;    // 10b max
    w |= (uint32_t)fse_decode_u32(&state2, ltab, &in) << 16;   // 10b max
    w |= (uint32_t)fse_decode_u32(&state3, ltab, &in) << 24;   // 10b max
    store4(lp, w);
#else
    if (fse_in_flush(&in, &buf, buf_start) != 0)
      return -1; // [25, 23] bits
    lp[0] = fse_decode_u32(&state0, ltab, &in); // 10b max
    lp[1] = fse_decode_u32(&state1, ltab, &in); // 10b max
    if (fse_in_flush(&in, &buf, buf_start) != 0)
      return -1; // [25, 23] bits
    lp[2] = fse_decode_u32(&state2, ltab, &in); // 10b max
    lp[3] = fse_decode_u32(&state3, ltab, &in); // 10b max
#endif
  }

  //  The LMD loop's wide copies read up to LZFSE_DECODE_COPY_MARGIN bytes
  //  past the last literal; zeroed here because the decoder state is not
  //  zeroed as a whole (see crushlzfse_decode_buffer).
  memset(bs->literals + header1->n_literals, 0, LZFSE_DECODE_COPY_MARGIN);
  bs->current_literal = bs->literals;
  return 0;
}

static LZFSE_HOT_ATTR __attribute__((noinline)) int
LZFSE_HOT(lzfse_decode_lmd)(lzfse_decoder_state *s) {
  lzfse_compressed_block_decoder_state *bs = &(s->compressed_lzfse_block_state);
  const fse_value_decoder_entry *const lmd_decoder = bs->lmd_decoder;
  uint32_t l_state = bs->l_state;
  uint32_t m_state = bs->m_state;
  uint32_t d_state = bs->d_state;
  fse_in_stream in = bs->lmd_in_stream;
  //  s->src is this block's own LMD payload start for its whole lifetime,
  //  and exactly the bound its initial fse_in_init call used — a resumed
  //  call must check against the same bound.
  const uint8_t *src_start = s->src;
  const uint8_t *src = s->src + bs->lmd_in_buf;
  const uint8_t *lit = bs->current_literal;
  //  One past the last literal byte a tuple may start at.
  //  The block declared n_literals literal bytes, and only those were
  //  written; a tuple ending past them is malformed.
  const uint8_t *const lit_end = bs->literals + bs->n_literals + 1;
  uint8_t *dst = s->dst;
  //  Local copy so it can live in a register: writes through dst may alias s.
  const uint8_t *const dst_begin = s->dst_begin;
  uint32_t symbols = bs->n_matches;
  //  L and M are non-negative (vbase >= 0), so ptrdiff_t needs no sign
  //  extension and L + M cannot overflow.
  ptrdiff_t L = bs->l_value;
  ptrdiff_t M = bs->m_value;
  int32_t D = bs->d_value;

  assert(l_state < LZFSE_ENCODE_L_STATES);
  assert(m_state < LZFSE_ENCODE_M_STATES);
  assert(d_state < LZFSE_ENCODE_D_STATES);

  //  Remaining destination bytes minus LZFSE_DECODE_COPY_MARGIN, so the fast
  //  path may overshoot its copies. May go negative near the end of the
  //  buffer; the careful path handles that.
  ptrdiff_t remaining_bytes = s->dst_end - dst - LZFSE_DECODE_COPY_MARGIN;

  //  Tuples that cannot reach lit_end, so the bound below is skipped while it
  //  lasts. Each tuple adds at most LZFSE_DECODE_L_MAX_VALUE; the -1 keeps
  //  `lit` strictly under lit_end, as the checked form does.
  ptrdiff_t lit_budget = 0;

  //  A pending L or M means decoding was interrupted for more output space;
  //  finish that symbol first.
  //  The LMD payload follows this block's header and literal payload, so
  //  the lookahead load below src_start stays inside the input.
  uint64_t next = FSE_LOOKAHEAD_REFILL ? load8(src - 8) : 0;
#if !defined(LZFSE_REDUCED_PROOF) || defined(LZFSE_LMD_RESUME_PROOF)
  if (L || M)
    goto ExecuteMatch;
#endif

  //  No CBMC loop contract in the shipping configuration: the goto above
  //  enters the body, so the loop is not natural.
  while (symbols > 0)
#ifdef LZFSE_REDUCED_PROOF
  LZFSE_LOOP_ASSIGNS(symbols, L, M, D, remaining_bytes, lit, dst, src, in, next, l_state, m_state, d_state)
  LZFSE_LOOP_INVARIANT(symbols <= bs->n_matches)
  LZFSE_LOOP_INVARIANT(__CPROVER_same_object(dst, s->dst_begin))
  LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(dst) >= LZFSE_OFFSET(s->dst_begin))
  LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(dst) >= LZFSE_OFFSET(s->dst))
  LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(dst) <= LZFSE_OFFSET(s->dst_end))
  LZFSE_LOOP_INVARIANT(__CPROVER_same_object(lit, bs->literals))
  LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(lit) >= LZFSE_OFFSET(bs->literals))
  LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(lit) <= LZFSE_OFFSET(lit_end))
  LZFSE_LOOP_INVARIANT(__CPROVER_same_object(src, src_start))
  LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(src) >= LZFSE_OFFSET(src_start))
  LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(src) <= LZFSE_OFFSET(s->src + bs->lmd_in_buf))
  LZFSE_LOOP_INVARIANT(remaining_bytes == (ptrdiff_t)(LZFSE_OFFSET(s->dst_end) - LZFSE_OFFSET(dst)) - LZFSE_DECODE_COPY_MARGIN)
  LZFSE_LOOP_INVARIANT(in.accum_nbits >= 0 && in.accum_nbits < 64)
  LZFSE_LOOP_INVARIANT(l_state < LZFSE_ENCODE_L_STATES)
  LZFSE_LOOP_INVARIANT(m_state < LZFSE_ENCODE_M_STATES)
  LZFSE_LOOP_INVARIANT(d_state < LZFSE_ENCODE_D_STATES)
  LZFSE_LOOP_DECREASES(symbols)
#endif
  {
    int res;
    res = fse_in_flush_next(&in, &src, src_start, &next);
    if (res) {
      return LZFSE_STATUS_ERROR;
    }
    L = fse_value_decode_u32(&l_state, lmd_decoder, LZFSE_L_DECODER_OFFSET, &in);
    assert(l_state < LZFSE_ENCODE_L_STATES);
#ifdef LZFSE_REDUCED_PROOF
    if ((size_t)L >= (size_t)(lit_end - lit)) {
      return LZFSE_STATUS_ERROR;
    }
#else
    if (__builtin_expect(lit_budget > 0, 1)) {
      lit_budget--;
    } else {
      if ((size_t)L >= (size_t)(lit_end - lit)) {
        return LZFSE_STATUS_ERROR;
      }
      lit_budget = (lit_end - (lit + L) - 1) / LZFSE_DECODE_L_MAX_VALUE;
    }
#endif
    res = fse_in_flush2(&in, &src, src_start);
    if (res) {
      return LZFSE_STATUS_ERROR;
    }
    M = fse_value_decode_u32(&m_state, lmd_decoder, LZFSE_M_DECODER_OFFSET, &in);
    assert(m_state < LZFSE_ENCODE_M_STATES);
    res = fse_in_flush2(&in, &src, src_start);
    if (res) {
      return LZFSE_STATUS_ERROR;
    }
    uint32_t new_d = fse_value_decode_u32(&d_state, lmd_decoder, LZFSE_D_DECODER_OFFSET, &in);
    assert(d_state < LZFSE_ENCODE_D_STATES);
    D = new_d ? (int32_t)new_d : D;
    symbols--;

#if !defined(LZFSE_REDUCED_PROOF) || defined(LZFSE_LMD_RESUME_PROOF)
  ExecuteMatch:
#endif
    //  D past dst_begin would read outside the destination buffer, and
    //  D <= 0 would copy without progress. Sign-extended, D - 1 wraps past
    //  any span for D <= 0, so one compare rejects both.
    if ((uint64_t)((int64_t)D - 1) >= (uint64_t)(dst - dst_begin) + (uint64_t)L)
      return LZFSE_STATUS_ERROR;

    if (L + M <= remaining_bytes) {
      //  Room for wide copies of both the literal and the match.
      remaining_bytes -= L + M;
#if defined(LZFSE_REDUCED_PROOF) && !defined(LZFSE_LMD_RESUME_PROOF)
      __CPROVER_assert(__CPROVER_r_ok(lit, (size_t)(L + LZFSE_DECODE_COPY_MARGIN)), "copy_literal_wide lit read");
      __CPROVER_assert(__CPROVER_w_ok(dst, (size_t)(L + LZFSE_DECODE_COPY_MARGIN)), "copy_literal_wide dst write");
#else
      copy_literal_wide(dst, lit, L);
#endif
      dst += L;
      lit += L;
#if defined(LZFSE_REDUCED_PROOF) && !defined(LZFSE_LMD_RESUME_PROOF)
      __CPROVER_assert(D >= 1, "lzfse_copy_match D >= 1");
      __CPROVER_assert(M >= 0, "lzfse_copy_match M >= 0");
      __CPROVER_assert(LZFSE_OFFSET(dst) >= (size_t)D, "lzfse_copy_match dst offset >= D");
      __CPROVER_assert(__CPROVER_r_ok(dst - D, (size_t)D), "lzfse_copy_match src read");
      __CPROVER_assert(__CPROVER_w_ok(dst, (size_t)(M + LZFSE_DECODE_COPY_MARGIN)), "lzfse_copy_match dst write");
#else
      lzfse_copy_match(dst, D, M);
#endif
      dst += M;
    }

    else {
      //  Near the end of the buffer: restore the true remaining length and
      //  copy byte by byte.
      remaining_bytes += LZFSE_DECODE_COPY_MARGIN;
      if (L <= remaining_bytes) {
#if defined(LZFSE_REDUCED_PROOF) && !defined(LZFSE_LMD_RESUME_PROOF)
        __CPROVER_assert(__CPROVER_r_ok(lit, (size_t)L), "copy_literal_bytes lit read");
        __CPROVER_assert(__CPROVER_w_ok(dst, (size_t)L), "copy_literal_bytes dst write");
#else
        lzfse_copy_literal_bytes(dst, lit, L);
#endif
        dst += L;
        lit += L;
        remaining_bytes -= L;
        L = 0;
      }
      //  Not enough room for the literal: copy what fits, keep the rest
      //  pending, and report the destination full.
      else {
#if defined(LZFSE_REDUCED_PROOF) && !defined(LZFSE_LMD_RESUME_PROOF)
        __CPROVER_assert(__CPROVER_r_ok(lit, (size_t)remaining_bytes), "copy_literal_bytes lit read partial");
        __CPROVER_assert(__CPROVER_w_ok(dst, (size_t)remaining_bytes), "copy_literal_bytes dst write partial");
#else
        lzfse_copy_literal_bytes(dst, lit, remaining_bytes);
#endif
        dst += remaining_bytes;
        lit += remaining_bytes;
        L -= remaining_bytes;
        goto DestinationBufferIsFull;
      }
      //  Same for the match.
      if (M <= remaining_bytes) {
#if defined(LZFSE_REDUCED_PROOF) && !defined(LZFSE_LMD_RESUME_PROOF)
        __CPROVER_assert(D >= 1, "copy_match_bytes D >= 1");
        __CPROVER_assert(LZFSE_OFFSET(dst) >= (size_t)D, "copy_match_bytes dst offset >= D");
        __CPROVER_assert(__CPROVER_r_ok(dst - D, (size_t)D), "copy_match_bytes src read");
        __CPROVER_assert(__CPROVER_w_ok(dst, (size_t)M), "copy_match_bytes dst write");
#else
        lzfse_copy_match_bytes(dst, D, M);
#endif
        dst += M;
        remaining_bytes -= M;
        M = 0;
        (void)M; // no dead store warning
      } else {
#if defined(LZFSE_REDUCED_PROOF) && !defined(LZFSE_LMD_RESUME_PROOF)
        __CPROVER_assert(D >= 1, "copy_match_bytes D >= 1 partial");
        __CPROVER_assert(LZFSE_OFFSET(dst) >= (size_t)D, "copy_match_bytes dst offset >= D partial");
        __CPROVER_assert(__CPROVER_r_ok(dst - D, (size_t)D), "copy_match_bytes src read partial");
        __CPROVER_assert(__CPROVER_w_ok(dst, (size_t)remaining_bytes), "copy_match_bytes dst write partial");
#else
        lzfse_copy_match_bytes(dst, D, remaining_bytes);
#endif
        dst += remaining_bytes;
        M -= remaining_bytes;
      DestinationBufferIsFull:
        //  Save everything needed to resume mid-symbol once the caller supplies
        //  more space.
        bs->l_value = L;
        bs->m_value = M;
        bs->d_value = D;
        bs->l_state = (fse_state)l_state;
        bs->m_state = (fse_state)m_state;
        bs->d_state = (fse_state)d_state;
        bs->lmd_in_stream = in;
        bs->n_matches = symbols;
        bs->lmd_in_buf = (uint32_t)(src - s->src);
        bs->current_literal = lit;
        s->dst = dst;
        return LZFSE_STATUS_DST_FULL;
      }
      //  Back to the sham value; the careful path only runs at the very end.
      remaining_bytes -= LZFSE_DECODE_COPY_MARGIN;
    }
  }
  s->dst = dst;
  return LZFSE_STATUS_OK;
}

#undef LZFSE_HOT
#undef LZFSE_HOT_CAT
#undef LZFSE_HOT_CAT_
