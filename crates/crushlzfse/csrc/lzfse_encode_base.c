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



// LZFSE encoder: a cost-based optimal parser, a shortest-path DP over byte
// positions in place of the stock greedy scan.
//
// The parse runs with an estimated cost model, tallies the symbol frequencies
// its result would produce, converts those to bit costs, and re-parses
// (`iterations` times). Only the best-scoring iteration's (L,M,D) sequence
// reaches the backend, so the cost model affects quality but never
// validity: a bad estimate gives a valid but larger stream. With
// table_search the backend then tunes each block's frequency tables.
//
// Literal-run length is its own FSE symbol, so DP states are indexed
// [position][L-symbol bucket]; paths within a bucket are cost-equivalent
// going forward, and match steps leave only from the cheapest bucket.
//
// Voluntary block splitting prices candidate cut points through the real
// fse_normalize_freq and header packing and commits any that beat one block.
//
// A call parses exactly one LZFSE_ZOPT_BLOCK_SIZE-or-smaller block: the real
// caller (decmpfs) never hands an Optimal-strategy call more than one such
// piece, so there is no cross-block match history to carry.
//
// All scratch lives in lzfse_zopt_scratch, so the encoder is reentrant. Only
// Step 3 touches decoder-visible bytes.

#include "lzfse_internal.h"
#include "lzfse_encode_tables.h"
#include "bt_match.h"
#include "fast_match.h"
#include "row_hash.h"
#include <math.h>
#include <string.h>

// Forced splits (a chunk exceeding the per-block caps) get no reparse: the
// backend builds a fresh table per physical block anyway. Voluntary splits
// do, see enable_reparse.

static inline uint64_t setField(uint32_t v, int offset, int nbits) {
  assert(offset + nbits < 64 && offset >= 0 && nbits <= 32);
  assert(nbits == 32 || (v < (1U << nbits)));
  (void)nbits;
  return ((uint64_t)v << (uint64_t)offset);
}

static inline void
lzfse_encode_v1_state(lzfse_compressed_block_header_v2 *out,
                      const lzfse_compressed_block_header_v1 *in) {
  out->magic = LZFSE_COMPRESSEDV2_BLOCK_MAGIC;
  out->n_raw_bytes = in->n_raw_bytes;
  out->packed_fields[0] = setField(in->n_literals, 0, 20) |
              setField(in->n_literal_payload_bytes, 20, 20) |
              setField(in->n_matches, 40, 20) |
              setField(7 + in->literal_bits, 60, 3);
  out->packed_fields[1] = setField(in->literal_state[0], 0, 10) |
              setField(in->literal_state[1], 10, 10) |
              setField(in->literal_state[2], 20, 10) |
              setField(in->literal_state[3], 30, 10) |
              setField(in->n_lmd_payload_bytes, 40, 20) |
              setField(7 + in->lmd_bits, 60, 3);
  out->packed_fields[2] = out->packed_fields[2]
              | setField(in->l_state, 32, 10) | setField(in->m_state, 42, 10) |
              setField(in->d_state, 52, 10);
}

static inline uint32_t lzfse_encode_v1_freq_value(int value, int *nbits) {
  switch (value) {
  case 0: *nbits = 2; return 0;
  case 1: *nbits = 2; return 2;
  case 2: *nbits = 3; return 1;
  case 3: *nbits = 3; return 5;
  case 4: *nbits = 5; return 3;
  case 5: *nbits = 5; return 11;
  case 6: *nbits = 5; return 19;
  case 7: *nbits = 5; return 27;
  default: break;
  }
  if (value < 24) { *nbits = 8; return 7 + ((value - 8) << 4); }
  *nbits = 14; return ((value - 24) << 4) + 15;
}

static inline size_t
lzfse_encode_v1_freq_table(lzfse_compressed_block_header_v2 *out,
                           const lzfse_compressed_block_header_v1 *in) {
  uint32_t accum = 0;
  int accum_nbits = 0;
  const uint16_t *src = &(in->l_freq[0]);
  uint8_t *dst = &(out->freq[0]);
  for (int i = 0; i < LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS +
                          LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS;
       i++) {
    int nbits = 0;
    uint32_t bits = lzfse_encode_v1_freq_value(src[i], &nbits);
    assert(bits < (1 << nbits));
    accum |= bits << accum_nbits;
    accum_nbits += nbits;
    while (accum_nbits >= 8) {
      *dst = (uint8_t)(accum & 0xff);
      accum >>= 8;
      accum_nbits -= 8;
      dst++;
    }
  }
  if (accum_nbits > 0) { *dst = (uint8_t)(accum & 0xff); dst++; }
  uint32_t header_size = (uint32_t)(dst - (uint8_t *)out);
  out->packed_fields[0] = 0;
  out->packed_fields[1] = 0;
  out->packed_fields[2] = setField(header_size, 0, 32);
  return header_size;
}

#define LZFSE_ENCODE_MAX_MATCH_LENGTH (100 * LZFSE_ENCODE_MAX_M_VALUE)


// ZOPT_PRICE_SHIFT, ZOPT_PRICE_ONE, ZOPT_MAX_STEP_PRICE and the two
// unreachable constants are in lzfse_zopt.h, next to the block cap they
// bound: prices are int32_t, so the two have to be chosen together.
#define ZOPT_PRICE_OF(bits) ((int32_t)((bits) * (double)ZOPT_PRICE_ONE + 0.5))

// An FSE encoder entry in the [nstates, 2 * nstates) state form: for state
// S = s + nstates, nbits = (S + dnb) >> 16 and the next S is
// (S >> nbits) + dstate. Emits exactly the bits of the usual step (k bits
// from s >= s0, else k - 1), with no compare or select on the state's path.
// On arm64 the pair is one 64-bit word, so a symbol costs one load and
// dstate folds into the add as a shifted operand; x86 cannot fold the shift
// and does better with two 32-bit fields it reads as memory operands.
#if defined(__aarch64__) || defined(_M_ARM64)
typedef uint64_t lzfse_fast_encoder_entry;
typedef uint64_t lzfse_fast_state; // the add then folds dstate's shift
#define LZFSE_FAST_ENTRY(dnb, dstate) ((uint64_t)(dstate) << 32 | (dnb))
#define LZFSE_FAST_DNB(e) ((uint32_t)(e))
#define LZFSE_FAST_DSTATE(e) ((uint32_t)((e) >> 32))
#else
typedef struct { uint32_t dnb, dstate; } lzfse_fast_encoder_entry;
typedef uint32_t lzfse_fast_state;
#define LZFSE_FAST_ENTRY(dnb, dstate) ((lzfse_fast_encoder_entry){(dnb), (dstate)})
#define LZFSE_FAST_DNB(e) ((e).dnb)
#define LZFSE_FAST_DSTATE(e) ((e).dstate)
#endif

static void lzfse_fast_encoder_table(int nstates, int nsymbols, const uint16_t *freq,
                                     lzfse_fast_encoder_entry *t) {
  fse_encoder_entry e[LZFSE_ENCODE_LITERAL_SYMBOLS];
  fse_init_encoder_table(nstates, nsymbols, freq, e);
  for (int i = 0; i < nsymbols; i++) {
    if (freq[i] == 0) { t[i] = LZFSE_FAST_ENTRY(0, 0); continue; }
    int k = e[i].k;
    uint32_t dnb = ((uint32_t)k << 16) - (uint32_t)e[i].s0 - (uint32_t)nstates;
    uint32_t dstate = (uint32_t)(e[i].delta0 - (nstates >> k) + nstates);
    t[i] = LZFSE_FAST_ENTRY(dnb, dstate);
  }
}

LZFSE_INLINE void lzfse_fast_encode(lzfse_fast_state *state, const lzfse_fast_encoder_entry *t,
                                    uint64_t *accum, uint32_t *accum_nbits, uint32_t symbol) {
  lzfse_fast_state S = *state;
  lzfse_fast_encoder_entry e = t[symbol];
  uint32_t nbits = ((uint32_t)S + LZFSE_FAST_DNB(e)) >> 16;
  *accum |= (uint64_t)((uint32_t)S & ((1u << nbits) - 1)) << *accum_nbits;
  *accum_nbits += nbits;
  *state = (S >> nbits) + LZFSE_FAST_DSTATE(e);
}

LZFSE_INLINE void lzfse_fast_push(uint64_t *accum, uint32_t *accum_nbits, uint32_t nbits, uint32_t bits) {
  *accum |= (uint64_t)bits << *accum_nbits;
  *accum_nbits += nbits;
}

LZFSE_INLINE void lzfse_fast_flush(uint64_t *accum, uint32_t *accum_nbits, uint8_t **buf) {
  uint32_t nbits = *accum_nbits & ~7u;
  store8(*buf, *accum);
  *buf += nbits >> 3;
  *accum >>= nbits;
  *accum_nbits -= nbits;
}

// Table search: the backend's normalized frequencies are a rounding of the
// counts, and LZFSE's unspread tables make a symbol's real cost depend on
// the state trajectory, so they are not the cheapest tables for the block.
// A hill-climb moves one state at a time between a symbol and the most
// frequent one, keeping a move when the block's exact payload bits plus the
// header's table bits drop.

static inline int32_t ts_freq_code_bits(int f) {
  return f < 2 ? 2 : f < 4 ? 3 : f < 8 ? 5 : f < 24 ? 8 : 14;
}

// A move that lost by more than this many bits is not retried in later
// passes: nearly all of the gain for under half the time.
#define TS_RETRY_MAX_LOSS 8

// Exact payload bits of syms[0, n) under ncand tables (1 or 2) at once,
// encoded last to first as the backend does, in nways interleaved states
// (1, or 4 for literals with n a multiple of 4). The state chains are
// independent, so a second table costs little more than the first.
static void ts_exact_bits(int nstates, int nsymbols, uint16_t freq[2][LZFSE_ENCODE_LITERAL_SYMBOLS],
                          int ncand, const uint8_t *syms, uint32_t n, int nways, uint32_t bits[2]) {
  lzfse_fast_encoder_entry t[2][LZFSE_ENCODE_LITERAL_SYMBOLS];
  for (int c = 0; c < ncand; c++)
    lzfse_fast_encoder_table(nstates, nsymbols, freq[c], t[c]);
  if (ncand == 1)
    memcpy(t[1], t[0], (size_t)nsymbols * sizeof t[0][0]);
  uint32_t xa = 0, xb = 0;
#define TS_STEP(S, tab, sym, acc) do { \
    lzfse_fast_encoder_entry e_ = tab[sym]; \
    uint32_t nb_ = ((uint32_t)S + LZFSE_FAST_DNB(e_)) >> 16; \
    S = (S >> nb_) + LZFSE_FAST_DSTATE(e_); \
    acc += nb_; \
  } while (0)
  const lzfse_fast_encoder_entry *ta = t[0], *tb = t[1];
  if (nways == 1) {
    lzfse_fast_state A = (lzfse_fast_state)nstates, B = A;
    for (uint32_t i = n; i > 0;) {
      uint32_t sy = syms[--i];
      TS_STEP(A, ta, sy, xa);
      TS_STEP(B, tb, sy, xb);
    }
  } else {
    lzfse_fast_state A0 = (lzfse_fast_state)nstates, A1 = A0, A2 = A0, A3 = A0;
    lzfse_fast_state B0 = A0, B1 = A0, B2 = A0, B3 = A0;
    for (uint32_t i = n; i > 0;) {
      i -= 4;
      uint32_t s3 = syms[i + 3], s2 = syms[i + 2], s1 = syms[i + 1], s0 = syms[i];
      TS_STEP(A3, ta, s3, xa); TS_STEP(B3, tb, s3, xb);
      TS_STEP(A2, ta, s2, xa); TS_STEP(B2, tb, s2, xb);
      TS_STEP(A1, ta, s1, xa); TS_STEP(B1, tb, s1, xb);
      TS_STEP(A0, ta, s0, xa); TS_STEP(B0, tb, s0, xb);
    }
  }
#undef TS_STEP
  bits[0] = xa;
  bits[1] = xb;
}

static void ts_search(int nstates, int nsymbols, uint16_t *freq,
                      const uint8_t *syms, uint32_t n, int nways, int passes) {
  int big = 0, used = 0;
  for (int i = 0; i < nsymbols; i++) {
    if (freq[i] > freq[big]) big = i;
    used += freq[i] != 0;
  }
  if (used < 2) return;
  uint16_t cand[2][LZFSE_ENCODE_LITERAL_SYMBOLS];
  uint32_t b[2];
  memcpy(cand[0], freq, (size_t)nsymbols * sizeof *freq);
  ts_exact_bits(nstates, nsymbols, cand, 1, syms, n, nways, b);
  int64_t cur = b[0];
  // Each move's loss when last tried, in bits; the -1 move is [i][0].
  int32_t loss[LZFSE_ENCODE_LITERAL_SYMBOLS][2] = {{0}};
  for (int pass = 0; pass < passes; pass++) {
    int moved = 0;
    for (int i = 0; i < nsymbols; i++) {
      // A single state cannot shrink, and growing one rarely pays.
      if (i == big || freq[i] < 2) continue;
      int f = freq[i], g = freq[big];
      int dirs[2], nc = 0;
      int32_t saved[2];
      for (int k = 0; k < 2; k++) {
        int dir = k ? 1 : -1, fi = f + dir, fb = g - dir;
        if (fb < 1 || (pass > 0 && loss[i][k] > TS_RETRY_MAX_LOSS)) continue;
        saved[nc] = ts_freq_code_bits(f) + ts_freq_code_bits(g) - ts_freq_code_bits(fi) - ts_freq_code_bits(fb);
        memcpy(cand[nc], freq, (size_t)nsymbols * sizeof *freq);
        cand[nc][i] = (uint16_t)fi;
        cand[nc][big] = (uint16_t)fb;
        dirs[nc++] = k;
      }
      if (!nc) continue;
      ts_exact_bits(nstates, nsymbols, cand, nc, syms, n, nways, b);
      int best = -1;
      int64_t bv = cur;
      for (int c = 0; c < nc; c++) {
        int64_t v = (int64_t)b[c] - saved[c];
        loss[i][dirs[c]] = (int32_t)(v - cur);
        if (v < bv) { bv = v; best = c; }
      }
      if (best >= 0) {
        memcpy(freq, cand[best], (size_t)nsymbols * sizeof *freq);
        cur = b[best];
        moved = 1;
      }
    }
    if (!moved) break;
  }
}

// Runs the search on all four tables of the block in s.
static void lzfse_table_search(lzfse_encoder_state *s, lzfse_compressed_block_header_v1 *h) {
  lzfse_zopt_scratch *z = s->zopt;
  uint8_t *ls = z->ts_sym, *ms = ls + LZFSE_MATCHES_PER_BLOCK, *ds = ms + LZFSE_MATCHES_PER_BLOCK;
  uint32_t d_prev = 0;
  for (uint32_t i = 0; i < s->n_matches; i++) {
    uint32_t d = s->d_values[i];
    ls[i] = l_base_from_value((int32_t)s->l_values[i]);
    ms[i] = m_base_from_value((int32_t)s->m_values[i]);
    ds[i] = (uint8_t)lzfse_d_symbol(d == d_prev ? 0 : d);
    d_prev = d;
  }
  int p = z->table_search;
  ts_search(LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, h->l_freq, ls, s->n_matches, 1, p);
  ts_search(LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, h->m_freq, ms, s->n_matches, 1, p);
  ts_search(LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, h->d_freq, ds, s->n_matches, 1, p);
  ts_search(LZFSE_ENCODE_LITERAL_STATES, LZFSE_ENCODE_LITERAL_SYMBOLS, h->literal_freq,
            s->literals, s->n_literals, 4, p);
}

#if defined(CRUSHLZFSE_DISPATCH_PROOF)
static __attribute__((noinline)) int lzfse_encode_matches(lzfse_encoder_state *s)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_ENSURES(LZFSE_ENCODE_STATUS(__CPROVER_return_value))
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_ENSURES(s->src_literal == __CPROVER_old(s->src_literal))
#else
static int lzfse_encode_matches(lzfse_encoder_state *s)
#endif
{
  if (s->n_literals == 0 && s->n_matches == 0)
    return LZFSE_STATUS_OK;

  uint32_t l_occ[LZFSE_ENCODE_L_SYMBOLS];
  uint32_t m_occ[LZFSE_ENCODE_M_SYMBOLS];
  uint32_t d_occ[LZFSE_ENCODE_D_SYMBOLS];
  uint32_t literal_occ[4][LZFSE_ENCODE_LITERAL_SYMBOLS];
  lzfse_fast_encoder_entry l_encoder[LZFSE_ENCODE_L_SYMBOLS];
  lzfse_fast_encoder_entry m_encoder[LZFSE_ENCODE_M_SYMBOLS];
  lzfse_fast_encoder_entry d_encoder[LZFSE_ENCODE_D_SYMBOLS];
  lzfse_fast_encoder_entry literal_encoder[LZFSE_ENCODE_LITERAL_SYMBOLS];
  lzfse_compressed_block_header_v1 header1 = {0};
  lzfse_compressed_block_header_v2 *header2 = 0;

  uint8_t *dst0 = s->dst;
  uint32_t n_literals0 = s->n_literals;
  const uint32_t n_matches = s->n_matches;
  const uint32_t *l_values = s->l_values;
  const uint32_t *m_values = s->m_values;
  const uint32_t *d_values = s->d_values;

  while (s->n_literals & 3) {
    uint32_t n = s->n_literals++;
    s->literals[n] = 0;
  }
  const uint32_t n_literals = s->n_literals;

  memset(l_occ, 0, sizeof(l_occ));
  memset(m_occ, 0, sizeof(m_occ));
  memset(d_occ, 0, sizeof(d_occ));
  memset(literal_occ, 0, sizeof(literal_occ));

  // A D equal to the one before it is sent as 0, the repeat symbol.
  uint32_t l_sum = 0;
  uint32_t m_sum = 0;
  uint32_t d_prev = 0;
  for (uint32_t i = 0; i < n_matches; i++) {
    uint32_t l = l_values[i], m = m_values[i], d = d_values[i];
    l_sum += l;
    m_sum += m;
    l_occ[l_base_from_value((int32_t)l)]++;
    m_occ[m_base_from_value((int32_t)m)]++;
    d_occ[lzfse_d_symbol(d == d_prev ? 0 : d)]++;
    d_prev = d;
  }
  // Four tallies, so consecutive equal bytes do not serialise on one counter.
  for (uint32_t i = 0; i < n_literals; i += 4) {
    literal_occ[0][s->literals[i + 0]]++;
    literal_occ[1][s->literals[i + 1]]++;
    literal_occ[2][s->literals[i + 2]]++;
    literal_occ[3][s->literals[i + 3]]++;
  }
  for (int c = 0; c < LZFSE_ENCODE_LITERAL_SYMBOLS; c++)
    literal_occ[0][c] += literal_occ[1][c] + literal_occ[2][c] + literal_occ[3][c];

  if ((size_t)(s->dst_end - s->dst) < sizeof(lzfse_compressed_block_header_v2))
    goto FULL;
  header2 = (lzfse_compressed_block_header_v2 *)(s->dst);

  header1.magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
  header1.n_raw_bytes = m_sum + l_sum;
  header1.n_matches = n_matches;
  header1.n_literals = n_literals;

  fse_normalize_freq(LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, l_occ, header1.l_freq);
  fse_normalize_freq(LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, m_occ, header1.m_freq);
  fse_normalize_freq(LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, d_occ, header1.d_freq);
  fse_normalize_freq(LZFSE_ENCODE_LITERAL_STATES, LZFSE_ENCODE_LITERAL_SYMBOLS, literal_occ[0], header1.literal_freq);

  if (s->zopt && s->zopt->ts_sym)
    lzfse_table_search(s, &header1);

  s->dst += lzfse_encode_v1_freq_table(header2, &header1);

  lzfse_fast_encoder_table(LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, header1.l_freq, l_encoder);
  lzfse_fast_encoder_table(LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, header1.m_freq, m_encoder);
  lzfse_fast_encoder_table(LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, header1.d_freq, d_encoder);
  lzfse_fast_encoder_table(LZFSE_ENCODE_LITERAL_STATES, LZFSE_ENCODE_LITERAL_SYMBOLS, header1.literal_freq, literal_encoder);

  {
    uint64_t accum = 0;
    uint32_t accum_nbits = 0;
    lzfse_fast_state state0, state1, state2, state3;
    state0 = state1 = state2 = state3 = LZFSE_ENCODE_LITERAL_STATES;
    uint8_t *buf = s->dst;
    // Up to 4 * 10 bits per round plus 7 left over fit the accumulator, and
    // a round writes at most 6 bytes, so one check up front covers the whole
    // loop when it fits.
    int checked = (size_t)(s->dst_end - buf) < (size_t)n_literals * 10 / 8 + 16;
    for (uint32_t i = n_literals; i > 0;) {
      if (checked && (size_t)(s->dst_end - buf) < 16) goto FULL;
      i -= 4;
      uint32_t q = load4(s->literals + i);
      lzfse_fast_encode(&state3, literal_encoder, &accum, &accum_nbits, q >> 24);
      lzfse_fast_encode(&state2, literal_encoder, &accum, &accum_nbits, (q >> 16) & 0xff);
      lzfse_fast_encode(&state1, literal_encoder, &accum, &accum_nbits, (q >> 8) & 0xff);
      lzfse_fast_encode(&state0, literal_encoder, &accum, &accum_nbits, q & 0xff);
      lzfse_fast_flush(&accum, &accum_nbits, &buf);
    }
    {
      fse_out_stream out;
      out.accum = accum;
      out.accum_nbits = (fse_bit_count)accum_nbits;
      if ((size_t)(s->dst_end - buf) < 8) goto FULL;
      fse_out_finish(&out, &buf);
      header1.literal_bits = out.accum_nbits;
    }
    header1.n_literal_payload_bytes = (uint32_t)(buf - s->dst);
    header1.literal_state[0] = (uint16_t)(state0 - LZFSE_ENCODE_LITERAL_STATES);
    header1.literal_state[1] = (uint16_t)(state1 - LZFSE_ENCODE_LITERAL_STATES);
    header1.literal_state[2] = (uint16_t)(state2 - LZFSE_ENCODE_LITERAL_STATES);
    header1.literal_state[3] = (uint16_t)(state3 - LZFSE_ENCODE_LITERAL_STATES);
    s->dst = buf;
  }

  {
    uint64_t accum = 0;
    uint32_t accum_nbits = 0;
    lzfse_fast_state l_state = LZFSE_ENCODE_L_STATES;
    lzfse_fast_state m_state = LZFSE_ENCODE_M_STATES;
    lzfse_fast_state d_state = LZFSE_ENCODE_D_STATES;
    uint8_t *buf = s->dst;
    if ((size_t)(s->dst_end - buf) < 8) goto FULL;
    store8(buf, 0);
    buf += 8;
    // At most 54 bits per match: one flush each. A match writes at most 7
    // bytes, so one check up front covers the whole loop when it fits.
    int checked = (size_t)(s->dst_end - buf) < (size_t)n_matches * 7 + 16;
    // d_values[i - 1] for i == 0 reads as 0, which no real D equals, so
    // the repeat test needs no branch.
    uint32_t d_next = n_matches ? d_values[n_matches - 1] : 0;
    // Each symbol's extra bit count and base value in one word, as
    // nbits | base << 5, on the stack: one load per value, no table
    // address to rebuild, and the base comes off with a shifted subtract.
    uint32_t l_info[LZFSE_ENCODE_L_SYMBOLS], m_info[LZFSE_ENCODE_M_SYMBOLS], d_info[LZFSE_ENCODE_D_SYMBOLS];
    for (int k = 0; k < LZFSE_ENCODE_L_SYMBOLS; k++) l_info[k] = l_extra_bits[k] | (uint32_t)l_base_value[k] << 5;
    for (int k = 0; k < LZFSE_ENCODE_M_SYMBOLS; k++) m_info[k] = m_extra_bits[k] | (uint32_t)m_base_value[k] << 5;
    for (int k = 0; k < LZFSE_ENCODE_D_SYMBOLS; k++) d_info[k] = d_extra_bits[k] | (uint32_t)d_base_value[k] << 5;
    const uint8_t *l_sym = l_sym_from_value, *m_sym = m_sym_from_value;
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(l_sym), "+r"(m_sym)); // held in registers, not rebuilt per match
#endif
    for (uint32_t i = n_matches; i > 0;) {
      if (checked && (size_t)(s->dst_end - buf) < 16) goto FULL;
      i -= 1;
      uint32_t d_value = d_next;
      d_next = i ? d_values[i - 1] : 0;
      d_value = d_next == d_value ? 0 : d_value;
      uint32_t d_symbol = lzfse_d_symbol(d_value);
      uint32_t info = d_info[d_symbol];
      lzfse_fast_push(&accum, &accum_nbits, info & 31, d_value - (info >> 5));
      lzfse_fast_encode(&d_state, d_encoder, &accum, &accum_nbits, d_symbol);
      uint32_t m_value = m_values[i];
      uint32_t m_symbol = m_sym[m_value];
      info = m_info[m_symbol];
      lzfse_fast_push(&accum, &accum_nbits, info & 31, m_value - (info >> 5));
      lzfse_fast_encode(&m_state, m_encoder, &accum, &accum_nbits, m_symbol);
      uint32_t l_value = l_values[i];
      uint32_t l_symbol = l_sym[l_value];
      info = l_info[l_symbol];
      lzfse_fast_push(&accum, &accum_nbits, info & 31, l_value - (info >> 5));
      lzfse_fast_encode(&l_state, l_encoder, &accum, &accum_nbits, l_symbol);
      lzfse_fast_flush(&accum, &accum_nbits, &buf);
    }
    {
      fse_out_stream out;
      out.accum = accum;
      out.accum_nbits = (fse_bit_count)accum_nbits;
      if ((size_t)(s->dst_end - buf) < 8) goto FULL;
      fse_out_finish(&out, &buf);
      header1.lmd_bits = out.accum_nbits;
    }
    header1.n_lmd_payload_bytes = (uint32_t)(buf - s->dst);
    header1.l_state = (uint16_t)(l_state - LZFSE_ENCODE_L_STATES);
    header1.m_state = (uint16_t)(m_state - LZFSE_ENCODE_M_STATES);
    header1.d_state = (uint16_t)(d_state - LZFSE_ENCODE_D_STATES);
    s->dst = buf;
  }

  if (s->lmd_stats) {
    uint32_t *o = s->lmd_stats;
    for (int i = 0; i < LZFSE_ENCODE_L_SYMBOLS; i++) *o++ += l_occ[i];
    for (int i = 0; i < LZFSE_ENCODE_M_SYMBOLS; i++) *o++ += m_occ[i];
    for (int i = 0; i < LZFSE_ENCODE_D_SYMBOLS; i++) *o++ += d_occ[i];
  }

  s->n_literals = 0;
  s->n_matches = 0;
  header1.n_payload_bytes = header1.n_literal_payload_bytes + header1.n_lmd_payload_bytes;
  lzfse_encode_v1_state(header2, &header1);
  return LZFSE_STATUS_OK;

FULL:
  s->n_literals = n_literals0;
  s->dst = dst0;
  return LZFSE_STATUS_DST_FULL;
}

#if defined(CRUSHLZFSE_PUSH_MATCH_PROOF) || defined(CRUSHLZFSE_PUSH_LMD_PROOF)
static __attribute__((noinline)) int lzfse_push_lmd(lzfse_encoder_state *s, uint32_t L, uint32_t M, uint32_t D)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_ENSURES(LZFSE_ENCODE_STATUS(__CPROVER_return_value))
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(s->dst == __CPROVER_old(s->dst))
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end)
#else
static inline int lzfse_push_lmd(lzfse_encoder_state *s, uint32_t L, uint32_t M, uint32_t D)
#endif
{
  if (s->n_matches + 1 + 8 > LZFSE_MATCHES_PER_BLOCK) return LZFSE_STATUS_DST_FULL;
  if (s->n_literals + L + 16 > LZFSE_LITERALS_PER_BLOCK) return LZFSE_STATUS_DST_FULL;
  uint32_t n = s->n_matches++;
  s->l_values[n] = L;
  s->m_values[n] = M;
  s->d_values[n] = D;
  uint8_t *dst = s->literals + s->n_literals;
  const uint8_t *src = s->src + s->src_literal;
  uint8_t *dst_end = dst + L;
  if (s->src_literal + L + 16 > s->src_end) {
    if (L > 0) memcpy(dst, src, L);
  } else {
    copy16(dst, src);
    dst += 16; src += 16;
    while (dst < dst_end) { copy16(dst, src); dst += 16; src += 16; }
  }
  s->n_literals += L;
  s->src_literal += L + M;
  return LZFSE_STATUS_OK;
}

#if defined(CRUSHLZFSE_BACKEND_MATCH_PROOF) || defined(CRUSHLZFSE_PUSH_MATCH_PROOF)
static __attribute__((noinline)) int lzfse_push_match(lzfse_encoder_state *s, const lzfse_match *match)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(match != NULL && __CPROVER_r_ok(match, sizeof *match))
LZFSE_REQUIRES(s->src_literal >= 0 && s->src_literal <= s->src_end)
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_ENSURES(LZFSE_ENCODE_STATUS(__CPROVER_return_value))
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(s->dst == __CPROVER_old(s->dst))
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end)
#else
static int lzfse_push_match(lzfse_encoder_state *s, const lzfse_match *match)
#endif
{
  uint32_t n_matches0 = s->n_matches;
  uint32_t n_literals0 = s->n_literals;
  lzfse_offset src_literals0 = s->src_literal;
  uint32_t L = (uint32_t)(match->pos - s->src_literal);
  uint32_t M = match->length;
  uint32_t D = (uint32_t)(match->pos - match->ref);
  int ok = 1;
  while (L > LZFSE_ENCODE_MAX_L_VALUE) {
    if (lzfse_push_lmd(s, LZFSE_ENCODE_MAX_L_VALUE, 0, 1) != 0) { ok = 0; goto END; }
    L -= LZFSE_ENCODE_MAX_L_VALUE;
  }
  while (M > LZFSE_ENCODE_MAX_M_VALUE) {
    if (lzfse_push_lmd(s, L, LZFSE_ENCODE_MAX_M_VALUE, D) != 0) { ok = 0; goto END; }
    L = 0;
    M -= LZFSE_ENCODE_MAX_M_VALUE;
  }
  if (L > 0 || M > 0) {
    if (lzfse_push_lmd(s, L, M, D) != 0) { ok = 0; goto END; }
    L = M = 0;
    (void)L; (void)M;
  }
END:
  if (!ok) {
    s->n_matches = n_matches0;
    s->n_literals = n_literals0;
    s->src_literal = src_literals0;
    return LZFSE_STATUS_DST_FULL;
  }
  return LZFSE_STATUS_OK;
}

#if defined(CRUSHLZFSE_DISPATCH_PROOF)
static __attribute__((noinline)) int lzfse_backend_match(lzfse_encoder_state *s, const lzfse_match *match)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(match != NULL && __CPROVER_r_ok(match, sizeof *match))
LZFSE_REQUIRES(s->src_literal >= 0 && s->src_literal <= s->src_end)
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_ENSURES(LZFSE_ENCODE_STATUS(__CPROVER_return_value))
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end)
#else
static int lzfse_backend_match(lzfse_encoder_state *s, const lzfse_match *match)
#endif
{
  if (lzfse_push_match(s, match) == LZFSE_STATUS_OK)
    return LZFSE_STATUS_OK;
  if (lzfse_encode_matches(s) != LZFSE_STATUS_OK)
    return LZFSE_STATUS_DST_FULL;
  return lzfse_push_match(s, match);
}

#if defined(LZFSE_BASE_PROOF) || defined(CRUSHLZFSE_DISPATCH_PROOF)
static __attribute__((noinline)) int lzfse_backend_literals(lzfse_encoder_state *s, lzfse_offset L)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_REQUIRES(s->src_end >= 0 && s->src_end <= PTRDIFF_MAX)
LZFSE_REQUIRES(s->src_literal >= 0 && s->src_literal <= s->src_end)
LZFSE_REQUIRES(L >= 0 && L <= s->src_end - s->src_literal)
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_ENSURES(LZFSE_ENCODE_STATUS(__CPROVER_return_value))
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end)
#else
static int lzfse_backend_literals(lzfse_encoder_state *s, lzfse_offset L)
#endif
{
  lzfse_match match;
  lzfse_offset pos = s->src_literal + L;
  match.pos = pos;
  match.ref = match.pos - 1;
  match.length = 0;
  return lzfse_backend_match(s, &match);
}

static int lzfse_backend_end_of_stream(lzfse_encoder_state *s) {
  if (lzfse_encode_matches(s) != LZFSE_STATUS_OK)
    return LZFSE_STATUS_DST_FULL;
  if ((size_t)(s->dst_end - s->dst) < 4)
    return LZFSE_STATUS_DST_FULL;
  store4(s->dst, LZFSE_ENDOFSTREAM_BLOCK_MAGIC);
  s->dst += 4;
  return LZFSE_STATUS_OK;
}

int lzfse_encode_init(lzfse_encoder_state *s) {
  const lzfse_match NO_MATCH = {0};
  s->pending = NO_MATCH;
  s->src_literal = 0;
  return LZFSE_STATUS_OK;
}

// ===============================================================
// Cost-based optimal parser. Single-shot: one lzfse_encode_base call encodes
// the whole of s->src.

// Tallies symbol occurrences for tuples [start, end); d_prev starts at 0, as
// at a real block boundary.
static void tally_tuple_subrange(const uint32_t *tup_L, const uint32_t *tup_M, const uint32_t *tup_D,
                                  int32_t start, int32_t end, const uint8_t *src_base, lzfse_offset base_pos,
                                  uint32_t *l_occ, uint32_t *m_occ, uint32_t *d_occ, uint32_t *lit_occ) {
  memset(l_occ, 0, LZFSE_ENCODE_L_SYMBOLS * sizeof(uint32_t));
  memset(m_occ, 0, LZFSE_ENCODE_M_SYMBOLS * sizeof(uint32_t));
  memset(d_occ, 0, LZFSE_ENCODE_D_SYMBOLS * sizeof(uint32_t));
  memset(lit_occ, 0, 256 * sizeof(uint32_t));
  uint32_t d_prev = 0;
  lzfse_offset pos = base_pos;
  for (int32_t t = start; t < end; t++) {
    uint32_t L = tup_L[t], M = tup_M[t], D = tup_D[t];
    for (uint32_t k = 0; k < L; k++) lit_occ[src_base[pos + k]]++;
    pos += L;
    uint32_t Lrem = L;
    while (Lrem > LZFSE_ENCODE_MAX_L_VALUE) {
      l_occ[l_base_from_value(LZFSE_ENCODE_MAX_L_VALUE)]++;
      Lrem -= LZFSE_ENCODE_MAX_L_VALUE;
    }
    l_occ[l_base_from_value(Lrem)]++;
    if (M > 0) {
      m_occ[m_base_from_value(M)]++;
      uint32_t d_sym_val = (D == d_prev && d_prev != 0) ? 0 : D;
      d_occ[lzfse_d_symbol(d_sym_val)]++;
      d_prev = D;
      pos += M;
    }
  }
}

// Prices through the backend's own fse_normalize_freq, so a symbol's cost
// reflects its real quantized slot count. Zero allocations are floored to 1:
// a used symbol never gets 0, so the floor only affects the DP's speculative
// lookups, which must be expensive rather than forbidden.
static void normalize_with_floor(const uint32_t *occ, int nstates, int nsymbols, uint16_t *freq_out) {
  fse_normalize_freq(nstates, nsymbols, occ, freq_out);
  for (int i = 0; i < nsymbols; i++) {
    if (freq_out[i] == 0) freq_out[i] = 1;
  }
}

// Quantized entropy plus extra bits, in bits. freq_scratch needs nsymbols
// entries (256 covers all four tables).
static double quantized_bits(const uint32_t *occ, const uint8_t *extra_bits, int nstates, int nsymbols, uint16_t *freq_scratch) {
  normalize_with_floor(occ, nstates, nsymbols, freq_scratch);
  double bits = 0.0;
  for (int i = 0; i < nsymbols; i++) {
    bits += (double)occ[i] * (-log2((double)freq_scratch[i] / nstates) + (double)extra_bits[i]);
  }
  return bits;
}

// Fixed bytes every block spends outside its symbols: the 32-byte header
// (magic, n_raw_bytes and packed_fields, not sizeof(the struct) with its
// oversized freq[]) and the 8 zero bytes lzfse_encode_matches opens the
// LMD payload with. Left out of the price, a split's second block looks 8
// bytes cheaper than it is.
#define LZFSE_BLOCK_FIXED_BITS (256.0 + 64.0)

// Header-table bits a block would spend, through the backend's own packing.
static double header_table_bits(const uint32_t *l_occ, const uint32_t *m_occ, const uint32_t *d_occ, const uint32_t *lit_occ) {
  uint16_t l_freq[LZFSE_ENCODE_L_SYMBOLS], m_freq[LZFSE_ENCODE_M_SYMBOLS];
  uint16_t d_freq[LZFSE_ENCODE_D_SYMBOLS], lit_freq[LZFSE_ENCODE_LITERAL_SYMBOLS];
  fse_normalize_freq(LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, l_occ, l_freq);
  fse_normalize_freq(LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, m_occ, m_freq);
  fse_normalize_freq(LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, d_occ, d_freq);
  fse_normalize_freq(LZFSE_ENCODE_LITERAL_STATES, LZFSE_ENCODE_LITERAL_SYMBOLS, lit_occ, lit_freq);
  double bits = LZFSE_BLOCK_FIXED_BITS;
  int nbits;
  for (int i = 0; i < LZFSE_ENCODE_L_SYMBOLS; i++) { lzfse_encode_v1_freq_value(l_freq[i], &nbits); bits += nbits; }
  for (int i = 0; i < LZFSE_ENCODE_M_SYMBOLS; i++) { lzfse_encode_v1_freq_value(m_freq[i], &nbits); bits += nbits; }
  for (int i = 0; i < LZFSE_ENCODE_D_SYMBOLS; i++) { lzfse_encode_v1_freq_value(d_freq[i], &nbits); bits += nbits; }
  for (int i = 0; i < LZFSE_ENCODE_LITERAL_SYMBOLS; i++) { lzfse_encode_v1_freq_value(lit_freq[i], &nbits); bits += nbits; }
  return bits;
}

// Literals have no extra bits.
static const uint8_t zero_extra_bits_256[256] = {0};

// Cost in bits of tuples [start, end) as their own block starting at
// base_pos; the histograms are written to the caller's scratch.
static double priced_block_bits(const uint32_t *tup_L, const uint32_t *tup_M, const uint32_t *tup_D,
                                 int32_t start, int32_t end, const uint8_t *src_base, lzfse_offset base_pos,
                                 uint32_t *l_occ, uint32_t *m_occ, uint32_t *d_occ, uint32_t *lit_occ) {
  tally_tuple_subrange(tup_L, tup_M, tup_D, start, end, src_base, base_pos, l_occ, m_occ, d_occ, lit_occ);
  uint16_t freq_scratch[256];
  double bits = quantized_bits(l_occ, l_extra_bits, LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, freq_scratch)
              + quantized_bits(m_occ, m_extra_bits, LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, freq_scratch)
              + quantized_bits(d_occ, d_extra_bits, LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, freq_scratch)
              + quantized_bits(lit_occ, zero_extra_bits_256, LZFSE_ENCODE_LITERAL_STATES, 256, freq_scratch)
              + header_table_bits(l_occ, m_occ, d_occ, lit_occ);
  // The backend pads the literal count to a multiple of 4 with zero bytes.
  uint32_t n_lit = 0;
  for (int i = 0; i < 256; i++) n_lit += lit_occ[i];
  bits += 8.0 * ((4 - (n_lit & 3)) & 3);
  return bits;
}


// --- Zopfli-style recursive block splitting; the driver is in lzfse_encode_base.

// Bits to commit tuple range [lo,hi) as ONE block, priced exactly.
static double split_range_bits(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                               int32_t lo, int32_t hi, uint32_t *l_occ,
                               uint32_t *m_occ, uint32_t *d_occ, uint32_t *lit_occ) {
  return priced_block_bits(z->best_tup_L, z->best_tup_M, z->best_tup_D, lo, hi,
                           s->src, z->tuple_start_pos[lo], l_occ, m_occ, d_occ, lit_occ);
}

// Bits to commit [lo,hi) as TWO blocks divided at tuple index t.
static double split_pair_bits(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                              int32_t lo, int32_t t, int32_t hi) {
  return split_range_bits(s, z, lo, t, z->split_l_occ_a, z->split_m_occ_a,
                          z->split_d_occ_a, z->split_lit_occ_a)
       + split_range_bits(s, z, t, hi, z->split_l_occ_b, z->split_m_occ_b,
                          z->split_d_occ_b, z->split_lit_occ_b);
}

// Best split point for [lo,hi), or -1 if none beats whole_bits. Zopfli's
// FindMinimum: sample NUM points, narrow to the neighbours of the best,
// repeat, then scan the remaining window. The curve is only roughly unimodal,
// so the `best > lastbest` guard stops once narrowing stops improving; every
// point evaluated is still compared against the running best.
static int32_t split_find_best(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                               int32_t lo, int32_t hi, double whole_bits) {
  enum { NUM = 9 };
  if (hi - lo < 2) return -1;
  const lzfse_offset min_side = ZOPT_SPLIT_MIN_SIDE;
  lzfse_offset lo_pos = z->tuple_start_pos[lo];
  lzfse_offset hi_pos = z->tuple_start_pos[hi];
  if (hi_pos - lo_pos < 2 * min_side) return -1;

  // Restrict to tuple indices leaving at least min_side bytes on each side.
  int32_t a = lo + 1, b = hi - 1;
  while (a <= b && z->tuple_start_pos[a] - lo_pos < min_side) a++;
  while (b >= a && hi_pos - z->tuple_start_pos[b] < min_side) b--;
  if (a > b) return -1;

  int32_t best_t = -1;
  double best_total = whole_bits;
  int32_t w0 = a, w1 = b;
  double lastbest = 1e300;

  while (w1 - w0 > NUM) {
    int32_t p[NUM];
    double vp[NUM];
    int32_t besti = 0;
    double best = 1e300;
    for (int32_t i = 0; i < NUM; i++) {
      p[i] = w0 + (int32_t)(((int64_t)(i + 1) * (int64_t)(w1 - w0)) / (NUM + 1));
      vp[i] = split_pair_bits(s, z, lo, p[i], hi);
      if (vp[i] < best) { best = vp[i]; besti = i; }
    }
    if (best < best_total) { best_total = best; best_t = p[besti]; }
    if (best > lastbest) break;
    lastbest = best;
    int32_t n0 = (besti == 0) ? w0 : p[besti - 1];
    int32_t n1 = (besti == NUM - 1) ? w1 : p[besti + 1];
    if (n0 == w0 && n1 == w1) break; // window stopped shrinking
    w0 = n0; w1 = n1;
  }
  for (int32_t t = w0; t <= w1; t++) {
    double v = split_pair_bits(s, z, lo, t, hi);
    if (v < best_total) { best_total = v; best_t = t; }
  }
  return best_t;
}

// Recursively split [lo,hi), appending chosen tuple indices to `out`: best
// split of the range, then both halves, until the block budget is spent or no
// split pays for its own second header.
#if defined(LZFSE_BASE_PROOF)
static __attribute__((noinline)) void split_recurse(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                                                    int32_t lo, int32_t hi, int32_t max_blocks,
                                                    int32_t *out, int32_t *n_out)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(z != NULL && __CPROVER_rw_ok(z, sizeof *z))
LZFSE_REQUIRES(max_blocks >= 1)
LZFSE_REQUIRES(out != NULL && __CPROVER_rw_ok(out, (size_t)max_blocks * sizeof(int32_t)))
LZFSE_REQUIRES(n_out != NULL && __CPROVER_rw_ok(n_out, sizeof *n_out))
LZFSE_REQUIRES(*n_out >= 0 && *n_out < max_blocks)
LZFSE_ASSIGNS(__CPROVER_object_whole(z), __CPROVER_object_whole(out), *n_out)
LZFSE_ENSURES(*n_out >= __CPROVER_old(*n_out) && *n_out < max_blocks)
#else
static void split_recurse(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                          int32_t lo, int32_t hi, int32_t max_blocks,
                          int32_t *out, int32_t *n_out)
#endif
{
  if (*n_out + 1 >= max_blocks) return; // blocks == splits + 1
  double whole = split_range_bits(s, z, lo, hi, z->split_l_occ_a, z->split_m_occ_a,
                                  z->split_d_occ_a, z->split_lit_occ_a);
  int32_t t = split_find_best(s, z, lo, hi, whole);
  if (t < 0) return;
  out[(*n_out)++] = t;
  split_recurse(s, z, lo, t, max_blocks, out, n_out);
  split_recurse(s, z, t, hi, max_blocks, out, n_out);
}

// Rebuilds the DP's cost model from a histogram. Returns the histogram's
// cross-entropy under that model, in bits, which run_dp_range compares across
// iterations to keep the best round.
static double zopt_refill_costs(lzfse_zopt_scratch *z,
                                const uint32_t *l_occ, const uint32_t *m_occ,
                                const uint32_t *d_occ, const uint32_t *lit_occ) {
  uint16_t freq[256];
  double l_bits_total = 0.0, m_bits_total = 0.0, d_bits_total = 0.0, lit_bits_total = 0.0;
  normalize_with_floor(l_occ, LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, freq);
  for (int i = 0; i < LZFSE_ENCODE_L_SYMBOLS; i++) {
    double bits = -log2((double)freq[i] / LZFSE_ENCODE_L_STATES);
    z->costq_l[i] = ZOPT_PRICE_OF(bits + l_extra_bits[i]);
    l_bits_total += (double)l_occ[i] * ((float)bits + l_extra_bits[i]);
  }
  normalize_with_floor(m_occ, LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, freq);
  for (int i = 0; i < LZFSE_ENCODE_M_SYMBOLS; i++) {
    double bits = -log2((double)freq[i] / LZFSE_ENCODE_M_STATES);
    z->costq_m[i] = ZOPT_PRICE_OF(bits + m_extra_bits[i]);
    m_bits_total += (double)m_occ[i] * ((float)bits + m_extra_bits[i]);
  }
  normalize_with_floor(d_occ, LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, freq);
  for (int i = 0; i < LZFSE_ENCODE_D_SYMBOLS; i++) {
    double bits = -log2((double)freq[i] / LZFSE_ENCODE_D_STATES);
    z->costq_d[i] = ZOPT_PRICE_OF(bits + d_extra_bits[i]);
    d_bits_total += (double)d_occ[i] * ((float)bits + d_extra_bits[i]);
  }
  normalize_with_floor(lit_occ, LZFSE_ENCODE_LITERAL_STATES, 256, freq);
  for (int i = 0; i < 256; i++) {
    double bits = -log2((double)freq[i] / LZFSE_ENCODE_LITERAL_STATES);
    z->costq_lit[i] = ZOPT_PRICE_OF(bits); // literals carry no extra bits
    lit_bits_total += (double)lit_occ[i] * (float)bits;
  }
  return l_bits_total + m_bits_total + d_bits_total + lit_bits_total;
}

// Steps 1.5 and 2 over [start_pos, end_pos), so each side of a split can be
static inline void copy_slot(lzfse_dp_slot *dst, const lzfse_dp_slot *src) {
  uint64_t w0;
  uint32_t w1;
  memcpy(&w0, src, 8);
  memcpy(&w1, (const char *)src + 8, 4);
  memcpy(dst, &w0, 8);
  memcpy((char *)dst + 8, &w1, 4);
}

// parsed under its own cost model. Step 1's candidates are whole-chunk and
// may reference earlier ranges, as the format allows: only the entropy tables
// and the repeat distance reset at a block boundary, never the LZ window. On
// return the winning sequence is in z->best_tup_L/M/D and best_n_tuples;
// returns 0 if backtracking overflowed z->max_tuples.
#if defined(LZFSE_BASE_PROOF)
static __attribute__((noinline)) int run_dp_range(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                                                  lzfse_offset start_pos, lzfse_offset end_pos,
                                                  lzfse_offset search_end, size_t cstride,
                                                  int max_iters,
                                                  const uint32_t *pre_l_occ, const uint32_t *pre_m_occ,
                                                  const uint32_t *pre_d_occ, const uint32_t *pre_lit_occ,
                                                  const uint32_t *lmd_seed)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(z != NULL && __CPROVER_rw_ok(z, sizeof *z))
LZFSE_ASSIGNS(__CPROVER_object_whole(z))
LZFSE_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == 1)
#else
static int run_dp_range(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                         lzfse_offset start_pos, lzfse_offset end_pos,
                         lzfse_offset search_end, size_t cstride,
                         int max_iters,
                         const uint32_t *pre_l_occ, const uint32_t *pre_m_occ,
                         const uint32_t *pre_d_occ, const uint32_t *pre_lit_occ,
                         const uint32_t *lmd_seed)
#endif
{
  int tuple_overflow = 0;
  const uint8_t bucket0 = l_base_from_value(0);
  const uint8_t maxb = l_base_from_value(LZFSE_ENCODE_MAX_L_VALUE);
  const int max_live = z->max_live_buckets;
  /* Read once; the inner loop below is the encoder's hottest. */
  const int32_t tuple_tax = z->tuple_tax;

  // --- Step 1.5: Seed iteration 0's costs from pre-tallied model or greedy
  // pre-pass. A chained lmd_seed replaces the pre-pass's L, M and D counts;
  // its literal counts measured worse than the chunk's own, so they stay.
  if (pre_l_occ != NULL) {
    zopt_refill_costs(z, pre_l_occ, pre_m_occ, pre_d_occ, pre_lit_occ);
  } else {
    uint32_t l_occ0[LZFSE_ENCODE_L_SYMBOLS] = {0};
    uint32_t m_occ0[LZFSE_ENCODE_M_SYMBOLS] = {0};
    uint32_t d_occ0[LZFSE_ENCODE_D_SYMBOLS] = {0};
    uint32_t lit_occ0[256] = {0};
    uint32_t l_total0 = 0;
    uint32_t d_prev0 = 0;
    uint32_t run_len = 0;
    lzfse_offset pos = start_pos;
    while (pos < end_pos) {
      int32_t best_len = 0, best_dist = 0;
      if (pos < search_end) {
        uint16_t cnt = z->cand_count[pos];
        const int32_t *lens = z->cand_len + (size_t)pos * cstride;
        const int32_t *dists = z->cand_dist + (size_t)pos * cstride;
        for (uint16_t k = 0; k < cnt; k++) {
          int32_t l = lens[k] & 0xffff;
          if (l > best_len) {
            best_len = l;
            best_dist = dists[k];
          }
        }
      }
      if (best_len >= ZOPT_MIN_MATCH_LEN && pos + best_len <= end_pos) {
        uint32_t Lrem = run_len;
        while (Lrem > LZFSE_ENCODE_MAX_L_VALUE) {
          l_occ0[l_base_from_value(LZFSE_ENCODE_MAX_L_VALUE)]++; l_total0++;
          Lrem -= LZFSE_ENCODE_MAX_L_VALUE;
        }
        l_occ0[l_base_from_value(Lrem)]++; l_total0++;
        run_len = 0;

        m_occ0[m_base_from_value((uint32_t)best_len)]++;
        uint32_t d_sym_val = (d_prev0 != 0 && (uint32_t)best_dist == d_prev0) ? 0 : (uint32_t)best_dist;
        d_occ0[lzfse_d_symbol(d_sym_val)]++;
        d_prev0 = (uint32_t)best_dist;
        pos += best_len;
      } else {
        lit_occ0[s->src[pos]]++;
        run_len++;
        pos++;
      }
    }
    if (run_len > 0 || l_total0 == 0) {
      uint32_t Lrem = run_len;
      while (Lrem > LZFSE_ENCODE_MAX_L_VALUE) {
        l_occ0[l_base_from_value(LZFSE_ENCODE_MAX_L_VALUE)]++; l_total0++;
        Lrem -= LZFSE_ENCODE_MAX_L_VALUE;
      }
      l_occ0[l_base_from_value(Lrem)]++; l_total0++;
    }

    if (lmd_seed != NULL) {
      memcpy(l_occ0, lmd_seed, sizeof l_occ0);
      memcpy(m_occ0, lmd_seed + LZFSE_ENCODE_L_SYMBOLS, sizeof m_occ0);
      memcpy(d_occ0, lmd_seed + LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS, sizeof d_occ0);
    }
    zopt_refill_costs(z, l_occ0, m_occ0, d_occ0, lit_occ0);
  }

  // --- Step 2: iterative cost-refined DP over [start_pos, end_pos).
  double best_cost = 1e300;
  z->best_n_tuples = 0;
  int have_prev_iter_cost = 0;
  double prev_iter_cost = 0.0;

  int iters = (max_iters > 0 && max_iters < z->iterations) ? max_iters : z->iterations;
  for (int iter = 0; iter < iters; iter++) {
    int32_t *__restrict const dp_cost0 = z->dp_cost0;
    int32_t *__restrict const dp_via_len = z->dp_via_len;
    int32_t *__restrict const dp_via_dist = z->dp_via_dist;
    const int32_t *__restrict const costq_l = z->costq_l;
    const int32_t *__restrict const costq_d = z->costq_d;
    const int32_t *__restrict const costq_lit = z->costq_lit;
    lzfse_dp_slot *__restrict const dp_slot = z->dp_slot;
    uint8_t *__restrict const dp_nslot = z->dp_nslot;
    const uint16_t *__restrict const cand_count = z->cand_count;
    const int32_t *__restrict const cand_len = z->cand_len;
    const int32_t *__restrict const cand_dist = z->cand_dist;
    const size_t dp_nslots = (size_t)z->dp_nslots;

    dp_cost0[start_pos] = 0;
    dp_via_dist[start_pos] = 0;
    dp_nslot[start_pos] = 0; // only bucket0 is live at the start
    for (lzfse_offset i = start_pos + 1; i <= end_pos; i++) {
      dp_cost0[i] = ZOPT_PRICE_UNREACHABLE;
      dp_nslot[i] = 0;
    }

    int32_t costq_m_len[LZFSE_ENCODE_MAX_M_VALUE + 1];
    for (int m = 0; m <= LZFSE_ENCODE_MAX_M_VALUE; m++)
      costq_m_len[m] = z->costq_m[m_base_from_value(m)];

    uint8_t l_sym_len[LZFSE_ENCODE_MAX_L_VALUE + 1];
    int32_t costq_l_len[LZFSE_ENCODE_MAX_L_VALUE + 1];
    for (int l = 0; l <= LZFSE_ENCODE_MAX_L_VALUE; l++) {
      uint8_t sym = l_base_from_value(l);
      l_sym_len[l] = sym;
      costq_l_len[l] = costq_l[sym];
    }

    const int32_t *lens_ptr = cand_len + (size_t)start_pos * cstride;
    const int32_t *dists_ptr = cand_dist + (size_t)start_pos * cstride;
    for (lzfse_offset i = start_pos; i < end_pos; i++, lens_ptr += cstride, dists_ptr += cstride) {
      // The cheapest state at i serves every match step (match cost does not
      // depend on the pending run); literal steps need each bucket separately.
      int32_t best_here = ZOPT_PRICE_UNREACHABLE;
      int best_b = -1;
      int32_t best_ld = 0;
      // Pass 1: gather this position's states in ascending bucket order
      // (bucket 0, then the sorted slots), find the cheapest, and drop any
      // over the literal-step cap.
      lzfse_dp_slot cand[LZFSE_ENCODE_L_SYMBOLS + 1];
      int ncand = 0;
      {
        int32_t c0 = dp_cost0[i];
        if (c0 < ZOPT_PRICE_UNREACHABLE_THRESHOLD) {
          cand[0].cost = c0;
          cand[0].last_dist = dp_via_dist[i];
          cand[0].run_len = 0; // bucket0 IS the run-length-0 state
          cand[0].bucket = (int8_t)bucket0;
          cand[0].prev_bucket = -1; // never read: bucket0 is a match landing
          ncand = 1;
          best_here = c0;
          best_b = bucket0;
          best_ld = dp_via_dist[i];
        }
        const lzfse_dp_slot *row = dp_slot + (size_t)i * dp_nslots;
        int ns = (int)dp_nslot[i];
        for (int t = 0; t < ns; t++) {
          copy_slot(&cand[ncand], &row[t]);
          if (cand[ncand].cost < best_here) {
            best_here = cand[ncand].cost;
            best_b = cand[ncand].bucket;
            best_ld = cand[ncand].last_dist;
          }
          ncand++;
        }

        // At most one state exceeds the cap (max_live slots plus bucket 0), so
        // drop the single dearest; `>=` drops the last of a tie.
        if (ncand > max_live) {
          int drop = 0;
          for (int t = 1; t < ncand; t++) if (cand[t].cost >= cand[drop].cost) drop = t;
          for (int t = drop; t + 1 < ncand; t++) copy_slot(&cand[t], &cand[t + 1]);
          ncand--;
        }
      }

      // Pass 2: the literal steps, over the survivors.
      if (ncand > 0) {
        uint8_t src_byte = s->src[i];
        int32_t lit_cost = costq_lit[src_byte];
        lzfse_dp_slot *next_row = dp_slot + (size_t)(i + 1) * dp_nslots;
        int next_ns = (int)dp_nslot[i + 1];

        for (int ci = 0; ci < ncand; ci++) {
          int b = cand[ci].bucket;
          int32_t c = cand[ci].cost;
          int32_t last_dist_b = cand[ci].last_dist;

          int32_t R = cand[ci].run_len;
          int32_t newR = R + 1;
          uint8_t newb;
          int32_t newc;
          if (newR > LZFSE_ENCODE_MAX_L_VALUE) {
            int32_t closed = c - costq_l[b] + costq_l[maxb];
            newR = 1;
            newb = l_sym_len[1];
            newc = closed + lit_cost + costq_l_len[1];
          } else {
            newb = l_sym_len[newR];
            newc = c - costq_l[b] + costq_l_len[newR] + lit_cost;
          }

          int t = 0;
          while (t < next_ns && next_row[t].bucket < (int8_t)newb) t++;
          if (t < next_ns && next_row[t].bucket == (int8_t)newb) {
            if (newc < next_row[t].cost) {
              next_row[t].cost = newc;
              next_row[t].run_len = (int16_t)newR;
              next_row[t].last_dist = last_dist_b;
              next_row[t].prev_bucket = (int8_t)b;
            }
          } else if (next_ns < (int)dp_nslots) {
            for (int u = next_ns; u > t; u--) copy_slot(&next_row[u], &next_row[u - 1]);
            next_row[t].cost = newc;
            next_row[t].run_len = (int16_t)newR;
            next_row[t].last_dist = last_dist_b;
            next_row[t].bucket = (int8_t)newb;
            next_row[t].prev_bucket = (int8_t)b;
            next_ns++;
          }
        }
        dp_nslot[i + 1] = (uint8_t)next_ns;
      }


      // Match steps from the cheapest state at i.
      if (best_b >= 0 && i < search_end) {
        int32_t last_d = best_ld;
        int32_t max_m = (int32_t)(end_pos - i);

        int32_t sublen_window = (z->search_depth >= 16) ? 2 : ZOPT_SUBLEN_WINDOW;
        int32_t *__restrict const cost0_i = dp_cost0 + i;
        int32_t *__restrict const via_len_i = dp_via_len + i;
        int32_t *__restrict const via_dist_i = dp_via_dist + i;

        // Repeat-distance probe; last_d is DP state, so it lives here rather
        // than in the candidate build.
        if (last_d > 0 && (lzfse_offset)last_d <= i) {
          const uint8_t *rp = s->src + i - last_d;
          const uint8_t *cp = s->src + i;
          if (load2(rp) == load2(cp)) {
            uint32_t rep_max = (uint32_t)(s->src_end - i - 8); // same 8-byte load headroom as the candidate search
            if (rep_max > LZFSE_ENCODE_MAX_M_VALUE) rep_max = LZFSE_ENCODE_MAX_M_VALUE;
            uint32_t rl = match_extend(rp, cp, 2, rep_max);
            int32_t rbase = best_here + costq_d[0] + costq_l[bucket0] + tuple_tax;
            int32_t rlo = (int32_t)rl - sublen_window; if (rlo < ZOPT_MIN_REPEAT_MATCH_LEN) rlo = ZOPT_MIN_REPEAT_MATCH_LEN;
            int32_t rhi = (int32_t)rl < max_m ? (int32_t)rl : max_m;
            if (sublen_window == 1) {
              int32_t c_hi = rbase + costq_m_len[rhi];
              if (c_hi < cost0_i[rhi]) {
                cost0_i[rhi] = c_hi;
                via_len_i[rhi] = rhi;
                via_dist_i[rhi] = last_d;
              }
              if (rlo < rhi) {
                int32_t r1 = rhi - 1;
                int32_t c1 = rbase + costq_m_len[r1];
                if (c1 < cost0_i[r1]) {
                  cost0_i[r1] = c1;
                  via_len_i[r1] = r1;
                  via_dist_i[r1] = last_d;
                }
              }
            } else {
              for (int32_t m = rlo; m <= rhi; m++) {
                int32_t c = rbase + costq_m_len[m];
                if (c < cost0_i[m]) {
                  cost0_i[m] = c;
                  via_len_i[m] = m;
                  via_dist_i[m] = last_d;
                }
              }
            }
          }
        }

        uint16_t cnt = cand_count[i];
        if (cnt > 0) {
          const int32_t *lens = lens_ptr;
          const int32_t *dists = dists_ptr;
          int32_t match_tax = best_here + costq_l[bucket0] + tuple_tax;
          // Sub-length expansion.
          for (uint16_t k = 0; k < cnt; k++) {
            int32_t raw = lens[k];
            int32_t length = raw & 0xffff;
            int32_t dist = dists[k];
            int is_repeat = (last_d != 0 && dist == last_d);
            uint8_t d_sym = is_repeat ? 0 : (uint8_t)(raw >> 16);
            int32_t base = match_tax + costq_d[d_sym];
            int32_t m_lo = length - sublen_window; if (m_lo < ZOPT_MIN_MATCH_LEN) m_lo = ZOPT_MIN_MATCH_LEN;
            int32_t m_hi = length < max_m ? length : max_m;
            if (sublen_window == 1) {
              int32_t c_hi = base + costq_m_len[m_hi];
              if (c_hi < cost0_i[m_hi]) {
                cost0_i[m_hi] = c_hi;
                via_len_i[m_hi] = m_hi;
                via_dist_i[m_hi] = dist;
              }
              if (m_lo < m_hi) {
                int32_t m1 = m_hi - 1;
                int32_t c1 = base + costq_m_len[m1];
                if (c1 < cost0_i[m1]) {
                  cost0_i[m1] = c1;
                  via_len_i[m1] = m1;
                  via_dist_i[m1] = dist;
                }
              }
            } else {
            for (int32_t m = m_lo; m <= m_hi; m++) {
              int32_t c = base + costq_m_len[m];
              if (c < cost0_i[m]) {
                cost0_i[m] = c;
                via_len_i[m] = m;
                via_dist_i[m] = dist;
              }
            }
          }
        }
      }
    }
  }

    // --- backtrack from end_pos to reconstruct this range's tuple sequence.
    z->n_tuples = 0;
    {
      int32_t final_best = z->dp_cost0[end_pos];
      int final_b = bucket0;
      {
        const lzfse_dp_slot *row = z->dp_slot + (size_t)end_pos * (size_t)z->dp_nslots;
        int ns = (int)z->dp_nslot[end_pos];
        for (int t = 0; t < ns; t++)
          if (row[t].cost < final_best) { final_best = row[t].cost; final_b = row[t].bucket; }
      }
      lzfse_offset pos = end_pos;
      int cur_b = final_b;
      int32_t *rev_len = z->rev_len, *rev_dist = z->rev_dist, *rev_lit_run = z->rev_lit_run;
      int32_t nrev = 0;
      int32_t pending_lit = 0;
      while (pos > start_pos) {
        // Bucket 0 is reached only by a match edge.
        if (cur_b == bucket0) {
          if (nrev >= z->max_tuples) { tuple_overflow = 1; break; }
          int32_t len = z->dp_via_len[pos];
          rev_len[nrev] = len;
          rev_dist[nrev] = z->dp_via_dist[pos];
          rev_lit_run[nrev] = pending_lit;
          nrev++;
          pending_lit = 0;
          pos -= len;
          int32_t best_c = z->dp_cost0[pos]; int best_bb = bucket0;
          {
            const lzfse_dp_slot *row = z->dp_slot + (size_t)pos * (size_t)z->dp_nslots;
            int ns = (int)z->dp_nslot[pos];
            for (int t = 0; t < ns; t++)
              if (row[t].cost < best_c) { best_c = row[t].cost; best_bb = row[t].bucket; }
          }
          cur_b = best_bb;
        } else {
          pending_lit++;
          // cur_b != bucket0 here, so it must be one of pos's slots.
          int prev_b = cur_b;
          {
            const lzfse_dp_slot *row = z->dp_slot + (size_t)pos * (size_t)z->dp_nslots;
            int ns = (int)z->dp_nslot[pos];
            for (int t = 0; t < ns; t++)
              if (row[t].bucket == (int8_t)cur_b) { prev_b = row[t].prev_bucket; break; }
          }
          pos--;
          cur_b = prev_b;
        }
      }
      if (!tuple_overflow) {
        uint32_t running_L = (uint32_t)pending_lit;
        for (int32_t r = nrev - 1; r >= 0 && !tuple_overflow; r--) {
          if (z->n_tuples >= z->max_tuples) { tuple_overflow = 1; break; }
          z->tup_L[z->n_tuples] = running_L;
          z->tup_M[z->n_tuples] = (uint32_t)rev_len[r];
          z->tup_D[z->n_tuples] = (uint32_t)rev_dist[r];
          z->n_tuples++;
          running_L = (uint32_t)rev_lit_run[r];
        }
        if (!tuple_overflow && (running_L > 0 || z->n_tuples == 0)) {
          if (z->n_tuples >= z->max_tuples) {
            tuple_overflow = 1;
          } else {
            z->tup_L[z->n_tuples] = running_L;
            z->tup_M[z->n_tuples] = 0;
            z->tup_D[z->n_tuples] = 0;
            z->n_tuples++;
          }
        }
      }
    }
    if (tuple_overflow) return 0;

    // --- tally this range's parse and refine the costs for the next pass;
    // tup_L/M/D are relative to start_pos.
    tally_tuple_subrange(z->tup_L, z->tup_M, z->tup_D, 0, z->n_tuples, s->src, start_pos,
                         z->l_occ, z->m_occ, z->d_occ, z->lit_occ);

    // The round is scored by its parse's cross-entropy under the model it
    // just produced, not by the DP cost the previous model priced.
    double iter_cost = zopt_refill_costs(z, z->l_occ, z->m_occ, z->d_occ, z->lit_occ);

    if (iter_cost < best_cost) {
      best_cost = iter_cost;
      memcpy(z->best_tup_L, z->tup_L, sizeof(uint32_t) * (size_t)z->n_tuples);
      memcpy(z->best_tup_M, z->tup_M, sizeof(uint32_t) * (size_t)z->n_tuples);
      memcpy(z->best_tup_D, z->tup_D, sizeof(uint32_t) * (size_t)z->n_tuples);
      z->best_n_tuples = z->n_tuples;
    }

    // Early exit when the round fails to improve by at least 4 bytes (32 bits).
    if (have_prev_iter_cost && (prev_iter_cost - iter_cost < 32.0)) break;
    prev_iter_cost = iter_cost;
    have_prev_iter_cost = 1;
  }

  return 1;
}

#if defined(LZFSE_BASE_PROOF)
static __attribute__((noinline)) void lzfse_zopt_build_candidates(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                                                                  lzfse_offset search_end, size_t cstride,
                                                                  lzfse_offset total_len)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(z != NULL && __CPROVER_rw_ok(z, sizeof *z))
LZFSE_ASSIGNS(__CPROVER_object_whole(z))
#else
static void lzfse_zopt_build_candidates(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                                        lzfse_offset search_end, size_t cstride,
                                        lzfse_offset total_len)
#endif
{
  int32_t *__restrict const son = z->bt_son;
  int32_t *__restrict const head = z->bt_head;
  uint16_t *__restrict const cand_count = z->cand_count;
  const uint32_t root_bits = bt_root_bits((uint32_t)z->hash_bits, (size_t)total_len);
  const int32_t depth = z->search_depth;
  const int cap = (int)cstride;
  memset(head, 0xFF, ((size_t)1 << root_bits) * sizeof(*head));
  // Only [0, total_len) is ever written below or read (guarded by
  // `pos < search_end` in run_dp_range).
  memset(cand_count, 0, (size_t)total_len * sizeof(*cand_count));

  lzfse_offset skip_until = 0, skip_end = 0;
  int32_t skip_dist = 0;
  int32_t ml[BT_MAX_MATCHES], md[BT_MAX_MATCHES];
  for (lzfse_offset pos = 0; pos < search_end; pos++) {
    int32_t *lp = z->cand_len + (size_t)pos * cstride;
    int32_t *dp = z->cand_dist + (size_t)pos * cstride;
    if (pos < skip_until) {
      uint32_t l = (uint32_t)(skip_end - pos);
      if (l > LZFSE_ENCODE_MAX_M_VALUE) l = LZFSE_ENCODE_MAX_M_VALUE;
      lp[0] = (int32_t)l | ((int32_t)lzfse_d_symbol((uint32_t)skip_dist) << 16);
      dp[0] = skip_dist;
      cand_count[pos] = 1;
      continue;
    }
    uint32_t longest;
    int32_t longest_dist;
    int n = bt_insert_find(s->src, (int32_t)pos, (uint32_t)(s->src_end - pos - 8), depth,
                           LZFSE_ENCODE_MAX_D_VALUE, ZOPT_MIN_MATCH_LEN, LZFSE_ENCODE_MAX_M_VALUE,
                           son, head + bt_hash3(s->src + pos, root_bits), ml, md, &longest, &longest_dist);
    int first = n > cap ? n - cap : 0;
    uint16_t cnt = 0;
    for (int k = first; k < n; k++, cnt++) {
      lp[cnt] = ml[k] | ((int32_t)lzfse_d_symbol((uint32_t)md[k]) << 16);
      dp[cnt] = md[k];
    }
    cand_count[pos] = cnt;
    if (longest >= ZOPT_BT_SKIP_LEN) {
      skip_end = pos + (lzfse_offset)longest;
      skip_until = skip_end - ZOPT_BT_SKIP_KEEP;
      skip_dist = longest_dist;
    }
  }
}

#if defined(LZFSE_BASE_PROOF)
static __attribute__((noinline)) void lzfse_zopt_find_splits(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                                                             int32_t *n_splits)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(z != NULL && __CPROVER_rw_ok(z, sizeof *z))
LZFSE_REQUIRES(__CPROVER_rw_ok(n_splits, sizeof *n_splits))
LZFSE_ASSIGNS(__CPROVER_object_whole(z), *n_splits)
LZFSE_ENSURES(*n_splits >= 0)
#else
static void lzfse_zopt_find_splits(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                                   int32_t *n_splits)
#endif
{
  int32_t *split_at = z->split_at;
  *n_splits = 0;
  if (z->split_max_blocks > 1 && z->best_n_tuples > 1) {
    z->tuple_start_pos[0] = 0;
    for (int32_t t = 0; t < z->best_n_tuples; t++) {
      z->tuple_start_pos[t + 1] = z->tuple_start_pos[t] + (lzfse_offset)z->best_tup_L[t] + (lzfse_offset)z->best_tup_M[t];
    }
    split_recurse(s, z, 0, z->best_n_tuples, z->split_max_blocks, split_at, n_splits);
    // The recursion records splits out of order; the commit loop wants them
    // ascending.
    for (int32_t i = 1; i < *n_splits; i++) {
      int32_t v = split_at[i], j = i - 1;
      while (j >= 0 && split_at[j] > v) { split_at[j + 1] = split_at[j]; j--; }
      split_at[j + 1] = v;
    }
  }
}

#if defined(LZFSE_BASE_PROOF)
static __attribute__((noinline)) int lzfse_zopt_commit(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                                                       int32_t n_splits,
                                                       lzfse_offset total_len, lzfse_offset search_end,
                                                       size_t cstride)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(z != NULL && __CPROVER_rw_ok(z, sizeof *z))
LZFSE_REQUIRES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_REQUIRES(s->src_literal >= 0 && s->src_literal <= s->src_end)
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == 1)
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end)
#else
static int lzfse_zopt_commit(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                             int32_t n_splits,
                             lzfse_offset total_len, lzfse_offset search_end,
                             size_t cstride)
#endif
{
  int ok = 1;
  const int32_t *split_at = z->split_at;
  if (z->enable_reparse && n_splits > 0) {
    enum { STACK_SPLITS = 8 };
    uint32_t sub_l[STACK_SPLITS][LZFSE_ENCODE_L_SYMBOLS];
    uint32_t sub_m[STACK_SPLITS][LZFSE_ENCODE_M_SYMBOLS];
    uint32_t sub_d[STACK_SPLITS][LZFSE_ENCODE_D_SYMBOLS];
    uint32_t sub_lit[STACK_SPLITS][256];
    int use_pre = (n_splits + 1 <= STACK_SPLITS);
    if (use_pre) {
      int32_t t_cur = 0;
      for (int32_t r = 0; r <= n_splits; r++) {
        int32_t t_next = (r < n_splits) ? split_at[r] : z->best_n_tuples;
        lzfse_offset r_pos = z->tuple_start_pos[t_cur];
        tally_tuple_subrange(z->best_tup_L, z->best_tup_M, z->best_tup_D, t_cur, t_next,
                             s->src, r_pos, sub_l[r], sub_m[r], sub_d[r], sub_lit[r]);
        t_cur = t_next;
      }
    }
    lzfse_offset range_start = 0;
    for (int32_t r = 0; r <= n_splits; r++) {
      lzfse_offset range_end = (r < n_splits) ? z->tuple_start_pos[split_at[r]] : total_len;
      // Overwrites best_tup_L/M/D; committed before the next range reuses the
      // scratch.
      const uint32_t *pl = use_pre ? sub_l[r] : NULL;
      const uint32_t *pm = use_pre ? sub_m[r] : NULL;
      const uint32_t *pd = use_pre ? sub_d[r] : NULL;
      const uint32_t *plit = use_pre ? sub_lit[r] : NULL;
      if (!run_dp_range(s, z, range_start, range_end, search_end, cstride, 1, pl, pm, pd, plit, NULL)) { ok = 0; goto END; }
      for (int32_t t = 0; t < z->best_n_tuples; t++) {
        uint32_t L = z->best_tup_L[t], M = z->best_tup_M[t], D = z->best_tup_D[t];
        if (M == 0) {
          if (L > 0 && lzfse_backend_literals(s, L) != LZFSE_STATUS_OK) { ok = 0; goto END; }
          continue;
        }
        lzfse_match match;
        match.pos = s->src_literal + L;
        match.ref = match.pos - D;
        match.length = M;
        if (lzfse_backend_match(s, &match) != LZFSE_STATUS_OK) { ok = 0; goto END; }
      }
      if (r < n_splits) {
        if (lzfse_encode_matches(s) != LZFSE_STATUS_OK) { ok = 0; goto END; }
      }
      range_start = range_end;
    }
  } else {
    int32_t next_split = 0;
    for (int32_t t = 0; t < z->best_n_tuples; t++) {
      if (next_split < n_splits && t == split_at[next_split]) {
        if (lzfse_encode_matches(s) != LZFSE_STATUS_OK) { ok = 0; goto END; }
        next_split++;
      }
      uint32_t L = z->best_tup_L[t], M = z->best_tup_M[t], D = z->best_tup_D[t];
      if (M == 0) {
        if (L > 0 && lzfse_backend_literals(s, L) != LZFSE_STATUS_OK) { ok = 0; goto END; }
        continue;
      }
      lzfse_match match;
      match.pos = s->src_literal + L;
      match.ref = match.pos - D;
      match.length = M;
      if (lzfse_backend_match(s, &match) != LZFSE_STATUS_OK) { ok = 0; goto END; }
    }
  }
END:
  return ok;
}

int lzfse_encode_base(lzfse_encoder_state *s) {
  int ok = 1;
  lzfse_offset total_len = s->src_end;
  assert(s->src_encode_i == 0); // single-shot usage only, see file header

  // The caller carves s->zopt out of its scratch (crushlzfse.c).
#ifndef CRUSHLZFSE_DISPATCH_PROOF
  assert(s->zopt != NULL);
#endif
  if (s->zopt == NULL) return LZFSE_STATUS_ERROR;
  lzfse_zopt_scratch *z = s->zopt;

  // Beyond what z was sized for: push it as literals so the caller's raw
  // fallback takes over.
  if (total_len > LZFSE_ZOPT_BLOCK_SIZE) {
    s->src_encode_i = s->src_end;
    return lzfse_backend_literals(s, total_len) == LZFSE_STATUS_OK ? LZFSE_STATUS_OK : LZFSE_STATUS_DST_FULL;
  }

  // Range-clamp the per-call fields rather than trust the caller. Capacity
  // says how much was allocated, so it is clamped into range, never up.
  if (z->cand_capacity < 1) z->cand_capacity = 1;
  if (z->cand_capacity > ZOPT_MAX_STORE_LIMIT) z->cand_capacity = ZOPT_MAX_STORE_LIMIT;
  if (z->search_depth < 1 || z->search_depth > ZOPT_MAX_SEARCH_DEPTH) z->search_depth = ZOPT_DEFAULT_SEARCH_DEPTH;
  if (z->iterations < 1 || z->iterations > ZOPT_MAX_ITERATIONS) z->iterations = ZOPT_DEFAULT_ITERATIONS;
  if (z->max_live_buckets < 1 || z->max_live_buckets > LZFSE_ENCODE_L_SYMBOLS)
    z->max_live_buckets = ZOPT_MAX_LIVE_BUCKETS;
  /* Negative would reward tuples; the ceiling keeps the summed price below
   * ZOPT_PRICE_UNREACHABLE. */
  if (z->tuple_tax < 0 || z->tuple_tax > ZOPT_MAX_TUPLE_TAX)
    z->tuple_tax = 0;
  // The slot rows are carved at init (dp_nslots); a larger cap would write a
  // slot the row does not have.
  if (z->dp_nslots >= 1 && z->max_live_buckets > z->dp_nslots)
    z->max_live_buckets = z->dp_nslots;

  const size_t cstride = (size_t)z->cand_capacity;

  s->src_encode_end = s->src_end - 8; // 8-byte padding, same convention as stock
  lzfse_offset search_end = s->src_encode_end;

  // --- Step 1: build match candidates once; only which ones are chosen
  // changes across iterations. Each position keeps the longest cand_capacity
  // of the increasing run its tree walk returns (bt_match.h).
  lzfse_zopt_build_candidates(s, z, search_end, cstride, total_len);

  // --- Steps 1.5 + 2 over the whole chunk.
  if (!run_dp_range(s, z, 0, total_len, search_end, cstride, 0, NULL, NULL, NULL, NULL, s->lmd_seed)) { ok = 0; goto END; }

  // --- Voluntary block splitting over the chosen best_tup_L/M/D: price
  // candidate cuts exactly and keep those that beat the one-block baseline.
  int32_t n_splits = 0;
  lzfse_zopt_find_splits(s, z, &n_splits);

  // --- Step 3: commit the best-scoring iteration's sequence to the backend,
  // flushing a block at each split point.
  if (!lzfse_zopt_commit(s, z, n_splits, total_len, search_end, cstride)) {
    ok = 0;
    goto END;
  }

END:
  s->src_encode_i = s->src_encode_end;
  return ok ? LZFSE_STATUS_OK : LZFSE_STATUS_DST_FULL;
}

// Fast strategy, levels -5 to -1. Tables hold 16-bit positions (a call never
// exceeds 64 KiB) and are written without a check: every entry, zeroed or
// stale, names an earlier position of this block, which the compare then
// accepts or rejects on its bytes. Every probe also tries the last distance
// one byte ahead, since LZFSE sends a repeated D as the single symbol 0.
//
// One table: two adjacent positions per probe, each match found taken.
// long_table adds a second table hashed on 8 bytes, consulted first; a
// short-table hit is traded for a long-table hit one byte later. lazy
// extends both candidates and then steps one byte ahead, at most twice,
// while that finds a match at least two bytes longer; a hit on the last
// distance is taken without the lazy steps. min_match is only the hashed
// length: candidates are verified on 4 bytes.
//
// Unmatched stretches are crossed with a stride that grows by one per
// 2^skip_shift bytes since the last match, up to max_step. Only probed
// positions and a few inside each match are indexed. Matches are written
// straight into the block's L/M/D and literal arrays.

// Every position in a block must fit the tables' uint16_t entries. A
// negative array bound rather than _Static_assert, since this file is C99.
typedef char crushlzfse_fast_positions_fit_16_bits[LZFSE_ZOPT_BLOCK_SIZE <= 65536 ? 1 : -1];

// Appends one match and the literals from anchor (s->src_literal) up to it,
// when they fit one LMD and the block has room; anything else takes the
// general path, which splits and flushes. Reads up to 15 bytes past the
// literals, which the caller's 16 byte end margin covers.
LZFSE_INLINE int crushlzfse_fast_emit(lzfse_encoder_state *s, lzfse_offset anchor, lzfse_offset mpos,
                                      uint32_t len, uint32_t d) {
  uint32_t L = (uint32_t)(mpos - anchor);
  uint32_t n = s->n_matches;
  uint32_t nl = s->n_literals;
  if (L <= LZFSE_ENCODE_MAX_L_VALUE && len <= LZFSE_ENCODE_MAX_M_VALUE &&
      n + 1 + 8 <= LZFSE_MATCHES_PER_BLOCK && nl + L + 16 <= LZFSE_LITERALS_PER_BLOCK) {
    s->l_values[n] = L;
    s->m_values[n] = len;
    s->d_values[n] = d;
    s->n_matches = n + 1;
    s->n_literals = nl + L;
    s->src_literal = mpos + len;
    uint8_t *dst = s->literals + nl;
    const uint8_t *lit = s->src + anchor;
    copy16(dst, lit);
    for (uint32_t i = 16; i < L; i += 16) copy16(dst + i, lit + i);
    return LZFSE_STATUS_OK;
  }
  lzfse_match m = {.pos = mpos, .ref = mpos - (lzfse_offset)d, .length = len};
  return lzfse_backend_match(s, &m);
}

// Advances ip past an unmatched probe of `probed` positions. Also bounds a
// literal run, as the greedy strategy does, so it can never outgrow
// LZFSE_LITERALS_PER_BLOCK on its own.
LZFSE_INLINE int crushlzfse_fast_skip(lzfse_encoder_state *s, lzfse_offset anchor, lzfse_offset *ip,
                                      int probed, int skip_shift, lzfse_offset max_step) {
  lzfse_offset step = probed + ((*ip - anchor) >> skip_shift);
  *ip += step < max_step ? step : max_step;
  if (*ip - anchor > 8 * LZFSE_ENCODE_MAX_L_VALUE)
    return lzfse_backend_literals(s, LZFSE_ENCODE_MAX_L_VALUE);
  return LZFSE_STATUS_OK;
}

#if defined(CRUSHLZFSE_DISPATCH_PROOF)
static __attribute__((noinline)) int crushlzfse_encode_base_fast_impl(lzfse_encoder_state *s, int hash_bits, int min_match,
                                                                      int skip_shift, int max_step, int long_table, int lazy,
                                                                      uint16_t *table, uint16_t *ltable)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_REQUIRES(hash_bits >= 10 && hash_bits <= 16)
LZFSE_REQUIRES(min_match >= 4 && min_match <= (long_table || lazy ? 6 : 8))
LZFSE_REQUIRES(skip_shift >= 1 && skip_shift <= 31)
LZFSE_REQUIRES(max_step >= 1 && max_step <= 64)
LZFSE_REQUIRES(long_table == 0 || long_table == 1)
LZFSE_REQUIRES(lazy == 0 || lazy == 1)
LZFSE_REQUIRES(__CPROVER_rw_ok(table, ((size_t)1 << hash_bits) * sizeof *table))
LZFSE_REQUIRES(!long_table || (ltable != NULL && __CPROVER_rw_ok(ltable, ((size_t)1 << hash_bits) * sizeof *ltable)))
LZFSE_ASSIGNS(__CPROVER_object_whole(table))
LZFSE_ASSIGNS(ltable != NULL: __CPROVER_object_whole(ltable))
LZFSE_ENSURES(LZFSE_ENCODE_STATUS(__CPROVER_return_value))
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end)
#else
LZFSE_INLINE int crushlzfse_encode_base_fast_impl(lzfse_encoder_state *s, int hash_bits, int min_match,
                                                  int skip_shift, int max_step, int long_table, int lazy,
                                                  uint16_t *table, uint16_t *ltable)
#endif
{
  const uint8_t *src = s->src;
  // Keeps every load8 below, and the emit's literal over-read, in bounds.
  const lzfse_offset ilimit = s->src_end - 16;
  // The stride never drops below the positions a probe covers.
  const int probed = (lazy || long_table) ? 1 : 2;
  const lzfse_offset max_stride = max_step > probed ? max_step : probed;
  uint64_t prime = CRUSHLZFSE_FAST_PRIME;
#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(prime)); // opaque, so it stays in a register
#endif
  lzfse_offset ip = s->src_encode_i;
  uint32_t rep = 0; // 0 until the first match: never a valid distance
  if (ip == 0) ip = 1;
  while (ip < ilimit) {
    // Read before the table stores below, which may alias it as far as the
    // compiler knows.
    const lzfse_offset anchor = s->src_literal;
    lzfse_offset mpos, mref;
    uint32_t len = crushlzfse_fast_find(src, s->src_end, ilimit, ip, anchor, rep, min_match, hash_bits, prime,
                                        table, ltable, long_table, lazy, &mpos, &mref);
    if (len == 0) {
      if (crushlzfse_fast_skip(s, anchor, &ip, probed, skip_shift, max_stride) != LZFSE_STATUS_OK) goto fail;
      continue;
    }
    rep = (uint32_t)(mpos - mref);
    if (crushlzfse_fast_emit(s, anchor, mpos, len, rep) != LZFSE_STATUS_OK) goto fail;
    lzfse_offset end = mpos + len;
    if (end < ilimit)
      crushlzfse_fast_index_match(src, mpos, end, min_match, hash_bits, prime, table, ltable, long_table);
    ip = end;
  }
  s->src_encode_i = ip;
  return LZFSE_STATUS_OK;
fail:
  s->src_encode_i = ip;
  return LZFSE_STATUS_DST_FULL;
}

// One instantiation per hashed length and mode, so each folds its hashes
// and branches. The long and lazy modes take min_match 4 to 6 only, which
// crushlzfse.c's validation enforces.
#define CRUSHLZFSE_FAST_INSTANCE(MM, LONG, LAZY)                                                   \
  static int crushlzfse_encode_base_fast_##MM##_##LONG##_##LAZY(lzfse_encoder_state *s, int hb,     \
                                                                 int ss, int ms, uint16_t *t,        \
                                                                 uint16_t *lt) {                     \
    return crushlzfse_encode_base_fast_impl(s, hb, MM, ss, ms, LONG, LAZY, t, lt);                  \
  }
CRUSHLZFSE_FAST_INSTANCE(4, 0, 0)
CRUSHLZFSE_FAST_INSTANCE(5, 0, 0)
CRUSHLZFSE_FAST_INSTANCE(6, 0, 0)
CRUSHLZFSE_FAST_INSTANCE(7, 0, 0)
CRUSHLZFSE_FAST_INSTANCE(8, 0, 0)
CRUSHLZFSE_FAST_INSTANCE(4, 1, 0)
CRUSHLZFSE_FAST_INSTANCE(5, 1, 0)
CRUSHLZFSE_FAST_INSTANCE(6, 1, 0)
CRUSHLZFSE_FAST_INSTANCE(4, 0, 1)
CRUSHLZFSE_FAST_INSTANCE(5, 0, 1)
CRUSHLZFSE_FAST_INSTANCE(6, 0, 1)
CRUSHLZFSE_FAST_INSTANCE(4, 1, 1)
CRUSHLZFSE_FAST_INSTANCE(5, 1, 1)
CRUSHLZFSE_FAST_INSTANCE(6, 1, 1)
#undef CRUSHLZFSE_FAST_INSTANCE

int crushlzfse_encode_base_fast(lzfse_encoder_state *s, int hash_bits, int min_match, int skip_shift,
                                int max_step, int long_table, int lazy, uint16_t *table, uint16_t *ltable) {
  int hb = hash_bits, ss = skip_shift, ms = max_step;
  if (!long_table && !lazy) {
    switch (min_match) {
    case 4: return crushlzfse_encode_base_fast_4_0_0(s, hb, ss, ms, table, ltable);
    case 5: return crushlzfse_encode_base_fast_5_0_0(s, hb, ss, ms, table, ltable);
    case 6: return crushlzfse_encode_base_fast_6_0_0(s, hb, ss, ms, table, ltable);
    case 7: return crushlzfse_encode_base_fast_7_0_0(s, hb, ss, ms, table, ltable);
    default: return crushlzfse_encode_base_fast_8_0_0(s, hb, ss, ms, table, ltable);
    }
  }
  if (long_table && !lazy) {
    switch (min_match) {
    case 4: return crushlzfse_encode_base_fast_4_1_0(s, hb, ss, ms, table, ltable);
    case 5: return crushlzfse_encode_base_fast_5_1_0(s, hb, ss, ms, table, ltable);
    default: return crushlzfse_encode_base_fast_6_1_0(s, hb, ss, ms, table, ltable);
    }
  }
  if (!long_table) {
    switch (min_match) {
    case 4: return crushlzfse_encode_base_fast_4_0_1(s, hb, ss, ms, table, ltable);
    case 5: return crushlzfse_encode_base_fast_5_0_1(s, hb, ss, ms, table, ltable);
    default: return crushlzfse_encode_base_fast_6_0_1(s, hb, ss, ms, table, ltable);
    }
  }
  switch (min_match) {
  case 4: return crushlzfse_encode_base_fast_4_1_1(s, hb, ss, ms, table, ltable);
  case 5: return crushlzfse_encode_base_fast_5_1_1(s, hb, ss, ms, table, ltable);
  default: return crushlzfse_encode_base_fast_6_1_1(s, hb, ss, ms, table, ltable);
  }
}

// Lazy strategy, levels 0 to 5: zstd's lazy and lazy2 parsers on a row
// history (row_hash.h): hist_pos holds positions, hist_tag their tag bytes
// and hist_cursor each bucket's next round-robin write slot. A reset zeroes
// the tags, which no key hashes to, so unwritten slots never match.
//
// Each position takes the row's longest match, or the last distance one
// byte ahead, which LZFSE codes as a single symbol. With lookahead 1 or 2 it
// then tries that many following positions, moving on whenever one scores
// higher. A score is 4 * length minus the distance's bit length, a repeated
// distance costing nothing; a match one or two bytes later must win by 4 or
// 7 more, roughly the literals it adds. Positions inside a taken match are
// indexed too. An unmatched stretch is crossed with a stride that grows by
// one byte per 256 since the last match.

LZFSE_INLINE uint32_t crushlzfse_lazy_score(uint32_t len, uint32_t d, uint32_t rep) {
  return 4 * len - (d == rep ? 0u : (uint32_t)(32 - __builtin_clz(d)));
}

// The row's longest match at pos, 0 if none, with its reference in *ref;
// pos is then inserted. Slots are visited newest first, so a length tie
// keeps the nearer reference.
LZFSE_INLINE uint32_t crushlzfse_lazy_search(const uint8_t *src, lzfse_offset pos, lzfse_offset src_end,
                                             int hash_shift, int hash_width, int32_t *hist_pos,
                                             uint8_t *hist_tag, uint16_t *hist_cursor, lzfse_offset *ref) {
  uint32_t x = load4(src + pos);
  uint32_t hash = (x * 2654435761U) >> hash_shift;
  uint8_t tag = row_hash_tag(x);
  int32_t *line_pos = hist_pos + (size_t)hash * (size_t)hash_width;
  uint8_t *line_tag = hist_tag + (size_t)hash * (size_t)hash_width;
  uint32_t cur = hist_cursor[hash];
  uint32_t max_length = (uint32_t)(src_end - pos - 8);
  uint32_t best = 0;
  uint64_t hits = row_hash_rotate(row_hash_tag_mask(line_tag, hash_width, tag), cur, hash_width);
  while (hits) {
    int bit = row_hash_top_bit(hits);
    hits &= ~((uint64_t)1 << bit);
    int slot = bit + (int)cur;
    if (slot >= hash_width) slot -= hash_width;
    int32_t r = line_pos[slot];
    // Newest first, so every later slot is farther still.
    if (r + LZFSE_ENCODE_MAX_D_VALUE < pos) break;
    const uint8_t *rp = src + r;
    if (load4(rp) != x) continue;
    if (best >= max_length) break;
    // Only a match agreeing at index best can beat it.
    if (best && rp[best] != src[pos + best]) continue;
    uint32_t len = match_extend(rp, src + pos, 4, max_length);
    if (len > best) { best = len; *ref = r; }
  }
  line_pos[cur] = (int32_t)pos;
  line_tag[cur] = tag;
  if (++cur == (uint32_t)hash_width) cur = 0;
  hist_cursor[hash] = (uint16_t)cur;
  return best;
}

LZFSE_INLINE void crushlzfse_lazy_insert(const uint8_t *src, lzfse_offset pos, int hash_shift, int hash_width,
                                         int32_t *hist_pos, uint8_t *hist_tag, uint16_t *hist_cursor) {
  uint32_t x = load4(src + pos);
  uint32_t hash = (x * 2654435761U) >> hash_shift;
  uint32_t cur = hist_cursor[hash];
  hist_pos[(size_t)hash * (size_t)hash_width + cur] = (int32_t)pos;
  hist_tag[(size_t)hash * (size_t)hash_width + cur] = row_hash_tag(x);
  if (++cur == (uint32_t)hash_width) cur = 0;
  hist_cursor[hash] = (uint16_t)cur;
}

#if defined(CRUSHLZFSE_DISPATCH_PROOF)
static __attribute__((noinline)) int crushlzfse_encode_base_lazy_hw(lzfse_encoder_state *s, int hash_bits, int hash_width,
                                                                    int lookahead, int32_t *hist_pos, uint8_t *hist_tag,
                                                                    uint16_t *hist_cursor)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_REQUIRES(hash_bits >= 10 && hash_bits <= 16)
LZFSE_REQUIRES(hash_width >= 1 && hash_width <= 32)
LZFSE_REQUIRES(lookahead >= 0 && lookahead <= 2)
LZFSE_REQUIRES(__CPROVER_rw_ok(hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos))
LZFSE_REQUIRES(__CPROVER_rw_ok(hist_tag, ((size_t)1 << hash_bits) * (size_t)hash_width + ROW_HASH_TAG_PADDING))
LZFSE_REQUIRES(__CPROVER_rw_ok(hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZFSE_ASSIGNS(__CPROVER_object_whole(hist_pos), __CPROVER_object_whole(hist_tag),
              __CPROVER_object_whole(hist_cursor))
LZFSE_ENSURES(LZFSE_ENCODE_STATUS(__CPROVER_return_value))
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end)
#else
LZFSE_INLINE int crushlzfse_encode_base_lazy_hw(lzfse_encoder_state *s, int hash_bits, int hash_width,
                                                int lookahead, int32_t *hist_pos, uint8_t *hist_tag,
                                                uint16_t *hist_cursor)
#endif
{
  const uint8_t *src = s->src;
  // Keeps every load below, and the emit's literal over-read, in bounds.
  const lzfse_offset ilimit = s->src_end - 16;
  const int hash_shift = 32 - hash_bits;
  lzfse_offset ip = s->src_encode_i;
  uint32_t rep = 0; // 0 until the first match: never a valid distance
  if (ip == 0) ip = 1;
  while (ip < ilimit) {
    const lzfse_offset anchor = s->src_literal;
    lzfse_offset start = ip, ref = 0;
    uint32_t ml = 0;
    // rep <= the previous match's position < ip, so ip + 1 - rep >= 1.
    if (rep != 0 && load4(src + ip + 1) == load4(src + ip + 1 - rep)) {
      start = ip + 1;
      ref = start - rep;
      ml = match_extend(src + ref, src + start, 4, (uint32_t)(s->src_end - start - 8));
    }
    lzfse_offset r0 = 0;
    uint32_t l0 = crushlzfse_lazy_search(src, ip, s->src_end, hash_shift, hash_width, hist_pos, hist_tag,
                                         hist_cursor, &r0);
    if (l0 > ml) { ml = l0; start = ip; ref = r0; }
    if (ml == 0) {
      ip += ((ip - anchor) >> 8) + 1;
      // Bounds a literal run, so it can never outgrow LZFSE_LITERALS_PER_BLOCK.
      if (ip - anchor > 8 * LZFSE_ENCODE_MAX_L_VALUE &&
          lzfse_backend_literals(s, LZFSE_ENCODE_MAX_L_VALUE) != LZFSE_STATUS_OK) goto fail;
      continue;
    }
    // step counts the bytes since the current match was found; a better
    // match restarts it.
    for (int step = 1; step <= lookahead && ip + 1 < ilimit;) {
      ip++;
      uint32_t bar = crushlzfse_lazy_score(ml, (uint32_t)(start - ref), rep) + (step == 1 ? 4 : 7);
      int better = 0;
      if (rep != 0 && load4(src + ip) == load4(src + ip - rep)) {
        uint32_t lr = match_extend(src + ip - rep, src + ip, 4, (uint32_t)(s->src_end - ip - 8));
        if (crushlzfse_lazy_score(lr, rep, rep) > bar) {
          ml = lr; start = ip; ref = ip - rep; better = 1;
          bar = crushlzfse_lazy_score(lr, rep, rep);
        }
      }
      lzfse_offset r1 = 0;
      uint32_t l1 = crushlzfse_lazy_search(src, ip, s->src_end, hash_shift, hash_width, hist_pos, hist_tag,
                                           hist_cursor, &r1);
      if (l1 && crushlzfse_lazy_score(l1, (uint32_t)(ip - r1), rep) > bar) {
        ml = l1; start = ip; ref = r1; better = 1;
      }
      step = better ? 1 : step + 1;
    }
    // Backwards over the pending literals, then emit.
    while (start > anchor && ref > 0 && src[start - 1] == src[ref - 1]) { start--; ref--; ml++; }
    rep = (uint32_t)(start - ref);
    if (crushlzfse_fast_emit(s, anchor, start, ml, rep) != LZFSE_STATUS_OK) goto fail;
    lzfse_offset end = start + ml;
    lzfse_offset lim = end < ilimit ? end : ilimit;
    for (lzfse_offset p = ip + 1; p < lim; p++)
      crushlzfse_lazy_insert(src, p, hash_shift, hash_width, hist_pos, hist_tag, hist_cursor);
    ip = end;
  }
  s->src_encode_i = ip;
  return LZFSE_STATUS_OK;
fail:
  s->src_encode_i = ip;
  return LZFSE_STATUS_DST_FULL;
}

// One instantiation per width in the level table, so each folds its tag row
// down to a fixed number of vector compares.
#define CRUSHLZFSE_LAZY_INSTANCE(HW)                                                                  \
  static int crushlzfse_encode_base_lazy_hw##HW(lzfse_encoder_state *s, int hash_bits, int lookahead, \
                                                int32_t *hist_pos, uint8_t *hist_tag,                 \
                                                uint16_t *hist_cursor) {                              \
    return crushlzfse_encode_base_lazy_hw(s, hash_bits, HW, lookahead, hist_pos, hist_tag, hist_cursor); \
  }
CRUSHLZFSE_LAZY_INSTANCE(4)
CRUSHLZFSE_LAZY_INSTANCE(8)
CRUSHLZFSE_LAZY_INSTANCE(16)
CRUSHLZFSE_LAZY_INSTANCE(32)
#undef CRUSHLZFSE_LAZY_INSTANCE

// A width the level table uses takes its own instance, anything else (the
// sweep tool passes arbitrary widths) the generic one.
int crushlzfse_encode_base_lazy(lzfse_encoder_state *s, int hash_bits, int hash_width, int lookahead,
                                int32_t *hist_pos, uint8_t *hist_tag, uint16_t *hist_cursor) {
  switch (hash_width) {
  case 4:  return crushlzfse_encode_base_lazy_hw4(s, hash_bits, lookahead, hist_pos, hist_tag, hist_cursor);
  case 8:  return crushlzfse_encode_base_lazy_hw8(s, hash_bits, lookahead, hist_pos, hist_tag, hist_cursor);
  case 16: return crushlzfse_encode_base_lazy_hw16(s, hash_bits, lookahead, hist_pos, hist_tag, hist_cursor);
  case 32: return crushlzfse_encode_base_lazy_hw32(s, hash_bits, lookahead, hist_pos, hist_tag, hist_cursor);
  default: return crushlzfse_encode_base_lazy_hw(s, hash_bits, hash_width, lookahead, hist_pos, hist_tag, hist_cursor);
  }
}

int lzfse_encode_finish(lzfse_encoder_state *s) {
  const lzfse_match NO_MATCH = {0};
  if (s->pending.length > 0) {
    if (lzfse_backend_match(s, &s->pending) != LZFSE_STATUS_OK)
      return LZFSE_STATUS_DST_FULL;
    s->pending = NO_MATCH;
  }
  lzfse_offset L = s->src_end - s->src_literal;
  if (L > 0) {
    if (lzfse_backend_literals(s, L) != LZFSE_STATUS_OK)
      return LZFSE_STATUS_DST_FULL;
  }
  if (lzfse_backend_end_of_stream(s) != LZFSE_STATUS_OK)
    return LZFSE_STATUS_DST_FULL;
  return LZFSE_STATUS_OK;
}
