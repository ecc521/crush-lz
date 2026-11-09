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


#include "lzfse_internal.h"

// Encoder table for nsymbols symbols over nstates states (a power of 2), from
// the normalized histogram freq with sum(freq) == nstates. A zero-frequency
// symbol must not appear in the data.
void fse_init_encoder_table(int nstates, int nsymbols,
                            const uint16_t *__restrict freq,
                            fse_encoder_entry *__restrict t) {
  int offset = 0; // current offset
  int n_clz = __builtin_clz(nstates);
  for (int i = 0; i < nsymbols; i++) {
    int f = (int)freq[i];
    if (f == 0)
      continue; // skip this symbol, no occurrences
    int k =
        __builtin_clz(f) - n_clz; // shift needed to ensure N <= (F<<K) < 2*N
    t[i].s0 = (int16_t)((f << k) - nstates);
    t[i].k = (int16_t)k;
    t[i].delta0 = (int16_t)(offset - f + (nstates >> k));
    offset += f;
  }
}

// The decoder tables are built one symbol at a time, and most symbols own
// few states (or none: an unused literal byte). When the frequencies cover
// exactly nstates, as every encoder's do, a symbol with at most FSE_FAST_RUN
// states is written branch-free as two fixed-width runs of FSE_FAST_RUN
// entries, the second starting where the first's real entries end; whatever
// either writes past the symbol's own states is rewritten by the symbols
// after it, which own those states, or lands in the table's
// FSE_DECODER_TABLE_SLACK. A larger symbol takes the exact loops.
//
// Frequencies summing below nstates (a header that omits its tables, or a
// malformed one) take the exact loops throughout, which write only owned
// states and leave the rest as the previous block's table had them, as the
// reference decoder does.
#define FSE_FAST_RUN 8
#ifdef LZFSE_TABLE_VALUE_PROOF
#define LZFSE_PROOF_LITERAL_ROW_VALID(q)                                      \
  ((((uint32_t)t[(q)] & 255) <= 10) &&                                       \
   (((uint32_t)t[(q)] >> 16) +                                               \
        (((uint32_t)1 << ((uint32_t)t[(q)] & 255)) - 1) < (uint32_t)nstates))
#endif
#ifdef LZFSE_VALUE_TABLE_PROOF
#ifdef LZFSE_VALUE_COVERAGE_PROOF
#define LZFSE_PROOF_VALUE_ROW_VALID(q) (proof_row_valid != 0)
#define LZFSE_PROOF_VALUE_COVERAGE_STORE(dst, owned)                          \
  do {                                                                        \
    if ((dst) == t + proof_value_query) proof_row_valid = (owned);           \
  } while (0)
#else
#define LZFSE_PROOF_VALUE_COVERAGE_STORE(dst, owned) ((void)0)
#ifdef LZFSE_VALUE_RANGE_PROOF
#define LZFSE_PROOF_VALUE_ROW_VALID(q)                                        \
  (t[(q)].value_bits <= 16 && t[(q)].vbase >= 0 &&                         \
   (uint32_t)t[(q)].vbase + (((uint32_t)1 << t[(q)].value_bits) - 1) <=      \
       (uint32_t)proof_value_limit)
#else
#define LZFSE_PROOF_VALUE_ROW_VALID(q)                                        \
  (t[(q)].value_bits <= 16 && t[(q)].total_bits >= t[(q)].value_bits &&      \
   t[(q)].total_bits - t[(q)].value_bits <= (nstates == 256 ? 8 : 6) &&      \
   t[(q)].delta >= 0 &&                                                       \
   (uint32_t)t[(q)].delta +                                                   \
           (((uint32_t)1 << (t[(q)].total_bits - t[(q)].value_bits)) - 1) <  \
       (uint32_t)nstates)
#endif
#endif
// fse_value_unpack proves these four stores equal the shipping eight-byte
// memcpy on the supported little-endian target, for every packed word.
#define LZFSE_STORE_VALUE_ROW(dst, word, owned)                               \
  do {                                                                        \
    fse_value_decoder_entry *proof_dst = (dst);                              \
    proof_dst->total_bits = (uint8_t)(word);                                 \
    proof_dst->value_bits = (uint8_t)((word) >> 8);                           \
    proof_dst->delta = (int16_t)((word) >> 16);                               \
    proof_dst->vbase = (int32_t)((word) >> 32);                               \
    LZFSE_PROOF_VALUE_COVERAGE_STORE(proof_dst, owned);                      \
  } while (0)
#else
#define LZFSE_STORE_VALUE_ROW(dst, word, owned) memcpy((dst), &(word), 8)
#endif
typedef char fse_fast_run_fits_slack[(FSE_FAST_RUN <= FSE_DECODER_TABLE_SLACK) ? 1 : -1];
//  fse_init_value_decoder_table writes each entry as one little-endian word.
typedef char fse_value_decoder_entry_is_one_word
    [(sizeof(fse_value_decoder_entry) == 8 &&
      offsetof(fse_value_decoder_entry, total_bits) == 0 &&
      offsetof(fse_value_decoder_entry, value_bits) == 1 &&
      offsetof(fse_value_decoder_entry, delta) == 2 &&
      offsetof(fse_value_decoder_entry, vbase) == 4) ? 1 : -1];

// Decoder table, same parameters as the encoder table, in a table of at least
// nstates + FSE_DECODER_TABLE_SLACK entries. Returns -1 if the frequencies
// sum past nstates.
int fse_init_decoder_table(int nstates, int nsymbols,
                           const uint16_t *__restrict freq,
                           int32_t *__restrict t)
{
  assert(nsymbols <= 256);
  assert(nstates > FSE_FAST_RUN);
  int n_clz = __builtin_clz(nstates);
#if defined(LZFSE_TABLE_VALUE_PROOF) && defined(LZFSE_TABLE_PREFIX_SUMMARY)
  // Frama-C's fse_table_prefix target enforces these exact-source relations.
  // CBMC's SAT backend ignores quantified loop invariants, so this proof
  // variant imports the relation one queried outer-loop step at a time.
  int proof_prefix[257];
  int sum_of_freq = nondet_int();
  proof_prefix[0] = 0;
  __CPROVER_assume(0 <= sum_of_freq &&
                   (size_t)sum_of_freq <= (size_t)nsymbols * 65535);
  __CPROVER_assume(proof_prefix[nsymbols] == sum_of_freq);
#else
  int sum_of_freq = 0;
#ifdef LZFSE_TABLE_VALUE_PROOF
  int proof_prefix[257];
  proof_prefix[0] = 0;
#endif
  for (int i = 0; i < nsymbols; i++)
#if defined(LZFSE_PROOF) && !defined(LZFSE_TABLE_VALUE_PROOF)
    LZFSE_LOOP_ASSIGNS(i, sum_of_freq)
    LZFSE_LOOP_INVARIANT(0 <= i && i <= nsymbols && sum_of_freq >= 0 && (size_t)sum_of_freq <= (size_t)i * 65535)
    LZFSE_LOOP_DECREASES(nsymbols - i)
#endif
  {
    sum_of_freq += freq[i];
#ifdef LZFSE_TABLE_VALUE_PROOF
    proof_prefix[i + 1] = sum_of_freq;
#endif
  }
#endif
  if (sum_of_freq > nstates)
    return -1;
  const int fast_run = sum_of_freq == nstates ? FSE_FAST_RUN : -1;
  int tp = 0;
  for (int i = 0; i < nsymbols; i++)
#if defined(LZFSE_TABLE_VALUE_PROOF)
    LZFSE_LOOP_ASSIGNS(i, tp, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
    LZFSE_LOOP_INVARIANT(0 <= i && i <= nsymbols && 0 <= tp && tp <= nstates &&
                         tp == proof_prefix[i])
    LZFSE_LOOP_INVARIANT(proof_literal_query < (size_t)nstates &&
                         ((proof_literal_query < (size_t)tp || fast_run < 0) ==>
                          LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query)))
    LZFSE_LOOP_DECREASES(nsymbols - i)
#elif defined(LZFSE_PROOF)
    LZFSE_LOOP_ASSIGNS(i, tp, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
    LZFSE_LOOP_INVARIANT(0 <= i && i <= nsymbols && 0 <= tp && tp <= nstates)
    LZFSE_LOOP_DECREASES(nsymbols - i)
#endif
  {
#if defined(LZFSE_TABLE_VALUE_PROOF) && defined(LZFSE_TABLE_PREFIX_SUMMARY)
    __CPROVER_assume(0 <= proof_prefix[i] &&
                     (size_t)proof_prefix[i] <= (size_t)i * 65535 &&
                     proof_prefix[i + 1] == proof_prefix[i] + (int)freq[i]);
#endif
    int f = (int)freq[i];
    if (tp + f > nstates)
      return -1;

    //  Shift needed to ensure N <= (F<<K) < 2*N; f | 1 gives an unused
    //  symbol a defined k, though nothing it writes is kept (with f == 0
    //  the exact loops write nothing).
    int k = __builtin_clz((unsigned)(f | 1)) - n_clz;
    if (k < 0 || k > 15)
      return -1;
    //  A well-formed table puts j0 in (0, f]. The runs below are bounded by
    //  j0 and f - j0, so both ends must be pinned for the pair to cover the
    //  symbol's f entries exactly.
    int j0 = ((2 * nstates) >> k) - f;
    if (j0 < 0)
      j0 = 0;
    if (j0 > f)
      j0 = f;

    //  All states S reached by this symbol: OFFSET <= S < OFFSET + F, in two
    //  runs in which only delta varies, by a constant step. Written as the
    //  packed word fse_decode_u32 reads back (k in bits 0-7, symbol 8-15,
    //  delta 16-31); stepping by step << 16 moves delta alone and wraps as
    //  int16_t would. f <= FSE_FAST_RUN < nstates keeps k - 1 >= 0 below.
    const uint32_t sym = (uint32_t)i << 8;
    uint32_t w0 = (uint8_t)(int8_t)k | sym |
                  ((uint32_t)(uint16_t)(int16_t)((f << k) - nstates) << 16);
    uint32_t step0 = (uint32_t)1 << (k + 16);
    uint32_t w1 = (uint8_t)(int8_t)(k - 1) | sym;
    uint32_t step1 = (uint32_t)1 << (k + 15);
    if (f <= fast_run) {
      for (int j = 0; j < FSE_FAST_RUN; j++)
#if defined(LZFSE_TABLE_VALUE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t + tp, FSE_FAST_RUN * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= FSE_FAST_RUN)
        LZFSE_LOOP_INVARIANT(proof_literal_query < (size_t)tp ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_INVARIANT((proof_literal_query >= (size_t)tp &&
                              proof_literal_query < (size_t)(tp + j) &&
                              proof_literal_query < (size_t)(tp + j0)) ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_DECREASES(FSE_FAST_RUN - j)
#elif defined(LZFSE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= FSE_FAST_RUN)
        LZFSE_LOOP_DECREASES(FSE_FAST_RUN - j)
#endif
        t[tp + j] = (int32_t)(w0 + (uint32_t)j * step0);
      for (int j = 0; j < FSE_FAST_RUN; j++)
#if defined(LZFSE_TABLE_VALUE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t + tp + j0, FSE_FAST_RUN * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= FSE_FAST_RUN)
        LZFSE_LOOP_INVARIANT(proof_literal_query < (size_t)tp ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_INVARIANT((proof_literal_query >= (size_t)tp &&
                              proof_literal_query < (size_t)(tp + j0)) ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_INVARIANT((proof_literal_query >= (size_t)(tp + j0) &&
                              proof_literal_query < (size_t)(tp + j0 + j) &&
                              proof_literal_query < (size_t)(tp + f)) ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_DECREASES(FSE_FAST_RUN - j)
#elif defined(LZFSE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= FSE_FAST_RUN)
        LZFSE_LOOP_DECREASES(FSE_FAST_RUN - j)
#endif
        t[tp + j0 + j] = (int32_t)(w1 + (uint32_t)j * step1);
    } else {
      for (int j = 0; j < j0; j++)
#if defined(LZFSE_TABLE_VALUE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t + tp, (size_t)j0 * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= j0)
        LZFSE_LOOP_INVARIANT(proof_literal_query < (size_t)tp ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_INVARIANT((proof_literal_query >= (size_t)tp &&
                              proof_literal_query < (size_t)(tp + j)) ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_INVARIANT((fast_run < 0 && proof_literal_query >= (size_t)(tp + f)) ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_DECREASES(j0 - j)
#elif defined(LZFSE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= j0)
        LZFSE_LOOP_DECREASES(j0 - j)
#endif
        t[tp + j] = (int32_t)(w0 + (uint32_t)j * step0);
      for (int j = 0; j < f - j0; j++)
#if defined(LZFSE_TABLE_VALUE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t + tp + j0, (size_t)(f - j0) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= f - j0)
        LZFSE_LOOP_INVARIANT(proof_literal_query < (size_t)tp ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_INVARIANT((proof_literal_query >= (size_t)tp &&
                              proof_literal_query < (size_t)(tp + j0)) ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_INVARIANT((proof_literal_query >= (size_t)(tp + j0) &&
                              proof_literal_query < (size_t)(tp + j0 + j)) ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_INVARIANT((fast_run < 0 && proof_literal_query >= (size_t)(tp + f)) ==>
                             LZFSE_PROOF_LITERAL_ROW_VALID(proof_literal_query))
        LZFSE_LOOP_DECREASES((f - j0) - j)
#elif defined(LZFSE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= f - j0)
        LZFSE_LOOP_DECREASES((f - j0) - j)
#endif
        t[tp + j0 + j] = (int32_t)(w1 + (uint32_t)j * step1);
    }
    tp += f;
  }
  return 0; // OK
}

// Value decoder table: as fse_init_decoder_table, with symbol_vbits and
// symbol_vbase giving each symbol's extra bit count and base value, in a
// table of at least nstates + FSE_DECODER_TABLE_SLACK entries. Returns -1 if
// the frequencies sum past nstates.
int fse_init_value_decoder_table(int nstates, int nsymbols,
                                 const uint16_t *__restrict freq,
                                 const uint8_t *__restrict symbol_vbits,
                                 const int32_t *__restrict symbol_vbase,
                                 fse_value_decoder_entry *__restrict t)
{
  assert(nsymbols <= 256);
  assert(nstates > FSE_FAST_RUN);
  int n_clz = __builtin_clz(nstates);
#if defined(LZFSE_VALUE_TABLE_PROOF) && defined(LZFSE_TABLE_PREFIX_SUMMARY)
  int proof_prefix[257];
  int sum_of_freq = nondet_int();
  proof_prefix[0] = 0;
  __CPROVER_assume(0 <= sum_of_freq &&
                   (size_t)sum_of_freq <= (size_t)nsymbols * 65535);
  __CPROVER_assume(proof_prefix[nsymbols] == sum_of_freq);
#else
  int sum_of_freq = 0;
#ifdef LZFSE_VALUE_TABLE_PROOF
  int proof_prefix[257];
  proof_prefix[0] = 0;
#endif
  for (int i = 0; i < nsymbols; i++)
#if defined(LZFSE_PROOF) && !defined(LZFSE_VALUE_TABLE_PROOF)
    LZFSE_LOOP_ASSIGNS(i, sum_of_freq)
    LZFSE_LOOP_INVARIANT(0 <= i && i <= nsymbols && sum_of_freq >= 0 && (size_t)sum_of_freq <= (size_t)i * 65535)
    LZFSE_LOOP_DECREASES(nsymbols - i)
#endif
  {
    sum_of_freq += freq[i];
#ifdef LZFSE_VALUE_TABLE_PROOF
    proof_prefix[i + 1] = sum_of_freq;
#endif
  }
#endif
  if (sum_of_freq > nstates)
    return -1;
  const int fast_run = sum_of_freq == nstates ? FSE_FAST_RUN : -1;
  int tp = 0;
  for (int i = 0; i < nsymbols; i++)
#if defined(LZFSE_VALUE_TABLE_PROOF)
    LZFSE_LOOP_ASSIGNS(i, tp, proof_row_valid, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
    LZFSE_LOOP_INVARIANT(0 <= i && i <= nsymbols && 0 <= tp && tp <= nstates &&
                         tp == proof_prefix[i])
    LZFSE_LOOP_INVARIANT(proof_value_query < (size_t)nstates &&
                         ((proof_value_query < (size_t)tp || fast_run < 0) ==>
                          LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query)))
    LZFSE_LOOP_DECREASES(nsymbols - i)
#elif defined(LZFSE_PROOF)
    LZFSE_LOOP_ASSIGNS(i, tp, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
    LZFSE_LOOP_INVARIANT(0 <= i && i <= nsymbols && 0 <= tp && tp <= nstates)
    LZFSE_LOOP_DECREASES(nsymbols - i)
#endif
  {
#if defined(LZFSE_VALUE_TABLE_PROOF) && defined(LZFSE_TABLE_PREFIX_SUMMARY)
    __CPROVER_assume(0 <= proof_prefix[i] &&
                     (size_t)proof_prefix[i] <= (size_t)i * 65535 &&
                     proof_prefix[i + 1] == proof_prefix[i] + (int)freq[i]);
#endif
    int f = (int)freq[i];
    if (tp + f > nstates)
      return -1;

    int k = __builtin_clz((unsigned)(f | 1)) - n_clz;
    if (k < 0 || k > 15)
      return -1;
    int j0 = ((2 * nstates) >> k) - f;
    if (j0 < 0)
      j0 = 0;
    if (j0 > f)
      j0 = f;

    //  Two runs, as in fse_init_decoder_table above, each entry built as the
    //  little-endian word its fields make: total_bits, value_bits, delta,
    //  vbase. delta stays below 1 << 16 for every entry written, overshoot
    //  included (below 16 << 8), so stepping it never carries into vbase.
    uint64_t vbits = symbol_vbits[i];
    uint64_t base = vbits << 8 | (uint64_t)(uint32_t)symbol_vbase[i] << 32;
    uint64_t w0 = base | (uint64_t)((uint32_t)k + vbits) |
                  (uint64_t)(uint16_t)(int16_t)((f << k) - nstates) << 16;
    uint64_t step0 = (uint64_t)1 << (k + 16);
    uint64_t w1 = base | (uint64_t)((uint32_t)(k - 1) + vbits);
    uint64_t step1 = (uint64_t)1 << (k + 15);
    if (f <= fast_run) {
      for (int j = 0; j < FSE_FAST_RUN; j++)
#if defined(LZFSE_VALUE_TABLE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, proof_row_valid, __CPROVER_object_upto(t + tp, FSE_FAST_RUN * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= FSE_FAST_RUN)
        LZFSE_LOOP_INVARIANT(proof_value_query < (size_t)tp ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_INVARIANT((proof_value_query >= (size_t)tp &&
                              proof_value_query < (size_t)(tp + j) &&
                              proof_value_query < (size_t)(tp + j0)) ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_DECREASES(FSE_FAST_RUN - j)
#elif defined(LZFSE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= FSE_FAST_RUN)
        LZFSE_LOOP_DECREASES(FSE_FAST_RUN - j)
#endif
      {
        uint64_t e = w0 + (uint64_t)j * step0;
        LZFSE_STORE_VALUE_ROW(t + tp + j, e, j < j0);
      }
      for (int j = 0; j < FSE_FAST_RUN; j++)
#if defined(LZFSE_VALUE_TABLE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, proof_row_valid, __CPROVER_object_upto(t + tp + j0, FSE_FAST_RUN * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= FSE_FAST_RUN)
        LZFSE_LOOP_INVARIANT(proof_value_query < (size_t)tp ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_INVARIANT((proof_value_query >= (size_t)tp &&
                              proof_value_query < (size_t)(tp + j0)) ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_INVARIANT((proof_value_query >= (size_t)(tp + j0) &&
                              proof_value_query < (size_t)(tp + j0 + j) &&
                              proof_value_query < (size_t)(tp + f)) ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_DECREASES(FSE_FAST_RUN - j)
#elif defined(LZFSE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= FSE_FAST_RUN)
        LZFSE_LOOP_DECREASES(FSE_FAST_RUN - j)
#endif
      {
        uint64_t e = w1 + (uint64_t)j * step1;
        LZFSE_STORE_VALUE_ROW(t + tp + j0 + j, e, j < f - j0);
      }
    } else {
      for (int j = 0; j < j0; j++)
#if defined(LZFSE_VALUE_TABLE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, proof_row_valid, __CPROVER_object_upto(t + tp, (size_t)j0 * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= j0)
        LZFSE_LOOP_INVARIANT(proof_value_query < (size_t)tp ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_INVARIANT((proof_value_query >= (size_t)tp &&
                              proof_value_query < (size_t)(tp + j)) ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_INVARIANT((fast_run < 0 && proof_value_query >= (size_t)(tp + f)) ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_DECREASES(j0 - j)
#elif defined(LZFSE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= j0)
        LZFSE_LOOP_DECREASES(j0 - j)
#endif
      {
        uint64_t e = w0 + (uint64_t)j * step0;
        LZFSE_STORE_VALUE_ROW(t + tp + j, e, j < j0);
      }
      for (int j = 0; j < f - j0; j++)
#if defined(LZFSE_VALUE_TABLE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, proof_row_valid, __CPROVER_object_upto(t + tp + j0, (size_t)(f - j0) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= f - j0)
        LZFSE_LOOP_INVARIANT(proof_value_query < (size_t)tp ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_INVARIANT((proof_value_query >= (size_t)tp &&
                              proof_value_query < (size_t)(tp + j0)) ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_INVARIANT((proof_value_query >= (size_t)(tp + j0) &&
                              proof_value_query < (size_t)(tp + j0 + j)) ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_INVARIANT((fast_run < 0 && proof_value_query >= (size_t)(tp + f)) ==>
                             LZFSE_PROOF_VALUE_ROW_VALID(proof_value_query))
        LZFSE_LOOP_DECREASES((f - j0) - j)
#elif defined(LZFSE_PROOF)
        LZFSE_LOOP_ASSIGNS(j, __CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
        LZFSE_LOOP_INVARIANT(0 <= j && j <= f - j0)
        LZFSE_LOOP_DECREASES((f - j0) - j)
#endif
      {
        uint64_t e = w1 + (uint64_t)j * step1;
        LZFSE_STORE_VALUE_ROW(t + tp + j0 + j, e, j < f - j0);
      }
    }
    tp += f;
  }
  return 0; // OK
}

// Remove states from symbols until the correct number of states is used.
static void fse_adjust_freqs(uint16_t *freq, int overrun, int nsymbols) {
  for (int shift = 3; overrun != 0; shift--) {
    for (int sym = 0; sym < nsymbols; sym++) {
      if (freq[sym] > 1) {
        int n = (freq[sym] - 1) >> shift;
        if (n > overrun)
          n = overrun;
        freq[sym] -= n;
        overrun -= n;
        if (overrun == 0)
          break;
      }
    }
  }
}

// Normalize a table T[NSYMBOLS] of occurrences to FREQ[NSYMBOLS].
void fse_normalize_freq(int nstates, int nsymbols, const uint32_t *__restrict t,
                        uint16_t *__restrict freq) {
  uint32_t s_count = 0;
  int remaining = nstates; // must be signed; this may become < 0
  int max_freq = 0;
  int max_freq_sym = 0;
  int shift = __builtin_clz(nstates) - 1;
  uint32_t highprec_step;

  for (int i = 0; i < nsymbols; i++)
    s_count += t[i];

  if (s_count == 0)
    highprec_step = 0; // no symbols used
  else
    highprec_step = ((uint32_t)1 << 31) / s_count;

  for (int i = 0; i < nsymbols; i++) {

    // Rescale to a normalized frequency, rounding to nearest.
    int f = (((t[i] * highprec_step) >> shift) + 1) >> 1;

    // If a symbol was used, it must be given a nonzero normalized frequency.
    if (f == 0 && t[i] != 0)
      f = 1;

    freq[i] = f;
    remaining -= f;

    if (f > max_freq) {
      max_freq = f;
      max_freq_sym = i;
    }
  }

  // Leftover states go to the most frequent symbol; a large overrun uses the
  // slower adjustment.
  if (-remaining < (max_freq >> 2)) {
    freq[max_freq_sym] += remaining;
  } else {
    fse_adjust_freqs(freq, -remaining, nsymbols);
  }
}
