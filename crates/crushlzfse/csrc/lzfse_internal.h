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


#ifndef LZFSE_INTERNAL_H
#define LZFSE_INTERNAL_H

//  The values in this header define the compressed format; changing them
//  breaks compatibility with Apple's decoder.

#include "lzfse_fse.h"
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER) && !defined(__clang__)
#  define LZFSE_INLINE __forceinline
#  define __builtin_expect(X, Y) (X)
#  define __attribute__(X)
#  pragma warning(disable : 4068) // warning C4068: unknown pragma
#else
#  define LZFSE_INLINE static inline __attribute__((__always_inline__))
#endif

//  LZFSE_PROOF alone selects the inherited reduced proof model (64-state
//  literal tables, small blocks, copies replaced by assertions). With
//  LZFSE_EXACT_FSE as well, the decoder keeps its shipping code and sizes and
//  proofs only add contracts and loop annotations.
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
#define LZFSE_REDUCED_PROOF 1
#endif

#if defined(LZFSE_PROOF) || defined(CRUSHLZVN_DISPATCH_PROOF)
#define LZFSE_REQUIRES(x)        __CPROVER_requires(x)
#define LZFSE_ENSURES(x)         __CPROVER_ensures(x)
#define LZFSE_ASSIGNS(...)       __CPROVER_assigns(__VA_ARGS__)
#define LZFSE_LOOP_ASSIGNS(...)  __CPROVER_assigns(__VA_ARGS__)
#define LZFSE_LOOP_INVARIANT(x)  __CPROVER_loop_invariant(x)
#define LZFSE_LOOP_DECREASES(x)  __CPROVER_decreases(x)
#define LZFSE_LOOP_ENTRY(x)      __CPROVER_loop_entry(x)
#define LZFSE_OLD(x)             __CPROVER_old(x)
#define LZFSE_OFFSET(p)          __CPROVER_POINTER_OFFSET(p)
#define LZFSE_DISJOINT_RANGES(a, an, b, bn)                             \
  (!__CPROVER_same_object((a), (b)) ||                                  \
   LZFSE_OFFSET(a) + (an) <= LZFSE_OFFSET(b) ||                         \
   LZFSE_OFFSET(b) + (bn) <= LZFSE_OFFSET(a))
#define LZFSE_DISJOINT_SPANS(a_begin, a_end, b_begin, b_end)             \
  (!__CPROVER_same_object((a_begin), (b_begin)) ||                      \
   LZFSE_OFFSET(a_end) <= LZFSE_OFFSET(b_begin) ||                     \
   LZFSE_OFFSET(b_end) <= LZFSE_OFFSET(a_begin))
#define LZFSE_NOINLINE           static __attribute__((noinline))

#ifndef FSE_FAST_RUN
#define FSE_FAST_RUN 8
#endif

#if defined(LZFSE_EXACT_FSE)
//  Decoder-table predicates shared by the shipping decoder contracts. A
//  literal row consumes at most ten bits and its successor states stay below
//  1024; a value row is exactly what fse_value_decode_u32 requires of the
//  entry it reads, with LIMIT the table's largest value.
#define LZFSE_LITERAL_ROW_OK(e)                                                \
  (((e) & 0xff) <= 10 && ((e) >> 16) >= 0 &&                                  \
   (uint32_t)((e) >> 16) + (((uint32_t)1 << ((e) & 0xff)) - 1) < 1024)
#define LZFSE_LITERAL_TABLE_OK(t)                                              \
  __CPROVER_forall {                                                          \
    int32_t proof_k;                                                          \
    (0 <= proof_k && proof_k < 1024) ==> LZFSE_LITERAL_ROW_OK((t)[proof_k])   \
  }
#define LZFSE_VALUE_ROW_OK(e, NSTATES, LIMIT)                                  \
  ((e).value_bits <= 16 && (e).total_bits >= (e).value_bits &&               \
   (e).total_bits - (e).value_bits <= ((NSTATES) == 256 ? 8 : 6) &&         \
   (e).delta >= 0 &&                                                          \
   (uint32_t)(e).delta +                                                      \
           (((uint32_t)1 << ((e).total_bits - (e).value_bits)) - 1) <        \
       (uint32_t)(NSTATES) &&                                                 \
   (e).vbase >= 0 &&                                                          \
   (uint32_t)(e).vbase + (((uint32_t)1 << (e).value_bits) - 1) <=            \
       (uint32_t)(LIMIT))
#define LZFSE_VALUE_TABLE_OK(t, NSTATES, LIMIT)                                \
  __CPROVER_forall {                                                          \
    int32_t proof_k;                                                          \
    (0 <= proof_k && proof_k < (NSTATES)) ==>                                 \
        LZFSE_VALUE_ROW_OK((t)[proof_k], NSTATES, LIMIT)                      \
  }
//  The L, M and D tables inside lmd_decoder (offsets 0, 72, 144).
#define LZFSE_LMD_TABLES_OK(t)                                                 \
  (LZFSE_VALUE_TABLE_OK((t), 64, 315) &&                                      \
   LZFSE_VALUE_TABLE_OK((t) + 72, 64, 2359) &&                                \
   LZFSE_VALUE_TABLE_OK((t) + 144, 256, 262139))
//  The largest value a value table can produce: the last symbol's base plus
//  its extra bits, since the shipping bases increase.
#define LZFSE_VALUE_TABLE_LIMIT(vbase, vbits, nsymbols)                        \
  ((uint32_t)(vbase)[(nsymbols) - 1] +                                        \
   (((uint32_t)1 << (vbits)[(nsymbols) - 1]) - 1))
#endif

#ifndef LZFSE_PROOF_FRAME_INTERFACE
int fse_init_decoder_table(int nstates, int nsymbols,
                           const uint16_t *__restrict freq,
                           int32_t *__restrict t)
LZFSE_REQUIRES(nsymbols >= 0 && nsymbols <= 256)
LZFSE_REQUIRES(nstates > FSE_FAST_RUN && nstates <= 1024)
LZFSE_REQUIRES((nstates & (nstates - 1)) == 0)
LZFSE_REQUIRES(__CPROVER_r_ok(freq, (size_t)nsymbols * sizeof *freq))
LZFSE_REQUIRES(__CPROVER_w_ok(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
LZFSE_REQUIRES(!__CPROVER_same_object(freq, t))
#if defined(LZFSE_EXACT_FSE)
//  Closure, not enforced by a contract target: fse_literal_table_valid (zero
//  seed) and fse_literal_table_preserve (valid seed) check an arbitrary row.
LZFSE_REQUIRES(nstates != 1024 || LZFSE_LITERAL_TABLE_OK(t))
LZFSE_ENSURES(__CPROVER_return_value != 0 || nstates != 1024 ||
              LZFSE_LITERAL_TABLE_OK(t))
#endif
LZFSE_ASSIGNS(__CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
LZFSE_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == -1);

int fse_init_value_decoder_table(int nstates, int nsymbols,
                                 const uint16_t *__restrict freq,
                                 const uint8_t *__restrict symbol_vbits,
                                 const int32_t *__restrict symbol_vbase,
                                 fse_value_decoder_entry *__restrict t)
LZFSE_REQUIRES(nsymbols >= 0 && nsymbols <= 256)
LZFSE_REQUIRES(nstates > FSE_FAST_RUN && nstates <= 1024)
LZFSE_REQUIRES((nstates & (nstates - 1)) == 0)
LZFSE_REQUIRES(__CPROVER_r_ok(freq, (size_t)nsymbols * sizeof *freq))
LZFSE_REQUIRES(__CPROVER_r_ok(symbol_vbits, (size_t)nsymbols * sizeof *symbol_vbits))
LZFSE_REQUIRES(__CPROVER_r_ok(symbol_vbase, (size_t)nsymbols * sizeof *symbol_vbase))
LZFSE_REQUIRES(__CPROVER_w_ok(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
LZFSE_REQUIRES(!__CPROVER_same_object(freq, t))
LZFSE_REQUIRES(!__CPROVER_same_object(symbol_vbits, t))
LZFSE_REQUIRES(!__CPROVER_same_object(symbol_vbase, t))
#if defined(LZFSE_EXACT_FSE)
//  Closure, not enforced by a contract target: the fse_{l,m,d}_table_coverage
//  (zero seed) and fse_{l,m,d}_table_preserve (valid seed) targets, with
//  fse_value_symbol_row, fse_value_unpack and fse_value_symbol_bounds, check
//  an arbitrary row.
LZFSE_REQUIRES(nsymbols >= 1)
LZFSE_REQUIRES(LZFSE_VALUE_TABLE_OK(t, nstates,
    LZFSE_VALUE_TABLE_LIMIT(symbol_vbase, symbol_vbits, nsymbols)))
LZFSE_ENSURES(__CPROVER_return_value != 0 ||
    LZFSE_VALUE_TABLE_OK(t, nstates,
        LZFSE_VALUE_TABLE_LIMIT(symbol_vbase, symbol_vbits, nsymbols)))
#endif
LZFSE_ASSIGNS(__CPROVER_object_upto(t, (size_t)(nstates + FSE_DECODER_TABLE_SLACK) * sizeof *t))
LZFSE_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == -1);
#endif // LZFSE_PROOF_FRAME_INTERFACE
#else
#define LZFSE_REQUIRES(x)
#define LZFSE_ENSURES(x)
#define LZFSE_ASSIGNS(...)
#define LZFSE_LOOP_ASSIGNS(...)
#define LZFSE_LOOP_INVARIANT(x)
#define LZFSE_LOOP_DECREASES(x)
#define LZFSE_NOINLINE           static inline
#endif

// Implement GCC bit scan builtins for MSVC
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>

LZFSE_INLINE int __builtin_clz(unsigned int val) {
    unsigned long r = 0;
    if (_BitScanReverse(&r, val)) {
        return 31 - r;
    }
    return 32;
}

LZFSE_INLINE int __builtin_ctzl(unsigned long val) {
  unsigned long r = 0;
  if (_BitScanForward(&r, val)) {
    return r;
  }
  return 32;
}

LZFSE_INLINE int __builtin_ctzll(uint64_t val) {
  unsigned long r = 0;
#if defined(_M_AMD64) || defined(_M_ARM)
  if (_BitScanForward64(&r, val)) {
    return r;
  }
#else
  if (_BitScanForward(&r, (uint32_t)val)) {
    return r;
  }
  if (_BitScanForward(&r, (uint32_t)(val >> 32))) {
    return 32 + r;
  }
#endif
  return 64;
}
#endif

//  L, M, D: literal count, match length and match distance of an LZ pair.
// Inputs below this size are tried as an LZVN block inside the LZFSE stream.
#define LZFSE_ENCODE_LZVN_THRESHOLD 4096
#define LZFSE_ENCODE_L_SYMBOLS 20
#define LZFSE_ENCODE_M_SYMBOLS 20
#define LZFSE_ENCODE_D_SYMBOLS 64
#define LZFSE_LMD_STATS_WORDS \
  (LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS)
#define LZFSE_ENCODE_LITERAL_SYMBOLS 256
#define LZFSE_ENCODE_L_STATES 64
#define LZFSE_ENCODE_M_STATES 64
#define LZFSE_ENCODE_D_STATES 256
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
#define LZFSE_ENCODE_LITERAL_STATES 64
#else
#define LZFSE_ENCODE_LITERAL_STATES 1024
#endif

//  Where each of the three value decoder tables starts inside lmd_decoder.
#define LZFSE_L_DECODER_OFFSET 0
//  Each is followed by FSE_DECODER_TABLE_SLACK entries of its own, so no
//  table's construction overshoot lands in another.
#define LZFSE_M_DECODER_OFFSET (LZFSE_ENCODE_L_STATES + FSE_DECODER_TABLE_SLACK)
#define LZFSE_D_DECODER_OFFSET                                                 \
  (LZFSE_M_DECODER_OFFSET + LZFSE_ENCODE_M_STATES + FSE_DECODER_TABLE_SLACK)
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
#define LZFSE_MATCHES_PER_BLOCK 64
#define LZFSE_LITERALS_PER_BLOCK (4 * LZFSE_MATCHES_PER_BLOCK)
#else
#define LZFSE_MATCHES_PER_BLOCK 10000
#define LZFSE_LITERALS_PER_BLOCK (4 * LZFSE_MATCHES_PER_BLOCK)
#endif

//  Bytes the LMD fast path may write past the output it is producing, so its
//  copies can be fixed width: copy_literal_wide and copy_match_wide each write
//  this many bytes for any run, and lzfse_decode_lmd keeps `remaining_bytes`
//  this far short of the true capacity. Must be a positive multiple of 16.
//  The best width differs by architecture.
#ifndef LZFSE_DECODE_COPY_MARGIN
#  if defined(__x86_64__)
#    define LZFSE_DECODE_COPY_MARGIN 32
#  else
#    define LZFSE_DECODE_COPY_MARGIN 64
#  endif
#endif

//  Internal status codes.
#define LZFSE_STATUS_OK 0
#define LZFSE_STATUS_SRC_EMPTY -1
#define LZFSE_STATUS_DST_FULL -2
#define LZFSE_STATUS_ERROR -3

//  Offset between buffer elements; 64-bit where that avoids sign extension
//  in addressing, but always representable as int32_t.
#if defined(_M_AMD64) || defined(__x86_64__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM64)
typedef int64_t lzfse_offset;
#else
typedef int32_t lzfse_offset;
#endif


/*! @abstract A match: bytes at pos that repeat the (possibly overlapping)
 *  bytes at the earlier ref. */
typedef struct {
  lzfse_offset pos;
  lzfse_offset ref;
  uint32_t length;
} lzfse_match;

// MARK: - Encoder and Decoder state objects

#include "lzfse_zopt.h"

/*! @abstract Encoder state object. */
typedef struct {
  const uint8_t *src;
  //  lzfse_offset, not size_t: a buffer is at most 2GB.
  lzfse_offset src_end;
  //  Offset of the next literal to encode.
  lzfse_offset src_literal;
  //  Offset of the byte currently being checked for a match.
  lzfse_offset src_encode_i;
  //  Last offset to consider for a match.
  lzfse_offset src_encode_end;
  uint8_t *dst;
  uint8_t *dst_begin;
  uint8_t *dst_end;
  //  Pending match; will be emitted unless a better match is found.
  lzfse_match pending;
  uint32_t n_matches;
  uint32_t n_literals;
  //  Chaining (crushlzfse_encode_buffer_chained), both optional. lmd_seed is
  //  LZFSE_LMD_STATS_WORDS counts, L then M then D, that the optimal parse's
  //  first pass prices from; lmd_stats accumulates the L, M and D symbols of
  //  every block emitted.
  const uint32_t *lmd_seed;
  uint32_t *lmd_stats;
  uint32_t l_values[LZFSE_MATCHES_PER_BLOCK];
  uint32_t m_values[LZFSE_MATCHES_PER_BLOCK];
  uint32_t d_values[LZFSE_MATCHES_PER_BLOCK];
  uint8_t literals[LZFSE_LITERALS_PER_BLOCK];
  //  DP scratch; the caller carves it out of its scratch buffer (crushlzfse.c).
  lzfse_zopt_scratch *zopt;
} lzfse_encoder_state;

/*! @abstract Decoder state object for lzfse compressed blocks. */
typedef struct {
  uint32_t n_matches;
  uint32_t n_literals;
  uint32_t n_lmd_payload_bytes;
  const uint8_t *current_literal;
  //  Pending L, M, D when decoding was interrupted mid-symbol for output space.
  int32_t l_value, m_value, d_value;
  fse_in_stream lmd_in_stream;
  //  Offset of the LMD stream in the input; it is read backwards.
  uint32_t lmd_in_buf;
  uint16_t l_state, m_state, d_state;
  //  The L, M and D value decoder tables concatenated, so the LMD loop indexes
  //  one base pointer with constant offsets. 8-byte aligned so an entry never
  //  spans two cache lines.
  fse_value_decoder_entry lmd_decoder[LZFSE_D_DECODER_OFFSET +
                                      LZFSE_ENCODE_D_STATES +
                                      FSE_DECODER_TABLE_SLACK]
      __attribute__((__aligned__(8)));
  int32_t literal_decoder[LZFSE_ENCODE_LITERAL_STATES + FSE_DECODER_TABLE_SLACK];
  //  The tail past LZFSE_LITERALS_PER_BLOCK is read slop for copy_literal_wide,
  //  which reads up to LZFSE_DECODE_COPY_MARGIN bytes past a block's last
  //  literal; lzfse_decode_literals zeroes that many.
  uint8_t literals[LZFSE_LITERALS_PER_BLOCK + LZFSE_DECODE_COPY_MARGIN];
} lzfse_compressed_block_decoder_state;

//  Decoder state object for uncompressed blocks.
typedef struct { uint32_t n_raw_bytes; } uncompressed_block_decoder_state;

/*! @abstract Decoder state object for lzvn-compressed blocks. */
typedef struct {
  uint32_t n_raw_bytes;
  uint32_t n_payload_bytes;
  uint32_t d_prev;
} lzvn_compressed_block_decoder_state;

/*! @abstract Decoder state object. */
typedef struct {
  //  src advances as we decode; src_begin and src_end describe the buffer.
  const uint8_t *src;
  const uint8_t *src_begin;
  const uint8_t *src_end;
  //  Likewise for dst.
  uint8_t *dst;
  uint8_t *dst_begin;
  uint8_t *dst_end;
  int end_of_stream;
  //  Magic of the current block, or LZFSE_NO_BLOCK_MAGIC between blocks.
  uint32_t block_magic;
  lzfse_compressed_block_decoder_state compressed_lzfse_block_state;
  lzvn_compressed_block_decoder_state compressed_lzvn_block_state;
  uncompressed_block_decoder_state uncompressed_block_state;
} lzfse_decoder_state;

// MARK: - Block header objects

#define LZFSE_NO_BLOCK_MAGIC             0x00000000 // 0    (invalid)
#define LZFSE_ENDOFSTREAM_BLOCK_MAGIC    0x24787662 // bvx$ (end of stream)
#define LZFSE_UNCOMPRESSED_BLOCK_MAGIC   0x2d787662 // bvx- (raw data)
#define LZFSE_COMPRESSEDV1_BLOCK_MAGIC   0x31787662 // bvx1 (lzfse compressed, uncompressed tables)
#define LZFSE_COMPRESSEDV2_BLOCK_MAGIC   0x32787662 // bvx2 (lzfse compressed, compressed tables)
#define LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC 0x6e787662 // bvxn (lzvn compressed)

/*! @abstract Uncompressed block header in encoder stream. */
typedef struct {
  uint32_t magic;
  uint32_t n_raw_bytes;
} uncompressed_block_header;

/*! @abstract Compressed block header with uncompressed tables. */
typedef struct {
  uint32_t magic;
  uint32_t n_raw_bytes;
  uint32_t n_payload_bytes;
  //  Number of literal bytes output by block (*not* the number of literals).
  uint32_t n_literals;
  uint32_t n_matches;
  uint32_t n_literal_payload_bytes;
  uint32_t n_lmd_payload_bytes;

  //  Final encoder states, which are the decoder's initial states; the four
  //  interleaved literal streams give four literal states.
  int32_t literal_bits;
  uint16_t literal_state[4];
  int32_t lmd_bits;
  uint16_t l_state;
  uint16_t m_state;
  uint16_t d_state;

  //  Normalized frequency tables; each sums to its number of states.
  uint16_t l_freq[LZFSE_ENCODE_L_SYMBOLS];
  uint16_t m_freq[LZFSE_ENCODE_M_SYMBOLS];
  uint16_t d_freq[LZFSE_ENCODE_D_SYMBOLS];
  uint16_t literal_freq[LZFSE_ENCODE_LITERAL_SYMBOLS];
} lzfse_compressed_block_header_v1;

#ifdef LZFSE_PROOF
void store4(void *ptr, uint32_t data)
LZFSE_REQUIRES(__CPROVER_w_ok(ptr, 4))
LZFSE_ASSIGNS(__CPROVER_object_upto(ptr, 4));

#ifndef LZFSE_PROOF_FRAME_INTERFACE
#if defined(LZFSE_EXACT_FSE)
//  Shipping decoder step contracts (LZFSE_EXACT_FSE), for the frame
//  dispatcher to replace both steps by. The shipping bodies are proved
//  against equivalent ACSL contracts (frama/lzfse_literals_native.py,
//  frama/lzfse_lmd_native.py; native 64-bit and ARM64), and
//  frama/lzfse_contract_bridge.py checks that those imply these clauses.
//  Enforcing them directly in CBMC exceeds memory on the 40 KB block state.
//
//  Literal step: from a header whose literal payload lies in the source
//  buffer with at least 16 bytes before it, a valid literal table and
//  in-range starting states, decodes n_literals (any count up to
//  LZFSE_LITERALS_PER_BLOCK, not only multiples of four) and advances s->src
//  past the payload.
int lzfse_decode_literals(lzfse_decoder_state *s,
                          const lzfse_compressed_block_header_v1 *header1,
                          lzfse_compressed_block_decoder_state *bs)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(bs == &s->compressed_lzfse_block_state)
LZFSE_REQUIRES(__CPROVER_r_ok(header1, sizeof *header1))
LZFSE_REQUIRES(!__CPROVER_same_object(header1, s))
LZFSE_REQUIRES(__CPROVER_same_object(s->src, s->src_begin))
LZFSE_REQUIRES(__CPROVER_same_object(s->src, s->src_end))
LZFSE_REQUIRES(LZFSE_OFFSET(s->src_begin) + 16 <= LZFSE_OFFSET(s->src))
LZFSE_REQUIRES(LZFSE_OFFSET(s->src) <= LZFSE_OFFSET(s->src_end))
LZFSE_REQUIRES(LZFSE_OFFSET(s->src_end) - LZFSE_OFFSET(s->src_begin) <= PTRDIFF_MAX)
LZFSE_REQUIRES(__CPROVER_r_ok(s->src_begin, (size_t)(LZFSE_OFFSET(s->src_end) - LZFSE_OFFSET(s->src_begin))))
LZFSE_REQUIRES(!__CPROVER_same_object(s, s->src_begin))
LZFSE_REQUIRES(!__CPROVER_same_object(header1, s->src_begin))
LZFSE_REQUIRES(header1->n_literal_payload_bytes <= (size_t)(LZFSE_OFFSET(s->src_end) - LZFSE_OFFSET(s->src)))
LZFSE_REQUIRES(header1->n_literals <= LZFSE_LITERALS_PER_BLOCK)
LZFSE_REQUIRES(header1->literal_bits >= -7 && header1->literal_bits <= 0)
LZFSE_REQUIRES(header1->literal_state[0] < LZFSE_ENCODE_LITERAL_STATES &&
               header1->literal_state[1] < LZFSE_ENCODE_LITERAL_STATES &&
               header1->literal_state[2] < LZFSE_ENCODE_LITERAL_STATES &&
               header1->literal_state[3] < LZFSE_ENCODE_LITERAL_STATES)
LZFSE_REQUIRES(LZFSE_LITERAL_TABLE_OK(bs->literal_decoder))
LZFSE_ASSIGNS(s->src, bs->current_literal,
              __CPROVER_object_upto(bs->literals, sizeof bs->literals))
LZFSE_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)
LZFSE_ENSURES(s->src == LZFSE_OLD(s->src) + header1->n_literal_payload_bytes)
LZFSE_ENSURES(__CPROVER_return_value == 0 ==> bs->current_literal == bs->literals);

#else
int lzfse_decode_literals(lzfse_decoder_state *s,
                          const lzfse_compressed_block_header_v1 *header1,
                          lzfse_compressed_block_decoder_state *bs)
LZFSE_REQUIRES(__CPROVER_w_ok(s, sizeof *s))
LZFSE_REQUIRES(__CPROVER_r_ok(header1, sizeof *header1))
LZFSE_REQUIRES(__CPROVER_w_ok(bs, sizeof *bs))
LZFSE_REQUIRES(s->src_begin <= s->src && s->src <= s->src_end)
LZFSE_REQUIRES(s->src - s->src_begin >= 16)
LZFSE_REQUIRES(header1->n_literal_payload_bytes <= (size_t)(s->src_end - s->src))
LZFSE_REQUIRES(header1->n_literals <= LZFSE_LITERALS_PER_BLOCK)
LZFSE_REQUIRES((header1->n_literals & 3) == 0)
LZFSE_REQUIRES(__CPROVER_r_ok(s->src - 16, header1->n_literal_payload_bytes + 16))
LZFSE_ASSIGNS(s->src, bs->current_literal,
              __CPROVER_object_upto(bs->literals, sizeof bs->literals))
LZFSE_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)
LZFSE_ENSURES(s->src == LZFSE_OLD(s->src) + header1->n_literal_payload_bytes)
LZFSE_ENSURES(__CPROVER_return_value == 0 ==> bs->current_literal == bs->literals);
#endif // LZFSE_EXACT_FSE
#endif // LZFSE_PROOF_FRAME_INTERFACE
#ifdef LZFSE_PROOF
void lzfse_copy_match(uint8_t *dst, ptrdiff_t D, ptrdiff_t M)
LZFSE_REQUIRES(__CPROVER_w_ok(dst, (size_t)(M + LZFSE_DECODE_COPY_MARGIN)))
LZFSE_REQUIRES(D >= 1)
LZFSE_REQUIRES(M >= 0)
LZFSE_REQUIRES(LZFSE_OFFSET(dst) >= (size_t)D)
LZFSE_REQUIRES(__CPROVER_r_ok(dst - D, (size_t)D))
LZFSE_ASSIGNS(__CPROVER_object_upto(dst, (size_t)(M + LZFSE_DECODE_COPY_MARGIN)));
#endif
#if defined(LZFSE_EXACT_FSE)
//  LMD step entry and resume predicate: the Frama-C predicate lmd_start
//  (frama/lzfse_lmd_native.py) in CBMC syntax. The frame establishes it at
//  block start (l_value = m_value = 0) and DST_FULL re-establishes it, so a
//  resumed call satisfies it too. Refills read only the bytes consumed by
//  the accumulator, including when the payload ends at the end of input.
#define LZFSE_LMD_STATE_OK(s)                                                  \
  (__CPROVER_same_object((s)->dst, (s)->dst_begin) &&                          \
   __CPROVER_same_object((s)->dst, (s)->dst_end) &&                            \
   LZFSE_OFFSET((s)->dst_begin) <= LZFSE_OFFSET((s)->dst) &&                   \
   LZFSE_OFFSET((s)->dst) <= LZFSE_OFFSET((s)->dst_end) &&                     \
   __CPROVER_w_ok((s)->dst_begin, (size_t)(LZFSE_OFFSET((s)->dst_end) -       \
                                           LZFSE_OFFSET((s)->dst_begin))) &&  \
   __CPROVER_same_object((s)->src, (s)->src_begin) &&                          \
   __CPROVER_same_object((s)->src, (s)->src_end) &&                            \
   LZFSE_OFFSET((s)->src_begin) + 8 <= LZFSE_OFFSET((s)->src) &&               \
   LZFSE_OFFSET((s)->src) <= LZFSE_OFFSET((s)->src_end) &&                     \
   __CPROVER_r_ok((s)->src_begin, (size_t)(LZFSE_OFFSET((s)->src_end) -       \
                                           LZFSE_OFFSET((s)->src_begin))) &&  \
   LZFSE_OFFSET((s)->dst_end) - LZFSE_OFFSET((s)->dst_begin) <= PTRDIFF_MAX &&  \
   LZFSE_OFFSET((s)->src_end) - LZFSE_OFFSET((s)->src_begin) <= PTRDIFF_MAX &&  \
   (size_t)(s)->compressed_lzfse_block_state.lmd_in_buf <=                     \
       (size_t)(LZFSE_OFFSET((s)->src_end) - LZFSE_OFFSET((s)->src)) &&        \
   !__CPROVER_same_object((s)->dst_begin, (s)) &&                              \
   !__CPROVER_same_object((s)->src_begin, (s)) &&                              \
   LZFSE_DISJOINT_SPANS((s)->dst_begin, (s)->dst_end,                       \
                         (s)->src_begin, (s)->src_end) &&                   \
   (s)->compressed_lzfse_block_state.n_literals <= LZFSE_LITERALS_PER_BLOCK && \
   __CPROVER_same_object((s)->compressed_lzfse_block_state.current_literal,    \
                         (s)->compressed_lzfse_block_state.literals) &&        \
   LZFSE_OFFSET((s)->compressed_lzfse_block_state.literals) <=                 \
       LZFSE_OFFSET((s)->compressed_lzfse_block_state.current_literal) &&      \
   LZFSE_OFFSET((s)->compressed_lzfse_block_state.current_literal) -           \
           LZFSE_OFFSET((s)->compressed_lzfse_block_state.literals) <=         \
       (s)->compressed_lzfse_block_state.n_literals &&                         \
   (s)->compressed_lzfse_block_state.l_state < LZFSE_ENCODE_L_STATES &&        \
   (s)->compressed_lzfse_block_state.m_state < LZFSE_ENCODE_M_STATES &&        \
   (s)->compressed_lzfse_block_state.d_state < LZFSE_ENCODE_D_STATES &&        \
   (s)->compressed_lzfse_block_state.lmd_in_stream.accum_nbits >= 0 &&         \
   (s)->compressed_lzfse_block_state.lmd_in_stream.accum_nbits < 64 &&         \
   ((s)->compressed_lzfse_block_state.lmd_in_stream.accum >>                   \
    (s)->compressed_lzfse_block_state.lmd_in_stream.accum_nbits) == 0 &&       \
   (s)->compressed_lzfse_block_state.l_value >= 0 &&                           \
   (s)->compressed_lzfse_block_state.l_value <= 315 &&                          \
   (s)->compressed_lzfse_block_state.m_value >= 0 &&                           \
   (s)->compressed_lzfse_block_state.m_value <= 2359 &&                         \
   (size_t)(s)->compressed_lzfse_block_state.l_value <=                        \
       (s)->compressed_lzfse_block_state.n_literals -                          \
           (LZFSE_OFFSET((s)->compressed_lzfse_block_state.current_literal) -  \
            LZFSE_OFFSET((s)->compressed_lzfse_block_state.literals)))

#ifndef LZFSE_PROOF_FRAME_INTERFACE
//  LMD step: decodes the remaining tuples (finishing a pending L or M first)
//  into dst. DST_FULL fills the supplied output exactly and leaves a state
//  that satisfies the entry predicate again.
int lzfse_decode_lmd(lzfse_decoder_state *s)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(LZFSE_LMD_STATE_OK(s))
LZFSE_REQUIRES(LZFSE_LMD_TABLES_OK(s->compressed_lzfse_block_state.lmd_decoder))
LZFSE_ASSIGNS(s->dst,
              __CPROVER_object_upto(s->dst_begin, (size_t)(LZFSE_OFFSET(s->dst_end) - LZFSE_OFFSET(s->dst_begin))),
              s->compressed_lzfse_block_state.l_value,
              s->compressed_lzfse_block_state.m_value,
              s->compressed_lzfse_block_state.d_value,
              s->compressed_lzfse_block_state.l_state,
              s->compressed_lzfse_block_state.m_state,
              s->compressed_lzfse_block_state.d_state,
              s->compressed_lzfse_block_state.lmd_in_stream,
              s->compressed_lzfse_block_state.n_matches,
              s->compressed_lzfse_block_state.lmd_in_buf,
              s->compressed_lzfse_block_state.current_literal)
LZFSE_ENSURES(__CPROVER_return_value == LZFSE_STATUS_OK ||
              __CPROVER_return_value == LZFSE_STATUS_DST_FULL ||
              __CPROVER_return_value == LZFSE_STATUS_ERROR)
LZFSE_ENSURES(__CPROVER_same_object(s->dst, s->dst_begin))
LZFSE_ENSURES(LZFSE_OFFSET(s->dst) >= LZFSE_OFFSET(LZFSE_OLD(s->dst)))
LZFSE_ENSURES(LZFSE_OFFSET(s->dst) <= LZFSE_OFFSET(s->dst_end))
LZFSE_ENSURES(__CPROVER_return_value != LZFSE_STATUS_DST_FULL || s->dst == s->dst_end)
LZFSE_ENSURES(__CPROVER_return_value != LZFSE_STATUS_DST_FULL || LZFSE_LMD_STATE_OK(s));
#endif // LZFSE_PROOF_FRAME_INTERFACE
#else
#ifndef LZFSE_PROOF_FRAME_INTERFACE
int lzfse_decode_lmd(lzfse_decoder_state *s)
LZFSE_REQUIRES(__CPROVER_w_ok(s, sizeof *s))
LZFSE_REQUIRES(__CPROVER_same_object(s->dst, s->dst_begin))
LZFSE_REQUIRES(__CPROVER_same_object(s->dst, s->dst_end))
LZFSE_REQUIRES(LZFSE_OFFSET(s->dst) >= LZFSE_OFFSET(s->dst_begin))
LZFSE_REQUIRES(LZFSE_OFFSET(s->dst) <= LZFSE_OFFSET(s->dst_end))
LZFSE_REQUIRES(__CPROVER_w_ok(s->dst_begin, (size_t)(LZFSE_OFFSET(s->dst_end) - LZFSE_OFFSET(s->dst_begin))))
LZFSE_REQUIRES(__CPROVER_same_object(s->src, s->src_begin))
LZFSE_REQUIRES(__CPROVER_same_object(s->src, s->src_end))
LZFSE_REQUIRES(LZFSE_OFFSET(s->src) >= LZFSE_OFFSET(s->src_begin))
LZFSE_REQUIRES(LZFSE_OFFSET(s->src) <= LZFSE_OFFSET(s->src_end))
LZFSE_REQUIRES(LZFSE_OFFSET(s->src) - LZFSE_OFFSET(s->src_begin) >= 8)
LZFSE_REQUIRES(s->compressed_lzfse_block_state.lmd_in_buf <= (size_t)(LZFSE_OFFSET(s->src_end) - LZFSE_OFFSET(s->src)))
LZFSE_REQUIRES(s->compressed_lzfse_block_state.n_literals <= LZFSE_LITERALS_PER_BLOCK)
LZFSE_REQUIRES(__CPROVER_same_object(s->compressed_lzfse_block_state.current_literal, s->compressed_lzfse_block_state.literals))
LZFSE_REQUIRES(LZFSE_OFFSET(s->compressed_lzfse_block_state.current_literal) >= LZFSE_OFFSET(s->compressed_lzfse_block_state.literals))
LZFSE_REQUIRES(LZFSE_OFFSET(s->compressed_lzfse_block_state.current_literal) <= LZFSE_OFFSET(s->compressed_lzfse_block_state.literals) + s->compressed_lzfse_block_state.n_literals)
LZFSE_REQUIRES(__CPROVER_r_ok(s->src - 8, (size_t)(LZFSE_OFFSET(s->src_end) - LZFSE_OFFSET(s->src)) + 8))
LZFSE_REQUIRES(s->compressed_lzfse_block_state.l_state < LZFSE_ENCODE_L_STATES)
LZFSE_REQUIRES(s->compressed_lzfse_block_state.m_state < LZFSE_ENCODE_M_STATES)
LZFSE_REQUIRES(s->compressed_lzfse_block_state.d_state < LZFSE_ENCODE_D_STATES)
LZFSE_REQUIRES(s->compressed_lzfse_block_state.l_value == 0)
LZFSE_REQUIRES(s->compressed_lzfse_block_state.m_value == 0)
LZFSE_REQUIRES(!__CPROVER_same_object(s->dst_begin, s))
LZFSE_REQUIRES(!__CPROVER_same_object(s->dst_begin, s->src_begin))
LZFSE_REQUIRES(!__CPROVER_same_object(s, s->src_begin))
LZFSE_ASSIGNS(s->dst,
              __CPROVER_object_upto(s->dst_begin, (size_t)(LZFSE_OFFSET(s->dst_end) - LZFSE_OFFSET(s->dst_begin))),
              s->compressed_lzfse_block_state.l_value,
              s->compressed_lzfse_block_state.m_value,
              s->compressed_lzfse_block_state.d_value,
              s->compressed_lzfse_block_state.l_state,
              s->compressed_lzfse_block_state.m_state,
              s->compressed_lzfse_block_state.d_state,
              s->compressed_lzfse_block_state.lmd_in_stream,
              s->compressed_lzfse_block_state.n_matches,
              s->compressed_lzfse_block_state.lmd_in_buf,
              s->compressed_lzfse_block_state.current_literal)
LZFSE_ENSURES(__CPROVER_return_value == LZFSE_STATUS_OK ||
              __CPROVER_return_value == LZFSE_STATUS_DST_FULL ||
              __CPROVER_return_value == LZFSE_STATUS_ERROR)
LZFSE_ENSURES(__CPROVER_same_object(s->dst, s->dst_begin))
LZFSE_ENSURES(LZFSE_OFFSET(s->dst) >= LZFSE_OFFSET(s->dst_begin))
LZFSE_ENSURES(LZFSE_OFFSET(s->dst) >= LZFSE_OFFSET(LZFSE_OLD(s->dst)))
LZFSE_ENSURES(LZFSE_OFFSET(s->dst) <= LZFSE_OFFSET(s->dst_end));
#endif // LZFSE_PROOF_FRAME_INTERFACE
#endif // LZFSE_EXACT_FSE
#endif // LZFSE_PROOF

/*! @abstract Compressed block header with compressed tables. As stored, the
 *  structure is truncated to the used bytes of freq[]. */
typedef struct {
  uint32_t magic;
  uint32_t n_raw_bytes;
  //  The v1 fields n_payload_bytes ... d_state packed into three 64-bit words:
  //
  //    offset  bits  value
  //    0       20    n_literals
  //    20      20    n_literal_payload_bytes
  //    40      20    n_matches
  //    60      3     literal_bits
  //    63      1     --- unused ---
  //
  //    0       10    literal_state[0]
  //    10      10    literal_state[1]
  //    20      10    literal_state[2]
  //    30      10    literal_state[3]
  //    40      20    n_lmd_payload_bytes
  //    60      3     lmd_bits
  //    63      1     --- unused ---
  //
  //    0       32    header_size (total header bytes; not a v1 field)
  //    32      10    l_state
  //    42      10    m_state
  //    52      10    d_state
  //    62      2     --- unused ---
  uint64_t packed_fields[3];
  //  Variable-size freq tables in a fixed prefix code; sized for the worst case.
  uint8_t freq[2 * (LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS +
                    LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS)];
} __attribute__((__packed__, __aligned__(1)))
lzfse_compressed_block_header_v2;

#ifdef LZFSE_PROOF
int lzfse_decode_v1(lzfse_compressed_block_header_v1 *out,
                    const lzfse_compressed_block_header_v2 *in, size_t available)
LZFSE_REQUIRES(__CPROVER_w_ok(out, sizeof *out))
LZFSE_REQUIRES(available >= 32 && __CPROVER_r_ok(in, available))
LZFSE_REQUIRES(!__CPROVER_same_object(out, in))
LZFSE_ASSIGNS(__CPROVER_object_upto(out, sizeof *out))
LZFSE_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)
LZFSE_ENSURES(__CPROVER_return_value == 0 ==>
              ((uint32_t)in->packed_fields[2] >= 32 && (uint32_t)in->packed_fields[2] <= sizeof *in &&
               (uint32_t)in->packed_fields[2] <= available))
LZFSE_ENSURES(__CPROVER_return_value == 0 ==> out->magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC);
#endif

/*! @abstract LZVN compressed block header. */
typedef struct {
  uint32_t magic;
  uint32_t n_raw_bytes;
  uint32_t n_payload_bytes;
} lzvn_compressed_block_header;

// MARK: - LZFSE encode/decode interfaces

#if defined(CRUSHLZFSE_DISPATCH_PROOF)
// Dispatcher-side contracts. The write frames are deliberate supersets of
// what the bodies write. Each is enforced by a proof target; see
// harness/proofs/COVERAGE.md.
#define LZFSE_ENCODE_STATUS(r) \
  ((r) == LZFSE_STATUS_OK || (r) == LZFSE_STATUS_DST_FULL || (r) == LZFSE_STATUS_ERROR)
#define LZFSE_ENCODE_KEEPS_BUFFERS(s) \
  ((s)->dst_begin == __CPROVER_old((s)->dst_begin) && (s)->dst_end == __CPROVER_old((s)->dst_end) && \
   (s)->src == __CPROVER_old((s)->src) && (s)->src_end == __CPROVER_old((s)->src_end) && \
   (s)->lmd_seed == __CPROVER_old((s)->lmd_seed) && (s)->lmd_stats == __CPROVER_old((s)->lmd_stats) && \
   (s)->zopt == __CPROVER_old((s)->zopt))
#define LZFSE_ENCODE_DST_IN_RANGE(s) \
  (__CPROVER_same_object((s)->dst, (s)->dst_begin) && \
   LZFSE_OFFSET((s)->dst) >= LZFSE_OFFSET((s)->dst_begin) && \
   LZFSE_OFFSET((s)->dst) <= LZFSE_OFFSET((s)->dst_end))
#define LZFSE_ENCODE_OUTPUT_FRAME(s) \
  LZFSE_ASSIGNS(__CPROVER_object_whole(s)) \
  LZFSE_ASSIGNS((s)->zopt != NULL: __CPROVER_object_whole((s)->zopt)) \
  LZFSE_ASSIGNS((s)->dst_begin != NULL: __CPROVER_object_whole((s)->dst_begin)) \
  LZFSE_ASSIGNS((s)->lmd_stats != NULL: __CPROVER_object_whole((s)->lmd_stats))

int lzfse_encode_init(lzfse_encoder_state *s)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_ASSIGNS(s->pending, s->src_literal)
LZFSE_ENSURES(__CPROVER_return_value == LZFSE_STATUS_OK)
LZFSE_ENSURES(s->pending.length == 0)
LZFSE_ENSURES(s->src_literal == 0);

int lzfse_encode_base(lzfse_encoder_state *s)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_REQUIRES(s->src_literal >= 0 && s->src_literal <= s->src_end)
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_ENSURES(LZFSE_ENCODE_STATUS(__CPROVER_return_value))
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(LZFSE_ENCODE_DST_IN_RANGE(s))
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end);

#ifndef ROW_HASH_TAG_PADDING
#define ROW_HASH_TAG_PADDING 16
#endif

int crushlzfse_encode_base_lazy(lzfse_encoder_state *s, int hash_bits, int hash_width, int lookahead,
                                int32_t *hist_pos, uint8_t *hist_tag, uint16_t *hist_cursor)
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
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end);

int crushlzfse_encode_base_fast(lzfse_encoder_state *s, int hash_bits, int min_match, int skip_shift,
                                int max_step, int long_table, int lazy, uint16_t *table, uint16_t *ltable)
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
LZFSE_ENSURES(s->src_literal >= 0 && s->src_literal <= s->src_end);

int lzfse_encode_finish(lzfse_encoder_state *s)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_ENCODE_OUTPUT_FRAME(s)
LZFSE_REQUIRES(s->dst_begin != NULL && s->dst_end >= s->dst_begin && __CPROVER_w_ok(s->dst_begin, (size_t)(s->dst_end - s->dst_begin)))
LZFSE_REQUIRES(s->dst >= s->dst_begin && s->dst <= s->dst_end)
LZFSE_REQUIRES(s->src_literal >= 0 && s->src_literal <= s->src_end)
LZFSE_ENSURES(LZFSE_ENCODE_STATUS(__CPROVER_return_value))
LZFSE_ENSURES(LZFSE_ENCODE_KEEPS_BUFFERS(s))
LZFSE_ENSURES(LZFSE_ENCODE_DST_IN_RANGE(s));
#else
int lzfse_encode_init(lzfse_encoder_state *s);
int lzfse_encode_base(lzfse_encoder_state *s);
// Lazy path for levels 0 to 5; shares lzfse_encode_init/finish with
// lzfse_encode_base. hist_pos and hist_tag hold (1<<hash_bits)*hash_width
// entries each, hash_width at most ROW_HASH_MAX_MASK_WIDTH, hist_tag with
// ROW_HASH_TAG_PADDING readable bytes past its end; hist_tag (with its
// padding) and hist_cursor, (1<<hash_bits) entries, have to be zeroed first,
// hist_pos never. lookahead is 0 to 2.
int crushlzfse_encode_base_lazy(lzfse_encoder_state *s, int hash_bits, int hash_width, int lookahead,
                                int32_t *hist_pos, uint8_t *hist_tag, uint16_t *hist_cursor);
// Fast path for levels -5 to -1. table, and ltable when long_table is set,
// hold (1<<hash_bits) zeroed entries each. min_match is 4 to 8, and at most
// 6 with long_table or lazy.
int crushlzfse_encode_base_fast(lzfse_encoder_state *s, int hash_bits, int min_match, int skip_shift,
                                int max_step, int long_table, int lazy, uint16_t *table, uint16_t *ltable);
int lzfse_encode_finish(lzfse_encoder_state *s);
#endif
#ifdef LZFSE_PROOF
//  Proof predicates for the frame dispatcher (lzfse_decode). A decoder state
//  is resumable when its buffers are well formed, its block magic is one the
//  dispatcher knows, the active block's saved work is in range, and every
//  row of the FSE decoder tables is valid. Rows are carried across blocks
//  because an underfull frequency table leaves earlier rows in place.
//
//  Table validity is an abstract predicate: the ghost lzfse_proof_tables_ok
//  stands for "every row of all four tables is valid" (the two TABLE_OK
//  macros below). It is set only after asserting them on zeroed tables (the
//  public wrappers) or by a table builder's success, whose row validity the
//  fse_*_table_coverage/preserve targets prove. The frame's assigns clause
//  includes the actual builder writes to the tables. The literal, LMD and
//  LZVN decoders do not write them. The frame proof never reads table
//  contents, so it sees only the ghost.
static int lzfse_proof_tables_ok;
#define LZFSE_PROOF_LITERAL_ROW_OK(e)                                         \
  (((e) & 0xff) <= 10 && ((e) >> 16) >= 0 &&                                 \
   (uint32_t)((e) >> 16) + (((uint32_t)1 << ((e) & 0xff)) - 1) <             \
       LZFSE_ENCODE_LITERAL_STATES)
#define LZFSE_PROOF_VALUE_ROW_OK(e, nstates, extra, vmax)                     \
  ((e).value_bits <= 16 && (e).total_bits >= (e).value_bits &&              \
   (e).total_bits - (e).value_bits <= (extra) && (e).delta >= 0 &&          \
   (uint32_t)(e).delta +                                                     \
           (((uint32_t)1 << ((e).total_bits - (e).value_bits)) - 1) <        \
       (uint32_t)(nstates) &&                                                \
   (e).vbase >= 0 &&                                                         \
   (uint32_t)(e).vbase + (((uint32_t)1 << (e).value_bits) - 1) <= (vmax))
#if defined(LZFSE_EXACT_FSE)
//  In exact FSE mode (1024-state tables), zeroed-table validity is checked
//  via an arbitrary symbolic entry query rather than 1408 quantifier expansions.
//  lzfse_decoder_tables_zero and fse_*_table_valid separately prove full table validity.
static inline int lzfse_proof_tables_zeroed(const lzfse_compressed_block_decoder_state *bs) {
  size_t proof_lit = nondet_size();
  size_t proof_lmd = nondet_size();
  if (proof_lit < LZFSE_ENCODE_LITERAL_STATES && bs->literal_decoder[proof_lit] != 0)
    return 0;
  if (proof_lmd < sizeof(bs->lmd_decoder) / sizeof(bs->lmd_decoder[0])) {
    fse_value_decoder_entry e = bs->lmd_decoder[proof_lmd];
    if (e.total_bits != 0 || e.value_bits != 0 || e.delta != 0 || e.vbase != 0)
      return 0;
  }
  return 1;
}
#define LZFSE_PROOF_LITERAL_TABLE_OK(bs, k) lzfse_proof_tables_zeroed(bs)
#define LZFSE_PROOF_VALUE_TABLES_OK(bs, k) 1
#else
//  k makes each quantified variable unique within a function's clauses.
#define LZFSE_PROOF_LITERAL_TABLE_OK(bs, k)                                   \
  __CPROVER_forall { int lit##k; (0 <= lit##k &&                            \
      lit##k < LZFSE_ENCODE_LITERAL_STATES) ==>                              \
      LZFSE_PROOF_LITERAL_ROW_OK((bs)->literal_decoder[lit##k]) }
#define LZFSE_PROOF_VALUE_REGION_OK(bs, q, off, n, extra, vmax)               \
  __CPROVER_forall { int q; (0 <= q && q < (n)) ==>                          \
      LZFSE_PROOF_VALUE_ROW_OK((bs)->lmd_decoder[(off) + q], n, extra, vmax) }
#define LZFSE_PROOF_VALUE_TABLES_OK(bs, k)                                    \
  (LZFSE_PROOF_VALUE_REGION_OK(bs, l##k, LZFSE_L_DECODER_OFFSET,            \
                               LZFSE_ENCODE_L_STATES, 6, 315) &&            \
   LZFSE_PROOF_VALUE_REGION_OK(bs, m##k, LZFSE_M_DECODER_OFFSET,            \
                               LZFSE_ENCODE_M_STATES, 6, 2359) &&           \
   LZFSE_PROOF_VALUE_REGION_OK(bs, d##k, LZFSE_D_DECODER_OFFSET,            \
                               LZFSE_ENCODE_D_STATES, 8, 262139))
#endif
//  Buffers: src and dst each a readable/writable span of one object, the
//  cursor inside it. Their spans may share an allocation but must be disjoint;
//  the decoder state is a separate object.
#define LZFSE_PROOF_DECODER_BUFFERS(s)                                        \
  (__CPROVER_same_object((s)->dst, (s)->dst_begin) &&                       \
   __CPROVER_same_object((s)->dst, (s)->dst_end) &&                         \
   LZFSE_OFFSET((s)->dst) >= LZFSE_OFFSET((s)->dst_begin) &&                \
   LZFSE_OFFSET((s)->dst) <= LZFSE_OFFSET((s)->dst_end) &&                  \
   __CPROVER_w_ok((s)->dst_begin, (size_t)(LZFSE_OFFSET((s)->dst_end) -     \
                                           LZFSE_OFFSET((s)->dst_begin))) && \
   __CPROVER_same_object((s)->src, (s)->src_begin) &&                       \
   __CPROVER_same_object((s)->src, (s)->src_end) &&                         \
   LZFSE_OFFSET((s)->src) >= LZFSE_OFFSET((s)->src_begin) &&                \
   LZFSE_OFFSET((s)->src) <= LZFSE_OFFSET((s)->src_end) &&                  \
   __CPROVER_r_ok((s)->src_begin, (size_t)(LZFSE_OFFSET((s)->src_end) -     \
                                           LZFSE_OFFSET((s)->src_begin))) && \
   !__CPROVER_same_object((s), (s)->dst_begin) &&                           \
   !__CPROVER_same_object((s), (s)->src_begin) &&                           \
   LZFSE_DISJOINT_SPANS((s)->dst_begin, (s)->dst_end,                       \
                         (s)->src_begin, (s)->src_end))
//  The LMD loop's starting and resume state (frama/lzfse_lmd_native.py
//  lmd_start, without its buffer and table parts).
#define LZFSE_PROOF_LMD_START(s)                                              \
  (LZFSE_OFFSET((s)->src) - LZFSE_OFFSET((s)->src_begin) >= 8 &&            \
   (size_t)(s)->compressed_lzfse_block_state.lmd_in_buf <=                  \
       (size_t)(LZFSE_OFFSET((s)->src_end) - LZFSE_OFFSET((s)->src)) &&     \
   (s)->compressed_lzfse_block_state.n_literals <= LZFSE_LITERALS_PER_BLOCK && \
   __CPROVER_same_object((s)->compressed_lzfse_block_state.current_literal, \
                         (s)->compressed_lzfse_block_state.literals) &&     \
   LZFSE_OFFSET((s)->compressed_lzfse_block_state.current_literal) >=       \
       LZFSE_OFFSET((s)->compressed_lzfse_block_state.literals) &&          \
   LZFSE_OFFSET((s)->compressed_lzfse_block_state.current_literal) <=       \
       LZFSE_OFFSET((s)->compressed_lzfse_block_state.literals) +           \
           (s)->compressed_lzfse_block_state.n_literals &&                  \
   (s)->compressed_lzfse_block_state.l_state < LZFSE_ENCODE_L_STATES &&     \
   (s)->compressed_lzfse_block_state.m_state < LZFSE_ENCODE_M_STATES &&     \
   (s)->compressed_lzfse_block_state.d_state < LZFSE_ENCODE_D_STATES &&     \
   (s)->compressed_lzfse_block_state.lmd_in_stream.accum_nbits >= 0 &&      \
   (s)->compressed_lzfse_block_state.lmd_in_stream.accum_nbits < 64 &&      \
   ((s)->compressed_lzfse_block_state.lmd_in_stream.accum >>                \
    (s)->compressed_lzfse_block_state.lmd_in_stream.accum_nbits) == 0 &&    \
   (s)->compressed_lzfse_block_state.l_value >= 0 &&                        \
   (s)->compressed_lzfse_block_state.l_value <= 315 &&                      \
   (s)->compressed_lzfse_block_state.m_value >= 0 &&                        \
   (s)->compressed_lzfse_block_state.m_value <= 2359 &&                     \
   (size_t)(s)->compressed_lzfse_block_state.l_value <=                     \
       (s)->compressed_lzfse_block_state.n_literals -                       \
           (LZFSE_OFFSET((s)->compressed_lzfse_block_state.current_literal) - \
            LZFSE_OFFSET((s)->compressed_lzfse_block_state.literals)))
//  The complete state span is the exact outer write footprint. Using *s
//  maintains typed struct assigns without creating untyped byte slices.
#define LZFSE_PROOF_STATE_FOOTPRINT(s) *s
#define LZFSE_PROOF_DECODER_RESUMABLE(s)                                      \
  (LZFSE_PROOF_DECODER_BUFFERS(s) &&                                        \
   ((s)->block_magic == LZFSE_NO_BLOCK_MAGIC ||                             \
    (s)->block_magic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC ||                   \
    (s)->block_magic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC ||                 \
    (s)->block_magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC ||                   \
    (s)->block_magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC) &&                  \
   ((s)->block_magic != LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC ||                 \
    (s)->compressed_lzvn_block_state.d_prev <=                              \
        (size_t)(LZFSE_OFFSET((s)->dst) - LZFSE_OFFSET((s)->dst_begin))) && \
   (((s)->block_magic != LZFSE_COMPRESSEDV1_BLOCK_MAGIC &&                  \
     (s)->block_magic != LZFSE_COMPRESSEDV2_BLOCK_MAGIC) ||                 \
    LZFSE_PROOF_LMD_START(s)))

int lzfse_decode(lzfse_decoder_state *s)
LZFSE_REQUIRES(__CPROVER_rw_ok(s, sizeof *s))
LZFSE_REQUIRES(LZFSE_PROOF_DECODER_RESUMABLE(s))
LZFSE_REQUIRES(lzfse_proof_tables_ok == 1)
LZFSE_ASSIGNS(LZFSE_PROOF_STATE_FOOTPRINT(s), lzfse_proof_tables_ok,
              __CPROVER_object_upto(s->dst_begin, (size_t)(LZFSE_OFFSET(s->dst_end) - LZFSE_OFFSET(s->dst_begin))))
LZFSE_ENSURES(__CPROVER_return_value == LZFSE_STATUS_OK ||
              __CPROVER_return_value == LZFSE_STATUS_SRC_EMPTY ||
              __CPROVER_return_value == LZFSE_STATUS_DST_FULL ||
              __CPROVER_return_value == LZFSE_STATUS_ERROR)
LZFSE_ENSURES(s->src_begin == LZFSE_OLD(s->src_begin) &&
              s->src_end == LZFSE_OLD(s->src_end) &&
              s->dst_begin == LZFSE_OLD(s->dst_begin) &&
              s->dst_end == LZFSE_OLD(s->dst_end))
LZFSE_ENSURES(LZFSE_PROOF_DECODER_BUFFERS(s))
LZFSE_ENSURES(LZFSE_OFFSET(s->dst) >= LZFSE_OFFSET(LZFSE_OLD(s->dst)))
LZFSE_ENSURES(LZFSE_OFFSET(s->src) >= LZFSE_OFFSET(LZFSE_OLD(s->src)))
LZFSE_ENSURES(__CPROVER_return_value != LZFSE_STATUS_ERROR ==>
              LZFSE_PROOF_DECODER_RESUMABLE(s))
LZFSE_ENSURES(__CPROVER_return_value != LZFSE_STATUS_ERROR ==>
              lzfse_proof_tables_ok == 1)
LZFSE_ENSURES(__CPROVER_return_value == LZFSE_STATUS_OK ==>
              s->end_of_stream == 1 && s->block_magic == LZFSE_NO_BLOCK_MAGIC);
#else
int lzfse_decode(lzfse_decoder_state *s);
#endif
int lzfse_declared_len(const uint8_t *src, const uint8_t *src_end, size_t *out_len);

// MARK: - LZVN encode/decode interfaces

//  Smaller inputs are not compressed.
#define LZVN_ENCODE_MIN_SRC_SIZE ((size_t)8)

//  Larger inputs are compressed partially.
#define LZVN_ENCODE_MAX_SRC_SIZE ((size_t)0xffffffffU)

//  No compression into a smaller destination.
#define LZVN_ENCODE_MIN_DST_SIZE ((size_t)8)

size_t lzvn_decode_buffer(void *__restrict dst, size_t dst_size,
                          const void *__restrict src, size_t src_size);

/*! Greedy LZVN encode over a runtime hash_bits/hash_width table.
 * hist_pos/hist_value hold (1<<hash_bits)*hash_width entries each and
 * hist_cursor (1<<hash_bits), all caller-owned. Returns bytes written, or 0
 * if dst is too small. */
#if defined(CRUSHLZVN_DISPATCH_PROOF)
size_t lzvn_encode_greedy_wide_buffer(void *__restrict dst, size_t dst_size,
                                      const void *__restrict src, size_t src_size,
                                      int32_t hash_bits, int32_t hash_width,
                                      int32_t *hist_pos, uint32_t *hist_value,
                                      uint16_t *hist_cursor)
LZFSE_REQUIRES(src != NULL && __CPROVER_r_ok(src, src_size))
LZFSE_REQUIRES(dst != NULL && __CPROVER_w_ok(dst, dst_size))
LZFSE_REQUIRES(!__CPROVER_same_object(src, dst))
LZFSE_REQUIRES(hash_bits >= 10 && hash_bits <= 16)
LZFSE_REQUIRES(hash_width >= 1 && hash_width <= 64)
LZFSE_REQUIRES(__CPROVER_rw_ok(hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos))
LZFSE_REQUIRES(__CPROVER_rw_ok(hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZFSE_REQUIRES(__CPROVER_rw_ok(hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZFSE_REQUIRES(!__CPROVER_same_object(src, hist_pos) &&
              !__CPROVER_same_object(src, hist_value) &&
              !__CPROVER_same_object(src, hist_cursor))
LZFSE_REQUIRES(CRUSHLZVN_PROOF_RANGES_DISJOINT(dst, dst_size,
              hist_pos, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos))
LZFSE_REQUIRES(CRUSHLZVN_PROOF_RANGES_DISJOINT(dst, dst_size,
              hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZFSE_REQUIRES(CRUSHLZVN_PROOF_RANGES_DISJOINT(dst, dst_size,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZFSE_REQUIRES(CRUSHLZVN_PROOF_RANGES_DISJOINT(hist_pos,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos,
              hist_value, ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value))
LZFSE_REQUIRES(CRUSHLZVN_PROOF_RANGES_DISJOINT(hist_pos,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_pos,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZFSE_REQUIRES(CRUSHLZVN_PROOF_RANGES_DISJOINT(hist_value,
              ((size_t)1 << hash_bits) * (size_t)hash_width * sizeof *hist_value,
              hist_cursor, ((size_t)1 << hash_bits) * sizeof *hist_cursor))
LZFSE_ASSIGNS(__CPROVER_object_upto(dst, dst_size))
LZFSE_ENSURES(__CPROVER_return_value <= dst_size);
#else
size_t lzvn_encode_greedy_wide_buffer(void *__restrict dst, size_t dst_size,
                                      const void *__restrict src, size_t src_size,
                                      int32_t hash_bits, int32_t hash_width,
                                      int32_t *hist_pos, uint32_t *hist_value,
                                      uint16_t *hist_cursor);
#endif

/*! @abstract Signed offset in buffers, stored on either 32 or 64 bits. */
#if defined(_M_AMD64) || defined(__x86_64__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM64)
typedef int64_t lzvn_offset;
#else
typedef int32_t lzvn_offset;
#endif

// MARK: - LZFSE utility functions

/*! @abstract Load bytes from memory location SRC. */
LZFSE_INLINE uint16_t load2(const void *ptr) {
#if (defined(LZVN_PROOF) || defined(LZFSE_PROOF)) && !defined(LZFSE_COPY_PROOF)
  const unsigned char *p = (const unsigned char *)ptr;
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
#else
  uint16_t data;
  memcpy(&data, ptr, sizeof data);
  return data;
#endif
}

LZFSE_INLINE uint32_t load4(const void *ptr) {
#if (defined(LZVN_PROOF) || defined(LZFSE_PROOF)) && !defined(LZFSE_COPY_PROOF)
  const unsigned char *p = (const unsigned char *)ptr;
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
#else
  uint32_t data;
  memcpy(&data, ptr, sizeof data);
  return data;
#endif
}

// Low 3 bytes of a 4-byte load. Callers already have load4's 8-byte
// read-ahead margin. Little-endian only, like the ctzll-based match code.
LZFSE_INLINE uint32_t load3(const void *ptr) { return load4(ptr) & 0xFFFFFFu; }

LZFSE_INLINE uint64_t load8(const void *ptr) {
#if (defined(LZVN_PROOF) || defined(LZFSE_PROOF)) && !defined(LZFSE_COPY_PROOF)
  const unsigned char *p = (const unsigned char *)ptr;
  return (uint64_t)p[0] |
         ((uint64_t)p[1] << 8) |
         ((uint64_t)p[2] << 16) |
         ((uint64_t)p[3] << 24) |
         ((uint64_t)p[4] << 32) |
         ((uint64_t)p[5] << 40) |
         ((uint64_t)p[6] << 48) |
         ((uint64_t)p[7] << 56);
#else
  uint64_t data;
  memcpy(&data, ptr, sizeof data);
  return data;
#endif
}

/*! @abstract Store bytes to memory location DST. */
LZFSE_INLINE void store2(void *ptr, uint16_t data) {
#if defined(LZVN_PROOF) && defined(LZVN_FAST_COPY)
  __CPROVER_assert(__CPROVER_w_ok(ptr, 2), "store2 write");
#elif (defined(LZVN_PROOF) || defined(LZFSE_PROOF)) && !defined(LZFSE_COPY_PROOF)
  unsigned char *p = (unsigned char *)ptr;
  p[0] = (unsigned char)data;
  p[1] = (unsigned char)(data >> 8);
#else
  memcpy(ptr, &data, sizeof data);
#endif
}

LZFSE_INLINE void store4(void *ptr, uint32_t data) {
#if defined(LZVN_PROOF) && defined(LZVN_FAST_COPY)
  __CPROVER_assert(__CPROVER_w_ok(ptr, 4), "store4 write");
#elif (defined(LZVN_PROOF) || defined(LZFSE_PROOF)) && !defined(LZFSE_COPY_PROOF)
  unsigned char *p = (unsigned char *)ptr;
  p[0] = (unsigned char)data;
  p[1] = (unsigned char)(data >> 8);
  p[2] = (unsigned char)(data >> 16);
  p[3] = (unsigned char)(data >> 24);
#else
  memcpy(ptr, &data, sizeof data);
#endif
}

LZFSE_INLINE void store8(void *ptr, uint64_t data) {
#if defined(LZVN_PROOF) && defined(LZVN_FAST_COPY)
  __CPROVER_assert(__CPROVER_w_ok(ptr, 8), "store8 write");
#elif (defined(LZVN_PROOF) || defined(LZFSE_PROOF)) && !defined(LZFSE_COPY_PROOF)
  unsigned char *p = (unsigned char *)ptr;
  p[0] = (unsigned char)data;
  p[1] = (unsigned char)(data >> 8);
  p[2] = (unsigned char)(data >> 16);
  p[3] = (unsigned char)(data >> 24);
  p[4] = (unsigned char)(data >> 32);
  p[5] = (unsigned char)(data >> 40);
  p[6] = (unsigned char)(data >> 48);
  p[7] = (unsigned char)(data >> 56);
#else
  memcpy(ptr, &data, sizeof data);
#endif
}

/*! @abstract Non-overlapping copy only: unlike a naive memcpy it does not
 *  splat the leading bytes when the buffers overlap. */
LZFSE_INLINE void copy8(void *dst, const void *src) { store8(dst, load8(src)); }
LZFSE_INLINE void copy16(void *dst, const void *src) {
  uint64_t m0 = load8(src);
  uint64_t m1 = load8((const unsigned char *)src + 8);
  store8(dst, m0);
  store8((unsigned char *)dst + 8, m1);
}

// Match-length extension, 16 bytes per step. On x86 this goes through
// pcmpeqb/pmovmskb (SSE2, so unconditional on x86_64): one comparison and one
// mask extraction find the first differing byte in the whole 16, in place of
// the portable vector_size path's pxor plus two 64-bit halves peeled out with
// a movq and a pextrq: pextrq is the expensive one, several cycles on top
// of everything else in the loop.
//
// ARM64 got the same portable vector_size path unmodified, on the untested
// assumption that only x86's pextrq was expensive. It isn't a safe
// assumption: clang lowers the 16-byte XOR to a real NEON register on
// aarch64 too, and the two memcpy'd-out 64-bit halves to a umov, the same
// class of vector-to-GPR move pextrq is. Measured on an Apple M5 Max
// (isolated cost-per-call at fixed match lengths, plus a 500 MB / 1.4B-call
// corpus sweep for the real length distribution): the vector_size path pays
// a real, unconditional ~0.48ns entry cost every call (vs ~0.40ns below),
// visible even when the very first byte differs, because the 16-byte vector
// load and both extractions happen before the result is known. 90% of real
// match_extend calls extend under 16 bytes and never reach a second loop
// iteration, so that entry cost is what most calls actually pay for.
// Splitting the same two 64-bit halves out as independent scalar loads,
// never forming a vector_size value at all, removes the round trip:
// same ~0.40ns entry cost as no vector path at all, while keeping the
// vector_size path's steady-state throughput on long matches (within noise
// of it, both clearly ahead of a plain 8-byte scalar loop). Net estimated
// impact on this corpus: about -0.29% of total match_extend-relevant encode
// time, real and directionally consistent with the per-call measurements,
// but small enough that it did not resolve above noise in guarded 4-round
// whole-encoder A/B runs; the isolated per-call measurement is what actually
// shows it.
//
// Little-endian only. Lives here because CrushLZVN's parser reuses it.
#if defined(CRUSH_SIMD_PORTABLE)
// Plain scalar loop for verification and portable builds
#elif defined(__x86_64__) || defined(_M_X64) || defined(__SSE2__)
#include <emmintrin.h>
#define LZFSE_MATCH_EXTEND_SSE2 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#define LZFSE_MATCH_EXTEND_DUAL64 1
#elif defined(__GNUC__) || defined(__clang__)
typedef uint8_t match_vec16 __attribute__((vector_size(16)));
#define LZFSE_MATCH_EXTEND_GENERIC_VEC 1
#endif

// Counters for tests: define LZFSE_COUNT_MATCH_EXTEND and provide
// g_match_extend_calls and g_match_extend_bytes (bytes past the given
// length) before including this header.
#ifdef LZFSE_COUNT_MATCH_EXTEND
extern size_t g_match_extend_calls, g_match_extend_bytes;
#define LZFSE_MATCH_EXTEND_HOOK() (g_match_extend_calls++)
#define LZFSE_MATCH_EXTEND_BYTES_HOOK(n) (g_match_extend_bytes += (n))
#else
#define LZFSE_MATCH_EXTEND_HOOK() ((void)0)
#define LZFSE_MATCH_EXTEND_BYTES_HOOK(n) ((void)0)
#endif

#if defined(LZVN_PROOF) || defined(LZFSE_PROOF)
static __attribute__((noinline))
#else
LZFSE_INLINE
#endif
uint32_t match_extend(const uint8_t *a, const uint8_t *b, uint32_t length, uint32_t max_length)
#if defined(LZVN_PROOF) || defined(LZFSE_PROOF)
__CPROVER_requires(length <= max_length && max_length <= 0xFFFFFFF0u)
__CPROVER_requires(__CPROVER_r_ok(a, (size_t)max_length + 7))
__CPROVER_requires(__CPROVER_r_ok(b, (size_t)max_length + 7))
__CPROVER_assigns()
__CPROVER_ensures(__CPROVER_return_value >= length && __CPROVER_return_value <= max_length)
#endif
{
  LZFSE_MATCH_EXTEND_HOOK();
#ifdef LZFSE_COUNT_MATCH_EXTEND
  const uint32_t start = length;
#endif
#if defined(LZFSE_MATCH_EXTEND_SSE2)
  while (length + 16 <= max_length) {
    __m128i va = _mm_loadu_si128((const __m128i *)(const void *)(a + length));
    __m128i vb = _mm_loadu_si128((const __m128i *)(const void *)(b + length));
    uint32_t mask = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(va, vb));
    if (mask == 0xFFFFu) { length += 16; continue; }
    length += (uint32_t)__builtin_ctz((~mask) & 0xFFFFu);
    goto clamp;
  }
#elif defined(LZFSE_MATCH_EXTEND_DUAL64)
  while (length + 16 <= max_length) {
    uint64_t lo = load8(a + length) ^ load8(b + length);
    uint64_t hi = load8(a + length + 8) ^ load8(b + length + 8);
    if (lo != 0) { length += (uint32_t)(__builtin_ctzll(lo) >> 3); goto clamp; }
    if (hi != 0) { length += 8 + (uint32_t)(__builtin_ctzll(hi) >> 3); goto clamp; }
    length += 16;
  }
#elif defined(LZFSE_MATCH_EXTEND_GENERIC_VEC)
  while (length + 16 <= max_length) {
    match_vec16 va, vb;
    memcpy(&va, a + length, 16);
    memcpy(&vb, b + length, 16);
    match_vec16 vx = va ^ vb;
    uint64_t lo, hi;
    memcpy(&lo, &vx, 8);
    memcpy(&hi, (const uint8_t *)&vx + 8, 8);
    if (lo != 0) { length += (uint32_t)(__builtin_ctzll(lo) >> 3); goto clamp; }
    if (hi != 0) { length += 8 + (uint32_t)(__builtin_ctzll(hi) >> 3); goto clamp; }
    length += 16;
  }
#endif
  while (length < max_length)
#if defined(LZVN_PROOF) && !defined(LZFSE_PROOF)
    __CPROVER_assigns(length)
    __CPROVER_loop_invariant(length >= __CPROVER_loop_entry(length) && (size_t)length <= (size_t)max_length + 7)
    __CPROVER_decreases((size_t)max_length + 8 - length)
#endif
  {
    uint64_t d = load8(a + length) ^ load8(b + length);
    if (d == 0) { length += 8; continue; }
    length += (uint32_t)(__builtin_ctzll(d) >> 3);
    break;
  }
#if defined(LZFSE_MATCH_EXTEND_SSE2) || defined(LZFSE_MATCH_EXTEND_DUAL64) || defined(LZFSE_MATCH_EXTEND_GENERIC_VEC)
clamp:
#endif
  if (length > max_length) length = max_length;
  LZFSE_MATCH_EXTEND_BYTES_HOOK(length - start);
  return length;
}

// ===============================================================
// Bitfield Operations

/*! @abstract Extracts \p width bits from \p container, starting with \p lsb; if
 * we view \p container as a bit array, we extract \c container[lsb:lsb+width]. */
LZFSE_INLINE uintmax_t extract(uintmax_t container, unsigned lsb,
                               unsigned width) {
#if defined(LZVN_PROOF) || defined(LZFSE_PROOF)
  return (container >> lsb) & (((uintmax_t)1 << width) - 1);
#else
  static const size_t container_width = sizeof container * 8;
  assert(lsb < container_width);
  assert(width > 0 && width <= container_width);
  assert(lsb + width <= container_width);
  if (width == container_width)
    return container;
  return (container >> lsb) & (((uintmax_t)1 << width) - 1);
#endif
}

/*! @abstract Check the header's field ranges and that each frequency table
 *  sums to at most its number of states. Returns 0, or a negative code with
 *  one bit set per failed test. */
#ifdef LZFSE_PROOF
LZFSE_NOINLINE int lzfse_check_block_header_v1(
#else
LZFSE_INLINE int lzfse_check_block_header_v1(
#endif
    const lzfse_compressed_block_header_v1 *header)
#ifdef LZFSE_PROOF
LZFSE_REQUIRES(__CPROVER_r_ok(header, sizeof *header))
LZFSE_ASSIGNS()
LZFSE_ENSURES(__CPROVER_return_value == 0 ==>
              (header->magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC &&
               header->n_literals <= LZFSE_LITERALS_PER_BLOCK &&
               header->n_matches <= LZFSE_MATCHES_PER_BLOCK &&
               header->literal_state[0] < LZFSE_ENCODE_LITERAL_STATES &&
               header->literal_state[1] < LZFSE_ENCODE_LITERAL_STATES &&
               header->literal_state[2] < LZFSE_ENCODE_LITERAL_STATES &&
               header->literal_state[3] < LZFSE_ENCODE_LITERAL_STATES &&
               header->l_state < LZFSE_ENCODE_L_STATES &&
               header->m_state < LZFSE_ENCODE_M_STATES &&
               header->d_state < LZFSE_ENCODE_D_STATES &&
               header->literal_bits >= -7 && header->literal_bits <= 0 &&
               header->lmd_bits >= -7 && header->lmd_bits <= 0))
#endif
{
  int tests_results = 0;
  tests_results =
      tests_results |
      ((header->magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC) ? 0 : (1 << 0));
  tests_results =
      tests_results |
      ((header->n_literals <= LZFSE_LITERALS_PER_BLOCK) ? 0 : (1 << 1));
  tests_results =
      tests_results |
      ((header->n_matches <= LZFSE_MATCHES_PER_BLOCK) ? 0 : (1 << 2));

  //  Read in place: the header is a properly aligned struct.
  const uint16_t *literal_state = header->literal_state;

  tests_results =
      tests_results |
      ((literal_state[0] < LZFSE_ENCODE_LITERAL_STATES) ? 0 : (1 << 3));
  tests_results =
      tests_results |
      ((literal_state[1] < LZFSE_ENCODE_LITERAL_STATES) ? 0 : (1 << 4));
  tests_results =
      tests_results |
      ((literal_state[2] < LZFSE_ENCODE_LITERAL_STATES) ? 0 : (1 << 5));
  tests_results =
      tests_results |
      ((literal_state[3] < LZFSE_ENCODE_LITERAL_STATES) ? 0 : (1 << 6));

  tests_results = tests_results |
                  ((header->l_state < LZFSE_ENCODE_L_STATES) ? 0 : (1 << 7));
  tests_results = tests_results |
                  ((header->m_state < LZFSE_ENCODE_M_STATES) ? 0 : (1 << 8));
  tests_results = tests_results |
                  ((header->d_state < LZFSE_ENCODE_D_STATES) ? 0 : (1 << 9));

  int res;
  res = fse_check_freq(header->l_freq, LZFSE_ENCODE_L_SYMBOLS,
                       LZFSE_ENCODE_L_STATES);
  tests_results = tests_results | ((res == 0) ? 0 : (1 << 10));
  res = fse_check_freq(header->m_freq, LZFSE_ENCODE_M_SYMBOLS,
                       LZFSE_ENCODE_M_STATES);
  tests_results = tests_results | ((res == 0) ? 0 : (1 << 11));
  res = fse_check_freq(header->d_freq, LZFSE_ENCODE_D_SYMBOLS,
                       LZFSE_ENCODE_D_STATES);
  tests_results = tests_results | ((res == 0) ? 0 : (1 << 12));
  res = fse_check_freq(header->literal_freq, LZFSE_ENCODE_LITERAL_SYMBOLS,
                       LZFSE_ENCODE_LITERAL_STATES);
  tests_results = tests_results | ((res == 0) ? 0 : (1 << 13));

  //  A V2 stream can only ever produce -7..0 here (a 3-bit field minus 7);
  //  a block claiming to be V1 is memcpy'd from the wire as a raw int32_t,
  //  so these need their own check. Checked once per block header, not per
  //  bit refill, since the value is fixed for the block's lifetime.
  tests_results = tests_results |
                  ((header->literal_bits >= -7 && header->literal_bits <= 0)
                       ? 0
                       : (1 << 14));
  tests_results = tests_results |
                  ((header->lmd_bits >= -7 && header->lmd_bits <= 0) ? 0
                                                                      : (1 << 15));

  if (tests_results) {
    return tests_results | 0x80000000; // each 1 bit is a test that failed
                                       // (except for the sign bit)
  }

  return 0; // OK
}

// MARK: - L, M, D encoding constants for LZFSE

//  Largest encodable L, M and D values.
#define LZFSE_ENCODE_MAX_L_VALUE 315
#define LZFSE_ENCODE_MAX_M_VALUE 2359
#define LZFSE_ENCODE_MAX_D_VALUE 262139
#ifdef LZFSE_EXACT_FSE
_Static_assert(LZFSE_ENCODE_MAX_L_VALUE == 315 &&
               LZFSE_ENCODE_MAX_M_VALUE == 2359 &&
               LZFSE_ENCODE_MAX_D_VALUE == 262139,
               "exact FSE value proof follows shipping value limits");
_Static_assert(LZFSE_ENCODE_LITERAL_STATES == 1024 &&
               LZFSE_ENCODE_L_STATES == 64 && LZFSE_ENCODE_M_STATES == 64 &&
               LZFSE_ENCODE_D_STATES == 256,
               "exact FSE value proof follows shipping table layouts");
#endif

/*! @abstract L, M and D are coded as an FSE base symbol plus raw extra bits
 *  (value - base). These tables give the extra bit count and base value per
 *  symbol; the inverse mappings are in lzfse_encode_tables.h. */
static const uint8_t l_extra_bits[LZFSE_ENCODE_L_SYMBOLS] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8
};
static const int32_t l_base_value[LZFSE_ENCODE_L_SYMBOLS] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60
};
//  Largest L the two tables above can produce, 60 + (1 << 8) - 1. The LMD loop
//  bounds `lit` with it, so a wrong value is a bounds bug;
//  lzfse_decode_extent_test checks it against the tables.
#define LZFSE_DECODE_L_MAX_VALUE 315
static const uint8_t m_extra_bits[LZFSE_ENCODE_M_SYMBOLS] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11
};
static const int32_t m_base_value[LZFSE_ENCODE_M_SYMBOLS] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312
};
static const uint8_t d_extra_bits[LZFSE_ENCODE_D_SYMBOLS] = {
  0,  0,  0,  0,  1,  1,  1,  1,  2,  2,  2,  2,  3,  3,  3,  3,
  4,  4,  4,  4,  5,  5,  5,  5,  6,  6,  6,  6,  7,  7,  7,  7,
  8,  8,  8,  8,  9,  9,  9,  9,  10, 10, 10, 10, 11, 11, 11, 11,
  12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15
};
static const int32_t d_base_value[LZFSE_ENCODE_D_SYMBOLS] = {
  0,      1,      2,      3,     4,     6,     8,     10,    12,    16,
  20,     24,     28,     36,    44,    52,    60,    76,    92,    108,
  124,    156,    188,    220,   252,   316,   380,   444,   508,   636,
  764,    892,    1020,   1276,  1532,  1788,  2044,  2556,  3068,  3580,
  4092,   5116,   6140,   7164,  8188,  10236, 12284, 14332, 16380, 20476,
  24572,  28668,  32764,  40956, 49148, 57340, 65532, 81916, 98300, 114684,
  131068, 163836, 196604, 229372
};

#endif // LZFSE_INTERNAL_H
