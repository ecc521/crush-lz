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


// Finite state entropy coding: Jarek Duda's tANS.

#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
#ifndef LZFSE_OFFSET
#define LZFSE_OFFSET(p) __CPROVER_POINTER_OFFSET(p)
#endif
#endif

//  64-bit I/O streams on 64-bit targets.
#if defined(_M_AMD64) || defined(__x86_64__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM64)
#define FSE_IOSTREAM_64 1
#else
#define FSE_IOSTREAM_64 0
#endif

#if defined(_MSC_VER) && !defined(__clang__)
#  define FSE_INLINE __forceinline
#  define inline __inline
#  pragma warning(disable : 4068) // warning C4068: unknown pragma
#else
#  define FSE_INLINE static inline __attribute__((__always_inline__))
#endif

// MARK: - Bit utils

/*! @abstract Signed type used to represent bit count. */
typedef int32_t fse_bit_count;

/*! @abstract Unsigned type used to represent FSE state. */
typedef uint16_t fse_state;

// Mask the NBITS lsb of X. 0 <= NBITS < 64
static inline uint64_t fse_mask_lsb64(uint64_t x, fse_bit_count nbits) {
  static const uint64_t mtable[65] = {
      0x0000000000000000LLU, 0x0000000000000001LLU, 0x0000000000000003LLU,
      0x0000000000000007LLU, 0x000000000000000fLLU, 0x000000000000001fLLU,
      0x000000000000003fLLU, 0x000000000000007fLLU, 0x00000000000000ffLLU,
      0x00000000000001ffLLU, 0x00000000000003ffLLU, 0x00000000000007ffLLU,
      0x0000000000000fffLLU, 0x0000000000001fffLLU, 0x0000000000003fffLLU,
      0x0000000000007fffLLU, 0x000000000000ffffLLU, 0x000000000001ffffLLU,
      0x000000000003ffffLLU, 0x000000000007ffffLLU, 0x00000000000fffffLLU,
      0x00000000001fffffLLU, 0x00000000003fffffLLU, 0x00000000007fffffLLU,
      0x0000000000ffffffLLU, 0x0000000001ffffffLLU, 0x0000000003ffffffLLU,
      0x0000000007ffffffLLU, 0x000000000fffffffLLU, 0x000000001fffffffLLU,
      0x000000003fffffffLLU, 0x000000007fffffffLLU, 0x00000000ffffffffLLU,
      0x00000001ffffffffLLU, 0x00000003ffffffffLLU, 0x00000007ffffffffLLU,
      0x0000000fffffffffLLU, 0x0000001fffffffffLLU, 0x0000003fffffffffLLU,
      0x0000007fffffffffLLU, 0x000000ffffffffffLLU, 0x000001ffffffffffLLU,
      0x000003ffffffffffLLU, 0x000007ffffffffffLLU, 0x00000fffffffffffLLU,
      0x00001fffffffffffLLU, 0x00003fffffffffffLLU, 0x00007fffffffffffLLU,
      0x0000ffffffffffffLLU, 0x0001ffffffffffffLLU, 0x0003ffffffffffffLLU,
      0x0007ffffffffffffLLU, 0x000fffffffffffffLLU, 0x001fffffffffffffLLU,
      0x003fffffffffffffLLU, 0x007fffffffffffffLLU, 0x00ffffffffffffffLLU,
      0x01ffffffffffffffLLU, 0x03ffffffffffffffLLU, 0x07ffffffffffffffLLU,
      0x0fffffffffffffffLLU, 0x1fffffffffffffffLLU, 0x3fffffffffffffffLLU,
      0x7fffffffffffffffLLU, 0xffffffffffffffffLLU,
  };
  return x & mtable[nbits];
}

// Mask the NBITS lsb of X. 0 <= NBITS < 32
static inline uint32_t fse_mask_lsb32(uint32_t x, fse_bit_count nbits) {
  static const uint32_t mtable[33] = {
      0x0000000000000000U, 0x0000000000000001U, 0x0000000000000003U,
      0x0000000000000007U, 0x000000000000000fU, 0x000000000000001fU,
      0x000000000000003fU, 0x000000000000007fU, 0x00000000000000ffU,
      0x00000000000001ffU, 0x00000000000003ffU, 0x00000000000007ffU,
      0x0000000000000fffU, 0x0000000000001fffU, 0x0000000000003fffU,
      0x0000000000007fffU, 0x000000000000ffffU, 0x000000000001ffffU,
      0x000000000003ffffU, 0x000000000007ffffU, 0x00000000000fffffU,
      0x00000000001fffffU, 0x00000000003fffffU, 0x00000000007fffffU,
      0x0000000000ffffffU, 0x0000000001ffffffU, 0x0000000003ffffffU,
      0x0000000007ffffffU, 0x000000000fffffffU, 0x000000001fffffffU,
      0x000000003fffffffU, 0x000000007fffffffU, 0x00000000ffffffffU,
  };
  return x & mtable[nbits];
}

//  Mask the NBITS lsb of X as a shift, for 0 <= NBITS <= 63 only. The decode
//  hot path stays in range because the input stream invariant is
//  56 <= accum_nbits < 64.
static inline uint64_t fse_mask_lsb64_lt(uint64_t x, fse_bit_count nbits) {
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  if (nbits < 0 || nbits >= 64) return 0;
#else
  assert(nbits >= 0 && nbits < 64);
#endif
  return x & ((1LLU << nbits) - 1LLU);
}

//  32-bit variant; accum_nbits is in [24, 32) there.
static inline uint32_t fse_mask_lsb32_lt(uint32_t x, fse_bit_count nbits) {
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  if (nbits < 0 || nbits >= 32) return 0;
#else
  assert(nbits >= 0 && nbits < 32);
#endif
  return x & ((1U << nbits) - 1U);
}

/*! @abstract Select \c nbits at index \c start from \c x.
 *  0 <= start <= start+nbits <= 64 */
FSE_INLINE uint64_t fse_extract_bits64(uint64_t x, fse_bit_count start,
                                       fse_bit_count nbits) {
#if defined(__GNUC__)
  // If START and NBITS are constants, map to bit-field extraction instructions
  if (__builtin_constant_p(start) && __builtin_constant_p(nbits))
    return (x >> start) & ((1LLU << nbits) - 1LLU);
#endif

  return fse_mask_lsb64(x >> start, nbits);
}

/*! @abstract Select \c nbits at index \c start from \c x.
 *  0 <= start <= start+nbits <= 32 */
FSE_INLINE uint32_t fse_extract_bits32(uint32_t x, fse_bit_count start,
                                       fse_bit_count nbits) {
#if defined(__GNUC__)
  // If START and NBITS are constants, map to bit-field extraction instructions
  if (__builtin_constant_p(start) && __builtin_constant_p(nbits))
    return (x >> start) & ((1U << nbits) - 1U);
#endif

  return fse_mask_lsb32(x >> start, nbits);
}

// MARK: - Bit stream

// Streams are shared between FSE encoders/decoders, so they are not in the
// state struct.

/*! @abstract Output stream, 64-bit accum. */
typedef struct {
  uint64_t accum;            // Output bits
  fse_bit_count accum_nbits; // Number of valid bits in ACCUM, other bits are 0
} fse_out_stream64;

typedef struct {
  uint32_t accum;            // Output bits
  fse_bit_count accum_nbits; // Number of valid bits in ACCUM, other bits are 0
} fse_out_stream32;

/*! @abstract Object representing an input stream. */
typedef struct {
  uint64_t accum;            // Input bits
  fse_bit_count accum_nbits; // Number of valid bits in ACCUM, other bits are 0
} fse_in_stream64;

typedef struct {
  uint32_t accum;            // Input bits
  fse_bit_count accum_nbits; // Number of valid bits in ACCUM, other bits are 0
} fse_in_stream32;

/*! @abstract Write the last bytes, zero-padded, leaving accum_nbits in
 *  [-7, 0]. Needs 8 writable bytes at *pbuf; advances *pbuf. */
FSE_INLINE void fse_out_finish64(fse_out_stream64 *s, uint8_t **pbuf) {
  fse_bit_count nbits =
      (s->accum_nbits + 7) & -8; // number of bits written, multiple of 8

  memcpy(*pbuf, &(s->accum), 8);
  *pbuf += (nbits >> 3); // bytes

  s->accum = 0; // remove nbits
  s->accum_nbits -= nbits;

  assert(s->accum_nbits >= -7 && s->accum_nbits <= 0);
}

/*! @abstract 32-bit variant of fse_out_finish64; needs 4 writable bytes. */
FSE_INLINE void fse_out_finish32(fse_out_stream32 *s, uint8_t **pbuf) {
  fse_bit_count nbits =
      (s->accum_nbits + 7) & -8; // number of bits written, multiple of 8

  // Write 8 bytes of current accumulator
  memcpy(*pbuf, &(s->accum), 4);
  *pbuf += (nbits >> 3); // bytes

  s->accum = 0; // remove nbits
  s->accum_nbits -= nbits;

  assert(s->accum_nbits >= -7 && s->accum_nbits <= 0);
}

#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
#define DEBUG_CHECK_INPUT_STREAM_PARAMETERS
#elif FSE_IOSTREAM_64
#define DEBUG_CHECK_INPUT_STREAM_PARAMETERS                                    \
  assert(s->accum_nbits >= 56 && s->accum_nbits < 64);                         \
  assert((s->accum >> s->accum_nbits) == 0);
#else
#define DEBUG_CHECK_INPUT_STREAM_PARAMETERS                                    \
  assert(s->accum_nbits >= 24 && s->accum_nbits < 32);                         \
  assert((s->accum >> s->accum_nbits) == 0);
#endif

/*! @abstract Initialize the input stream so accum holds 56 to 63 bits, never
 *  64, which is what lets fse_in_pull avoid a special case; hence n == 0
 *  loads 7 bytes instead of 8. */
FSE_INLINE int fse_in_checked_init64(fse_in_stream64 *s, fse_bit_count n,
                                     const uint8_t **pbuf,
                                     const uint8_t *buf_start)
#if defined(LZFSE_EXACT_FSE)
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))
__CPROVER_requires(__CPROVER_rw_ok(pbuf, sizeof *pbuf))
__CPROVER_requires(n >= -7 && n <= 0)
__CPROVER_requires(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_requires(__CPROVER_r_ok(buf_start,
    (size_t)(__CPROVER_POINTER_OFFSET(*pbuf) - __CPROVER_POINTER_OFFSET(buf_start))))
__CPROVER_requires(!__CPROVER_same_object(s, pbuf))
__CPROVER_requires(!__CPROVER_same_object(s, buf_start))
__CPROVER_requires(!__CPROVER_same_object(pbuf, buf_start))
__CPROVER_assigns(s->accum, s->accum_nbits, *pbuf)
__CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)
__CPROVER_ensures(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) <= __CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)) - __CPROVER_POINTER_OFFSET(*pbuf) <= 8)
__CPROVER_ensures(__CPROVER_return_value == 0 ==>
    __CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)) - __CPROVER_POINTER_OFFSET(*pbuf) == (n ? 8 : 7))
__CPROVER_ensures(__CPROVER_return_value == 0 ==>
    s->accum_nbits == (n ? n + 64 : 56))
__CPROVER_ensures(__CPROVER_return_value == 0 ==>
    (s->accum >> s->accum_nbits) == 0)
#endif
{
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  if (n) {
    if ((size_t)(*pbuf - buf_start) < 8)
      return -1; // out of range
    *pbuf -= 8;
    s->accum_nbits = n + 64;
  } else {
    if ((size_t)(*pbuf - buf_start) < 7)
      return -1; // out of range
    *pbuf -= 7;
    s->accum_nbits = n + 56;
  }
#else
  if (n) {
    if ((size_t)(*pbuf - buf_start) < 8)
      return -1; // out of range
    *pbuf -= 8;
    memcpy(&(s->accum), *pbuf, 8);
    s->accum_nbits = n + 64;
  } else {
    if ((size_t)(*pbuf - buf_start) < 7)
      return -1; // out of range
    *pbuf -= 7;
    memcpy(&(s->accum), *pbuf, 7);
    s->accum &= 0xffffffffffffff;
    s->accum_nbits = n + 56;
  }
#endif

#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  if (s->accum_nbits < 56 || s->accum_nbits >= 64) {
    return -1;
  }
#else
  if ((s->accum_nbits < 56 || s->accum_nbits >= 64) ||
      ((s->accum >> s->accum_nbits) != 0)) {
    return -1; // the incoming input is wrong (encoder should have zeroed the
               // upper bits)
  }
#endif

  return 0; // OK
}

/*! @abstract 32-bit variant: accum holds 24 to 31 bits. */
FSE_INLINE int fse_in_checked_init32(fse_in_stream32 *s, fse_bit_count n,
                                     const uint8_t **pbuf,
                                     const uint8_t *buf_start)
#if defined(LZFSE_EXACT_FSE)
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))
__CPROVER_requires(__CPROVER_rw_ok(pbuf, sizeof *pbuf))
__CPROVER_requires(n >= -7 && n <= 0)
__CPROVER_requires(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_requires(__CPROVER_r_ok(buf_start,
    (size_t)(__CPROVER_POINTER_OFFSET(*pbuf) - __CPROVER_POINTER_OFFSET(buf_start))))
__CPROVER_requires(!__CPROVER_same_object(s, pbuf))
__CPROVER_requires(!__CPROVER_same_object(s, buf_start))
__CPROVER_requires(!__CPROVER_same_object(pbuf, buf_start))
__CPROVER_assigns(s->accum, s->accum_nbits, *pbuf)
__CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)
__CPROVER_ensures(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) <= __CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)))
__CPROVER_ensures(__CPROVER_return_value == 0 ==>
    __CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)) - __CPROVER_POINTER_OFFSET(*pbuf) == (n ? 4 : 3))
__CPROVER_ensures(__CPROVER_return_value == 0 ==>
    s->accum_nbits == (n ? n + 32 : 24))
__CPROVER_ensures(__CPROVER_return_value == 0 ==>
    (s->accum >> s->accum_nbits) == 0)
#endif
{
  if (n) {
    if ((size_t)(*pbuf - buf_start) < 4)
      return -1; // out of range
    *pbuf -= 4;
    memcpy(&(s->accum), *pbuf, 4);
    s->accum_nbits = n + 32;
  } else {
    if ((size_t)(*pbuf - buf_start) < 3)
      return -1; // out of range
    *pbuf -= 3;
    memcpy(&(s->accum), *pbuf, 3);
    s->accum &= 0xffffff;
    s->accum_nbits = n + 24;
  }

#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  if (s->accum_nbits < 24 || s->accum_nbits >= 32) {
    return -1;
  }
#else
  if ((s->accum_nbits < 24 || s->accum_nbits >= 32) ||
      ((s->accum >> s->accum_nbits) != 0)) {
    return -1; // the incoming input is wrong (encoder should have zeroed the
               // upper bits)
  }
#endif

  return 0; // OK
}

/*! @abstract Refill accum to 56..63 bits, checking *pbuf stays >= buf_start.
 *  Returns 0, or -1 on underrun. The 8 bytes below buf_start must be
 *  readable: the refill loads the word ending at *pbuf. Both decoder
 *  streams have their block header there. */
FSE_INLINE int fse_in_checked_flush64(fse_in_stream64 *s, const uint8_t **pbuf,
                                      const uint8_t *buf_start)
#if defined(LZFSE_EXACT_FSE)
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))
__CPROVER_requires(__CPROVER_rw_ok(pbuf, sizeof *pbuf))
__CPROVER_requires(s->accum_nbits >= 0 && s->accum_nbits < 64)
__CPROVER_requires((s->accum >> s->accum_nbits) == 0)
__CPROVER_requires(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(buf_start) >= 8)
__CPROVER_requires(__CPROVER_r_ok(buf_start - 8,
    (size_t)(__CPROVER_POINTER_OFFSET(*pbuf) - __CPROVER_POINTER_OFFSET(buf_start)) + 8))
__CPROVER_requires(!__CPROVER_same_object(s, pbuf))
__CPROVER_requires(!__CPROVER_same_object(s, buf_start))
__CPROVER_requires(!__CPROVER_same_object(pbuf, buf_start))
__CPROVER_assigns(s->accum, s->accum_nbits, *pbuf)
__CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)
__CPROVER_ensures(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) <= __CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)) - __CPROVER_POINTER_OFFSET(*pbuf) <= 8)
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)) - __CPROVER_POINTER_OFFSET(buf_start) >= 8 ==> __CPROVER_return_value == 0)
__CPROVER_ensures(__CPROVER_return_value == 0 ==>
    s->accum_nbits >= 56 && s->accum_nbits < 64)
__CPROVER_ensures(__CPROVER_return_value == -1 ==> *pbuf == __CPROVER_old(*pbuf))
__CPROVER_ensures(__CPROVER_return_value == -1 ==> s->accum == __CPROVER_old(s->accum))
__CPROVER_ensures(__CPROVER_return_value == -1 ==> s->accum_nbits == __CPROVER_old(s->accum_nbits))
//  After the clauses that bound accum_nbits on both returns, so a caller
//  assuming this one never shifts by an unconstrained width.
__CPROVER_ensures((s->accum >> s->accum_nbits) == 0)
#endif
{
  fse_bit_count nbits = (63 - s->accum_nbits) & -8;

  //  A full accumulator asks for nbits == 0, where the load below would read 8
  //  bytes and mask every one away. *pbuf can sit 7 bytes from the end of the
  //  input, so that discarded load runs past the buffer and faults when the
  //  input ends on a page. The 32-bit variant has always skipped it.
  if (nbits > 0) {
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
    if (nbits >= 64)
      return -1;
    if (LZFSE_OFFSET(*pbuf) < LZFSE_OFFSET(buf_start) + (size_t)(nbits >> 3))
      return -1;
    *pbuf = (*pbuf) - (nbits >> 3);
    s->accum_nbits += nbits;
    if (s->accum_nbits > 63) s->accum_nbits = 63;
#else
    //  Check the remaining span before forming a pointer, then load the
    //  word ending at *pbuf: no load reaches past *pbuf, and the caller
    //  guarantees 8 readable bytes below buf_start, so none falls outside
    //  the input either.
    size_t nbytes = (size_t)(nbits >> 3);
    if ((size_t)(*pbuf - buf_start) < nbytes)
      return -1; // out of range
    uint64_t word;
    memcpy(&word, *pbuf - 8, 8);
    *pbuf -= nbytes;
    s->accum = (s->accum << nbits) | (word >> (64 - nbits));
    s->accum_nbits += nbits;
#endif
  }
  DEBUG_CHECK_INPUT_STREAM_PARAMETERS
  return 0; // OK
}

/*! @abstract 32-bit variant; the 4 bytes below buf_start must be readable. */
FSE_INLINE int fse_in_checked_flush32(fse_in_stream32 *s, const uint8_t **pbuf,
                                      const uint8_t *buf_start)
#if defined(LZFSE_EXACT_FSE)
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))
__CPROVER_requires(__CPROVER_rw_ok(pbuf, sizeof *pbuf))
__CPROVER_requires(s->accum_nbits >= 0 && s->accum_nbits < 32)
__CPROVER_requires((s->accum >> s->accum_nbits) == 0)
__CPROVER_requires(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(buf_start) >= 4)
__CPROVER_requires(__CPROVER_r_ok(buf_start - 4,
    (size_t)(__CPROVER_POINTER_OFFSET(*pbuf) - __CPROVER_POINTER_OFFSET(buf_start)) + 4))
__CPROVER_requires(!__CPROVER_same_object(s, pbuf))
__CPROVER_requires(!__CPROVER_same_object(s, buf_start))
__CPROVER_requires(!__CPROVER_same_object(pbuf, buf_start))
__CPROVER_assigns(s->accum, s->accum_nbits, *pbuf)
__CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)
__CPROVER_ensures(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) <= __CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)))
__CPROVER_ensures(__CPROVER_return_value == 0 ==>
    s->accum_nbits >= 24 && s->accum_nbits < 32)
__CPROVER_ensures(__CPROVER_return_value == -1 ==> *pbuf == __CPROVER_old(*pbuf))
__CPROVER_ensures(__CPROVER_return_value == -1 ==> s->accum == __CPROVER_old(s->accum))
__CPROVER_ensures(__CPROVER_return_value == -1 ==> s->accum_nbits == __CPROVER_old(s->accum_nbits))
//  After the clauses that bound accum_nbits on both returns, so a caller
//  assuming this one never shifts by an unconstrained width.
__CPROVER_ensures((s->accum >> s->accum_nbits) == 0)
#endif
{
  fse_bit_count nbits = (31 - s->accum_nbits) & -8;

  if (nbits > 0) {
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
    if (nbits >= 32)
      return -1;
#endif
    size_t nbytes = (size_t)(nbits >> 3);
    if ((size_t)(*pbuf - buf_start) < nbytes)
      return -1; // out of range
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
    *pbuf -= nbytes;
    s->accum_nbits += nbits;
    if (s->accum_nbits > 31) s->accum_nbits = 31;
#else
    //  As in fse_in_checked_flush64, with a 4-byte word and 4 readable
    //  bytes below buf_start.
    uint32_t word;
    memcpy(&word, *pbuf - 4, 4);
    *pbuf -= nbytes;
    s->accum = (s->accum << nbits) | (word >> (32 - nbits));
    s->accum_nbits += nbits;
#endif
  }
#if !defined(LZFSE_PROOF) || defined(LZFSE_EXACT_FSE)
  // This explicit variant retains its 32-bit invariant on 64-bit hosts too.
  assert(s->accum_nbits >= 24 && s->accum_nbits < 32);
  assert((s->accum >> s->accum_nbits) == 0);
#endif
  return 0; // OK
}

/*! @abstract As fse_in_checked_flush64 without the bound check. It loads the
 *  8 bytes below *pbuf, and each flush moves *pbuf down by at most 7 bytes,
 *  so N unchecked flushes are safe when *pbuf - buf_start >= 8*N at entry. */
FSE_INLINE void fse_in_flush64_unchecked(fse_in_stream64 *s, const uint8_t **pbuf)
#if defined(LZFSE_EXACT_FSE)
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))
__CPROVER_requires(__CPROVER_rw_ok(pbuf, sizeof *pbuf))
__CPROVER_requires(s->accum_nbits >= 0 && s->accum_nbits < 64)
__CPROVER_requires((s->accum >> s->accum_nbits) == 0)
__CPROVER_requires(__CPROVER_POINTER_OFFSET(*pbuf) >= 8)
__CPROVER_requires(s->accum_nbits >= 56 || __CPROVER_r_ok(*pbuf - 8, 8))
__CPROVER_requires(!__CPROVER_same_object(s, pbuf))
__CPROVER_requires(!__CPROVER_same_object(s, *pbuf))
__CPROVER_requires(!__CPROVER_same_object(pbuf, *pbuf))
__CPROVER_assigns(s->accum, s->accum_nbits, *pbuf)
__CPROVER_ensures(s->accum_nbits >= 56 && s->accum_nbits < 64)
__CPROVER_ensures((s->accum >> s->accum_nbits) == 0)
__CPROVER_ensures(*pbuf == __CPROVER_old(*pbuf) - ((63 - __CPROVER_old(s->accum_nbits)) >> 3))
#endif
{
  fse_bit_count nbits = (63 - s->accum_nbits) & -8;
  if (nbits > 0) { // as in fse_in_checked_flush64
    const uint8_t *buf = (*pbuf) - (nbits >> 3);
    *pbuf = buf;
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
    s->accum_nbits += nbits;
    if (s->accum_nbits > 63) s->accum_nbits = 63;
#else
    //  At least 8 bytes lie below the old *pbuf (see above), so the
    //  word ending there is in bounds.
    uint64_t word;
    memcpy(&word, buf + (nbits >> 3) - 8, 8);
    s->accum = (s->accum << nbits) | (word >> (64 - nbits));
    s->accum_nbits += nbits;
#endif
  }
  DEBUG_CHECK_INPUT_STREAM_PARAMETERS
}

/*! @abstract Pull n bits out of the fse stream object. */
FSE_INLINE uint64_t fse_in_pull64(fse_in_stream64 *s, fse_bit_count n)
#if defined(LZFSE_EXACT_FSE)
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))
__CPROVER_requires(s->accum_nbits >= 0 && s->accum_nbits < 64)
__CPROVER_requires(n >= 0 && n <= s->accum_nbits)
__CPROVER_requires((s->accum >> s->accum_nbits) == 0)
__CPROVER_assigns(s->accum, s->accum_nbits)
__CPROVER_ensures(s->accum_nbits == __CPROVER_old(s->accum_nbits) - n)
__CPROVER_ensures(__CPROVER_return_value ==
    (__CPROVER_old(s->accum) >> (__CPROVER_old(s->accum_nbits) - n)))
__CPROVER_ensures((s->accum >> s->accum_nbits) == 0)
#endif
{
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  if (n < 0) n = 0;
  if (n > s->accum_nbits) n = s->accum_nbits;
  s->accum_nbits -= n;
  return (uint64_t)(n & 0x3f);
#else
  assert(n >= 0 && n <= s->accum_nbits);
  s->accum_nbits -= n;
  uint64_t result = s->accum >> s->accum_nbits;
  s->accum = fse_mask_lsb64_lt(s->accum, s->accum_nbits);
  return result;
#endif
}

FSE_INLINE uint32_t fse_in_pull32(fse_in_stream32 *s, fse_bit_count n)
#if defined(LZFSE_EXACT_FSE)
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))
__CPROVER_requires(s->accum_nbits >= 0 && s->accum_nbits < 32)
__CPROVER_requires(n >= 0 && n <= s->accum_nbits)
__CPROVER_requires((s->accum >> s->accum_nbits) == 0)
__CPROVER_assigns(s->accum, s->accum_nbits)
__CPROVER_ensures(s->accum_nbits == __CPROVER_old(s->accum_nbits) - n)
__CPROVER_ensures(__CPROVER_return_value ==
    (__CPROVER_old(s->accum) >> (__CPROVER_old(s->accum_nbits) - n)))
__CPROVER_ensures((s->accum >> s->accum_nbits) == 0)
#endif
{
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  if (n < 0) n = 0;
  if (n > s->accum_nbits) n = s->accum_nbits;
  s->accum_nbits -= n;
  return (uint32_t)(n & 0x1f);
#else
  assert(n >= 0 && n <= s->accum_nbits);
  s->accum_nbits -= n;
  uint32_t result = s->accum >> s->accum_nbits;
  s->accum = fse_mask_lsb32_lt(s->accum, s->accum_nbits);
  return result;
#endif
}

// MARK: - Encode/Decode

// Map to 32/64-bit implementations and types for I/O
#if FSE_IOSTREAM_64

typedef fse_out_stream64 fse_out_stream;
typedef fse_in_stream64 fse_in_stream;
#define fse_mask_lsb_lt fse_mask_lsb64_lt
#define fse_extract_bits fse_extract_bits64
#define fse_out_finish fse_out_finish64
#define fse_in_init fse_in_checked_init64
#define fse_in_flush fse_in_checked_flush64
#define fse_in_flush2(_unused, _parameters, _unused2) 0 /* nothing */
#define fse_in_pull fse_in_pull64

#else

typedef fse_out_stream32 fse_out_stream;
typedef fse_in_stream32 fse_in_stream;
#define fse_mask_lsb_lt fse_mask_lsb32_lt
#define fse_extract_bits fse_extract_bits32
#define fse_out_finish fse_out_finish32
#define fse_in_init fse_in_checked_init32
#define fse_in_flush fse_in_checked_flush32
#define fse_in_flush2 fse_in_checked_flush32
#define fse_in_pull fse_in_pull32

#endif

/*! @abstract As fse_in_checked_flush64, taking the incoming bytes from
 *  *next, the 8 bytes below *pbuf loaded by the previous refill, so the
 *  accumulator update does not wait on a load. Reloads *next for the
 *  following refill: the caller guarantees the 8 bytes below buf_start are
 *  readable. Only ARM64 uses it (FSE_LOOKAHEAD_REFILL); elsewhere it is
 *  the plain refill, since the extra live register is unmeasured on x86. */
#if (defined(__aarch64__) || defined(_M_ARM64)) && (!defined(LZFSE_PROOF) || defined(LZFSE_EXACT_FSE))
#define FSE_LOOKAHEAD_REFILL 1
#else
#define FSE_LOOKAHEAD_REFILL 0
#endif
FSE_INLINE int fse_in_flush_next(fse_in_stream *s, const uint8_t **pbuf,
                                 const uint8_t *buf_start, uint64_t *next)
#if defined(LZFSE_EXACT_FSE) && FSE_LOOKAHEAD_REFILL
__CPROVER_requires(__CPROVER_rw_ok(s, sizeof *s))
__CPROVER_requires(__CPROVER_rw_ok(pbuf, sizeof *pbuf))
__CPROVER_requires(__CPROVER_rw_ok(next, sizeof *next))
__CPROVER_requires(s->accum_nbits >= 0 && s->accum_nbits < 64)
__CPROVER_requires((s->accum >> s->accum_nbits) == 0)
__CPROVER_requires(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(buf_start) >= 8)
__CPROVER_requires(__CPROVER_r_ok(buf_start - 8,
    (size_t)(__CPROVER_POINTER_OFFSET(*pbuf) - __CPROVER_POINTER_OFFSET(buf_start)) + 8))
__CPROVER_requires(!__CPROVER_same_object(s, pbuf))
__CPROVER_requires(!__CPROVER_same_object(s, buf_start))
__CPROVER_requires(!__CPROVER_same_object(pbuf, buf_start))
__CPROVER_requires(!__CPROVER_same_object(next, s))
__CPROVER_requires(!__CPROVER_same_object(next, pbuf))
__CPROVER_requires(!__CPROVER_same_object(next, buf_start))
__CPROVER_assigns(s->accum, s->accum_nbits, *pbuf, *next)
__CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)
__CPROVER_ensures(__CPROVER_same_object(*pbuf, buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) >= __CPROVER_POINTER_OFFSET(buf_start))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(*pbuf) <= __CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)) - __CPROVER_POINTER_OFFSET(*pbuf) <= 8)
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(__CPROVER_old(*pbuf)) - __CPROVER_POINTER_OFFSET(buf_start) >= 8 ==> __CPROVER_return_value == 0)
__CPROVER_ensures(__CPROVER_return_value == 0 ==>
    s->accum_nbits >= 56 && s->accum_nbits < 64)
__CPROVER_ensures(__CPROVER_return_value == -1 ==> *pbuf == __CPROVER_old(*pbuf))
__CPROVER_ensures(__CPROVER_return_value == -1 ==> s->accum == __CPROVER_old(s->accum))
__CPROVER_ensures(__CPROVER_return_value == -1 ==> s->accum_nbits == __CPROVER_old(s->accum_nbits))
//  After the clauses that bound accum_nbits on both returns, so a caller
//  assuming this one never shifts by an unconstrained width.
__CPROVER_ensures((s->accum >> s->accum_nbits) == 0)
__CPROVER_ensures(__CPROVER_return_value == -1 ==> *next == __CPROVER_old(*next))
#endif
{
#if FSE_LOOKAHEAD_REFILL
  fse_bit_count nbits = (63 - s->accum_nbits) & -8;
  if (nbits <= 0)
    return 0;
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  if (nbits >= 64)
    return -1;
  if (LZFSE_OFFSET(*pbuf) < LZFSE_OFFSET(buf_start) + (size_t)(nbits >> 3))
    return -1;
  const uint8_t *buf = (*pbuf) - (nbits >> 3);
  *pbuf = buf;
  s->accum_nbits += nbits;
  if (s->accum_nbits > 63) s->accum_nbits = 63;
  *next = 0;
  return 0;
#else
  const uint8_t *buf = (*pbuf) - (nbits >> 3);
  if (buf < buf_start)
    return -1;
  *pbuf = buf;
  s->accum = (s->accum << nbits) | ((*next >> 1) >> (63 - nbits));
  s->accum_nbits += nbits;
  memcpy(next, buf - 8, 8);
  return 0;
#endif
#else
  (void)next;
  return fse_in_flush(s, pbuf, buf_start);
#endif
}


/*! @abstract Entry for one symbol in the encoder table. */
typedef struct {
  int16_t s0;     // First state requiring a K-bit shift
  int16_t k;      // States S >= S0 are shifted K bits. States S < S0 are
                  // shifted K-1 bits
  int16_t delta0; // Relative increment used to compute next state if S >= S0
} fse_encoder_entry;

/*! @abstract  Entry for one state in the decoder table (32b). */
typedef struct {  // DO NOT REORDER THE FIELDS
  int8_t k;       // Number of bits to read
  uint8_t symbol; // Emitted symbol
  int16_t delta;  // Signed increment used to compute next state (+bias)
} fse_decoder_entry;

/*! @abstract  Entry for one state in the value decoder table (64b). */
typedef struct {      // DO NOT REORDER THE FIELDS
  uint8_t total_bits; // state bits + extra value bits = shift for next decode
  uint8_t value_bits; // extra value bits
  int16_t delta;      // state base (delta)
  int32_t vbase;      // value base
} fse_value_decoder_entry;

/*! @abstract Decode and return a symbol, updating *pstate and in. The caller
 *  must have enough bits in the input accumulator. */
FSE_INLINE uint8_t fse_decode(fse_state *__restrict pstate,
                              const int32_t *__restrict decoder_table,
                              fse_in_stream *__restrict in) {
  int32_t e = decoder_table[*pstate];

  *pstate = (fse_state)(e >> 16) + (fse_state)fse_in_pull(in, e & 0xff);

  return fse_extract_bits(e, 8, 8); // symbol
}


/*! @abstract As fse_decode with a uint32_t state, dropping the uint16
 *  truncation: delta >= 0 and delta + pull(k) <= nstates - 1 for every table
 *  fse_check_freq admits, so the state stays in range without it. */
#ifndef LZFSE_ENCODE_LITERAL_STATES
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
#define LZFSE_ENCODE_LITERAL_STATES 64
#else
#define LZFSE_ENCODE_LITERAL_STATES 1024
#endif
#endif

FSE_INLINE uint8_t fse_decode_u32(uint32_t *__restrict pstate,
                                  const int32_t *__restrict decoder_table,
                                  fse_in_stream *__restrict in)
#if defined(LZFSE_EXACT_FSE)
#if FSE_IOSTREAM_64
__CPROVER_requires(__CPROVER_rw_ok(pstate, sizeof *pstate))
__CPROVER_requires(__CPROVER_rw_ok(in, sizeof *in))
__CPROVER_requires(__CPROVER_r_ok(decoder_table, LZFSE_ENCODE_LITERAL_STATES * sizeof *decoder_table))
__CPROVER_requires(*pstate < LZFSE_ENCODE_LITERAL_STATES)
__CPROVER_requires(in->accum_nbits >= 0 && in->accum_nbits < 64)
__CPROVER_requires((in->accum >> in->accum_nbits) == 0)
__CPROVER_requires((decoder_table[*pstate] & 0xff) <= 10)
__CPROVER_requires((decoder_table[*pstate] & 0xff) <= in->accum_nbits)
__CPROVER_requires((decoder_table[*pstate] >> 16) >= 0)
__CPROVER_requires((uint32_t)(decoder_table[*pstate] >> 16) +
    (((uint32_t)1 << (decoder_table[*pstate] & 0xff)) - 1) < LZFSE_ENCODE_LITERAL_STATES)
__CPROVER_requires(!__CPROVER_same_object(pstate, in))
__CPROVER_requires(!__CPROVER_same_object(pstate, decoder_table))
__CPROVER_requires(!__CPROVER_same_object(in, decoder_table))
__CPROVER_assigns(*pstate, in->accum, in->accum_nbits)
__CPROVER_ensures(*pstate < LZFSE_ENCODE_LITERAL_STATES)
__CPROVER_ensures(in->accum_nbits == __CPROVER_old(in->accum_nbits) -
    (decoder_table[__CPROVER_old(*pstate)] & 0xff))
__CPROVER_ensures((in->accum >> in->accum_nbits) == 0)
#else
__CPROVER_requires(__CPROVER_rw_ok(pstate, sizeof *pstate))
__CPROVER_requires(__CPROVER_rw_ok(in, sizeof *in))
__CPROVER_requires(__CPROVER_r_ok(decoder_table, LZFSE_ENCODE_LITERAL_STATES * sizeof *decoder_table))
__CPROVER_requires(*pstate < LZFSE_ENCODE_LITERAL_STATES)
__CPROVER_requires(in->accum_nbits >= 10 && in->accum_nbits < 32)
__CPROVER_requires((in->accum >> in->accum_nbits) == 0)
__CPROVER_requires((decoder_table[*pstate] & 0xff) <= 10)
__CPROVER_requires((decoder_table[*pstate] >> 16) >= 0)
__CPROVER_requires((uint32_t)(decoder_table[*pstate] >> 16) +
    (((uint32_t)1 << (decoder_table[*pstate] & 0xff)) - 1) < LZFSE_ENCODE_LITERAL_STATES)
__CPROVER_requires(!__CPROVER_same_object(pstate, in))
__CPROVER_requires(!__CPROVER_same_object(pstate, decoder_table))
__CPROVER_requires(!__CPROVER_same_object(in, decoder_table))
__CPROVER_assigns(*pstate, in->accum, in->accum_nbits)
__CPROVER_ensures(*pstate < LZFSE_ENCODE_LITERAL_STATES)
__CPROVER_ensures(in->accum_nbits >= 0 && in->accum_nbits < 32)
__CPROVER_ensures(__CPROVER_old(in->accum_nbits) - in->accum_nbits >= 0 &&
    __CPROVER_old(in->accum_nbits) - in->accum_nbits <= 10)
__CPROVER_ensures(in->accum_nbits == __CPROVER_old(in->accum_nbits) -
    (decoder_table[__CPROVER_old(*pstate)] & 0xff))
__CPROVER_ensures((in->accum >> in->accum_nbits) == 0)
#endif
#endif
{
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  *pstate &= (LZFSE_ENCODE_LITERAL_STATES - 1);
#endif
  int32_t e = decoder_table[*pstate];

  *pstate = (uint32_t)(e >> 16) + (uint32_t)fse_in_pull(in, e & 0xff);
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  *pstate &= (LZFSE_ENCODE_LITERAL_STATES - 1);
#endif

  return (uint8_t)((uint32_t)e >> 8); // symbol
}

/*! @abstract Decode and return a value, updating *pstate and in. The caller
 *  must have enough bits in the input accumulator. */
FSE_INLINE int32_t
fse_value_decode(fse_state *__restrict pstate,
                 const fse_value_decoder_entry *value_decoder_table,
                 fse_in_stream *__restrict in) {
  fse_value_decoder_entry entry = value_decoder_table[*pstate];
  uint32_t state_and_value_bits = (uint32_t)fse_in_pull(in, entry.total_bits);
  *pstate =
      (fse_state)(entry.delta + (state_and_value_bits >> entry.value_bits));
  return (int32_t)(entry.vbase +
                   fse_mask_lsb_lt(state_and_value_bits, entry.value_bits));
}


/*! @abstract As fse_value_decode with uint32_t state and result. Both are
 *  non-negative (vbase >= 0 in every base-value table), so the widening
 *  changes no value and drops the sign extensions. */
FSE_INLINE uint32_t
fse_value_decode_u32(uint32_t *__restrict pstate,
                     const fse_value_decoder_entry *value_decoder_table,
                     size_t table_offset,
                     fse_in_stream *__restrict in)
#if defined(LZFSE_EXACT_FSE)
__CPROVER_requires(__CPROVER_rw_ok(pstate, sizeof *pstate))
__CPROVER_requires(__CPROVER_rw_ok(in, sizeof *in))
__CPROVER_requires(__CPROVER_r_ok(value_decoder_table, 408 * sizeof *value_decoder_table))
__CPROVER_requires(table_offset == 0 || table_offset == 72 || table_offset == 144)
__CPROVER_requires(*pstate < (table_offset == 144 ? 256 : 64))
__CPROVER_requires(in->accum_nbits >= 0 && in->accum_nbits < 64)
__CPROVER_requires((in->accum >> in->accum_nbits) == 0)
__CPROVER_requires(value_decoder_table[table_offset + *pstate].value_bits <= 16)
__CPROVER_requires(value_decoder_table[table_offset + *pstate].total_bits >=
    value_decoder_table[table_offset + *pstate].value_bits)
__CPROVER_requires(value_decoder_table[table_offset + *pstate].total_bits -
    value_decoder_table[table_offset + *pstate].value_bits <= (table_offset == 144 ? 8 : 6))
__CPROVER_requires(value_decoder_table[table_offset + *pstate].total_bits <= in->accum_nbits)
__CPROVER_requires(value_decoder_table[table_offset + *pstate].delta >= 0)
__CPROVER_requires((uint32_t)value_decoder_table[table_offset + *pstate].delta +
    (((uint32_t)1 << (value_decoder_table[table_offset + *pstate].total_bits -
                       value_decoder_table[table_offset + *pstate].value_bits)) - 1) <
    (table_offset == 144 ? 256 : 64))
__CPROVER_requires(value_decoder_table[table_offset + *pstate].vbase >= 0)
__CPROVER_requires((uint32_t)value_decoder_table[table_offset + *pstate].vbase <=
    (table_offset == 0 ? 315 : table_offset == 72 ? 2359 : 262139))
__CPROVER_requires((uint32_t)value_decoder_table[table_offset + *pstate].vbase +
    (((uint32_t)1 << value_decoder_table[table_offset + *pstate].value_bits) - 1) <=
    (table_offset == 0 ? 315 : table_offset == 72 ? 2359 : 262139))
__CPROVER_requires(!__CPROVER_same_object(pstate, in))
__CPROVER_requires(!__CPROVER_same_object(pstate, value_decoder_table))
__CPROVER_requires(!__CPROVER_same_object(in, value_decoder_table))
__CPROVER_assigns(*pstate, in->accum, in->accum_nbits)
__CPROVER_ensures(*pstate < (table_offset == 144 ? 256 : 64))
__CPROVER_ensures(__CPROVER_return_value <=
    (table_offset == 0 ? 315 : table_offset == 72 ? 2359 : 262139))
__CPROVER_ensures(in->accum_nbits == __CPROVER_old(in->accum_nbits) -
    value_decoder_table[table_offset + __CPROVER_old(*pstate)].total_bits)
__CPROVER_ensures((in->accum >> in->accum_nbits) == 0)
#endif
{
#if defined(LZFSE_PROOF) && !defined(LZFSE_EXACT_FSE)
  if (table_offset == 0) {
    *pstate &= 63;
  } else if (table_offset == 72) {
    *pstate &= 63;
  } else {
    *pstate &= 255;
  }
  const fse_value_decoder_entry *entry_ptr = value_decoder_table + table_offset + *pstate;
  __CPROVER_assert(__CPROVER_r_ok(entry_ptr, sizeof(*entry_ptr)), "decoder table entry readable");
  uint8_t nondet_u8(void);
  uint16_t nondet_u16(void);
  uint32_t nondet_u32(void);
  (void)fse_in_pull(in, (fse_bit_count)(nondet_u8() & 63));
  *pstate = (uint32_t)nondet_u16();
  if (table_offset == 0) {
    *pstate &= 63;
    return (uint32_t)(nondet_u16() & 511);
  } else if (table_offset == 72) {
    *pstate &= 63;
    return (uint32_t)(nondet_u16() & 4095);
  } else {
    *pstate &= 255;
    return (uint32_t)(nondet_u32() & 0x7FFFF);
  }
#else
  fse_value_decoder_entry entry = value_decoder_table[table_offset + *pstate];
  uint32_t state_and_value_bits = (uint32_t)fse_in_pull(in, entry.total_bits);
  *pstate =
      (uint32_t)entry.delta + (state_and_value_bits >> entry.value_bits);
  return (uint32_t)entry.vbase +
         (uint32_t)fse_mask_lsb_lt(state_and_value_bits, entry.value_bits);
#endif
}

// MARK: - Tables

// Encoder and decoder tables must be built from the same freq[] array.

/*! @abstract Returns 0 if sum(freq) <= number_of_states, else -1. */
FSE_INLINE int fse_check_freq(const uint16_t *freq_table,
                              const size_t table_size,
                              const size_t number_of_states) {
  size_t sum_of_freq = 0;
  for (size_t i = 0; i < table_size; i++) {
    sum_of_freq += freq_table[i];
  }
  return (sum_of_freq > number_of_states) ? -1 : 0;
}

/*! @abstract Encoder table; see lzfse_fse.c. */
void fse_init_encoder_table(int nstates, int nsymbols,
                            const uint16_t *__restrict freq,
                            fse_encoder_entry *__restrict t);

/*! @abstract Entries a decoder table needs past its nstates, which the
 *  builders below write as overshoot. */
#define FSE_DECODER_TABLE_SLACK 8

int fse_init_decoder_table(int nstates, int nsymbols,
                           const uint16_t *__restrict freq,
                           int32_t *__restrict t);

int fse_init_value_decoder_table(int nstates, int nsymbols,
                                 const uint16_t *__restrict freq,
                                 const uint8_t *__restrict symbol_vbits,
                                 const int32_t *__restrict symbol_vbase,
                                 fse_value_decoder_entry *__restrict t);

/*! @abstract Normalize occurrence counts t[nsymbols] to freq[nsymbols]. */
void fse_normalize_freq(int nstates, int nsymbols, const uint32_t *__restrict t,
                        uint16_t *__restrict freq);
