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
#include "lzvn_decode_base.h"

/*! @abstract Bits offset .. offset+nbits-1 of v, zero-extended; nbits <= 32. */
static inline uint32_t get_field(uint64_t v, int offset, int nbits) {
  assert(offset + nbits < 64 && offset >= 0 && nbits <= 32);
  if (nbits == 32)
    return (uint32_t)(v >> offset);
  return (uint32_t)((v >> offset) & ((1 << nbits) - 1));
}

/*! @abstract Return \c header_size field from a \c lzfse_compressed_block_header_v2. */
static inline uint32_t
lzfse_decode_v2_header_size(const lzfse_compressed_block_header_v2 *in) {
  return get_field(in->packed_fields[2], 0, 32);
}

/*! @abstract Unpack a v2 header into a v1 header. Returns 0, or -1 on a
 *  malformed header. */
#ifdef LZFSE_PROOF
LZFSE_NOINLINE int lzfse_decode_v1(lzfse_compressed_block_header_v1 *out,
                                  const lzfse_compressed_block_header_v2 *in, size_t available)
#else
static inline int lzfse_decode_v1(lzfse_compressed_block_header_v1 *out,
                                const lzfse_compressed_block_header_v2 *in, size_t available)
#endif
{
  memset(out, 0x00, sizeof(lzfse_compressed_block_header_v1));

  uint64_t v0 = in->packed_fields[0];
  uint64_t v1 = in->packed_fields[1];
  uint64_t v2 = in->packed_fields[2];

  out->magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
  out->n_raw_bytes = in->n_raw_bytes;

  out->n_literals = get_field(v0, 0, 20);
  out->n_literal_payload_bytes = get_field(v0, 20, 20);
  out->literal_bits = (int)get_field(v0, 60, 3) - 7;
  out->literal_state[0] = get_field(v1, 0, 10);
  out->literal_state[1] = get_field(v1, 10, 10);
  out->literal_state[2] = get_field(v1, 20, 10);
  out->literal_state[3] = get_field(v1, 30, 10);

  out->n_matches = get_field(v0, 40, 20);
  out->n_lmd_payload_bytes = get_field(v1, 40, 20);
  out->lmd_bits = (int)get_field(v1, 60, 3) - 7;
  out->l_state = get_field(v2, 32, 10);
  out->m_state = get_field(v2, 42, 10);
  out->d_state = get_field(v2, 52, 10);

  out->n_payload_bytes =
      out->n_literal_payload_bytes + out->n_lmd_payload_bytes;

  uint16_t *dst = &(out->l_freq[0]);
  const uint8_t *src_in = (const uint8_t *)in;
  uint32_t header_size = get_field(v2, 0, 32);
  /* PROOF GUARD: header_size > available. Believed unnecessary: both callers
     reject header_size beyond the remaining source first. It makes this
     function's read footprint self-contained for proof composition. */
  if (header_size < 32 || header_size > sizeof(lzfse_compressed_block_header_v2) ||
      header_size > available)
    return -1;
  if (header_size == 32)
    // OK, freq tables were omitted: out->l_freq/m_freq/d_freq/literal_freq
    // stay zeroed above, so this block's decoder tables get built from no
    // symbols and it decodes with whatever the previous block left in them.
    // Safe only because every nstates the table builders use is a compile-
    // time constant, so any leftover entry is still in range.
    return 0;

  //  Each frequency is a variable-length code, read from the low bits up:
  //  2 bits (..0) for 0 and 1, 3 bits (..01) for 2 and 3, 5 bits (..011) for
  //  4 to 7, and an 8-bit (0111 prefix) or 14-bit (1111 prefix) code adding
  //  the 4 or 10 bits after its prefix to 8 or 24. Indexed by a code's low 5
  //  bits, this holds its length (bits 0-3), its value or base (bits 4-8)
  //  and the mask of the bits above a 4-bit prefix that add to it (bits
  //  16-25), so a code decodes with one load and no branch.
#define LZFSE_FREQ_CODE(n, base, mask) ((n) | (base) << 4 | (mask) << 16)
  static const uint32_t freq_code[32] = {
#define S2(v) LZFSE_FREQ_CODE(2, v, 0)
#define S3(v) LZFSE_FREQ_CODE(3, v, 0)
#define S5(v) LZFSE_FREQ_CODE(5, v, 0)
#define S8 LZFSE_FREQ_CODE(8, 8, 0xf)
#define S14 LZFSE_FREQ_CODE(14, 24, 0x3ff)
      S2(0), S3(2), S2(1), S5(4), S2(0), S3(3), S2(1), S8,
      S2(0), S3(2), S2(1), S5(5), S2(0), S3(3), S2(1), S14,
      S2(0), S3(2), S2(1), S5(6), S2(0), S3(3), S2(1), S8,
      S2(0), S3(2), S2(1), S5(7), S2(0), S3(3), S2(1), S14,
#undef S2
#undef S3
#undef S5
#undef S8
#undef S14
  };
#undef LZFSE_FREQ_CODE

  //  The codes need not end on a byte, so they are read from a bit
  //  accumulator refilled 8 bytes at a time while 8 remain and bytewise
  //  after. Bytes loaded past those counted in accum_nbits land at the bit
  //  positions the next refill puts them at, so ORing them in twice is
  //  harmless. Once the bytes run out, missing bits read as zero and
  //  accum_nbits goes negative; it is clamped to zero for the next read and
  //  the header is rejected below.
  const size_t header_bits = 8 * (size_t)(header_size - 32);
  size_t used_bits = 0;
  uint64_t accum = 0;
  int accum_nbits = 0;
  size_t sp = 32;
  for (int i = 0; i < LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS +
                          LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS;
       i++)
#ifdef LZFSE_PROOF
    LZFSE_LOOP_ASSIGNS(i, sp, accum, accum_nbits, used_bits,
                       __CPROVER_object_upto(out, sizeof *out))
    LZFSE_LOOP_INVARIANT(0 <= i && i <= (LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS +
                                         LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS) &&
                         sp >= 32 && sp <= header_size &&
                         accum_nbits >= -16 && accum_nbits <= 72 &&
                         out->magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC)
    LZFSE_LOOP_DECREASES((LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS +
                          LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS) - i)
#endif
  {
    if (accum_nbits < 0)
      accum_nbits = 0;
    if (accum_nbits < 14) {
      if (header_size - sp >= 8) {
        accum |= load8(src_in + sp) << accum_nbits;
        int bytes = (63 - accum_nbits) >> 3;
        sp += bytes;
        accum_nbits += 8 * bytes;
      } else {
        while (sp < header_size && accum_nbits <= 56)
#ifdef LZFSE_PROOF
          LZFSE_LOOP_ASSIGNS(sp, accum, accum_nbits)
          LZFSE_LOOP_INVARIANT(sp >= 32 && sp <= header_size &&
                               accum_nbits >= 0 && accum_nbits <= 64)
          LZFSE_LOOP_DECREASES(header_size - sp)
#endif
        {
          accum |= (uint64_t)src_in[sp++] << accum_nbits;
          accum_nbits += 8;
        }
      }
    }
    const uint32_t code = freq_code[accum & 31];
    const int nbits = (int)(code & 15);
    dst[i] = (uint16_t)(((code >> 4) & 31) + ((uint32_t)(accum >> 4) & (code >> 16)));
    accum >>= nbits;
    accum_nbits -= nbits;
    used_bits += (size_t)nbits;
  }

  //  The codes must fit in the header and end in its last byte, as the
  //  reference reader requires: it fails on a code that runs past the end,
  //  and after the last code on 8 or more bits left over.
  if (used_bits > header_bits || header_bits - used_bits >= 8)
    return -1;

  return 0;
}

#ifdef LZFSE_PROOF
LZFSE_NOINLINE void lzfse_copy_match_bytes(uint8_t *dst, ptrdiff_t D, size_t count)
LZFSE_REQUIRES(D > 0)
LZFSE_REQUIRES(LZFSE_OFFSET(dst) >= (size_t)D)
LZFSE_REQUIRES(__CPROVER_r_ok(dst - D, (size_t)D))
LZFSE_REQUIRES(__CPROVER_w_ok(dst, count))
LZFSE_ASSIGNS(__CPROVER_object_upto(dst, count))
#else
static inline void lzfse_copy_match_bytes(uint8_t *dst, ptrdiff_t D, size_t count)
#endif
{
  for (size_t i = 0; i < count; i++)
#ifdef LZFSE_PROOF
    LZFSE_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst, count))
    LZFSE_LOOP_INVARIANT(i <= count)
    LZFSE_LOOP_DECREASES(count - i)
#endif
    dst[i] = dst[(ptrdiff_t)i - D];
}

#ifdef LZFSE_PROOF
LZFSE_NOINLINE void lzfse_copy_literal_bytes(uint8_t *dst, const uint8_t *src, size_t count)
LZFSE_REQUIRES(__CPROVER_r_ok(src, count))
LZFSE_REQUIRES(__CPROVER_w_ok(dst, count))
LZFSE_REQUIRES(!__CPROVER_same_object(dst, src))
LZFSE_ASSIGNS(__CPROVER_object_upto(dst, count))
#else
static inline void lzfse_copy_literal_bytes(uint8_t *dst, const uint8_t *src, size_t count)
#endif
{
  for (size_t i = 0; i < count; i++)
#ifdef LZFSE_PROOF
    LZFSE_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst, count))
    LZFSE_LOOP_INVARIANT(i <= count)
    LZFSE_LOOP_DECREASES(count - i)
#endif
    dst[i] = src[i];
}

#ifdef LZFSE_PROOF
LZFSE_NOINLINE void copy(uint8_t *dst, const uint8_t *src, size_t length)
LZFSE_REQUIRES(length > 0)
LZFSE_REQUIRES(__CPROVER_r_ok(src, length + 8))
LZFSE_REQUIRES(__CPROVER_w_ok(dst, length + 8))
LZFSE_REQUIRES(!__CPROVER_same_object(dst, src) || (const char *)dst >= (const char *)src + 8)
LZFSE_ASSIGNS(__CPROVER_object_upto(dst, length + 8))
#else
static inline void copy(uint8_t *dst, const uint8_t *src, size_t length)
#endif
{
#ifdef LZFSE_PROOF
  uint8_t *dst_base = dst;
  const uint8_t *src_base = src;
#endif
  const uint8_t *dst_end = dst + length;
  do
#ifdef LZFSE_PROOF
    LZFSE_LOOP_ASSIGNS(dst, src, __CPROVER_object_upto(dst_base, length + 8))
    LZFSE_LOOP_INVARIANT(__CPROVER_same_object(dst, dst_base) &&
                         __CPROVER_same_object(src, src_base))
    LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(dst) >= LZFSE_OFFSET(dst_base) &&
                         LZFSE_OFFSET(dst) < LZFSE_OFFSET(dst_end))
    LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(src) - LZFSE_OFFSET(src_base) ==
                         LZFSE_OFFSET(dst) - LZFSE_OFFSET(dst_base))
    LZFSE_LOOP_DECREASES(LZFSE_OFFSET(dst_end) - LZFSE_OFFSET(dst))
#endif
  {
    copy8(dst, src);
    dst += 8;
    src += 8;
  } while (dst < dst_end);
}

//  Both copies below peel LZFSE_DECODE_COPY_MARGIN bytes as separate 16-byte
//  units (see copy_match_wide for why they cannot be fused into one wider
//  copy); the constant-bound loop keeps the margin the only knob. A negative
//  array bound rather than _Static_assert, since this file is built as C99.
typedef char lzfse_decode_copy_margin_is_whole_16_byte_units
    [(LZFSE_DECODE_COPY_MARGIN > 0 && LZFSE_DECODE_COPY_MARGIN % 16 == 0) ? 1
                                                                          : -1];

// The literal source never aliases dst, so this copy widens unconditionally.
#ifdef LZFSE_PROOF
LZFSE_NOINLINE void copy_literal_wide(uint8_t *dst, const uint8_t *src, size_t length)
LZFSE_REQUIRES(__CPROVER_r_ok(src, length + LZFSE_DECODE_COPY_MARGIN))
LZFSE_REQUIRES(__CPROVER_w_ok(dst, length + LZFSE_DECODE_COPY_MARGIN))
LZFSE_REQUIRES(!__CPROVER_same_object(dst, src))
LZFSE_ASSIGNS(__CPROVER_object_upto(dst, length + LZFSE_DECODE_COPY_MARGIN))
#else
static inline void copy_literal_wide(uint8_t *dst, const uint8_t *src, size_t length)
#endif
{
  //  LZFSE_DECODE_COPY_MARGIN bytes are always written, so a one-byte literal
  //  writes that much; lzfse_decode_lmd reserves exactly that margin before
  //  using this path.
  for (size_t k = 0; k < LZFSE_DECODE_COPY_MARGIN; k += 16)
#ifdef LZFSE_PROOF
    LZFSE_LOOP_ASSIGNS(k, __CPROVER_object_upto(dst, length + LZFSE_DECODE_COPY_MARGIN))
    LZFSE_LOOP_INVARIANT(k <= LZFSE_DECODE_COPY_MARGIN && k % 16 == 0)
    LZFSE_LOOP_DECREASES(LZFSE_DECODE_COPY_MARGIN - k)
#endif
    copy16(dst + k, src + k);
  if (__builtin_expect(length > LZFSE_DECODE_COPY_MARGIN, 0)) {
#ifdef LZFSE_PROOF
    uint8_t *dst_base = dst;
    const uint8_t *src_base = src;
#endif
    const uint8_t *dst_end = dst + length;
    dst += LZFSE_DECODE_COPY_MARGIN;
    src += LZFSE_DECODE_COPY_MARGIN;
    do
#ifdef LZFSE_PROOF
      LZFSE_LOOP_ASSIGNS(dst, src,
                         __CPROVER_object_upto(dst_base, length + LZFSE_DECODE_COPY_MARGIN))
      LZFSE_LOOP_INVARIANT(__CPROVER_same_object(dst, dst_base) &&
                           __CPROVER_same_object(src, src_base))
      LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(dst) >= LZFSE_OFFSET(dst_base) + LZFSE_DECODE_COPY_MARGIN &&
                           LZFSE_OFFSET(dst) < LZFSE_OFFSET(dst_end))
      LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(src) - LZFSE_OFFSET(src_base) ==
                           LZFSE_OFFSET(dst) - LZFSE_OFFSET(dst_base))
      LZFSE_LOOP_DECREASES(LZFSE_OFFSET(dst_end) - LZFSE_OFFSET(dst))
#endif
    {
      copy16(dst, src);
      dst += 16;
      src += 16;
    } while (dst < dst_end);
  }
}

// src (dst - D) can overlap the range this call writes, and each byte read
// must see every earlier write. copy16 loads both halves before storing, so
// the read window must end at or before dst: only call this when D >= 16 or
// D >= M.
#ifdef LZFSE_PROOF
LZFSE_NOINLINE void copy_match_wide(uint8_t *dst, const uint8_t *src, size_t length)
LZFSE_REQUIRES(__CPROVER_r_ok(src, length + LZFSE_DECODE_COPY_MARGIN))
LZFSE_REQUIRES(__CPROVER_w_ok(dst, length + LZFSE_DECODE_COPY_MARGIN))
LZFSE_ASSIGNS(__CPROVER_object_upto(dst, length + LZFSE_DECODE_COPY_MARGIN))
#else
static inline void copy_match_wide(uint8_t *dst, const uint8_t *src, size_t length)
#endif
{
  //  Unit k reads [dst+16k-D, dst+16k-D+16), which for D >= 16 lies inside
  //  what earlier units wrote; fusing units into a 32-byte copy would need
  //  D >= 32.
  for (size_t k = 0; k < LZFSE_DECODE_COPY_MARGIN; k += 16)
#ifdef LZFSE_PROOF
    LZFSE_LOOP_ASSIGNS(k, __CPROVER_object_upto(dst, length + LZFSE_DECODE_COPY_MARGIN))
    LZFSE_LOOP_INVARIANT(k <= LZFSE_DECODE_COPY_MARGIN && k % 16 == 0)
    LZFSE_LOOP_DECREASES(LZFSE_DECODE_COPY_MARGIN - k)
#endif
    copy16(dst + k, src + k);
  if (__builtin_expect(length > LZFSE_DECODE_COPY_MARGIN, 0)) {
    size_t k = LZFSE_DECODE_COPY_MARGIN;
    do
#ifdef LZFSE_PROOF
      LZFSE_LOOP_ASSIGNS(k, __CPROVER_object_upto(dst, length + LZFSE_DECODE_COPY_MARGIN))
      LZFSE_LOOP_INVARIANT(k >= LZFSE_DECODE_COPY_MARGIN && k < length && (k - LZFSE_DECODE_COPY_MARGIN) % 16 == 0)
      LZFSE_LOOP_DECREASES(length - k)
#endif
    {
      copy16(dst + k, src + k);
      k += 16;
    } while (k < length);
  }
}

//  Width the period is grown to before the tail copy. p is also the distance
//  between a store and the load that consumes it, so a wider period puts more
//  independent iterations between them.
#define LZFSE_MATCH_PERIOD_TARGET 64

//  A long match with D < 16 overlaps its own output, so no copy wider than D
//  is valid against it. Seed D bytes from committed output, double the filled
//  prefix (disjoint copies) up to the target, then copy the rest at distance
//  p. The caller guarantees M >= 32 and 1 <= D < 16: doubling runs only while
//  2p <= M, so the fill never passes dst + M, and on exit p >= 16, which the
//  tail copy_match_wide requires.
static __attribute__((noinline)) void copy_match_periodic(uint8_t *dst, ptrdiff_t D, ptrdiff_t M)
#ifdef LZFSE_PROOF
LZFSE_REQUIRES(D >= 1 && D < 16)
LZFSE_REQUIRES(M >= 32)
LZFSE_REQUIRES(LZFSE_OFFSET(dst) >= (size_t)D)
LZFSE_REQUIRES(__CPROVER_r_ok(dst - D, (size_t)D))
LZFSE_REQUIRES(__CPROVER_w_ok(dst, (size_t)(M + LZFSE_DECODE_COPY_MARGIN)))
LZFSE_ASSIGNS(__CPROVER_object_upto(dst, (size_t)(M + LZFSE_DECODE_COPY_MARGIN)))
#endif
{
  memcpy(dst, dst - D, (size_t)D);
  ptrdiff_t p = D;
  while (p < LZFSE_MATCH_PERIOD_TARGET && p + p <= M) {
    memcpy(dst + p, dst, (size_t)p);
    p += p;
  }
  if (M > p)
    copy_match_wide(dst + p, dst, (size_t)(M - p));
}

#ifdef LZFSE_PROOF
LZFSE_NOINLINE void lzfse_copy_match(uint8_t *dst, ptrdiff_t D, ptrdiff_t M)
#else
static inline void lzfse_copy_match(uint8_t *dst, ptrdiff_t D, ptrdiff_t M)
#endif
{
  //  copy_match_wide needs D >= 16 or D >= M, which is the single test
  //  D >= min(16, M); a long match with a shorter distance materialises
  //  its period; an 8-byte copy is safe for D >= 8; anything else goes
  //  byte by byte.
  if (D >= (M < 16 ? M : 16))
    copy_match_wide(dst, dst - D, (size_t)M);
  else if (M >= 32)
    copy_match_periodic(dst, D, M);
  else if (D >= 8)
    copy(dst, dst - D, (size_t)M);
  else
    for (ptrdiff_t i = 0; i < M; i++)
#ifdef LZFSE_PROOF
      LZFSE_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst, (size_t)(M + LZFSE_DECODE_COPY_MARGIN)))
      LZFSE_LOOP_INVARIANT(i >= 0 && i <= M)
      LZFSE_LOOP_DECREASES(M - i)
#endif
      dst[i] = dst[i - D];
}

// MARK: - Instruction-set variants
//
//  Both hot loops are dominated by fse_in_pull's variable-count shifts.
//  Without BMI2, x86-64 routes every shift count through CL; SHRX/SHLX take
//  it in any register. So on x86-64 builds that lack BMI2 the two loops are
//  emitted twice, baseline and target("bmi2"), and one is picked at run time.
//  A build that already has BMI2 emits only the baseline variant. Scoped to
//  these two functions so nothing else's codegen changes.
#if defined(__x86_64__) && !defined(__BMI2__) &&                               \
    (defined(__clang__) || defined(__GNUC__))
#define LZFSE_X86_BMI2_DISPATCH 1
#else
#define LZFSE_X86_BMI2_DISPATCH 0
#endif

#define LZFSE_HOT_SUFFIX _baseline
#define LZFSE_HOT_ATTR
#define LZFSE_HOT_ATTR_DEFINED 1
#include "lzfse_decode_hot.h"
#undef LZFSE_HOT_SUFFIX
#undef LZFSE_HOT_ATTR
#undef LZFSE_HOT_ATTR_DEFINED

#if LZFSE_X86_BMI2_DISPATCH
#define LZFSE_HOT_SUFFIX _bmi2
#define LZFSE_HOT_ATTR __attribute__((target("bmi2")))
#define LZFSE_HOT_ATTR_DEFINED 1
#include "lzfse_decode_hot.h"
#undef LZFSE_HOT_SUFFIX
#undef LZFSE_HOT_ATTR
#undef LZFSE_HOT_ATTR_DEFINED

#include <cpuid.h>

//  CPUID rather than __builtin_cpu_supports: the builtin reads __cpu_model
//  from compiler-rt, which the Rust crates (linked with -nodefaultlibs) do
//  not provide. BMI2 is leaf 7, subleaf 0, EBX bit 8.
//
//  Memoised because CPUID is an unconditional VM exit, and both hot loops ask
//  once per block. Racers compute the same answer, so the cache only has to
//  not tear; -1 is "not yet determined", which no CPUID result can be.
static int lzfse_x86_bmi2_cached = -1;

static inline int lzfse_x86_has_bmi2(void) {
  int cached = __atomic_load_n(&lzfse_x86_bmi2_cached, __ATOMIC_RELAXED);
  if (__builtin_expect(cached >= 0, 1))
    return cached;

  unsigned eax, ebx, ecx, edx;
  cached = __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)
               ? (int)((ebx >> 8) & 1u)
               : 0;
  __atomic_store_n(&lzfse_x86_bmi2_cached, cached, __ATOMIC_RELAXED);
  return cached;
}
#endif

#ifdef LZFSE_PROOF
LZFSE_NOINLINE int lzfse_decode_literals(lzfse_decoder_state *s,
                                         const lzfse_compressed_block_header_v1 *header1,
                                         lzfse_compressed_block_decoder_state *bs)
#else
static int lzfse_decode_literals(lzfse_decoder_state *s,
                                 const lzfse_compressed_block_header_v1 *header1,
                                 lzfse_compressed_block_decoder_state *bs)
#endif
{
#if LZFSE_X86_BMI2_DISPATCH
  if (lzfse_x86_has_bmi2())
    return lzfse_decode_literals_bmi2(s, header1, bs);
#endif
  return lzfse_decode_literals_baseline(s, header1, bs);
}

#ifdef LZFSE_PROOF
LZFSE_NOINLINE int lzfse_decode_lmd(lzfse_decoder_state *s)
#else
static int lzfse_decode_lmd(lzfse_decoder_state *s)
#endif
{
#if LZFSE_X86_BMI2_DISPATCH
  if (lzfse_x86_has_bmi2())
    return lzfse_decode_lmd_bmi2(s);
#endif
  return lzfse_decode_lmd_baseline(s);
}

int lzfse_decode(lzfse_decoder_state *s) {
#ifdef LZFSE_PROOF
  // The contract's resumable state is the loop invariant; every pass that
  // does not return lowers the rank in the decreases clause.
  const uint8_t *const frame_src_begin = s->src_begin;
  const uint8_t *const frame_src_end = s->src_end;
  uint8_t *const frame_dst_begin = s->dst_begin;
  uint8_t *const frame_dst_end = s->dst_end;
  const uint8_t *const frame_src_entry = s->src;
  uint8_t *const frame_dst_entry = s->dst;
  while (1)
  LZFSE_LOOP_ASSIGNS(LZFSE_PROOF_STATE_FOOTPRINT(s), lzfse_proof_tables_ok,
                     __CPROVER_object_upto(frame_dst_begin,
                       (size_t)(LZFSE_OFFSET(frame_dst_end) - LZFSE_OFFSET(frame_dst_begin))))
  LZFSE_LOOP_INVARIANT(s->src_begin == frame_src_begin && s->src_end == frame_src_end &&
                       s->dst_begin == frame_dst_begin && s->dst_end == frame_dst_end)
  LZFSE_LOOP_INVARIANT(LZFSE_PROOF_DECODER_RESUMABLE(s))
  LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(s->src) >= LZFSE_OFFSET(frame_src_entry) &&
                       LZFSE_OFFSET(s->dst) >= LZFSE_OFFSET(frame_dst_entry))
  LZFSE_LOOP_INVARIANT(lzfse_proof_tables_ok == 1)
  LZFSE_LOOP_DECREASES(2u * (size_t)(LZFSE_OFFSET(frame_src_end) - LZFSE_OFFSET(s->src)) +
                       (s->block_magic != LZFSE_NO_BLOCK_MAGIC))
#else
  while (1)
#endif
  {
    switch (s->block_magic) {
    case LZFSE_NO_BLOCK_MAGIC: {
      if ((size_t)(s->src_end - s->src) < 4)
        return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
      uint32_t magic = load4(s->src);

      if (magic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC) {
        s->src += 4;
        s->end_of_stream = 1;
        return LZFSE_STATUS_OK; // done
      }

      if (magic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC) {
        if ((size_t)(s->src_end - s->src) < sizeof(uncompressed_block_header))
          return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
        uncompressed_block_decoder_state *bs = &(s->uncompressed_block_state);
        bs->n_raw_bytes =
            load4(s->src + offsetof(uncompressed_block_header, n_raw_bytes));
        s->src += sizeof(uncompressed_block_header);
        s->block_magic = magic;
        break;
      }

      if (magic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC) {
        if ((size_t)(s->src_end - s->src) < sizeof(lzvn_compressed_block_header))
          return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
        lzvn_compressed_block_decoder_state *bs =
            &(s->compressed_lzvn_block_state);
        bs->n_raw_bytes =
            load4(s->src + offsetof(lzvn_compressed_block_header, n_raw_bytes));
        bs->n_payload_bytes = load4(
            s->src + offsetof(lzvn_compressed_block_header, n_payload_bytes));
        bs->d_prev = 0;
        s->src += sizeof(lzvn_compressed_block_header);
        s->block_magic = magic;
        break;
      }

      if (magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC ||
          magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC) {
        lzfse_compressed_block_header_v1 header1;
        size_t header_size = 0;

        if (magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC) {
          if ((size_t)(s->src_end - s->src) < offsetof(lzfse_compressed_block_header_v2, freq))
            return LZFSE_STATUS_SRC_EMPTY; // SRC truncated

          const lzfse_compressed_block_header_v2 *header2 =
              (const lzfse_compressed_block_header_v2 *)s->src; // not aligned, OK
          header_size = lzfse_decode_v2_header_size(header2);
          if (header_size < 32 || (size_t)(s->src_end - s->src) < header_size)
            return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
          int decodeStatus = lzfse_decode_v1(&header1, header2,
                                            (size_t)(s->src_end - s->src));
          if (decodeStatus != 0)
            return LZFSE_STATUS_ERROR; // failed
        } else {
          if ((size_t)(s->src_end - s->src) < sizeof(lzfse_compressed_block_header_v1))
            return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
          memcpy(&header1, s->src, sizeof(lzfse_compressed_block_header_v1));
          header_size = sizeof(lzfse_compressed_block_header_v1);
        }

        // The header and the entire encoded block must be present in SRC for
        // the whole block decode. Subtracting from the available count
        // (rather than adding the three sizes to s->src) never overflows,
        // unlike the pointer arithmetic it replaces: V1's 32-bit payload
        // counts can sum past what a 32-bit size_t can add to a pointer.
        size_t avail = (size_t)(s->src_end - s->src);
        if (header_size > avail ||
            header1.n_literal_payload_bytes > avail - header_size ||
            header1.n_lmd_payload_bytes >
                avail - header_size - header1.n_literal_payload_bytes)
          return LZFSE_STATUS_SRC_EMPTY; // need all encoded block

        if (lzfse_check_block_header_v1(&header1) != 0) {
          return LZFSE_STATUS_ERROR;
        }

        s->src += header_size;

        lzfse_compressed_block_decoder_state *bs =
            &(s->compressed_lzfse_block_state);
        bs->n_lmd_payload_bytes = header1.n_lmd_payload_bytes;
        bs->n_matches = header1.n_matches;
        bs->n_literals = header1.n_literals;
        // header1.n_raw_bytes (and n_payload_bytes) is never propagated to
        // bs or checked against anything below: the decode loop is bounded
        // by dst_end, not by what this header claims to produce, so a block
        // can expand far past its declared n_raw_bytes. Not memory-unsafe,
        // just decompression-bomb shaped: a caller sizing dst tightly to a
        // claimed n_raw_bytes should know this field isn't enforced.
        // lzfse_check_block_header_v1 above already rejects an over-full
        // freq[], but these tables write past their fixed-size arrays if
        // ever called on one anyway; check here too rather than trust a
        // caller two functions away to have done it.
        if (fse_init_decoder_table(LZFSE_ENCODE_LITERAL_STATES,
                                   LZFSE_ENCODE_LITERAL_SYMBOLS,
                                   header1.literal_freq, bs->literal_decoder) != 0)
          return LZFSE_STATUS_ERROR;
        if (fse_init_value_decoder_table(
                LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, header1.l_freq,
                l_extra_bits, l_base_value,
                bs->lmd_decoder + LZFSE_L_DECODER_OFFSET) != 0)
          return LZFSE_STATUS_ERROR;
        if (fse_init_value_decoder_table(
                LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, header1.m_freq,
                m_extra_bits, m_base_value,
                bs->lmd_decoder + LZFSE_M_DECODER_OFFSET) != 0)
          return LZFSE_STATUS_ERROR;
        if (fse_init_value_decoder_table(
                LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, header1.d_freq,
                d_extra_bits, d_base_value,
                bs->lmd_decoder + LZFSE_D_DECODER_OFFSET) != 0)
          return LZFSE_STATUS_ERROR;

        // Decode literals.
        if (lzfse_decode_literals(s, &header1, bs) != 0)
          return LZFSE_STATUS_ERROR;

        // SRC stays at the LMD payload until the block is done.

        {
          fse_in_stream in;
          // read bits backwards from the end
          const uint8_t *buf = s->src + header1.n_lmd_payload_bytes;
          if (fse_in_init(&in, header1.lmd_bits, &buf, s->src) != 0)
            return LZFSE_STATUS_ERROR;

          bs->l_state = header1.l_state;
          bs->m_state = header1.m_state;
          bs->d_state = header1.d_state;
          bs->lmd_in_buf = (uint32_t)(buf - s->src);
          bs->l_value = bs->m_value = 0;
          //  Illegal D, so a stale "previous" value cannot be used.
          bs->d_value = -1;
          bs->lmd_in_stream = in;
        }

        s->block_magic = magic;
        break;
      }

      return LZFSE_STATUS_ERROR;
    } // LZFSE_NO_BLOCK_MAGIC

    case LZFSE_UNCOMPRESSED_BLOCK_MAGIC: {
      uncompressed_block_decoder_state *bs = &(s->uncompressed_block_state);

      //  Copy min(bs->n_raw_bytes, space in src, space in dst).

      uint32_t copy_size = bs->n_raw_bytes; // bytes left to copy
      if (copy_size == 0) {
        s->block_magic = 0;
        break;
      } // end of block

      if (s->src_end <= s->src)
        return LZFSE_STATUS_SRC_EMPTY; // need more SRC data
      const size_t src_space = s->src_end - s->src;
      if (copy_size > src_space)
        copy_size = (uint32_t)src_space; // limit to SRC data (> 0)

      if (s->dst_end <= s->dst)
        return LZFSE_STATUS_DST_FULL; // need more DST capacity
      const size_t dst_space = s->dst_end - s->dst;
      if (copy_size > dst_space)
        copy_size = (uint32_t)dst_space; // limit to DST capacity (> 0)

      memcpy(s->dst, s->src, copy_size);
      s->src += copy_size;
      s->dst += copy_size;
      bs->n_raw_bytes -= copy_size;

      break;
    } // LZFSE_UNCOMPRESSED_BLOCK_MAGIC

    case LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
    case LZFSE_COMPRESSEDV2_BLOCK_MAGIC: {
      lzfse_compressed_block_decoder_state *bs =
          &(s->compressed_lzfse_block_state);
      // Require the entire LMD payload to be in SRC
      if (s->src_end <= s->src ||
          bs->n_lmd_payload_bytes > (size_t)(s->src_end - s->src))
        return LZFSE_STATUS_SRC_EMPTY;

      int status = lzfse_decode_lmd(s);
      if (status != LZFSE_STATUS_OK)
        return status;

      s->block_magic = LZFSE_NO_BLOCK_MAGIC;
      s->src += bs->n_lmd_payload_bytes; // to next block
      break;
    } // LZFSE_COMPRESSEDV1_BLOCK_MAGIC || LZFSE_COMPRESSEDV2_BLOCK_MAGIC

    case LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC: {
      lzvn_compressed_block_decoder_state *bs =
          &(s->compressed_lzvn_block_state);
      if (bs->n_payload_bytes > 0 && s->src_end <= s->src)
        return LZFSE_STATUS_SRC_EMPTY; // need more SRC data

      lzvn_decoder_state dstate;
      memset(&dstate, 0x00, sizeof(dstate));
      dstate.src = s->src;
      dstate.src_end = s->src_end;
      if (dstate.src_end - s->src > bs->n_payload_bytes)
        dstate.src_end = s->src + bs->n_payload_bytes; // limit to payload bytes
      dstate.dst_begin = s->dst_begin;
      dstate.dst = s->dst;
      dstate.dst_end = s->dst_end;
      if (dstate.dst_end - s->dst > bs->n_raw_bytes)
        dstate.dst_end = s->dst + bs->n_raw_bytes; // limit to raw bytes
      dstate.d_prev = bs->d_prev;
      dstate.end_of_stream = 0;
#ifdef LZFSE_PROOF
      dstate.truncated_mid_op = 0;
#endif

      lzvn_decode(&dstate);

      size_t src_used = dstate.src - s->src;
      size_t dst_used = dstate.dst - s->dst;
      if (src_used > bs->n_payload_bytes || dst_used > bs->n_raw_bytes)
        return LZFSE_STATUS_ERROR; // sanity check
      s->src = dstate.src;
      s->dst = dstate.dst;
      bs->n_payload_bytes -= (uint32_t)src_used;
      bs->n_raw_bytes -= (uint32_t)dst_used;
      bs->d_prev = (uint32_t)dstate.d_prev;

      if (bs->n_payload_bytes == 0 && bs->n_raw_bytes == 0 &&
          dstate.end_of_stream) {
        s->block_magic = 0;
        break;
      } // block done

      if (bs->n_payload_bytes == 0 || bs->n_raw_bytes == 0 ||
          dstate.end_of_stream)
        return LZFSE_STATUS_ERROR;

      if (s->dst < s->dst_end)
        return LZFSE_STATUS_SRC_EMPTY; // need more SRC data
      return LZFSE_STATUS_DST_FULL;
    }

    default:
      return LZFSE_STATUS_ERROR; // invalid magic

    } // switch magic

  } // block loop

  return LZFSE_STATUS_OK;
}

/*! @abstract Sums each block's declared n_raw_bytes for src[0, src_end),
 *  without decoding any block's payload: every field this reads is
 *  already sitting in its header. Returns 0 and the total in *out_len when
 *  the blocks parse cleanly through to the end-of-stream marker; returns -1
 *  otherwise (unknown magic, a length past src_end, or a header that fails
 *  lzfse_check_block_header_v1). This is only ever a hint for sizing a
 *  decode buffer, never authoritative, so -1 just means "ask the decoder
 *  for the true answer", exactly what a dishonest total would need
 *  anyway once the real decode catches it. The source byte range and
 *  out_len storage must be disjoint, but may share an allocation. */
int lzfse_declared_len(const uint8_t *src, const uint8_t *src_end, size_t *out_len)
#ifdef LZFSE_PROOF
LZFSE_REQUIRES(__CPROVER_same_object(src, src_end))
LZFSE_REQUIRES(LZFSE_OFFSET(src) <= LZFSE_OFFSET(src_end))
LZFSE_REQUIRES(__CPROVER_r_ok(src, (size_t)(LZFSE_OFFSET(src_end)-LZFSE_OFFSET(src))))
LZFSE_REQUIRES(__CPROVER_w_ok(out_len, sizeof *out_len))
LZFSE_REQUIRES(!__CPROVER_same_object(src, out_len) ||
               LZFSE_OFFSET(out_len) + sizeof *out_len <= LZFSE_OFFSET(src) ||
               LZFSE_OFFSET(src_end) <= LZFSE_OFFSET(out_len))
LZFSE_ASSIGNS(*out_len)
LZFSE_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)
#endif
{
  size_t total = 0;
#ifdef LZFSE_PROOF
  const uint8_t *const src_initial = src;
#endif

  for (;;)
#ifdef LZFSE_PROOF
    LZFSE_LOOP_ASSIGNS(src, total, *out_len)
    LZFSE_LOOP_INVARIANT(__CPROVER_same_object(src, src_end))
    LZFSE_LOOP_INVARIANT(LZFSE_OFFSET(src_initial) <= LZFSE_OFFSET(src) && LZFSE_OFFSET(src) <= LZFSE_OFFSET(src_end))
    LZFSE_LOOP_DECREASES(LZFSE_OFFSET(src_end) - LZFSE_OFFSET(src))
#endif
  {
    if ((size_t)(src_end - src) < 4)
      return -1;
    uint32_t magic = load4(src);

    if (magic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC) {
      *out_len = total;
      return 0;
    }

    if (magic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC) {
      if ((size_t)(src_end - src) < sizeof(uncompressed_block_header))
        return -1;
      uint32_t n_raw_bytes =
          load4(src + offsetof(uncompressed_block_header, n_raw_bytes));
      src += sizeof(uncompressed_block_header);
      if ((size_t)(src_end - src) < n_raw_bytes)
        return -1;
      src += n_raw_bytes;
      total += n_raw_bytes;
      continue;
    }

    if (magic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC) {
      if ((size_t)(src_end - src) < sizeof(lzvn_compressed_block_header))
        return -1;
      uint32_t n_raw_bytes =
          load4(src + offsetof(lzvn_compressed_block_header, n_raw_bytes));
      uint32_t n_payload_bytes =
          load4(src + offsetof(lzvn_compressed_block_header, n_payload_bytes));
      src += sizeof(lzvn_compressed_block_header);
      if ((size_t)(src_end - src) < n_payload_bytes)
        return -1;
      src += n_payload_bytes;
      total += n_raw_bytes;
      continue;
    }

    if (magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC ||
        magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC) {
      lzfse_compressed_block_header_v1 header1;
      size_t header_size;

      if (magic == LZFSE_COMPRESSEDV2_BLOCK_MAGIC) {
        if ((size_t)(src_end - src) < offsetof(lzfse_compressed_block_header_v2, freq))
          return -1;
        const lzfse_compressed_block_header_v2 *header2 =
            (const lzfse_compressed_block_header_v2 *)src; // not aligned, OK
        header_size = lzfse_decode_v2_header_size(header2);
        if ((size_t)(src_end - src) < header_size)
          return -1;
        if (lzfse_decode_v1(&header1, header2,
                            (size_t)(src_end - src)) != 0)
          return -1;
      } else {
        if ((size_t)(src_end - src) < sizeof(lzfse_compressed_block_header_v1))
          return -1;
        memcpy(&header1, src, sizeof(lzfse_compressed_block_header_v1));
        header_size = sizeof(lzfse_compressed_block_header_v1);
      }

      if (lzfse_check_block_header_v1(&header1) != 0)
        return -1;

      size_t advance = header_size + (size_t)header1.n_literal_payload_bytes +
                       (size_t)header1.n_lmd_payload_bytes;
      if ((size_t)(src_end - src) < advance)
        return -1;
      src += advance;
      total += header1.n_raw_bytes;
      continue;
    }

    return -1; // unknown magic
  }
}
