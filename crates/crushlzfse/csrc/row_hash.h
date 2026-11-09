// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Tag rows for the LZFSE greedy match finder.
//
// Each hash bucket holds a ring of the last `width` positions that hashed
// there; finding the ones whose 4-byte key matches, slot by slot, costs
// `width` loads and compares per input byte — 64 at the widest tier — for
// the four or so that hit. A tag row is a second copy of one byte of each
// key, packed contiguously, so a bucket becomes one to four vector compares
// yielding a bitmask of the slots worth touching. A slot passes the tag but
// not the key about once in 256 and the caller re-checks the key exactly, so
// this changes speed only, never which candidates the search accepts. Same
// idea as zstd's row-based match finder.
//
// LZVN's greedy encoder deliberately does not use it: it matches on three
// bytes and buckets on a hash of those same three, so a tag adds almost
// nothing a slot's presence in the bucket did not — over the corpus, 84% of
// the slots it would test pass the tag, against about 7% for LZFSE.

#ifndef ROW_HASH_H
#define ROW_HASH_H

#include <stdint.h>
#include <string.h>

// ROW_HASH_PORTABLE forces the scalar path on any target, so a test can
// exercise it where the vector one would otherwise be chosen.
#if defined(ROW_HASH_PORTABLE) || defined(CRUSH_SIMD_PORTABLE) || defined(LZFSE_PROOF)
   // no vector path
#elif defined(__aarch64__) && defined(__ARM_NEON)
#  include <arm_neon.h>
#  define ROW_HASH_NEON 1
#elif defined(__x86_64__) || defined(_M_X64) || defined(__SSE2__)
#  include <emmintrin.h>
#  if defined(__SSE4_1__)
#    include <smmintrin.h>
#  endif
#  define ROW_HASH_SSE2 1
#endif

// Readable bytes a tag row needs past its last slot: the mask is built 16
// slots at a time, so a row whose width is not a multiple of 16 is read past
// its end. Allocators add this once at the end of the whole tag array, since
// every row but the last is followed by another row.
#define ROW_HASH_TAG_PADDING 16

// Widest row row_hash_tag_mask can answer for; past this the caller walks
// slots itself.
#define ROW_HASH_MAX_MASK_WIDTH 64

/*! One byte of a 32-bit key, for the tag row. A different multiplier from the
 *  bucket hash, so the tag is independent of the bucket index and stays a real
 *  filter inside a bucket. Never 0: a zeroed row then reads as one nothing has
 *  been written to, which is what lets a reset clear the tags alone. */
static inline uint8_t row_hash_tag(uint32_t key) {
  uint8_t tag = (uint8_t)((key * 2246822519u) >> 24);
  return tag | (uint8_t)(tag == 0);
}

/*! Bitmask of the 16 slots at `tags` whose tag is `tag`. */
static inline uint32_t row_hash_eq16(const uint8_t *tags, uint8_t tag) {
#if defined(ROW_HASH_SSE2)
  __m128i row = _mm_loadu_si128((const __m128i *)(const void *)tags);
  return (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(row, _mm_set1_epi8((char)tag)));
#elif defined(ROW_HASH_NEON)
  static const uint8_t k_bit[16] = {1, 2, 4, 8, 16, 32, 64, 128,
                                    1, 2, 4, 8, 16, 32, 64, 128};
  uint8x16_t eq = vceqq_u8(vld1q_u8(tags), vdupq_n_u8(tag));
  uint64x2_t veq = vreinterpretq_u64_u8(eq);
  if (__builtin_expect((vgetq_lane_u64(veq, 0) | vgetq_lane_u64(veq, 1)) == 0, 1))
    return 0;
  uint8x16_t bits = vandq_u8(eq, vld1q_u8(k_bit));
  return (uint32_t)vaddv_u8(vget_low_u8(bits)) |
         ((uint32_t)vaddv_u8(vget_high_u8(bits)) << 8);
#else
  // SWAR: set the high bit of every zero byte of (row ^ tag) and nothing
  // else, then gather those eight bits into one byte. The saturating add
  // stays inside its byte, so unlike the shorter (x - 0x0101..) & ~x form
  // a zero byte cannot borrow into its neighbour and flag it too.
  const uint64_t ones = 0x0101010101010101ull, lo7 = 0x7f7f7f7f7f7f7f7full;
  uint32_t mask = 0;
  for (int half = 0; half < 2; half++) {
    uint64_t row;
    memcpy(&row, tags + 8 * half, 8);
    uint64_t x = row ^ (ones * tag);
    uint64_t zero = ~(((x & lo7) + lo7) | x | lo7);
    mask |= (uint32_t)((zero * 0x0002040810204081ull) >> 56) << (8 * half);
  }
  return mask;
#endif
}

/*! Bitmask of the `width` slots at `tags` whose tag is `tag`; bit k is slot
 *  k. Reads ROW_HASH_TAG_PADDING bytes past the row when width is not a
 *  multiple of 16. width must be in [1, ROW_HASH_MAX_MASK_WIDTH]. */
static inline uint64_t row_hash_tag_mask(const uint8_t *tags, int width, uint8_t tag) {
#if defined(ROW_HASH_SSE2)
  if (width == 64) {
    __m128i vtag = _mm_set1_epi8((char)tag);
    __m128i eq0 = _mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)(const void *)(tags + 0)), vtag);
    __m128i eq1 = _mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)(const void *)(tags + 16)), vtag);
    __m128i eq2 = _mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)(const void *)(tags + 32)), vtag);
    __m128i eq3 = _mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)(const void *)(tags + 48)), vtag);
    __m128i or01 = _mm_or_si128(eq0, eq1);
    __m128i or23 = _mm_or_si128(eq2, eq3);
    __m128i any = _mm_or_si128(or01, or23);
#if defined(__SSE4_1__)
    if (__builtin_expect(_mm_testz_si128(any, any), 1))
      return 0;
#else
    if (__builtin_expect(_mm_movemask_epi8(any) == 0, 1))
      return 0;
#endif
    uint64_t m0 = (uint32_t)(uint16_t)_mm_movemask_epi8(eq0);
    uint64_t m1 = (uint32_t)(uint16_t)_mm_movemask_epi8(eq1);
    uint64_t m2 = (uint32_t)(uint16_t)_mm_movemask_epi8(eq2);
    uint64_t m3 = (uint32_t)(uint16_t)_mm_movemask_epi8(eq3);
    return m0 | (m1 << 16) | (m2 << 32) | (m3 << 48);
  }
  if (width == 32) {
    __m128i vtag = _mm_set1_epi8((char)tag);
    __m128i eq0 = _mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)(const void *)(tags + 0)), vtag);
    __m128i eq1 = _mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)(const void *)(tags + 16)), vtag);
    __m128i any = _mm_or_si128(eq0, eq1);
#if defined(__SSE4_1__)
    if (__builtin_expect(_mm_testz_si128(any, any), 1))
      return 0;
#else
    if (__builtin_expect(_mm_movemask_epi8(any) == 0, 1))
      return 0;
#endif
    uint64_t m0 = (uint32_t)(uint16_t)_mm_movemask_epi8(eq0);
    uint64_t m1 = (uint32_t)(uint16_t)_mm_movemask_epi8(eq1);
    return m0 | (m1 << 16);
  }
#elif defined(ROW_HASH_NEON)
  if (width == 64) {
    uint8x16_t vtag = vdupq_n_u8(tag);
    uint8x16_t eq0 = vceqq_u8(vld1q_u8(tags + 0), vtag);
    uint8x16_t eq1 = vceqq_u8(vld1q_u8(tags + 16), vtag);
    uint8x16_t eq2 = vceqq_u8(vld1q_u8(tags + 32), vtag);
    uint8x16_t eq3 = vceqq_u8(vld1q_u8(tags + 48), vtag);
    uint8x16_t or01 = vorrq_u8(eq0, eq1);
    uint8x16_t or23 = vorrq_u8(eq2, eq3);
    uint8x16_t any = vorrq_u8(or01, or23);
    uint64x2_t vany = vreinterpretq_u64_u8(any);
    if (__builtin_expect((vgetq_lane_u64(vany, 0) | vgetq_lane_u64(vany, 1)) == 0, 1))
      return 0;
    static const uint8_t k_bit[16] = {1, 2, 4, 8, 16, 32, 64, 128,
                                      1, 2, 4, 8, 16, 32, 64, 128};
    uint8x16_t vk = vld1q_u8(k_bit);
    uint64_t mask = 0;
    uint64x2_t v0 = vreinterpretq_u64_u8(eq0);
    if (vgetq_lane_u64(v0, 0) | vgetq_lane_u64(v0, 1)) {
      uint8x16_t b0 = vandq_u8(eq0, vk);
      mask |= ((uint64_t)vaddv_u8(vget_low_u8(b0)) | ((uint64_t)vaddv_u8(vget_high_u8(b0)) << 8));
    }
    uint64x2_t v1 = vreinterpretq_u64_u8(eq1);
    if (vgetq_lane_u64(v1, 0) | vgetq_lane_u64(v1, 1)) {
      uint8x16_t b1 = vandq_u8(eq1, vk);
      mask |= ((uint64_t)vaddv_u8(vget_low_u8(b1)) | ((uint64_t)vaddv_u8(vget_high_u8(b1)) << 8)) << 16;
    }
    uint64x2_t v2 = vreinterpretq_u64_u8(eq2);
    if (vgetq_lane_u64(v2, 0) | vgetq_lane_u64(v2, 1)) {
      uint8x16_t b2 = vandq_u8(eq2, vk);
      mask |= ((uint64_t)vaddv_u8(vget_low_u8(b2)) | ((uint64_t)vaddv_u8(vget_high_u8(b2)) << 8)) << 32;
    }
    uint64x2_t v3 = vreinterpretq_u64_u8(eq3);
    if (vgetq_lane_u64(v3, 0) | vgetq_lane_u64(v3, 1)) {
      uint8x16_t b3 = vandq_u8(eq3, vk);
      mask |= ((uint64_t)vaddv_u8(vget_low_u8(b3)) | ((uint64_t)vaddv_u8(vget_high_u8(b3)) << 8)) << 48;
    }
    return mask;
  }
  if (width == 32) {
    uint8x16_t vtag = vdupq_n_u8(tag);
    uint8x16_t eq0 = vceqq_u8(vld1q_u8(tags + 0), vtag);
    uint8x16_t eq1 = vceqq_u8(vld1q_u8(tags + 16), vtag);
    uint8x16_t any = vorrq_u8(eq0, eq1);
    uint64x2_t vany = vreinterpretq_u64_u8(any);
    if (__builtin_expect((vgetq_lane_u64(vany, 0) | vgetq_lane_u64(vany, 1)) == 0, 1))
      return 0;
    static const uint8_t k_bit[16] = {1, 2, 4, 8, 16, 32, 64, 128,
                                      1, 2, 4, 8, 16, 32, 64, 128};
    uint8x16_t vk = vld1q_u8(k_bit);
    uint64_t mask = 0;
    uint64x2_t v0 = vreinterpretq_u64_u8(eq0);
    if (vgetq_lane_u64(v0, 0) | vgetq_lane_u64(v0, 1)) {
      uint8x16_t b0 = vandq_u8(eq0, vk);
      mask |= ((uint64_t)vaddv_u8(vget_low_u8(b0)) | ((uint64_t)vaddv_u8(vget_high_u8(b0)) << 8));
    }
    uint64x2_t v1 = vreinterpretq_u64_u8(eq1);
    if (vgetq_lane_u64(v1, 0) | vgetq_lane_u64(v1, 1)) {
      uint8x16_t b1 = vandq_u8(eq1, vk);
      mask |= ((uint64_t)vaddv_u8(vget_low_u8(b1)) | ((uint64_t)vaddv_u8(vget_high_u8(b1)) << 8)) << 16;
    }
    return mask;
  }
#endif
  uint64_t mask = 0;
  for (int i = 0; i < width; i += 16)
    mask |= (uint64_t)row_hash_eq16(tags + i, tag) << i;
  if (width < 64)
    mask &= ((uint64_t)1 << width) - 1;
  return mask;
}


/*! Rotates a `width`-bit slot mask so that bit j is slot (j + cursor) % width.
 *  Slots are then in insertion order: the newest live slot, cursor - 1, is the
 *  highest bit, so a search walking bits downwards sees newest first.
 *  Branchless: a cursor of 0 is common but not common enough to predict, and
 *  `width` is a constant in every instantiation that matters. */
static inline uint64_t row_hash_rotate(uint64_t mask, uint32_t cursor, int width) {
  if (width == 64) // the shift below would be by 64 at cursor 0
    return (mask >> cursor) | (mask << ((64u - cursor) & 63u));
  return ((mask >> cursor) | (mask << ((uint32_t)width - cursor))) &
         (((uint64_t)1 << width) - 1);
}

/*! Index of the highest set bit; the mask must be non-zero. */
static inline int row_hash_top_bit(uint64_t mask) {
  return 63 - __builtin_clzll(mask);
}

#endif // ROW_HASH_H
