// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// row_hash.h drives which slots the LZFSE greedy search looks at, so a wrong
// mask silently changes what the encoder finds rather than crashing. Checked
// against the definition it stands for — a slot-by-slot compare — for every
// width the encoder instantiates and the awkward ones in between.
//
// The scalar fallback is compiled a second time under its own names, so a
// target that always takes the vector path still covers the one that other
// targets take.
#include "row_hash.h"

#undef ROW_HASH_H
#define ROW_HASH_PORTABLE 1
#define row_hash_tag row_hash_tag_portable
#define row_hash_eq16 row_hash_eq16_portable
#define row_hash_tag_mask row_hash_tag_mask_portable
#define row_hash_rotate row_hash_rotate_portable
#define row_hash_top_bit row_hash_top_bit_portable
#include "row_hash.h"

#include <stdio.h>

static int failures;

static uint32_t next_rand(void) {
  static uint32_t s = 0x1234567u;
  s ^= s << 13;
  s ^= s >> 17;
  s ^= s << 5;
  return s;
}

/*! What the mask means: bit k set exactly when slot k carries the tag. */
static uint64_t reference_mask(const uint8_t *tags, int width, uint8_t tag) {
  uint64_t mask = 0;
  for (int k = 0; k < width; k++)
    if (tags[k] == tag)
      mask |= (uint64_t)1 << k;
  return mask;
}

/*! What the rotation means: bit j is slot (j + cursor) % width. */
static uint64_t reference_rotate(uint64_t mask, uint32_t cursor, int width) {
  uint64_t out = 0;
  for (int j = 0; j < width; j++)
    if ((mask >> (((uint32_t)j + cursor) % (uint32_t)width)) & 1)
      out |= (uint64_t)1 << j;
  return out;
}

static void fail(const char *what, int width, uint32_t cursor) {
  if (failures++ < 10)
    printf("FAIL %s: width=%d cursor=%u\n", what, width, cursor);
}

int main(void) {
  // Every width the level table instantiates, plus ones that are not a
  // multiple of 16, not a power of two, and either side of the vector path's
  // 16-slot step.
  static const int widths[] = {1,  2,  3,  4,  7,  8,  12, 15,
                               16, 17, 20, 31, 32, 33, 48, 63, 64};
  // ROW_HASH_TAG_PADDING of trailing slop, as the encoder's table has: a row
  // narrower than 16 is read past its end and the extra bits masked off.
  static uint8_t tags[ROW_HASH_MAX_MASK_WIDTH + ROW_HASH_TAG_PADDING];
  int cases = 0;

  for (int trial = 0; trial < 4000; trial++) {
    // A small tag alphabet, so hits are common enough to be interesting.
    for (size_t i = 0; i < sizeof tags; i++)
      tags[i] = (uint8_t)(next_rand() >> 13) & 0x7u;
    uint8_t tag = (uint8_t)(trial & 0x7);

    for (size_t wi = 0; wi < sizeof widths / sizeof widths[0]; wi++) {
      int width = widths[wi];
      uint64_t want = reference_mask(tags, width, tag);
      if (row_hash_tag_mask(tags, width, tag) != want)
        fail("mask", width, 0);
      if (row_hash_tag_mask_portable(tags, width, tag) != want)
        fail("mask (portable)", width, 0);
      cases += 2;

      for (uint32_t cursor = 0; cursor < (uint32_t)width; cursor++) {
        uint64_t want_rot = reference_rotate(want, cursor, width);
        if (row_hash_rotate(want, cursor, width) != want_rot)
          fail("rotate", width, cursor);
        if (row_hash_rotate_portable(want, cursor, width) != want_rot)
          fail("rotate (portable)", width, cursor);
        cases += 2;
      }
    }
  }

  // A tag is what marks a slot as written, so no key may produce the zero an
  // uninitialised row is full of.
  for (uint32_t i = 0; i < 2000000u; i++) {
    uint32_t key = (i < 1000000u) ? i : next_rand();
    if (row_hash_tag(key) == 0)
      fail("tag is 0", 0, 0);
    if (row_hash_tag_portable(key) != row_hash_tag(key))
      fail("tag disagrees with portable", 0, 0);
    cases += 2;
  }

  if (failures == 0) {
    printf("PASS: %d cases: tag masks, rotations and tags agree with the "
           "definition, vector and portable\n",
           cases);
    return 0;
  }
  printf("FAIL: %d checks failed\n", failures);
  return 1;
}
