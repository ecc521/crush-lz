// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// A source object that ends exactly at the cursor must suffice for FSE
// refills: no load may reach above it. The refills load the word ending at
// the cursor, so the object starts one word below the lower bound, as the
// decoder's streams do (a block header lies below each payload).
#include "lzfse_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check64(int bits) {
  int nbits = (63 - bits) & -8;
  size_t count = (size_t)(nbits >> 3);
  uint8_t padded[16];
  for (size_t i = 0; i < sizeof padded; ++i)
    padded[i] = (uint8_t)(17 + 29 * i);
  uint8_t *object = malloc(8 + count);
  if (!object) return 1;
  memset(object, 0xA5, 8);
  uint8_t *exact = object + 8;
  if (count) memcpy(exact, padded, count);
  const uint8_t *cursor = exact + count;
  fse_in_stream64 in = {0};
  in.accum_nbits = bits;
  int status = fse_in_checked_flush64(&in, &cursor, exact);
  uint64_t word = 0;
  memcpy(&word, padded, sizeof word);
  uint64_t expected = nbits ? fse_mask_lsb64_lt(word, nbits) : 0;
  int bad = status != 0 || cursor != exact || in.accum != expected ||
            in.accum_nbits != bits + nbits;
  const uint8_t *unchecked_cursor = exact + count;
  fse_in_stream64 unchecked = {0};
  unchecked.accum_nbits = bits;
  fse_in_flush64_unchecked(&unchecked, &unchecked_cursor);
  bad |= unchecked_cursor != exact || unchecked.accum != expected ||
         unchecked.accum_nbits != bits + nbits;
  free(object);
  return bad;
}

static int check32(int bits) {
  int nbits = (31 - bits) & -8;
  size_t count = (size_t)(nbits >> 3);
  uint8_t padded[8];
  for (size_t i = 0; i < sizeof padded; ++i)
    padded[i] = (uint8_t)(7 + 31 * i);
  uint8_t *object = malloc(4 + count);
  if (!object) return 1;
  memset(object, 0xA5, 4);
  uint8_t *exact = object + 4;
  if (count) memcpy(exact, padded, count);
  const uint8_t *cursor = exact + count;
  fse_in_stream32 in = {0};
  in.accum_nbits = bits;
  int status = fse_in_checked_flush32(&in, &cursor, exact);
  uint32_t word = 0;
  memcpy(&word, padded, sizeof word);
  uint32_t expected = nbits ? fse_mask_lsb32_lt(word, nbits) : 0;
  int bad = status != 0 || cursor != exact || in.accum != expected ||
            in.accum_nbits != bits + nbits;
  free(object);
  return bad;
}

int main(void) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
  return 0;
#else
  for (int bits = 0; bits < 64; ++bits)
    if (check64(bits)) {
      fprintf(stderr, "64-bit refill failed at %d bits\n", bits);
      return 1;
    }
  for (int bits = 0; bits < 32; ++bits)
    if (check32(bits)) {
      fprintf(stderr, "32-bit refill failed at %d bits\n", bits);
      return 1;
    }
  return 0;
#endif
}
