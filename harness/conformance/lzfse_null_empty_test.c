// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// The public LZFSE decoders accept NULL for a zero-length buffer without
// forming NULL + 0 (undefined in C; UBSan's pointer-overflow check reports
// it) and keep their status and length results.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crushlzfse.h"
#include "lzfse.h"

static int fail(const char *what, long got) {
  fprintf(stderr, "%s: got %ld\n", what, got);
  return 1;
}

int main(void) {
  // End-of-stream marker alone, and a stored 3-byte block before it.
  static const uint8_t eos[4] = {'b', 'v', 'x', '$'};
  static const uint8_t stored[15] = {'b', 'v', 'x', '-', 3, 0, 0, 0, 'a', 'b', 'c',
                                     'b', 'v', 'x', '$'};
  uint8_t scratch_dst[8];
  size_t n = 99;
  int rc;

  if (lzfse_decode_buffer(NULL, 0, NULL, 0, NULL) != 0)
    return fail("lzfse null/empty", 1);
  if (lzfse_decode_buffer(NULL, 0, eos, sizeof eos, NULL) != 0)
    return fail("lzfse null dst, end marker", 1);
  if (lzfse_decode_buffer(NULL, 0, stored, sizeof stored, NULL) != 0)
    return fail("lzfse null dst, stored block (DST_FULL reports dst_size)", 1);
  if (lzfse_decode_buffer(scratch_dst, sizeof scratch_dst, NULL, 0, NULL) != 0)
    return fail("lzfse null src", 1);
  if (lzfse_decode_buffer(scratch_dst, sizeof scratch_dst, stored, sizeof stored, NULL) != 3 ||
      memcmp(scratch_dst, "abc", 3) != 0)
    return fail("lzfse stored block", 1);

  rc = crushlzfse_decode_buffer(NULL, 0, NULL, 0, &n);
  if (rc != CRUSHLZFSE_INVALID) return fail("crush null/empty", rc);
  n = 99;
  rc = crushlzfse_decode_buffer(NULL, 0, eos, sizeof eos, &n);
  if (rc != 0 || n != 0) return fail("crush null dst, end marker", rc);
  n = 99;
  rc = crushlzfse_decode_buffer(NULL, 0, stored, sizeof stored, &n);
  if (rc != CRUSHLZFSE_OUTPUT_TOO_SMALL || n != 0) return fail("crush null dst, stored block", rc);
  rc = crushlzfse_decode_buffer(scratch_dst, sizeof scratch_dst, NULL, 0, &n);
  if (rc != CRUSHLZFSE_INVALID) return fail("crush null src", rc);
  rc = crushlzfse_decode_buffer(scratch_dst, sizeof scratch_dst, stored, sizeof stored, &n);
  if (rc != 0 || n != 3 || memcmp(scratch_dst, "abc", 3) != 0) return fail("crush stored block", rc);
  return 0;
}
