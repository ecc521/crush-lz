// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// The declared-length parser permits disjoint source and output ranges of
// one allocation, on either side of each other.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lzfse_internal.h"

static int check_same_allocation(int output_before_source) {
  union {
    size_t words[8];
    uint8_t bytes[8 * sizeof(size_t)];
  } arena = {{0}};
  uint8_t *src = arena.bytes + (output_before_source ? 2 * sizeof(size_t) : 0);
  size_t *out_len = output_before_source ? &arena.words[0] : &arena.words[2];
  const uint32_t magic = LZFSE_ENDOFSTREAM_BLOCK_MAGIC;
  memcpy(src, &magic, sizeof magic);
  *out_len = SIZE_MAX;

  int status = lzfse_declared_len(src, src + sizeof magic, out_len);
  if(status != 0 || *out_len != 0 || memcmp(src, &magic, sizeof magic) != 0) {
    fprintf(stderr, "declared length alias layout %d: status=%d length=%zu\n",
            output_before_source, status, *out_len);
    return 1;
  }
  return 0;
}

int main(void) {
  if(check_same_allocation(0) || check_same_allocation(1)) return 1;
  puts("ok");
  return 0;
}
