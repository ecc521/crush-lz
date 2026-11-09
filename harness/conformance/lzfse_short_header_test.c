// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Every truncated frame-header branch must return before reading past src_end.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lzfse_internal.h"

static int check(const uint8_t *src, size_t len, const char *name) {
  // Keep the decoder's declared source extent equal to its allocation.
  uint8_t *input = malloc(len ? len : 1);
  if (!input) return 1;
  memcpy(input, src, len);
  uint8_t dst[64] = {0};
  lzfse_decoder_state state;
  memset(&state, 0, sizeof state);
  state.src_begin = input;
  state.src = input;
  state.src_end = input + len;
  state.dst_begin = dst;
  state.dst = dst;
  state.dst_end = dst + sizeof dst;
  int result = lzfse_decode(&state);
  if (result != LZFSE_STATUS_SRC_EMPTY || state.src != input || state.dst != dst) {
    fprintf(stderr, "%s length %zu: result %d, src advance %td, dst advance %td\n",
            name, len, result, state.src - input, state.dst - dst);
    free(input);
    return 1;
  }
  free(input);
  return 0;
}

static int check_fixed(uint32_t magic, size_t complete, const char *name) {
  uint8_t src[sizeof(lzfse_compressed_block_header_v1)] = {0};
  memcpy(src, &magic, sizeof magic);
  for (size_t len = sizeof magic; len < complete; ++len)
    if (check(src, len, name)) return 1;
  return 0;
}

int main(void) {
  uint8_t short_magic[4] = {0};
  for (size_t len = 0; len < 4; ++len)
    if (check(short_magic, len, "magic")) return 1;
  if (check_fixed(LZFSE_UNCOMPRESSED_BLOCK_MAGIC,
                  sizeof(uncompressed_block_header), "uncompressed")) return 1;
  if (check_fixed(LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC,
                  sizeof(lzvn_compressed_block_header), "lzvn")) return 1;
  if (check_fixed(LZFSE_COMPRESSEDV1_BLOCK_MAGIC,
                  sizeof(lzfse_compressed_block_header_v1), "v1")) return 1;

  lzfse_compressed_block_header_v2 v2 = {0};
  v2.magic = LZFSE_COMPRESSEDV2_BLOCK_MAGIC;
  v2.packed_fields[2] = 80; // declared V2 header extent
  const uint8_t *v2_bytes = (const uint8_t *)&v2;
  for (size_t len = 4; len < 80; ++len)
    if (check(v2_bytes, len, "v2")) return 1;
  return 0;
}
