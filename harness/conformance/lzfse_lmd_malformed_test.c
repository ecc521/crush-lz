// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Exercise the shipping LMD loop with a malformed zero-distance tuple.
// Before the distance guard, periodic match copy could loop forever.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lzfse_decode_base.c"

int main(void) {
  uint8_t input[32] = {0};
  uint8_t output[128] = {0};
  lzfse_decoder_state state;
  memset(&state, 0, sizeof state);
  state.src_begin = input;
  state.src = input + 16;
  state.src_end = input + sizeof input;
  state.dst_begin = output;
  state.dst = output;
  state.dst_end = output + sizeof output;

  lzfse_compressed_block_decoder_state *bs = &state.compressed_lzfse_block_state;
  bs->n_matches = 1;
  bs->current_literal = bs->literals;
  bs->lmd_in_stream.accum_nbits = 56;
  bs->lmd_decoder[LZFSE_M_DECODER_OFFSET].vbase = 32;

  int status = lzfse_decode_lmd(&state);
  if (status != LZFSE_STATUS_ERROR) {
    fprintf(stderr, "zero-distance LMD tuple returned %d\n", status);
    return 1;
  }
  return 0;
}
