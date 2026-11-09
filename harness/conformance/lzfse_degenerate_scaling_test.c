// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// LZFSE counterpart to crushlzvn_degenerate_scaling_test.c: the match tree
// (bt_match.h) must stay bounded on repetitive input, where every position
// matches every earlier one in its phase. A walk stops at the first match
// that reaches the end of the block, and a long match's interior is skipped. Counts match_extend calls
// (LZFSE_COUNT_MATCH_EXTEND) instead of wall-clock time so the assertion is
// deterministic; includes lzfse_encode_base.c so the instrumented copy is
// the one exercised.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t g_match_extend_calls = 0, g_match_extend_bytes = 0;
#define LZFSE_COUNT_MATCH_EXTEND
#include "lzfse_encode_base.c"
#include "lzfse.h" // the decode side needs no instrumentation

static int g_failures = 0;

// Exceeds the deepest shipped level's search depth, widening the margin.
#define TEST_SEARCH_DEPTH 512
#define TEST_N 65536

static size_t run_encode(const unsigned char *content, int32_t n, int32_t search_depth) {
  const int32_t cand_capacity = 8; // < search_depth, so only the longest are kept
  lzfse_encoder_state state;
  memset(&state, 0, sizeof(state));
  void *zopt_mem = malloc(lzfse_zopt_scratch_size(cand_capacity, ZOPT_DEFAULT_SPLIT_MAX_BLOCKS, ZOPT_DEFAULT_HASH_BITS, ZOPT_MAX_LIVE_BUCKETS, 0));
  state.zopt = (lzfse_zopt_scratch *)zopt_mem;
  lzfse_zopt_scratch_init(state.zopt, cand_capacity, ZOPT_DEFAULT_SPLIT_MAX_BLOCKS, ZOPT_DEFAULT_HASH_BITS, ZOPT_MAX_LIVE_BUCKETS, 0);

  size_t dst_cap = (size_t)n * 2 + 4096;
  uint8_t *dst = malloc(dst_cap);

  if (lzfse_encode_init(&state) != LZFSE_STATUS_OK) {
    printf("FAIL: encode_init failed\n");
    g_failures++;
    free(zopt_mem); free(dst);
    return 0;
  }
  state.dst = dst;
  state.dst_begin = dst;
  state.dst_end = dst + dst_cap;
  state.src = content;
  state.src_encode_i = 0;
  state.src_end = (lzfse_offset)n;

  // One candidate build and one DP pass.
  state.zopt->search_depth = search_depth;
  state.zopt->iterations = 1;
  state.zopt->enable_reparse = 0;

  g_match_extend_calls = 0;
  int base_ok = lzfse_encode_base(&state);
  size_t calls = g_match_extend_calls;

  if (base_ok != LZFSE_STATUS_OK) {
    printf("FAIL: lzfse_encode_base failed on a degenerate %d-byte block\n", n);
    g_failures++;
  } else if (lzfse_encode_finish(&state) != LZFSE_STATUS_OK) {
    printf("FAIL: encode_finish failed\n");
    g_failures++;
  } else {
    size_t out_size = (size_t)(state.dst - dst);
    void *dscratch = malloc(lzfse_decode_scratch_size() ? lzfse_decode_scratch_size() : 1);
    uint8_t *back = malloc((size_t)n);
    size_t back_len = lzfse_decode_buffer(back, (size_t)n, dst, out_size, dscratch);
    if (back_len != (size_t)n || memcmp(back, content, (size_t)n) != 0) {
      printf("FAIL: round-trip mismatch on degenerate block\n");
      g_failures++;
    }
    free(dscratch); free(back);
  }

  free(zopt_mem); free(dst);
  return calls;
}

// Bounded, match_extend runs a few times per position (the tree walk and the
// DP's repeat probe), independent of search_depth; unbounded, up to
// search_depth times. The floor catches a miswired counter reporting 0.
#define CALLS_UPPER_BOUND ((size_t)TEST_N * 160)
#define CALLS_LOWER_BOUND ((size_t)TEST_N / 2)

static void check_degenerate(const char *label, const unsigned char *content) {
  size_t calls = run_encode(content, TEST_N, TEST_SEARCH_DEPTH);
  printf("%-24s calls=%-10zu (floor=%zu ceiling=%zu, unbounded would be ~%zu)\n",
         label, calls, (size_t)CALLS_LOWER_BOUND, (size_t)CALLS_UPPER_BOUND,
         (size_t)TEST_N * (size_t)TEST_SEARCH_DEPTH);
  if (calls < CALLS_LOWER_BOUND) {
    printf("FAIL %s: match_extend called suspiciously few times (%zu < %zu): "
           "counter likely not wired up, not evidence of a fast short-circuit\n",
           label, calls, (size_t)CALLS_LOWER_BOUND);
    g_failures++;
  }
  if (calls > CALLS_UPPER_BOUND) {
    printf("FAIL %s: match_extend called %zu times over %d positions (limit %zu): "
           "the match tree's walk is not bounded, "
           "candidate search has gone quadratic\n",
           label, calls, TEST_N, (size_t)CALLS_UPPER_BOUND);
    g_failures++;
  }
}

int main(void) {
  static unsigned char zeros[TEST_N];
  memset(zeros, 0, sizeof(zeros));
  check_degenerate("zeros", zeros);

  static unsigned char rep4[TEST_N];
  for (int32_t i = 0; i < TEST_N; i += 4) memcpy(rep4 + i, "\xDE\xAD\xBE\xEF", 4);
  check_degenerate("period4", rep4);

  if (g_failures == 0) {
    printf("PASS: the match tree bounds match_extend calls on both shapes\n");
    return 0;
  }
  printf("FAIL: %d check(s) failed\n", g_failures);
  return 1;
}
