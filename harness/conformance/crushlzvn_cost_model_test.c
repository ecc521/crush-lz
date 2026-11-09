// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Validates the closed-form LZVN op-code cost helpers in lzvn_encode_base.c
// against the real emit()/emit_literal() writers, byte-for-byte, across
// every threshold boundary. A wrong cost never fails a round-trip; it only
// biases the DP, so this is the one place that can catch it.

#include "lzvn_encode_base.c"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_failures = 0;
static unsigned char g_src[1 << 16];
static unsigned char g_dst[1 << 20];

static void check_literal_final(int32_t L) {
  unsigned char *end = emit_literal(g_src, g_dst, g_dst + sizeof(g_dst), (size_t)L);
  int32_t actual = (int32_t)(end - g_dst);
  int32_t expected = lzvn_literal_final_cost(L);
  if (actual != expected) {
    printf("FAIL literal_final L=%d: actual=%d expected=%d\n", L, actual, expected);
    g_failures++;
  }
}

static void check_combo(int32_t L, int32_t M, int32_t D, int32_t D_prev) {
  unsigned char *end = emit(g_src, g_dst, g_dst + sizeof(g_dst), (size_t)L,
                            (size_t)M, (size_t)D, (size_t)D_prev);
  int32_t actual = (int32_t)(end - g_dst);
  int32_t tail = -1;
  int32_t expected = lzvn_literal_prefix_cost(L, &tail) +
                     lzvn_match_op_cost(tail, M, D, D_prev);
  if (actual != expected) {
    printf("FAIL L=%d M=%d D=%d D_prev=%d: actual=%d expected=%d (tail=%d)\n",
           L, M, D, D_prev, actual, expected, tail);
    g_failures++;
  }
}

int main(void) {
  memset(g_src, 0xAB, sizeof(g_src));

  // Literal-run lengths crossing every peeling boundary.
  int32_t Ls[] = {0,   1,   2,   3,   4,   5,   14,  15,
                  16,  17,  270, 271, 272, 300, 542, 543,
                  544, 800, 1000};
  int32_t n_Ls = (int32_t)(sizeof(Ls) / sizeof(Ls[0]));

  // Match lengths crossing every inline-capacity and extension boundary.
  int32_t Ms[] = {3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
                  14, 15, 16, 17, 24, 25, 33, 34, 35, 36,
                  50, 270, 271, 272, 300};
  int32_t n_Ms = (int32_t)(sizeof(Ms) / sizeof(Ms[0]));

  // Distances crossing the short/medium and medium/long tier boundaries.
  int32_t Ds[] = {1, 2, 100, 1535, 1536, 1537, 2000,
                  16383, 16384, 16385, 20000, 65535};
  int32_t n_Ds = (int32_t)(sizeof(Ds) / sizeof(Ds[0]));

  for (int32_t i = 0; i < n_Ls; i++)
    check_literal_final(Ls[i]);

  for (int32_t i = 0; i < n_Ls; i++) {
    for (int32_t j = 0; j < n_Ms; j++) {
      for (int32_t k = 0; k < n_Ds; k++) {
        int32_t L = Ls[i], M = Ms[j], D = Ds[k];
        check_combo(L, M, D, /*D_prev=*/0);
        check_combo(L, M, D, /*D_prev=*/D);
        if (D > 1)
          check_combo(L, M, D, D - 1);
      }
    }
  }

  if (g_failures == 0) {
    printf("PASS: cost model matches emit()/emit_literal() exactly\n");
    return 0;
  }
  printf("FAIL: %d mismatches\n", g_failures);
  return 1;
}
