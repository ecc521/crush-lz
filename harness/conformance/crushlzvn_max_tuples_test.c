// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Stress test for z->max_tuples (lzvn_zopt.h): drives the DP's tuple count
// toward its analytic ceiling so a bound that is silently too small fails
// here rather than as an encode failure in a caller. Mirrors
// crushlzfse_max_tuples_test.c, adapted for LZVN's 3-byte match floor, and
// calls lzvn_pareto_run_dp directly so an overflow is not absorbed by
// crushlzvn's fallback.
#include "lzvn_encode_base.c"
#include "lzvn_decode_base.c"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void build_worst_case(uint8_t *buf, size_t n) {
  // As crushlzfse_max_tuples_test.c, with 4-byte words: still LZVN-eligible
  // without the accidental-extension risk of exact 3-byte words.
  size_t n_words = n / 4;
  size_t pool = n_words / 16;
  for (size_t i = 0; i < pool; i++) {
    uint32_t v = (uint32_t)i;
    memcpy(buf + 4 * i, &v, 4);
  }
  for (size_t i = pool; i < n_words; i++) {
    uint32_t h = (uint32_t)(i * 2654435761u) ^ ((uint32_t)i >> 3);
    size_t src = h % (pool - 1);
    uint32_t v = (uint32_t)src;
    memcpy(buf + 4 * i, &v, 4);
  }
}

int main(void) {
  const int32_t n = LZVN_ZOPT_BLOCK_SIZE;
  uint8_t *src = malloc((size_t)n + LZVN_ZOPT_SRC_PADDING);
  build_worst_case(src, (size_t)n);
  memset(src + n, 0, LZVN_ZOPT_SRC_PADDING);

  const int32_t cand_capacity =
      LZVN_ZOPT_DEFAULT_STORE_LIMIT < LZVN_ZOPT_MAX_STORE_LIMIT ? LZVN_ZOPT_DEFAULT_STORE_LIMIT : LZVN_ZOPT_MAX_STORE_LIMIT;
  size_t zopt_size = lzvn_zopt_scratch_size(cand_capacity, LZVN_ZOPT_DEFAULT_HASH_BITS);
  lzvn_zopt_scratch *z = (lzvn_zopt_scratch *)malloc(zopt_size);
  lzvn_zopt_scratch_init(z, cand_capacity, LZVN_ZOPT_DEFAULT_HASH_BITS);
  size_t pareto_size = lzvn_pareto_scratch_size(1);
  lzvn_pareto_scratch *p = (lzvn_pareto_scratch *)malloc(pareto_size);
  lzvn_pareto_scratch_init(p, 1);
  z->search_depth = 256;
  const int32_t max_tuples = z->max_tuples;

  lzvn_offset padded_end = (lzvn_offset)n + LZVN_ZOPT_SRC_PADDING;
  lzvn_zopt_build_candidates(z, src, padded_end, n);
  int dp_ok = lzvn_pareto_run_dp(z, p, src, padded_end, 0, n);
  if (!dp_ok) {
    fprintf(stderr, "*** lzvn_pareto_run_dp FAILED (tuple_overflow?) on a %d-byte worst-case input: "
                    "max_tuples (%d) is too small ***\n", n, max_tuples);
    return 1;
  }

  int32_t n_tuples = z->n_tuples;

  size_t dst_cap = (size_t)n * 2 + 4096;
  uint8_t *dst = malloc(dst_cap);
  size_t out_size = lzvn_zopt_commit(src, dst, dst_cap, z, 0);

  uint8_t *back = malloc((size_t)n);
  size_t back_len = lzvn_decode_buffer(back, (size_t)n, dst, out_size);
  int roundtrip_ok = (back_len == (size_t)n) && (memcmp(back, src, (size_t)n) == 0);

  int32_t ceiling = n / LZVN_ZOPT_MIN_MATCH_LEN + 1;
  // Threshold set comfortably below what the construction reaches.
  int32_t min_expected = (int32_t)(0.35 * (n / LZVN_ZOPT_MIN_MATCH_LEN));

  printf("n_tuples=%d  ceiling=%d (%.1f%% of max_tuples=%d)  out_size=%zu  roundtrip=%s\n",
         n_tuples, ceiling, 100.0 * n_tuples / max_tuples, max_tuples, out_size,
         roundtrip_ok ? "OK" : "*** MISMATCH ***");

  int all_ok = roundtrip_ok && (n_tuples >= min_expected) && (n_tuples <= max_tuples);
  if (!all_ok) {
    fprintf(stderr, "*** FAIL: expected n_tuples >= %d (got %d), roundtrip=%s ***\n",
            min_expected, n_tuples, roundtrip_ok ? "OK" : "MISMATCH");
  }

  free(src); free(dst); free(back); free(z); free(p);
  printf("%s\n", all_ok ? "max_tuples STRESS TEST PASSED" : "*** max_tuples STRESS TEST FAILED ***");
  return all_ok ? 0 : 1;
}
