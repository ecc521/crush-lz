// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Stress test for the DP's tuple bound (z->max_tuples, lzfse_zopt.h): drives
// the tuple count toward its analytic ceiling so a bound that is silently
// too small fails here rather than as an encode failure in a caller. Calls
// lzfse_encode_base directly so the overflow is not absorbed by a fallback.
#include "lzfse_internal.h"
#include "lzfse_zopt.h"
#include "lzfse.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void build_worst_case(uint8_t *buf, size_t n) {
    // ZOPT_MIN_MATCH_LEN-byte words: a unique pool in the first 1/16, then
    // copies drawn only from the pool, so matches cannot extend past one word.
    size_t n_words = n / ZOPT_MIN_MATCH_LEN;
    size_t pool = n_words / 16;
    for (size_t i = 0; i < pool; i++) {
        uint32_t v = (uint32_t)i;
        memcpy(buf + ZOPT_MIN_MATCH_LEN * i, &v, ZOPT_MIN_MATCH_LEN);
    }
    for (size_t i = pool; i < n_words; i++) {
        uint32_t h = (uint32_t)(i * 2654435761u) ^ ((uint32_t)i >> 3);
        size_t src = h % (pool - 1);
        uint32_t v = (uint32_t)src;
        memcpy(buf + ZOPT_MIN_MATCH_LEN * i, &v, ZOPT_MIN_MATCH_LEN);
    }
    for (size_t i = n_words * ZOPT_MIN_MATCH_LEN; i < n; i++) buf[i] = 0;
}

int main(void) {
    const size_t n = LZFSE_ZOPT_BLOCK_SIZE;
    uint8_t *src = malloc(n);
    build_worst_case(src, n);

    const int32_t cand_capacity = ZOPT_DEFAULT_STORE_LIMIT;
    lzfse_encoder_state state;
    memset(&state, 0, sizeof(state));
    void *zopt_mem = malloc(lzfse_zopt_scratch_size(cand_capacity, ZOPT_DEFAULT_SPLIT_MAX_BLOCKS, ZOPT_DEFAULT_HASH_BITS, ZOPT_MAX_LIVE_BUCKETS, 0));
    state.zopt = (lzfse_zopt_scratch *)zopt_mem;
    lzfse_zopt_scratch_init(state.zopt, cand_capacity, ZOPT_DEFAULT_SPLIT_MAX_BLOCKS, ZOPT_DEFAULT_HASH_BITS, ZOPT_MAX_LIVE_BUCKETS, 0);
    const int32_t max_tuples = state.zopt->max_tuples;

    size_t dst_cap = n * 2 + 4096;
    uint8_t *dst = malloc(dst_cap);

    if (lzfse_encode_init(&state) != LZFSE_STATUS_OK) { fprintf(stderr, "encode_init failed\n"); return 1; }
    state.dst = dst;
    state.dst_begin = dst;
    state.dst_end = dst + dst_cap;
    state.src = src;
    state.src_encode_i = 0;
    state.src_end = (lzfse_offset)n;

    // enable_reparse=0: reparse overwrites z->best_n_tuples per sub-range.
    state.zopt->search_depth = 256;
    state.zopt->iterations = 4;
    state.zopt->enable_reparse = 0;

    int base_ok = lzfse_encode_base(&state);
    if (base_ok != LZFSE_STATUS_OK) {
        fprintf(stderr, "*** lzfse_encode_base FAILED (tuple_overflow?) on a %zu-byte worst-case input: "
                        "max_tuples (%d) is too small ***\n", n, max_tuples);
        return 1;
    }

    int32_t n_tuples = state.zopt->best_n_tuples;
    if (lzfse_encode_finish(&state) != LZFSE_STATUS_OK) { fprintf(stderr, "encode_finish failed\n"); return 1; }
    size_t out_size = (size_t)(state.dst - dst);

    void *dscratch = malloc(lzfse_decode_scratch_size() ? lzfse_decode_scratch_size() : 1);
    uint8_t *back = malloc(n);
    size_t back_len = lzfse_decode_buffer(back, n, dst, out_size, dscratch);
    int roundtrip_ok = (back_len == n) && (memcmp(back, src, n) == 0);

    int32_t ceiling = (int32_t)(n / ZOPT_MIN_MATCH_LEN) + 1;
    // Threshold set comfortably below what the construction reaches.
    int32_t min_expected = (int32_t)(0.65 * (n / ZOPT_MIN_MATCH_LEN));

    printf("n_tuples=%d  ceiling=%d (%.1f%% of max_tuples=%d)  out_size=%zu  roundtrip=%s\n",
           n_tuples, ceiling, 100.0 * n_tuples / max_tuples, max_tuples, out_size,
           roundtrip_ok ? "OK" : "*** MISMATCH ***");

    int all_ok = roundtrip_ok && (n_tuples >= min_expected) && (n_tuples <= max_tuples);
    if (!all_ok) {
        fprintf(stderr, "*** FAIL: expected n_tuples >= %d (got %d), roundtrip=%s ***\n",
                min_expected, n_tuples, roundtrip_ok ? "OK" : "MISMATCH");
    }

    free(src); free(dst); free(back); free(dscratch); free(zopt_mem);
    printf("%s\n", all_ok ? "max_tuples STRESS TEST PASSED" : "*** max_tuples STRESS TEST FAILED ***");
    return all_ok ? 0 : 1;
}
