// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test for a heap out-of-bounds write: zbm_decide_block_row_generic()
// recorded up to 2 DP candidates into a block's row without clamping to
// state->dp_cand_stride (the row width scratch was actually sized for).
// With CRUSHLZBITMAP_STRATEGY_DP and max_candidates == 1 (documented-legal:
// crushlzbitmap_get_capabilities().dp_max_candidates_min == 1, and reachable
// from safe Rust via Params::Dp{max_candidates: 1, ..}), the stride is 1, so
// the second candidate write lands one slot past the row. For the table's
// last row — which is exactly what happens whenever the final chunk is a
// full 32768-byte block — that write lands past the end of the scratch
// allocation entirely:
//
//   ==ERROR: AddressSanitizer: heap-buffer-overflow ...
//   WRITE of size 1 at 0x... thread T0
//       #0 zbm_decide_chunk_dp libzbitmap.c
//       #1 zbm_build_compressed_chunk_dp libzbitmap.c
//       #2 crushlzbitmap_encode_buffer_advanced libzbitmap.c
//   ... is located 0 bytes after N-byte region [...]
//
// The fix clamps the recorded candidate count to state->dp_cand_stride
// before the loop that writes them (matching the vector path's own
// `n < stride` loop guard, which never had this bug), so this test exercises
// exactly the shape that reached the last row with an alternate, non-current
// period in play, under scratch allocated at the library's own exact
// crushlzbitmap_scratch_size() — the ASan redzone sits immediately after it.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzbitmap.h"

#define N 32768

static uint8_t src[N];
static uint8_t dst[1 << 17];

static int try_one(const char *what) {
    crushlzbitmap_params p;
    size_t sbytes, out;
    void *scratch;

    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_DP, &p);
    p.p.dp.max_candidates = 1;  // documented minimum; the stride this bug ignored
    p.p.dp.iterations = 1;

    sbytes = crushlzbitmap_scratch_size(&p);
    scratch = malloc(sbytes);  // exact size: ASan redzone sits right after it
    if (!scratch) { perror("malloc"); exit(2); }

    out = crushlzbitmap_encode_buffer_advanced(dst, sizeof dst, src, N, scratch, sbytes, &p);
    printf("%-28s scratch=%zu out=%zu\n", what, sbytes, out);
    free(scratch);
    return out != 0;
}

int main(void) {
    unsigned d;
    size_t i;
    int failures = 0;

    // A text-like body (so most blocks are decided, not fast-pathed away)
    // whose final 8-byte block is made to match some distance further back
    // than the period already in force — this is what puts a second,
    // alternate candidate into the last row's slot 1, the write this bug
    // dropped the bounds check on.
    for (i = 0; i < N; i++)
        src[i] = (uint8_t)("the quick brown fox jumps over the lazy dog "[i % 43]);

    for (d = 8; d <= 2048; d += 8) {
        char lbl[64];
        for (i = N - 24; i < N - 8; i++) src[i] = (uint8_t)(i * 13 + d);
        memcpy(src + N - 8, src + N - 8 - d, 8);
        snprintf(lbl, sizeof lbl, "tail distance d=%u", d);
        if (!try_one(lbl)) { printf("FAIL: encode rejected input unexpectedly\n"); failures++; }
    }

    printf("%d failures\n", failures);
    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
