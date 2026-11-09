// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Small-input invariants of crushlzfse_encode_buffer, asserted at every
// level over text, repetitive and incompressible content:
//   1. Given a dst large enough, the output is never larger than
//      src_size + 12 (the stored-block fallback).
//   2. Below LZFSE_ENCODE_LZVN_THRESHOLD, levels 0 and up are never worse
//      than lzfse_encode_buffer, which defers to LZVN there.
//   3. Every truncation of the stream is CRUSHLZFSE_INVALID, given a dst
//      with room for the whole output.
// Every stream is also round-trip checked.
#include "crushlzfse.h"
#include "lzfse.h"
#include "lzfse_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fill_text(uint8_t *buf, size_t n, unsigned *seed) {
    static const char *words[] = {"the ", "quick ", "brown ", "fox ", "jumps ",
                                   "over ", "lazy ", "dog ", "data ", "test "};
    size_t pos = 0;
    while (pos < n) {
        const char *w = words[rand_r(seed) % 10];
        size_t wl = strlen(w);
        if (pos + wl > n) wl = n - pos;
        memcpy(buf + pos, w, wl);
        pos += wl;
    }
}

static void fill_repetitive(uint8_t *buf, size_t n, unsigned *seed) {
    uint8_t b = (uint8_t)(rand_r(seed) & 0xff);
    for (size_t i = 0; i < n; i++) buf[i] = b;
}

static void fill_random(uint8_t *buf, size_t n, unsigned *seed) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(rand_r(seed) & 0xff);
}

static int check_case(const char *label, size_t n, const uint8_t *src,
                       void *scratch, size_t scratch_size, int *all_ok) {
    size_t cap = n * 2 + 4096;
    uint8_t *dst_stock = malloc(cap);
    uint8_t *dst_crush = malloc(cap);
    uint8_t *back = malloc(n ? n : 1);
    size_t stock_size = lzfse_encode_buffer(dst_stock, cap, src, n, NULL);
    int ok = 1;

    for (int level = CRUSHLZFSE_LEVEL_MIN; level <= CRUSHLZFSE_LEVEL_MAX; level++) {
        size_t crush_size = crushlzfse_encode_buffer(dst_crush, cap, src, n, scratch, scratch_size, level);

        if (crush_size == 0) {
            if (n != 0) {
                printf("FAIL(encode=0) %-12s n=%-6zu level=%d\n", label, n, level);
                ok = 0;
            }
            continue;
        }

        // Invariant 1.
        if (n + 12 <= cap && crush_size > n + 12) {
            printf("FAIL(expanded) %-12s n=%-6zu level=%d crush=%zu raw+12=%zu\n",
                   label, n, level, crush_size, n + 12);
            ok = 0;
        }

        // Invariant 2. lzfse_encode_buffer runs level 0; levels below it are
        // documented as weaker.
        if (level >= 0 && n < LZFSE_ENCODE_LZVN_THRESHOLD && stock_size > 0 && crush_size > stock_size) {
            printf("FAIL(worse-than-stock) %-12s n=%-6zu level=%d crush=%zu stock=%zu\n",
                   label, n, level, crush_size, stock_size);
            ok = 0;
        }

        size_t back_len = 0;
        int rc = crushlzfse_decode_buffer(back, n ? n : 1, dst_crush, crush_size, &back_len);
        if (rc != 0 || back_len != n || (n > 0 && memcmp(back, src, n) != 0)) {
            printf("FAIL(roundtrip) %-12s n=%-6zu level=%d crush_size=%zu back_len=%zu\n",
                   label, n, level, crush_size, back_len);
            ok = 0;
        }

        // Invariant 3. Long streams are cut at a stride, plus every one of
        // their last 16 bytes.
        size_t stride = crush_size / 1024 + 1;
        for (size_t cut = 0; cut < crush_size; cut += (cut + 16 >= crush_size) ? 1 : stride) {
            size_t got = 0;
            int trc = crushlzfse_decode_buffer(back, n ? n : 1, dst_crush, cut, &got);
            if (trc != CRUSHLZFSE_INVALID) {
                printf("FAIL(truncated) %-12s n=%-6zu level=%d cut=%zu/%zu rc=%d\n",
                       label, n, level, cut, crush_size, trc);
                ok = 0;
                break;
            }
        }
    }

    free(dst_stock); free(dst_crush); free(back);
    *all_ok &= ok;
    return ok;
}

int main(void) {
    size_t scratch_size = 0;
    for (int level = CRUSHLZFSE_LEVEL_MIN; level <= CRUSHLZFSE_LEVEL_MAX; level++) {
        crushlzfse_encode_params params;
        crushlzfse_params_for_level(level, &params);
        size_t n = crushlzfse_scratch_size(&params);
        if (n > scratch_size) scratch_size = n;
    }
    void *scratch = malloc(scratch_size);

    size_t sizes[] = {0, 1, 3, 8, 9, 15, 16, 50, 100, 200, 499, 500, 999, 1000,
                       1999, 2000, 3999, 4000, 4095, 4096, 4097, 8000, 20000, 65535, 65536};
    unsigned seed = 12345;
    int all_ok = 1;

    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t n = sizes[si];
        uint8_t *text = malloc(n ? n : 1);
        uint8_t *rep = malloc(n ? n : 1);
        uint8_t *rnd = malloc(n ? n : 1);
        fill_text(text, n, &seed);
        fill_repetitive(rep, n, &seed);
        fill_random(rnd, n, &seed);

        check_case("text", n, text, scratch, scratch_size, &all_ok);
        check_case("repetitive", n, rep, scratch, scratch_size, &all_ok);
        check_case("random", n, rnd, scratch, scratch_size, &all_ok);

        free(text); free(rep); free(rnd);
    }

    free(scratch);
    printf(all_ok ? "ALL SMALL-INPUT CHECKS PASSED\n" : "*** SMALL-INPUT CHECKS FAILED ***\n");
    return all_ok ? 0 : 1;
}
