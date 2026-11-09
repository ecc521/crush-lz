// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Differential decoder test: the shipped LZBITMAP decoder against the same
 * source with its bulk fast paths compiled out (ZBM_TEST_DECODER_FALLBACK),
 * over real encoder output at every level, so any disagreement is a
 * fast-path bug. Inputs are periodic bases perturbed at a fixed cadence,
 * swept over period, cadence and length. BUILD_DIFF_TEST in harness/Makefile
 * links the two builds into one binary.
 *
 * ZBM_DIFF_LEVELS, a comma-separated list, restricts the sweep; unset means
 * every level.
 */
#include "crushlzbitmap.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* After <stdint.h>: the generated table carries no includes of its own. */
#include "zbm_blend_tables.h"

/* The fallback build's decoder, renamed at compile time. */
int ref_crushlzbitmap_decode_buffer(void *dst, size_t dst_size, const void *src, size_t src_size,
                                    size_t *out_len);

static long cases, fails;

/*
 * The generated blend table, checked against the definition it encodes.
 * Every index must stay in 0..15: TBL (arm64) and PSHUFB (x86) only agree
 * in that range, and nothing in the generator enforces it.
 */
static long check_blend_table(void)
{
    long bad = 0;
    int bmp, i;

    for (bmp = 0; bmp < 256; bmp++) {
        const uint8_t *row = zbm_blend_row[bmp];

        for (i = 0; i < 16; i++) {
            if (row[i] > 15) {
                if (++bad <= 10)
                    printf("  row %3d byte %2d = %u: above 15, TBL and PSHUFB "
                           "disagree here\n", bmp, i, row[i]);
            }
        }
        for (i = 0; i < ZBM_BLEND_ROW_CNT; i++) {
            unsigned want = ((bmp >> i) & 1)
                          ? (unsigned)__builtin_popcount(bmp & ((1 << i) - 1))
                          : (unsigned)(8 + i);
            if (row[i] != want) {
                if (++bad <= 10)
                    printf("  row %3d lane %d selects %u, want %u\n",
                           bmp, i, row[i], want);
            }
        }
        if (row[ZBM_BLEND_ROW_CNT] != (unsigned)__builtin_popcount(bmp)) {
            if (++bad <= 10)
                printf("  row %3d literal count %u, want %d\n", bmp,
                       row[ZBM_BLEND_ROW_CNT], __builtin_popcount(bmp));
        }
        for (i = ZBM_BLEND_ROW_CNT + 1; i < 16; i++) {
            if (row[i]) {
                if (++bad <= 10)
                    printf("  row %3d padding byte %d = %u, want 0\n",
                           bmp, i, row[i]);
            }
        }
    }
    printf("blend table: 256 rows checked, %ld problems\n", bad);
    return bad;
}

static void check(const char *label, int level, const uint8_t *data, size_t len)
{
    size_t max_out = crushlzbitmap_encode_bound(len), out, d_fast = 0, d_slow = 0;
    uint8_t *comp, *fast, *slow;
    int e_fast, e_slow, agree, correct;

    comp = malloc(max_out);
    out = crushlzbitmap_encode_buffer(comp, max_out, data, len, NULL, 0, level);
    if (!out) { free(comp); return; }

    fast = calloc(len ? len : 1, 1);
    slow = calloc(len ? len : 1, 1);
    e_fast = crushlzbitmap_decode_buffer(fast, len, comp, out, &d_fast);
    e_slow = ref_crushlzbitmap_decode_buffer(slow, len, comp, out, &d_slow);

    cases++;
    agree = (e_fast == e_slow) && (d_fast == d_slow) && (len == 0 || !memcmp(fast, slow, len));
    correct = !e_fast && d_fast == len && (len == 0 || !memcmp(fast, data, len));
    if (!agree || !correct) {
        size_t at = 0;
        while (at < len && fast[at] == slow[at]) at++;
        if (++fails <= 10)
            printf("  level %-2d %-28s len=%-6zu %s%sfirst diff @%zu\n", level, label, len,
                   agree ? "" : "DECODERS-DISAGREE ", correct ? "" : "WRONG-OUTPUT ", at);
    }
    free(comp); free(fast); free(slow);
}

/* Whether ZBM_DIFF_LEVELS names this level; every level when it is unset. */
static int level_selected(int level)
{
    const char *env = getenv("ZBM_DIFF_LEVELS");
    if (!env || !*env) return 1;
    while (*env) {
        char *end;
        long v = strtol(env, &end, 10);
        if (end == env) return 0;
        if (v == level) return 1;
        env = *end == ',' ? end + 1 : end;
    }
    return 0;
}

int main(void)
{
    static const size_t lens[] = {256, 1024, 4096, 20000};
    char label[64];
    int level, period, perturb;
    size_t li;

    long table_bad = check_blend_table();

    for (level = CRUSHLZBITMAP_LEVEL_MIN; level <= CRUSHLZBITMAP_LEVEL_MAX; level++) {
        if (!level_selected(level)) continue;
        for (period = 1; period <= 40; period++) {
            for (perturb = 0; perturb <= 16; perturb++) {
                for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
                    size_t n = lens[li], j;
                    uint8_t *buf = malloc(n);
                    for (j = 0; j < n; j++) {
                        buf[j] = (uint8_t)(0x30 + (j % (size_t)period));
                        if (perturb && j % (size_t)perturb == 0)
                            buf[j] = (uint8_t)(0xc0 + (j / perturb) % 5);
                    }
                    snprintf(label, sizeof(label), "period=%d perturb=%d", period, perturb);
                    check(label, level, buf, n);
                    free(buf);
                }
            }
        }
    }

    printf("\n%ld cases, %ld disagreements\n", cases, fails);
    if (table_bad)
        printf("*** BLEND TABLE IS NOT WHAT BOTH SHUFFLES REQUIRE ***\n");
    printf("%s\n", fails ? "*** DECODER FAST PATHS DIFFER FROM THE SLOW PATH ***"
                         : "ALL DECODER PATHS AGREE");
    return (fails || table_bad) ? 1 : 0;
}
