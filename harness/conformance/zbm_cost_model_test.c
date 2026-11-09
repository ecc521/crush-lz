// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Validates the closed-form LZBITMAP helpers the metadata writers and the
// greedy cost model depend on, against the real nibble writer:
//  * zbm_nibble_cost_for_run() must match zbm_write_metadata_3()'s output
//    length, or the greedy search is silently biased;
//  * cost(R) <= R for every R, which is what makes zbm_write_metadata_3()'s
//    single one-nibble-per-block bound check safe;
//  * zbm_nibble_extend_delta() must equal cost(L + 1) - cost(L).
// zbm_diff_bitmap()'s SWAR lane extraction is checked exhaustively against a
// byte loop.

#include "libzbitmap.c"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_failures = 0;

#define MAX_RUN 5000

/* Nibbles zbm_write_metadata_3() emits for one run of length R. */
static int emitted_nibbles_for_run(int repeat)
{
    static uint8_t buf[MAX_RUN + 64];
    struct zbm_nybl_out out;
    int j;

    memset(buf, 0, sizeof(buf));
    out.addr = buf;
    out.acc = 0;
    out.n = 0;

    zbm_write_nibble(&out, 7); /* the run's bitmap number; value is immaterial */
    if(repeat <= 3) {
        for(j = 1; j < repeat; ++j)
            zbm_write_nibble(&out, 7);
    } else {
        zbm_write_repetition_count(&out, repeat);
    }

    return (int)(out.addr - buf) * 2 + out.n;
}

static void check_run_costs(void)
{
    int r;

    for(r = 1; r <= MAX_RUN; ++r) {
        int actual = emitted_nibbles_for_run(r);
        int expected = zbm_nibble_cost_for_run(r);

        if(actual != expected) {
            printf("FAIL cost_for_run R=%d: writer emitted %d, model says %d\n",
                   r, actual, expected);
            ++g_failures;
        }
        if(expected > r) {
            printf("FAIL cost bound R=%d: cost %d exceeds run length; the "
                   "single bounds check in zbm_write_metadata_3() is unsafe\n",
                   r, expected);
            ++g_failures;
        }
    }
}

static void check_extend_delta(void)
{
    int l;

    for(l = 1; l < MAX_RUN; ++l) {
        int expected = zbm_nibble_cost_for_run(l + 1) - zbm_nibble_cost_for_run(l);
        int actual = zbm_nibble_extend_delta(l);

        if(actual != expected) {
            printf("FAIL extend_delta L=%d: got %d, want %d\n", l, actual, expected);
            ++g_failures;
        }
    }
}

/* Byte-at-a-time reference for zbm_diff_bitmap(). */
static uint8_t diff_bitmap_ref(uint64_t x)
{
    uint8_t bitmap = 0;
    int i;

    for(i = 0; i < 8; ++i)
        if((x >> 8 * i & 0xff) != 0)
            bitmap |= (uint8_t)(1 << i);
    return bitmap;
}

static void check_diff_bitmap(void)
{
    /* Every pattern of differing lanes, crossed with byte values that
     * exercise the low bit, the high bit, all bits and a mixed one. */
    static const uint64_t vals[] = { 0x01, 0x80, 0xff, 0x7f, 0x5a, 0x10 };
    unsigned mask;
    size_t k;

    for(mask = 0; mask < 256; ++mask) {
        for(k = 0; k < sizeof(vals) / sizeof(vals[0]); ++k) {
            uint64_t x = 0;
            int i;

            for(i = 0; i < 8; ++i)
                if(mask >> i & 1)
                    x |= vals[((size_t)i + k) % (sizeof(vals) / sizeof(vals[0]))] << 8 * i;

            if(zbm_diff_bitmap(x) != diff_bitmap_ref(x)) {
                printf("FAIL diff_bitmap mask=%02x k=%zu x=%016llx: got %02x, want %02x\n",
                       mask, k, (unsigned long long)x,
                       zbm_diff_bitmap(x), diff_bitmap_ref(x));
                ++g_failures;
            }
        }
    }
}

int main(void)
{
    check_run_costs();
    check_extend_delta();
    check_diff_bitmap();

    if(g_failures) {
        printf("COST MODEL TEST FAILED (%d failures)\n", g_failures);
        return 1;
    }
    printf("COST MODEL TEST PASSED\n");
    return 0;
}
