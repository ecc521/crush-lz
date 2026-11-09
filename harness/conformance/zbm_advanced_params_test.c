// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * The params API: crushlzbitmap_default_params(), crushlzbitmap_params_for_level()
 * and crushlzbitmap_encode_buffer_advanced(). Every strategy's defaults
 * round-trip, custom params at every field's ceiling round-trip, every
 * numbered level round-trips and the greedy ladder (the fast tier
 * included) is monotone on this fixture, out-of-range levels clamp, and
 * every out-of-range field is rejected rather than silently clamped.
 */
#include "crushlzbitmap.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t data[65536];

static int roundtrip_with(const char *label, crushlzbitmap_params *params) {
    size_t max_out = crushlzbitmap_encode_bound(sizeof(data)), out_len, decmp = 0;
    uint8_t *dst = malloc(max_out);
    out_len = crushlzbitmap_encode_buffer_advanced(dst, max_out, data, sizeof(data), NULL, 0, params);
    if (!out_len) { printf("%-30s COMPRESS FAILED\n", label); free(dst); return 0; }
    uint8_t *back = malloc(sizeof(data));
    int err = crushlzbitmap_decode_buffer(back, sizeof(data), dst, out_len, &decmp);
    int ok = !err && decmp == sizeof(data) && memcmp(back, data, sizeof(data)) == 0;
    printf("%-30s out=%-8zu %s\n", label, out_len, ok ? "OK" : "*** MISMATCH ***");
    free(dst); free(back);
    return ok;
}

/* Compressed size for a params set, for the preset-ordering check. */
static size_t compressed_size(crushlzbitmap_params *params) {
    size_t max_out = crushlzbitmap_encode_bound(sizeof(data)), out_len;
    uint8_t *dst = malloc(max_out);
    out_len = crushlzbitmap_encode_buffer_advanced(dst, max_out, data, sizeof(data), NULL, 0, params);
    free(dst);
    return out_len ? out_len : (size_t)-1;
}

/* A wholly legal row-params set with one field overridden. Every field is
 * named so a field added later cannot default to an out-of-range 0. */
static crushlzbitmap_params row_params(int hash_bits, int depth, int dist_cache_size,
                                             int accept_diff, int scan_window, int lookahead) {
    crushlzbitmap_params p;
    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_ROW, &p);
    p.p.row.hash_bits = hash_bits;
    p.p.row.depth = depth;
    p.p.row.dist_cache_size = dist_cache_size;
    p.p.row.accept_diff = accept_diff;
    p.p.row.scan_window = scan_window;
    p.p.row.lookahead = lookahead;
    return p;
}

/* A wholly legal fast-params set, every field named. */
static crushlzbitmap_params fast_params(int hash_bits, int windows, int dist_cache_size,
                                        int accept_diff, int skip_shift) {
    crushlzbitmap_params p;
    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_FAST, &p);
    p.p.fast.hash_bits = hash_bits;
    p.p.fast.windows = windows;
    p.p.fast.dist_cache_size = dist_cache_size;
    p.p.fast.accept_diff = accept_diff;
    p.p.fast.skip_shift = skip_shift;
    return p;
}

static crushlzbitmap_params dp_params_bad(int field, int value) {
    crushlzbitmap_params p;
    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_DP, &p);
    switch (field) {
    case 0: p.p.dp.row.hash_bits = value; break;
    case 1: p.p.dp.row.depth = value; break;
    case 2: p.p.dp.row.lookahead = value; break;
    case 3: p.p.dp.row.dist_cache_size = value; break;
    case 4: p.p.dp.iterations = value; break;
    case 5: p.p.dp.max_candidates = value; break;
    default: break;
    }
    return p;
}

int main(void) {
    int all_ok = 1;
    size_t i;

    for (i = 0; i < sizeof(data); i++) {
        int period = 11 + 2 * ((i / 137) % 5); /* cycles 11,13,15,17,19 */
        data[i] = (uint8_t)((i % period) * 7 + (i / 400));
    }

    crushlzbitmap_params p;

    /* 1. every strategy's documented defaults */
    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_ROW, &p);
    all_ok &= roundtrip_with("row defaults", &p);

    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_DP, &p);
    all_ok &= roundtrip_with("dp defaults", &p);

    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_FAST, &p);
    all_ok &= roundtrip_with("fast defaults", &p);

    /* 4. custom row params at the ceilings and the floors */
    p = row_params(14, CRUSHLZBITMAP_MAX_ROW_DEPTH, 8, 8, CRUSHLZBITMAP_MAX_ROW_SCAN, 1);
    all_ok &= roundtrip_with("row at ceilings", &p);
    p = row_params(CRUSHLZBITMAP_MIN_ROW_HASH_BITS, 1, 0, 0, 0, 0);
    all_ok &= roundtrip_with("row at floors", &p);

    /* 4a. custom fast params at the ceilings and the floors, and every
     * window count */
    p = fast_params(CRUSHLZBITMAP_MAX_FAST_HASH_BITS, CRUSHLZBITMAP_MAX_FAST_WINDOWS,
                    CRUSHLZBITMAP_MAX_FAST_DIST_CACHE, CRUSHLZBITMAP_MAX_FAST_ACCEPT_DIFF,
                    CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT);
    all_ok &= roundtrip_with("fast at ceilings", &p);
    p = fast_params(CRUSHLZBITMAP_MIN_FAST_HASH_BITS, 1, 0, 0, 0);
    all_ok &= roundtrip_with("fast at floors", &p);
    {
        int windows;
        for (windows = 1; windows <= CRUSHLZBITMAP_MAX_FAST_WINDOWS; windows *= 2) {
            char label[64];
            snprintf(label, sizeof(label), "fast windows=%d", windows);
            p = fast_params(14, windows, 1, 1, 2);
            all_ok &= roundtrip_with(label, &p);
        }
    }

    /* 4b. every legal depth, both wave flavours, a few scan windows */
    {
        int depth, scan, la;
        for (depth = 1; depth <= CRUSHLZBITMAP_MAX_ROW_DEPTH; depth *= 2) {
            for (la = 0; la <= 1; la++) {
                for (scan = 0; scan <= (la ? 64 : 32); scan += 16) {
                    char label[64];
                    snprintf(label, sizeof(label), "row depth=%d la=%d scan=%d", depth, la, scan);
                    p = row_params(14, depth, la ? 8 : 4, 1, scan, la);
                    all_ok &= roundtrip_with(label, &p);
                }
            }
        }
    }

    /* 4e. every numbered level round-trips, and the greedy levels (-5 to 6)
     * form a ladder: output may not grow by more than 1% from one level to
     * the next and the endpoints must differ. The slack is for the greedy
     * levels, whose ordering is a corpus average: a wider search makes
     * different locally-equal choices, and on this one fixture level 0's
     * two-way buckets lose half a percent to level -1's one-way. Levels 7
     * and up are a different algorithm, so they only have to round-trip. */
    {
        size_t prev = (size_t)-1, first = 0, last = 0;
        int level;

        for (level = CRUSHLZBITMAP_LEVEL_MIN; level <= 6; level++) {
            char label[64];
            size_t sz;
            snprintf(label, sizeof(label), "level %d", level);
            if (crushlzbitmap_params_for_level(level, &p) != level) { printf("%-30s LEVEL FAILED\n", label); all_ok = 0; continue; }
            all_ok &= roundtrip_with(label, &p);
            sz = compressed_size(&p);
            printf("%-30s out=%-8zu %s\n", "  within 1% of previous", sz,
                   sz <= prev + prev / 100 ? "OK" : "*** NOT ORDERED ***");
            all_ok &= (sz <= prev + prev / 100);
            prev = sz;
            if (level == CRUSHLZBITMAP_LEVEL_MIN) first = sz;
            last = sz;
        }
        printf("%-30s %zu vs %zu %s\n", "ladder endpoints differ", first, last,
               last < first ? "OK" : "*** DEGENERATE ***");
        all_ok &= (last < first);

        for (level = 7; level <= CRUSHLZBITMAP_LEVEL_MAX; level++) {
            char label[64];
            snprintf(label, sizeof(label), "level %d (DP tier)", level);
            if (crushlzbitmap_params_for_level(level, &p) != level) { printf("%-30s LEVEL FAILED\n", label); all_ok = 0; continue; }
            all_ok &= roundtrip_with(label, &p);
        }

        /* The top of the ladder searches at least as hard as the level
         * below it. */
        {
            crushlzbitmap_params top, below;
            crushlzbitmap_params_for_level(CRUSHLZBITMAP_LEVEL_MAX, &top);
            crushlzbitmap_params_for_level(CRUSHLZBITMAP_LEVEL_MAX - 1, &below);
            printf("%-30s %s\n", "max level searches hardest",
                   top.p.beam.max_candidates >= below.p.beam.max_candidates &&
                   top.p.beam.beam_width >= below.p.beam.beam_width
                       ? "OK" : "*** DRIFTED ***");
            all_ok &= top.p.beam.max_candidates >= below.p.beam.max_candidates &&
                      top.p.beam.beam_width >= below.p.beam.beam_width;
        }

        {
            crushlzbitmap_params lo, hi, mn, mx;
            int lo_ok, hi_ok;

            crushlzbitmap_params_for_level(-1000000, &lo);
            crushlzbitmap_params_for_level(CRUSHLZBITMAP_LEVEL_MIN, &mn);
            crushlzbitmap_params_for_level(1000000, &hi);
            crushlzbitmap_params_for_level(CRUSHLZBITMAP_LEVEL_MAX, &mx);
            lo_ok = !memcmp(&lo, &mn, sizeof(lo));
            hi_ok = !memcmp(&hi, &mx, sizeof(hi));
            printf("%-30s %s\n",
                   "out-of-range levels clamp", (lo_ok && hi_ok) ? "OK" : "*** WRONG ***");
            all_ok &= (lo_ok && hi_ok);
            printf("%-30s %s\n", "NULL params rejected",
                   crushlzbitmap_params_for_level(0, NULL) == CRUSHLZBITMAP_LEVEL_INVALID
                       ? "OK" : "*** WRONG ***");
            all_ok &= (crushlzbitmap_params_for_level(0, NULL) == CRUSHLZBITMAP_LEVEL_INVALID);
            {
                /* The clamped level comes back, so a caller can see what it got. */
                int got_lo = crushlzbitmap_params_for_level(-1000000, &lo);
                int got_hi = crushlzbitmap_params_for_level(1000000, &hi);
                int ok = got_lo == CRUSHLZBITMAP_LEVEL_MIN && got_hi == CRUSHLZBITMAP_LEVEL_MAX;
                printf("%-30s %s\n", "clamped level is returned", ok ? "OK" : "*** WRONG ***");
                all_ok &= ok;
            }
            printf("%-30s %s\n", "unknown strategy rejected",
                   crushlzbitmap_default_params(99, &lo) == CRUSHLZBITMAP_INVALID ? "OK" : "*** WRONG ***");
            all_ok &= (crushlzbitmap_default_params(99, &lo) == CRUSHLZBITMAP_INVALID);
        }
    }

    /* 5. validation: out-of-range fields must be rejected, not clamped. Each
     * case varies exactly one field; the final all-legal case must be
     * accepted. */
    {
        struct { const char *label; crushlzbitmap_params p; int expect_err; } bad[] = {
            {"dp iterations=0",      dp_params_bad(4, 0), 1},
            {"dp iterations>MAX",    dp_params_bad(4, CRUSHLZBITMAP_MAX_ITERATIONS+1), 1},
            {"dp hash_bits<MIN",     dp_params_bad(0, CRUSHLZBITMAP_MIN_ROW_HASH_BITS-1), 1},
            {"dp depth=3",           dp_params_bad(1, 3), 1},
            {"dp lookahead=0",       dp_params_bad(2, 0), 1},
            {"dp dist_cache<0",      dp_params_bad(3, -1), 1},
            {"dp max_cands=0",       dp_params_bad(5, 0), 1},
            {"dp max_cands>MAX",     dp_params_bad(5, CRUSHLZBITMAP_MAX_DP_CANDS+1), 1},
            {"row hash_bits<MIN",    row_params(CRUSHLZBITMAP_MIN_ROW_HASH_BITS-1, 2, 4, 1, 0, 0), 1},
            {"row hash_bits>MAX",    row_params(CRUSHLZBITMAP_MAX_ROW_HASH_BITS+1, 2, 4, 1, 0, 0), 1},
            {"row depth=0",          row_params(16, 0, 4, 1, 0, 0), 1},
            {"row depth=3",          row_params(16, 3, 4, 1, 0, 0), 1},
            {"row depth>MAX",        row_params(16, CRUSHLZBITMAP_MAX_ROW_DEPTH+1, 4, 1, 0, 0), 1},
            {"row table too big",    row_params(16, 8, 4, 1, 0, 0), 1},
            {"row dist_cache<0",     row_params(16, 2, -1, 1, 0, 0), 1},
            {"row dist_cache>8",     row_params(16, 2, 9, 1, 0, 0), 1},
            {"row accept_diff<0",    row_params(16, 2, 4, -1, 0, 0), 1},
            {"row accept_diff>8",    row_params(16, 2, 4, 9, 0, 0), 1},
            {"row scan not 16-step", row_params(16, 2, 4, 1, 8, 0), 1},
            {"row scan>MAX",         row_params(16, 2, 4, 1, CRUSHLZBITMAP_MAX_ROW_SCAN+16, 0), 1},
            {"row lookahead=2",      row_params(16, 2, 4, 1, 0, 2), 1},
            {"row deep ring, plain", row_params(16, 2, 8, 1, 0, 0), 1},
            {"row wide scan, plain", row_params(16, 2, 4, 1, 64, 0), 1},
            {"all row fields legal", row_params(16, 2, 4, 1, 16, 1), 0},
            {"fast hash_bits<MIN",   fast_params(CRUSHLZBITMAP_MIN_FAST_HASH_BITS-1, 4, 2, 2, 4), 1},
            {"fast hash_bits>MAX",   fast_params(CRUSHLZBITMAP_MAX_FAST_HASH_BITS+1, 4, 2, 2, 4), 1},
            {"fast windows=0",       fast_params(16, 0, 2, 2, 4), 1},
            {"fast windows=3",       fast_params(16, 3, 2, 2, 4), 1},
            {"fast windows>MAX",     fast_params(16, CRUSHLZBITMAP_MAX_FAST_WINDOWS*2, 2, 2, 4), 1},
            {"fast dist_cache<0",    fast_params(16, 4, -1, 2, 4), 1},
            {"fast dist_cache>MAX",  fast_params(16, 4, CRUSHLZBITMAP_MAX_FAST_DIST_CACHE+1, 2, 4), 1},
            {"fast accept_diff<0",   fast_params(16, 4, 2, -1, 4), 1},
            {"fast accept_diff=8",   fast_params(16, 4, 2, 8, 4), 1},
            {"fast skip_shift<0",    fast_params(16, 4, 2, 2, -1), 1},
            {"fast skip_shift>MAX",  fast_params(16, 4, 2, 2, CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT+1), 1},
            {"all fast fields legal", fast_params(12, 2, 1, 3, 2), 0},
            {"bad strategy",         dp_params_bad(-1, 0), 1},
        };
        bad[sizeof(bad)/sizeof(bad[0]) - 1].p.strategy = 99;

        for (i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
            uint8_t *dst = malloc(4096);
            size_t out_len = crushlzbitmap_encode_buffer_advanced(dst, 4096, data, 100, NULL, 0, &bad[i].p);
            int got_err = (out_len == 0);
            printf("validate %-22s out=%-4zu %s\n", bad[i].label, out_len,
                   got_err == bad[i].expect_err ? "OK" : "*** WRONG ***");
            all_ok &= (got_err == bad[i].expect_err);
            free(dst);
        }
    }

    /* Beam width controls both scratch carving and parent indices. Exercise
     * every legal width and reject malformed widths before scratch is sized. */
    for(int width = 1; width <= CRUSHLZBITMAP_MAX_BEAM_WIDTH; width *= 2) {
        crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_BEAM, &p);
        p.p.beam.beam_width = width;
        all_ok &= roundtrip_with("beam width", &p);
    }
    {
        int widths[] = {0, -1, 3, 63, 65, INT_MAX};
        uint8_t dst[4096];
        for(unsigned i = 0; i < sizeof(widths) / sizeof(*widths); ++i) {
            crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_BEAM, &p);
            p.p.beam.beam_width = widths[i];
            all_ok &= crushlzbitmap_scratch_size(&p) == 0;
            all_ok &= crushlzbitmap_encode_buffer_advanced(dst, sizeof(dst), data, 100, NULL, 0, &p) == 0;
        }
        for(int field = 0; field < 3; ++field) {
            crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_BEAM, &p);
            if(field == 0) p.p.beam.max_candidates = 0;
            if(field == 1) p.p.beam.max_candidates = CRUSHLZBITMAP_MAX_DP_CANDS + 1;
            if(field == 2) p.p.beam.row.lookahead = 0;
            all_ok &= crushlzbitmap_scratch_size(&p) == 0;
            all_ok &= crushlzbitmap_encode_buffer_advanced(dst, sizeof(dst), data, 100, NULL, 0, &p) == 0;
        }
    }

    /* 6. encode_chunk with custom params, and with a caller scratch */
    {
        uint8_t dest[CRUSHLZBITMAP_MAX_CHUNK_SIZE];
        size_t scratch_bytes;
        void *scratch;
        size_t out_len;
        p = row_params(16, 4, 4, 1, 32, 1);
        scratch_bytes = crushlzbitmap_scratch_size(&p);
        scratch = calloc(1, scratch_bytes);
        out_len = crushlzbitmap_encode_chunk(dest, sizeof(dest), data, sizeof(data), 0, scratch, scratch_bytes, &p);
        printf("encode_chunk row      out=%zu %s\n", out_len, out_len ? "OK" : "*** FAIL ***");
        all_ok &= (out_len != 0);
        free(scratch);

        p = fast_params(14, 4, 2, 2, 4);
        scratch_bytes = crushlzbitmap_scratch_size(&p);
        scratch = calloc(1, scratch_bytes);
        out_len = crushlzbitmap_encode_chunk(dest, sizeof(dest), data, sizeof(data), 1, scratch, scratch_bytes, &p);
        printf("encode_chunk fast     out=%zu %s\n", out_len, out_len ? "OK" : "*** FAIL ***");
        all_ok &= (out_len != 0);
        free(scratch);
    }

    printf("\n%s\n", all_ok ? "ALL ADVANCED-API CHECKS PASSED" : "*** FAILURE ***");
    return all_ok ? 0 : 1;
}
