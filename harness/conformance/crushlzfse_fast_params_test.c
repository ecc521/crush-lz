// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// CRUSHLZFSE_STRATEGY_FAST through crushlzfse_encode_buffer_advanced:
//
//   1. The levels that use it resolve to params inside the reported ranges.
//   2. Every field outside its range is rejected, not clamped, and so is a
//      min_match above 6 with long_table or lazy set.
//   3. Every hashed length, table mode and stride extreme round-trips over
//      inputs shaped to reach the paths a corpus rarely does: the per-block
//      match and literal caps, matches past the largest M, literal runs past
//      the run bound, and inputs shorter than the matcher's end margin.
//   4. Output does not depend on what the scratch held before, and the
//      scratch the API asks for is exactly enough.
#include "crushlzfse.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond, ...)                                    \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);     \
            printf(__VA_ARGS__);                            \
            printf("\n");                                   \
            failures++;                                     \
        }                                                   \
    } while (0)

static uint32_t rng = 0x9E3779B9u;
static uint32_t next(void) {
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
    return rng;
}

enum { N_INPUTS = 6, MAX = 65536 };
static uint8_t inputs[N_INPUTS][MAX];
static size_t input_len[N_INPUTS];
static const char *input_name[N_INPUTS];

static void make_inputs(void) {
    // Text-like: words from a small vocabulary.
    static const char *words[] = {"the ", "lazy ", "dog ", "jumps ", "over ", "quick ", "brown ",
                                  "fox ", "and ", "then ", "again, ", "repeatedly. "};
    size_t n = 0;
    while (n < MAX) {
        const char *w = words[next() % 12];
        while (*w && n < MAX) inputs[0][n++] = (uint8_t)*w++;
    }
    input_len[0] = MAX; input_name[0] = "words";

    // Short matches as densely as possible: more tuples than a block holds.
    for (size_t i = 0; i < MAX; i++) inputs[1][i] = (i % 4 == 2) ? (uint8_t)next() : (uint8_t)"abca"[i % 4];
    input_len[1] = MAX; input_name[1] = "short-match spam";

    // A 9000-byte random run repeated: matches far past the largest M.
    for (size_t i = 0; i < 9000; i++) inputs[2][i] = (uint8_t)next();
    for (size_t i = 9000; i < MAX; i++) inputs[2][i] = inputs[2][i - 9000];
    input_len[2] = MAX; input_name[2] = "long matches";

    // Random runs well past the literal-run bound, between repeats.
    for (size_t i = 0; i < MAX; i++)
        inputs[3][i] = (i % 12000 < 9000) ? (uint8_t)next() : inputs[3][i - 9000 + (i % 7)];
    input_len[3] = MAX; input_name[3] = "long literal runs";

    // Incompressible.
    for (size_t i = 0; i < MAX; i++) inputs[4][i] = (uint8_t)next();
    input_len[4] = MAX; input_name[4] = "random";

    // One repeated byte, and a period that changes partway.
    for (size_t i = 0; i < MAX; i++) inputs[5][i] = (uint8_t)(i < 30000 ? 'x' : "0123456789"[i % 10]);
    input_len[5] = MAX; input_name[5] = "runs";
}

static int roundtrip(const crushlzfse_encode_params *p, const uint8_t *src, size_t n,
                     void *scratch, size_t scratch_size, uint8_t *dst, size_t dst_cap, size_t *out) {
    uint8_t *back = malloc(n ? n : 1);
    size_t enc = crushlzfse_encode_buffer_advanced(dst, dst_cap, src, n, scratch, scratch_size, p);
    *out = enc;
    int ok = 0;
    if (enc != 0) {
        size_t got = 0;
        ok = crushlzfse_decode_buffer(back, n, dst, enc, &got) == 0 && got == n &&
             (n == 0 || memcmp(back, src, n) == 0);
    } else {
        ok = n == 0; // an empty input may encode to nothing
    }
    free(back);
    return ok;
}

int main(void) {
    crushlzfse_capabilities c = crushlzfse_get_capabilities();
    CHECK(c.level_min == CRUSHLZFSE_LEVEL_MIN, "level_min %d", c.level_min);
    CHECK(c.fast_long_table_min == 0 && c.fast_long_table_max == 1, "long_table range");
    CHECK(c.fast_lazy_min == 0 && c.fast_lazy_max == 1, "lazy range");

    // 1. The level table.
    int fast_levels = 0;
    for (int level = CRUSHLZFSE_LEVEL_MIN; level <= CRUSHLZFSE_LEVEL_MAX; level++) {
        crushlzfse_encode_params p;
        crushlzfse_params_for_level(level, &p);
        if (p.strategy != CRUSHLZFSE_STRATEGY_FAST) continue;
        fast_levels++;
        CHECK(level < CRUSHLZFSE_LEVEL_DEFAULT, "level %d is fast at or above the default", level);
        CHECK(p.p.fast.hash_bits >= c.fast_hash_bits_min && p.p.fast.hash_bits <= c.fast_hash_bits_max, "level %d hash_bits", level);
        CHECK(p.p.fast.min_match >= c.fast_min_match_min && p.p.fast.min_match <= c.fast_min_match_max, "level %d min_match", level);
        CHECK(p.p.fast.skip_shift >= c.fast_skip_shift_min && p.p.fast.skip_shift <= c.fast_skip_shift_max, "level %d skip_shift", level);
        CHECK(p.p.fast.max_step >= c.fast_max_step_min && p.p.fast.max_step <= c.fast_max_step_max, "level %d max_step", level);
    }
    CHECK(fast_levels == 5, "%d fast levels, expected -5 to -1", fast_levels);

    make_inputs();
    size_t dst_cap = MAX + 4096;
    uint8_t *dst = malloc(dst_cap), *dst2 = malloc(dst_cap);

    // 2. Rejection, field by field.
    crushlzfse_encode_params base;
    crushlzfse_params_for_level(CRUSHLZFSE_LEVEL_MIN, &base);
    struct { int *field; int bad; } bad[] = {
        {&base.p.fast.hash_bits, c.fast_hash_bits_min - 1}, {&base.p.fast.hash_bits, c.fast_hash_bits_max + 1},
        {&base.p.fast.min_match, c.fast_min_match_min - 1}, {&base.p.fast.min_match, c.fast_min_match_max + 1},
        {&base.p.fast.skip_shift, c.fast_skip_shift_min - 1}, {&base.p.fast.skip_shift, c.fast_skip_shift_max + 1},
        {&base.p.fast.max_step, c.fast_max_step_min - 1}, {&base.p.fast.max_step, c.fast_max_step_max + 1},
        {&base.p.fast.long_table, -1}, {&base.p.fast.long_table, 2},
        {&base.p.fast.lazy, -1}, {&base.p.fast.lazy, 2},
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        int keep = *bad[i].field;
        *bad[i].field = bad[i].bad;
        size_t got = crushlzfse_encode_buffer_advanced(dst, dst_cap, inputs[0], 1000, NULL, 0, &base);
        CHECK(got == 0, "out-of-range field %zu (value %d) was accepted", i, bad[i].bad);
        *bad[i].field = keep;
    }
    for (int mm = 7; mm <= c.fast_min_match_max; mm++)
    for (int mode = 1; mode <= 3; mode++) {
        crushlzfse_encode_params p = base;
        p.p.fast.min_match = mm;
        p.p.fast.long_table = mode & 1;
        p.p.fast.lazy = mode >> 1;
        size_t got = crushlzfse_encode_buffer_advanced(dst, dst_cap, inputs[0], 1000, NULL, 0, &p);
        CHECK(got == 0, "min_match %d with long_table=%d lazy=%d was accepted", mm, mode & 1, mode >> 1);
    }

    // 3 and 4. Every mode over every input, twice: on a scratch of exactly
    // the reported size filled with 0x00, and again filled with garbage.
    static const size_t short_sizes[] = {0, 1, 7, 8, 15, 16, 17, 23, 24, 25, 40, 1000};
    long cases = 0;
    for (int mm = c.fast_min_match_min; mm <= c.fast_min_match_max; mm++)
    for (int long_table = 0; long_table <= 1; long_table++)
    for (int lazy = 0; lazy <= 1; lazy++)
    for (int hb = c.fast_hash_bits_min; hb <= c.fast_hash_bits_max; hb += c.fast_hash_bits_max - c.fast_hash_bits_min)
    for (int stride = 0; stride <= 1; stride++) {
        if ((long_table || lazy) && mm > 6) continue; // rejected, checked above
        crushlzfse_encode_params p = base;
        p.p.fast.hash_bits = hb;
        p.p.fast.min_match = mm;
        p.p.fast.long_table = long_table;
        p.p.fast.lazy = lazy;
        p.p.fast.skip_shift = stride ? c.fast_skip_shift_min : c.fast_skip_shift_max;
        p.p.fast.max_step = stride ? c.fast_max_step_max : c.fast_max_step_min;
        size_t scratch_size = crushlzfse_scratch_size(&p);
        uint8_t *scratch = malloc(scratch_size + 1);
        for (int k = 0; k < N_INPUTS + (int)(sizeof short_sizes / sizeof short_sizes[0]); k++) {
            const uint8_t *src = k < N_INPUTS ? inputs[k] : inputs[0];
            size_t n = k < N_INPUTS ? input_len[k] : short_sizes[k - N_INPUTS];
            const char *name = k < N_INPUTS ? input_name[k] : "short";
            size_t a = 0, b = 0;
            memset(scratch, 0x00, scratch_size + 1);
            int ok = roundtrip(&p, src, n, scratch, scratch_size, dst, dst_cap, &a);
            CHECK(ok, "mm=%d long=%d lazy=%d hb=%d stride=%d %s n=%zu: round trip", mm, long_table, lazy, hb, stride, name, n);
            CHECK(n == 0 || a <= n + 12 + 4, "mm=%d %s: %zu bytes from %zu, over the stored bound", mm, name, a, n);
            for (size_t i = 0; i < scratch_size; i++) scratch[i] = (uint8_t)next();
            scratch[scratch_size] = 0xA5;
            roundtrip(&p, src, n, scratch, scratch_size, dst2, dst_cap, &b);
            CHECK(a == b && memcmp(dst, dst2, a) == 0,
                  "mm=%d long=%d lazy=%d %s n=%zu: output depends on prior scratch contents", mm, long_table, lazy, name, n);
            CHECK(scratch[scratch_size] == 0xA5, "wrote past the reported scratch size");
            cases++;
        }
        CHECK(crushlzfse_encode_buffer_advanced(dst, dst_cap, inputs[0], 1000, scratch, scratch_size - 1, &p) == 0,
              "an undersized scratch was accepted");
        free(scratch);
    }

    free(dst); free(dst2);
    printf("%ld fast-strategy cases, %d failures\n", cases, failures);
    return failures ? 1 : 0;
}
