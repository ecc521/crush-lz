// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Differential SIMD test: libzbitmap.c built for the host's vector fast path
 * against the same source built with CRUSH_SIMD_PORTABLE (crush_simd.h's
 * scalar, array-backed branch), with every public symbol renamed so both
 * land in one binary. Unlike zbm_decoder_diff_test.c (which only compares
 * decoders), this covers encode too: the row/DP tier depends on
 * crush_simd.h's vector primitives as much as decode's blend does, and a
 * byte-for-byte match on compressed output is a much stronger check than
 * "both decode correctly" -- it means the portable branch's arithmetic
 * reaches the exact same candidate at every tie, not just a valid one.
 *
 * Inputs are the same periodic-plus-perturbation generator as
 * zbm_decoder_diff_test.c, swept over period, cadence, length and level.
 * BUILD_SIMD_DIFF_TEST in harness/Makefile links the two builds together.
 *
 * ZBM_DIFF_LEVELS, a comma-separated list, restricts the sweep; unset means
 * every level.
 */
#include "crushlzbitmap.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The CRUSH_SIMD_PORTABLE build's entry points, renamed at compile time. */
size_t portable_crushlzbitmap_encode_bound(size_t src_size);
size_t portable_crushlzbitmap_encode_buffer(void *dst, size_t dst_size,
                                            const void *src, size_t src_size,
                                            void *scratch, size_t scratch_size, int level);
int portable_crushlzbitmap_decode_buffer(void *dst, size_t dst_size, const void *src, size_t src_size,
                                         size_t *out_len);

static long cases, fails;

static void check(const char *label, int level, const uint8_t *data, size_t len)
{
    size_t vec_max = crushlzbitmap_encode_bound(len);
    size_t port_max = portable_crushlzbitmap_encode_bound(len);
    uint8_t *vec_comp, *port_comp, *vec_dec, *port_dec;
    size_t vec_out, port_out, vec_dlen = 0, port_dlen = 0;
    int vec_derr, port_derr;
    int encode_agree, vec_correct, port_correct;

    vec_comp = malloc(vec_max ? vec_max : 1);
    port_comp = malloc(port_max ? port_max : 1);
    vec_out = crushlzbitmap_encode_buffer(vec_comp, vec_max, data, len, NULL, 0, level);
    port_out = portable_crushlzbitmap_encode_buffer(port_comp, port_max, data, len, NULL, 0, level);

    cases++;
    if (!vec_out || !port_out) {
        /* Either both refuse (fine, e.g. a level/size combination the
         * format rejects) or they disagree on refusing, which is itself a
         * bug worth reporting. */
        if ((!vec_out) != (!port_out)) {
            if (++fails <= 10)
                printf("  level %-2d %-28s len=%-6zu ENCODE-REFUSAL-DISAGREES "
                       "vec=%zu portable=%zu\n", level, label, len, vec_out, port_out);
        }
        free(vec_comp); free(port_comp);
        return;
    }

    encode_agree = (vec_out == port_out) && !memcmp(vec_comp, port_comp, vec_out);
    if (!encode_agree) {
        size_t at = 0, n = vec_out < port_out ? vec_out : port_out;
        while (at < n && vec_comp[at] == port_comp[at]) at++;
        if (++fails <= 10)
            printf("  level %-2d %-28s len=%-6zu ENCODE-DIFFERS vec=%zu portable=%zu "
                   "first diff @%zu\n", level, label, len, vec_out, port_out, at);
    }

    vec_dec = calloc(len ? len : 1, 1);
    port_dec = calloc(len ? len : 1, 1);
    vec_derr = crushlzbitmap_decode_buffer(vec_dec, len, vec_comp, vec_out, &vec_dlen);
    port_derr = portable_crushlzbitmap_decode_buffer(port_dec, len, port_comp, port_out, &port_dlen);
    vec_correct = !vec_derr && vec_dlen == len && (len == 0 || !memcmp(vec_dec, data, len));
    port_correct = !port_derr && port_dlen == len && (len == 0 || !memcmp(port_dec, data, len));
    cases++;
    if (!vec_correct || !port_correct) {
        if (++fails <= 10)
            printf("  level %-2d %-28s len=%-6zu %s%sWRONG-ROUND-TRIP\n", level, label, len,
                   vec_correct ? "" : "vector-build ", port_correct ? "" : "portable-build ");
    }

    free(vec_comp); free(port_comp); free(vec_dec); free(port_dec);
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
    printf("%s\n", fails ? "*** VECTOR AND PORTABLE BUILDS DIFFER ***"
                         : "ALL VECTOR/PORTABLE PATHS AGREE");
    return fails ? 1 : 0;
}
