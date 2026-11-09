// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Round-trips the LZBITMAP encoder on the shapes the committed fixtures do
 * not cover: partial and tiny inputs, empty input, highly repetitive data
 * (run lengths straddling multiples of 15), incompressible data, sizes
 * at and across the 0x8000 chunk boundary, and short-period content with a
 * literal cadence over it. Every case runs through the default level, the
 * fast level and the top DP level, which share almost no decide-side code.
 */
#include "crushlzbitmap.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_with(const char *label, const char *tier, int level,
                      const uint8_t *data, size_t len)
{
    size_t max_out = crushlzbitmap_encode_bound(len), out_size, decmp_len = 0;
    uint8_t *dst = malloc(max_out), *back;
    int err;

    out_size = crushlzbitmap_encode_buffer(dst, max_out, data, len, NULL, 0, level);
    if (!out_size) {
        printf("%-40s %-10s len=%-8zu -> COMPRESS FAILED\n", label, tier, len);
        free(dst);
        return 0;
    }

    back = malloc(len ? len : 1);
    err = crushlzbitmap_decode_buffer(back, len, dst, out_size, &decmp_len);
    int ok = !err && decmp_len == len && (len == 0 || memcmp(back, data, len) == 0);
    printf("%-40s %-10s len=%-8zu out=%-8zu %s\n", label, tier, len, out_size, ok ? "OK" : "*** MISMATCH ***");

    free(dst);
    free(back);
    return ok;
}

static int check_one(const char *label, const uint8_t *data, size_t len)
{
    int ok = check_with(label, "default", CRUSHLZBITMAP_LEVEL_DEFAULT, data, len);
    ok &= check_with(label, "fast", CRUSHLZBITMAP_LEVEL_MIN, data, len);
    ok &= check_with(label, "dp", CRUSHLZBITMAP_LEVEL_MAX, data, len);
    return ok;
}

int main(int argc, char **argv)
{
    int all_ok = 1;
    uint8_t *file_data = NULL;
    long fsize = 0;

    if (argc >= 2) {
        FILE *f = fopen(argv[1], "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            fsize = ftell(f);
            fseek(f, 0, SEEK_SET);
            file_data = malloc(fsize);
            if (fread(file_data, 1, fsize, f) != (size_t)fsize) fsize = 0;
            fclose(f);
        }
    }

    /* Partial/short chunks. */
    size_t partial_sizes[] = {0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 63, 64, 65, 100, 1000,
                               4095, 4096, 4097, 32767, 32768, 32769, 65535, 65536, 100000};
    for (size_t i = 0; i < sizeof(partial_sizes) / sizeof(partial_sizes[0]); i++) {
        size_t n = partial_sizes[i];
        uint8_t *buf = malloc(n ? n : 1);
        if (file_data && fsize > 0) {
            for (size_t j = 0; j < n; j++) buf[j] = file_data[j % fsize];
        } else {
            for (size_t j = 0; j < n; j++) buf[j] = (uint8_t)(j * 2654435761u);
        }
        char label[64];
        snprintf(label, sizeof(label), "partial-%zu", n);
        all_ok &= check_one(label, buf, n);
        free(buf);
    }

    /* Highly repetitive: run lengths straddling multiples of 15. */
    uint8_t *rep = malloc(65536);
    memset(rep, 0x41, 65536);
    all_ok &= check_one("65536x same byte", rep, 65536);
    for (size_t n = 0; n < 65536; n++) rep[n] = (uint8_t)(n % 3);
    all_ok &= check_one("period-3 pattern, 65536", rep, 65536);
    for (size_t n = 0; n < 65536; n++) rep[n] = (uint8_t)(n % 8);
    all_ok &= check_one("period-8 pattern, 65536", rep, 65536);
    /* exact run-length boundaries: 3->4 (free), and multiples of 15 (d%15==0) */
    for (int run_target = 1; run_target <= 40; run_target++) {
        size_t n = (size_t)run_target * 8 + 64;
        uint8_t *buf = malloc(n);
        memset(buf, 0x7a, n);
        char label[64];
        snprintf(label, sizeof(label), "run-boundary target=%d", run_target);
        all_ok &= check_one(label, buf, n);
        free(buf);
    }
    free(rep);

    /* Short natural periods with a literal cadence over them, so blocks form
     * one long run with mixed bitmaps: the encoder must hold its output at
     * period 8 and up, and the run fill's bulk path must stay correct when a
     * copy's source is a literal position within the same run. */
    for (int period = 1; period < 8; period++) {
        for (int perturb = 2; perturb <= 11; perturb++) {
            size_t n = 4096;
            uint8_t *buf = malloc(n);
            char label[64];
            for (size_t j = 0; j < n; j++) {
                buf[j] = (uint8_t)(0x40 + (j % (size_t)period));
                if (j % (size_t)perturb == 0)
                    buf[j] = (uint8_t)(0xd0 + (j % 7));
            }
            snprintf(label, sizeof(label), "small-period=%d perturb=%d", period, perturb);
            all_ok &= check_one(label, buf, n);
            free(buf);
        }
    }
    for (int period = 1; period <= 40; period++) {
        if (period % 8 == 0)
            continue;
        for (int perturb = 8; perturb <= 24; perturb += 8) {
            size_t lens[] = {256, 1024, 4096, 20000};
            for (size_t li = 0; li < sizeof(lens)/sizeof(lens[0]); li++) {
                size_t n = lens[li];
                uint8_t *buf = malloc(n);
                char label[80];
                for (size_t j = 0; j < n; j++) {
                    buf[j] = (uint8_t)(0x30 + (j % (size_t)period));
                    if (j % (size_t)perturb == 0)
                        buf[j] = (uint8_t)(0xc0 + (j / perturb) % 5);
                }
                snprintf(label, sizeof(label), "run-mixed p=%d perturb=%d n=%zu", period, perturb, n);
                all_ok &= check_one(label, buf, n);
                free(buf);
            }
        }
    }

    /* Fully random/incompressible. */
    uint8_t *rnd = malloc(65536);
    uint32_t x = 0x2545F491;
    for (int i = 0; i < 65536; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        rnd[i] = (uint8_t)(x & 0xff);
    }
    all_ok &= check_one("65536 random bytes", rnd, 65536);
    free(rnd);

    /* Multi-chunk sizes around the 0x8000 boundary. */
    if (file_data && fsize > 0) {
        size_t multi_sizes[] = {0x8000, 0x8000 - 1, 0x8000 + 1, 0x10000, 0x10000 + 100, 3 * 0x8000 - 7};
        for (size_t i = 0; i < sizeof(multi_sizes) / sizeof(multi_sizes[0]); i++) {
            size_t n = multi_sizes[i];
            uint8_t *buf = malloc(n);
            for (size_t j = 0; j < n; j++) buf[j] = file_data[j % fsize];
            char label[64];
            snprintf(label, sizeof(label), "multi-chunk-%zu", n);
            all_ok &= check_one(label, buf, n);
            free(buf);
        }
        /* mid-file slices, not chunk-aligned */
        if (fsize > 200000) {
            all_ok &= check_one("mid-file 37-byte slice", (const uint8_t *)file_data + 150000, 37);
            all_ok &= check_one("mid-file 5000-byte slice", (const uint8_t *)file_data + 150000, 5000);
        }
    }

    /* The lowest greedy level at the sizes where cross-chunk reach matters. */
    {
        size_t sizes[] = {0, 1, 7, 8, 9, 4096, 0x8000 - 1, 0x8000, 0x8000 + 1, 0x10000 + 100};
        size_t i;

        for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            size_t n = sizes[i];
            uint8_t *periodic = malloc(n ? n : 1);
            uint8_t *incompressible = malloc(n ? n : 1);
            uint32_t x = 0x9E3779B9 ^ (uint32_t)n;
            char label[64];
            size_t j;

            for (j = 0; j < n; j++) periodic[j] = (uint8_t)((j % 13) * 7 + j / 400);
            for (j = 0; j < n; j++) {
                x ^= x << 13; x ^= x >> 17; x ^= x << 5;
                incompressible[j] = (uint8_t)(x & 0xff);
            }

            snprintf(label, sizeof(label), "ladder ends periodic n=%zu", n);
            all_ok &= check_with(label, "greedy-min", -1, periodic, n);

            snprintf(label, sizeof(label), "ladder ends incompr n=%zu", n);
            all_ok &= check_with(label, "greedy-min", -1, incompressible, n);

            free(periodic);
            free(incompressible);
        }
    }

    free(file_data);

    printf("\n%s\n", all_ok ? "ALL EDGE CASES PASSED" : "*** AT LEAST ONE FAILURE ABOVE ***");
    return all_ok ? 0 : 1;
}
