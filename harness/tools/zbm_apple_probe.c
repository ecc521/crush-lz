// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Localises an LZBITMAP disagreement with Apple's decoder: which levels,
 * which strides, and the byte offset at which each stream first diverges.
 * The per-level sweep works on the file's first 64 KiB; each whole file is
 * also run through both encoders and both decoders. macOS only.
 *
 *   zbm_apple_probe <file> [file...]
 *
 * Exit status is the number of (file, level) pairs Apple rejected, capped at
 * 125, so it is usable as a `git bisect run` script.
 */
#include <compression.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzbitmap.h"

#define BLOCK 65536

static uint8_t src[BLOCK], dst[BLOCK * 6], back[BLOCK * 3];

/* First offset at which two buffers differ, or -1. */
static long first_diff(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (a[i] != b[i]) return (long)i;
    return -1;
}

/* Compress with `params`, then report whether our decoder and Apple's agree.
 * Returns 1 if Apple disagreed. */
static int check(const crushlzbitmap_params *params, size_t len,
                 size_t *out_size, long *out_diff, int *ours_ok) {
    size_t out = 0;
    *out_size = 0;
    *out_diff = -1;
    *ours_ok = 0;

    out = crushlzbitmap_encode_buffer_advanced(dst, sizeof dst, src, len, NULL, 0, params);
    if (out == 0)
        return 0;
    *out_size = out;

    size_t got = 0;
    *ours_ok = (crushlzbitmap_decode_buffer(back, sizeof back, dst, out, &got) == 0 &&
                got == len && memcmp(back, src, len) == 0);

    memset(back, 0, len);
    size_t alen = compression_decode_buffer(back, sizeof back, dst, out, NULL,
                                            COMPRESSION_LZBITMAP);
    if (alen == len) {
        *out_diff = first_diff(back, src, len);
        if (*out_diff < 0) return 0;
    }
    return 1;
}

static int probe_levels(const char *path, size_t len) {
    crushlzbitmap_params p;
    int bad = 0;

    printf("  %-6s %-6s %-9s %-9s %s\n", "LEVEL", "TIER", "OUT", "APPLE", "FIRST DIFF");
    for (int level = CRUSHLZBITMAP_LEVEL_MIN; level <= CRUSHLZBITMAP_LEVEL_MAX; level++) {
        if (crushlzbitmap_params_for_level(level, &p) != 0) continue;
        size_t out; long diff; int ours_ok;
        int failed = check(&p, len, &out, &diff, &ours_ok);
        bad += failed;
        printf("  %-6d %-6s %-9zu %-9s ", level,
               p.strategy == CRUSHLZBITMAP_STRATEGY_DP ? "dp" : "row", out,
               failed ? "MISMATCH" : "ok");
        if (failed && diff >= 0) printf("@%ld", diff);
        else if (failed) printf("(length differed)");
        if (!ours_ok) printf("   [our own decoder also failed]");
        printf("\n");
    }
    (void)path;
    return bad;
}

/* The whole file, both directions: our default level through Apple's decoder,
 * and Apple's encoder through ours. Returns the number of failures. */
static int probe_whole_file(const char *path, FILE *f) {
    long size;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET) != 0) return 0;
    size_t n = (size_t)size, bound = crushlzbitmap_encode_bound(n), got = 0;
    uint8_t *whole = malloc(n), *enc = malloc(bound), *dec = malloc(n);
    int bad = 0;
    if (!whole || !enc || !dec || fread(whole, 1, n, f) != n) { bad = 0; goto out; }

    size_t elen = crushlzbitmap_encode_buffer(enc, bound, whole, n, NULL, 0, CRUSHLZBITMAP_LEVEL_DEFAULT);
    if (!elen || compression_decode_buffer(dec, n, enc, elen, NULL, COMPRESSION_LZBITMAP) != n ||
        memcmp(dec, whole, n) != 0) {
        printf("  whole file: Apple could not read our stream (%zu bytes)\n", elen);
        bad++;
    }
    elen = compression_encode_buffer(enc, bound, whole, n, NULL, COMPRESSION_LZBITMAP);
    if (!elen || crushlzbitmap_decode_buffer(dec, n, enc, elen, &got) != 0 || got != n ||
        memcmp(dec, whole, n) != 0) {
        printf("  whole file: we could not read Apple's stream (%zu bytes, decoded %zu)\n", elen, got);
        bad++;
    }
    if (bad) printf("%s: %zu bytes, whole-file round trip failed\n", path, n);
out:
    free(whole); free(enc); free(dec);
    return bad;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file> [file...]\n", argv[0]);
        return 1;
    }

    int total_bad = 0, files = 0, files_bad = 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); continue; }
        size_t len = fread(src, 1, BLOCK, f);
        int bad = len ? probe_whole_file(argv[i], f) : 0;
        fclose(f);
        if (!len) continue;
        files++;

        bad += probe_levels(argv[i], len);
        if (bad) {
            files_bad++;
            printf("\n%s (%zu bytes): %d level(s) Apple could not read\n",
                   argv[i], len, bad);
        }
        total_bad += bad;
        if (argc > 2) printf("\r");
    }

    printf("\n%d files, %d with at least one failing level, %d failing "
           "(file, level) pairs total\n", files, files_bad, total_bad);
    return total_bad > 125 ? 125 : total_bad;
}
