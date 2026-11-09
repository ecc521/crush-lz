// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Raw-params sweep driver for CrushLZVN's greedy strategy, mirroring
 * crushlzfse_sweep.c: hands crushlzvn_encode_buffer_advanced() arbitrary
 * hash_bits and hash_width (see crushlzvn.h) and reports saved% and MB/s.
 *
 *   crushlzvn_sweep <manifest> --hash-bits 12 --hash-width 1
 *
 * The manifest is one file path per line, as for bench. Each file is split
 * into --block (default 65536) byte blocks; a short final block is kept.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <compression.h>
#define CRUSHLZVN_SWEEP_HAVE_APPLE 1
/* COMPRESSION_LZVN was dropped from the public enum in recent SDKs, but
 * libcompression still implements it at its long-stable value. */
#ifndef COMPRESSION_LZVN
#define COMPRESSION_LZVN ((compression_algorithm)0x900)
#endif
#endif

#include "crushlzvn.h"

static double now_secs(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <manifest> --hash-bits N --hash-width N\n"
        "           [--block N] [--max-blocks N] [--no-apple]\n"
        "\n"
        "  --hash-bits N   10-16\n"
        "  --hash-width N  1-64\n"
        "  --block N       block size in bytes (default 65536)\n"
        "  --max-blocks N  stop after N blocks, 0 = no limit (default 0)\n"
        "  --no-apple      skip the Apple-decoder oracle check (faster, less safe)\n",
        argv0);
}

int main(int argc, char **argv) {
    const char *manifest_path = NULL;
    size_t block_size = 65536;
    long max_blocks = 0;
    int skip_apple = 0;

    crushlzvn_encode_params params;
    memset(&params, 0, sizeof params);
    /* Start from CRUSHLZVN_LEVEL_MIN's params; flags override fields. */
    crushlzvn_params_for_level(CRUSHLZVN_LEVEL_MIN, &params);
    params.strategy = CRUSHLZVN_STRATEGY_GREEDY;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (fprintf(stderr, "%s needs a value\n", a), exit(1), (char *)0))
        if (!strcmp(a, "--hash-bits")) { params.p.greedy.hash_bits = atoi(NEXT()); }
        else if (!strcmp(a, "--hash-width")) { params.p.greedy.hash_width = atoi(NEXT()); }
        else if (!strcmp(a, "--block")) block_size = (size_t)atol(NEXT());
        else if (!strcmp(a, "--max-blocks")) max_blocks = atol(NEXT());
        else if (!strcmp(a, "--no-apple")) skip_apple = 1;
        else if (a[0] != '-' && !manifest_path) manifest_path = a;
        else { fprintf(stderr, "unrecognized arg %s\n", a); usage(argv[0]); return 1; }
        #undef NEXT
    }

    if (!manifest_path) { usage(argv[0]); return 1; }

    #ifndef CRUSHLZVN_SWEEP_HAVE_APPLE
    skip_apple = 1;
    #endif

    FILE *mf = fopen(manifest_path, "rb");
    if (!mf) { perror(manifest_path); return 1; }

    size_t scratch_bytes = crushlzvn_scratch_size(&params);
    void *scratch = malloc(scratch_bytes);
    if (!scratch) {
        fprintf(stderr, "scratch allocation failed\n");
        return 1;
    }

    uint8_t *raw = malloc(block_size);
    uint8_t *dst = malloc(block_size * 2 + 4096);
    uint8_t *back = malloc(block_size + 4096);
    if (!raw || !dst || !back) { fprintf(stderr, "oom\n"); return 1; }

    long nblocks = 0, ours_failed = 0, apple_failed = 0, refused = 0;
    unsigned long long total_in = 0, total_out = 0;
    double enc_secs = 0;

    char line[4096];
    while (fgets(line, sizeof line, mf)) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = 0;
        if (!len) continue;

        FILE *f = fopen(line, "rb");
        if (!f) { perror(line); continue; }

        size_t got;
        while ((got = fread(raw, 1, block_size, f)) > 0) {
            if (max_blocks && nblocks >= max_blocks) break;

            size_t out = 0;
            double t0 = now_secs();
            out = crushlzvn_encode_buffer_advanced(dst, block_size * 2 + 4096, raw, got, scratch, scratch_bytes, &params);
            enc_secs += now_secs() - t0;

            if (out == 0) { refused++; nblocks++; continue; }

            size_t back_got = 0;
            int ours_ok = (crushlzvn_decode_buffer(back, block_size + 4096, dst, out, &back_got) == 0 &&
                           back_got == got && memcmp(back, raw, got) == 0);
            if (!ours_ok) ours_failed++;

            if (!skip_apple) {
                #ifdef CRUSHLZVN_SWEEP_HAVE_APPLE
                memset(back, 0, got);
                size_t alen = compression_decode_buffer(back, block_size + 4096, dst, out, NULL, COMPRESSION_LZVN);
                if (alen != got || memcmp(back, raw, got) != 0) apple_failed++;
                #endif
            }

            total_in += got;
            total_out += out;
            nblocks++;
        }
        fclose(f);
        if (max_blocks && nblocks >= max_blocks) break;
    }
    fclose(mf);

    if (!nblocks) { fprintf(stderr, "no blocks read\n"); return 1; }

    double ratio = total_out ? (double)total_in / (double)total_out : 0;
    double saved_pct = total_in ? 100.0 * (1.0 - (double)total_out / (double)total_in) : 0;
    double mb_s = enc_secs > 0 ? ((double)total_in / (1024.0 * 1024.0)) / enc_secs : 0;

    printf("hash_bits=%d hash_width=%d\n", params.p.greedy.hash_bits, params.p.greedy.hash_width);
    printf("blocks: %ld   refused: %ld   our-decoder-failed: %ld   apple-failed: %ld%s\n",
           nblocks, refused, ours_failed, apple_failed, skip_apple ? " (skipped)" : "");
    printf("ratio: %.4f   saved: %.2f%%   enc MB/s: %.2f\n", ratio, saved_pct, mb_s);

    return (ours_failed || apple_failed) ? 2 : 0;
}
