// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Raw-params sweep driver for CrushLZFSE: hands
 * crushlzfse_encode_buffer_advanced() arbitrary params (see crushlzfse.h),
 * round-trips every block (through Apple's decoder too on macOS), and
 * reports saved% and encode MB/s.
 *
 *   crushlzfse_sweep <manifest> --hash-bits 14 --hash-width 8 --lookahead 1
 *   crushlzfse_sweep <manifest> --fast --hash-bits 13 --min-match 6 --max-step 12
 *   crushlzfse_sweep <manifest> --level 11 --table-search 2
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
#define CRUSHLZFSE_SWEEP_HAVE_APPLE 1
#endif

#include "crushlzfse.h"

static double now_secs(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <manifest> --hash-bits N --hash-width N --lookahead N\n"
        "       %s <manifest> --fast [--hash-bits N] [--min-match N] [--skip-shift N]\n"
        "           [--max-step N] [--long-table 0|1] [--lazy 0|1]\n"
        "       %s <manifest> --level N [--table-search N]\n"
        "           [--block N] [--max-blocks N] [--no-apple]\n"
        "\n"
        "  --hash-bits N   10-16\n"
        "  --hash-width N  1-64\n"
        "  --lookahead N   0-2\n"
        "  --fast          the fast strategy, starting from the lowest level's settings\n"
        "  --min-match N   4-8 (4-6 with a long table or lazy), bytes the fast strategy hashes\n"
        "  --skip-shift N  1-31\n"
        "  --max-step N    1-64\n"
        "  --level N       start from level N's params (any strategy)\n"
        "  --table-search N  optimal levels: table search passes\n"
        "  --block N       block size in bytes (default 65536)\n"
        "  --max-blocks N  stop after N blocks, 0 = no limit (default 0)\n"
        "  --no-apple      skip the Apple-decoder oracle check (faster, less safe)\n",
        argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    const char *manifest_path = NULL;
    size_t block_size = 65536;
    long max_blocks = 0;
    int skip_apple = 0;

    crushlzfse_encode_params params;
    memset(&params, 0, sizeof params);
    /* Starts from --level's params (the default level's if absent), --fast
     * from the lowest level's; flags override fields. */
    int fast = 0, level = CRUSHLZFSE_LEVEL_DEFAULT;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--fast")) level = CRUSHLZFSE_LEVEL_MIN;
        else if (!strcmp(argv[i], "--level") && i + 1 < argc) level = atoi(argv[i + 1]);
    }
    crushlzfse_params_for_level(level, &params);
    fast = params.strategy == CRUSHLZFSE_STRATEGY_FAST;
    int optimal = params.strategy == CRUSHLZFSE_STRATEGY_OPTIMAL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (fprintf(stderr, "%s needs a value\n", a), exit(1), (char *)0))
        if (!strcmp(a, "--fast")) continue;
        else if (!strcmp(a, "--level")) { NEXT(); }
        else if (optimal && !strcmp(a, "--table-search")) { params.p.optimal.table_search = atoi(NEXT()); }
        else if (fast && !strcmp(a, "--hash-bits")) { params.p.fast.hash_bits = atoi(NEXT()); }
        else if (fast && !strcmp(a, "--min-match")) { params.p.fast.min_match = atoi(NEXT()); }
        else if (fast && !strcmp(a, "--skip-shift")) { params.p.fast.skip_shift = atoi(NEXT()); }
        else if (fast && !strcmp(a, "--max-step")) { params.p.fast.max_step = atoi(NEXT()); }
        else if (fast && !strcmp(a, "--long-table")) { params.p.fast.long_table = atoi(NEXT()); }
        else if (fast && !strcmp(a, "--lazy")) { params.p.fast.lazy = atoi(NEXT()); }
        else if (!optimal && !strcmp(a, "--hash-bits")) { params.p.lazy.hash_bits = atoi(NEXT()); }
        else if (!optimal && !strcmp(a, "--hash-width")) { params.p.lazy.hash_width = atoi(NEXT()); }
        else if (!optimal && !strcmp(a, "--lookahead")) { params.p.lazy.lookahead = atoi(NEXT()); }
        else if (!strcmp(a, "--block")) block_size = (size_t)atol(NEXT());
        else if (!strcmp(a, "--max-blocks")) max_blocks = atol(NEXT());
        else if (!strcmp(a, "--no-apple")) skip_apple = 1;
        else if (a[0] != '-' && !manifest_path) manifest_path = a;
        else { fprintf(stderr, "unrecognized arg %s\n", a); usage(argv[0]); return 1; }
        #undef NEXT
    }

    if (!manifest_path) { usage(argv[0]); return 1; }

    #ifndef CRUSHLZFSE_SWEEP_HAVE_APPLE
    skip_apple = 1;
    #endif

    FILE *mf = fopen(manifest_path, "rb");
    if (!mf) { perror(manifest_path); return 1; }

    size_t scratch_bytes = crushlzfse_scratch_size(&params);
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
            out = crushlzfse_encode_buffer_advanced(dst, block_size * 2 + 4096, raw, got, scratch, scratch_bytes, &params);
            enc_secs += now_secs() - t0;

            if (out == 0) { refused++; nblocks++; continue; }

            size_t back_got = 0;
            int ours_ok = (crushlzfse_decode_buffer(back, block_size + 4096, dst, out, &back_got) == 0 &&
                           back_got == got && memcmp(back, raw, got) == 0);
            if (!ours_ok) ours_failed++;

            if (!skip_apple) {
                #ifdef CRUSHLZFSE_SWEEP_HAVE_APPLE
                memset(back, 0, got);
                size_t alen = compression_decode_buffer(back, block_size + 4096, dst, out, NULL, COMPRESSION_LZFSE);
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

    if (optimal)
        printf("level=%d table_search=%d\n", level, params.p.optimal.table_search);
    else if (fast)
        printf("fast hash_bits=%d min_match=%d skip_shift=%d max_step=%d long_table=%d lazy=%d\n",
               params.p.fast.hash_bits, params.p.fast.min_match, params.p.fast.skip_shift,
               params.p.fast.max_step, params.p.fast.long_table, params.p.fast.lazy);
    else
        printf("hash_bits=%d hash_width=%d lookahead=%d\n",
               params.p.lazy.hash_bits, params.p.lazy.hash_width, params.p.lazy.lookahead);
    printf("blocks: %ld   refused: %ld   our-decoder-failed: %ld   apple-failed: %ld%s\n",
           nblocks, refused, ours_failed, apple_failed, skip_apple ? " (skipped)" : "");
    printf("ratio: %.4f   saved: %.4f%%   enc MB/s: %.2f\n", ratio, saved_pct, mb_s);

    return (ours_failed || apple_failed) ? 2 : 0;
}
