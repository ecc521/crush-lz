// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Raw-params sweep driver for CrushLZ4: hands
 * crushlz4_encode_buffer_advanced() arbitrary params (see crushlz4.h),
 * round-trips every block (through Apple's decoder too on macOS), and
 * reports saved% and encode MB/s.
 *
 *   crushlz4_sweep <manifest> --mode fast --acceleration 16
 *   crushlz4_sweep <manifest> --mode hc --hc-level 12
 *
 * This is what regenerates the level ladder. It is a thin tool now: the
 * encoder is upstream LZ4 and upstream exposes one knob per mode, so a
 * sweep is a loop over acceleration or over hc_level, not a search of a
 * parameter space. It stays in the tree so the ladder can be re-measured
 * rather than re-argued, and so an upstream bump that moves a rung shows up
 * as a number rather than a surprise.
 *
 * The manifest is one file path per line, as for bench. Each file is split
 * into --block (default 65536) byte blocks; a short final block is kept.
 * Blocks are encoded independently, which is what a caller does.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <compression.h>
#define CRUSHLZ4_SWEEP_HAVE_APPLE 1
#endif

#include "crushlz4.h"

static double now_secs(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void usage(const char *argv0) {
    crushlz4_capabilities c = crushlz4_get_capabilities();
    fprintf(stderr,
        "usage: %s <manifest> [--mode fast|hc] [--acceleration N] [--hc-level N]\n"
        "           [--level N] [--block N] [--max-blocks N] [--reps N] [--no-apple]\n"
        "\n"
        "  --mode fast|hc     which upstream encoder; the knob below it reads\n"
        "  --acceleration N   %d-%d, fast mode. Higher is faster and worse.\n"
        "  --hc-level N       %d-%d, hc mode. %d and up run the optimal parse.\n"
        "  --level N          start from this level's params, then apply the flags\n"
        "  --block N          block size in bytes (default 65536)\n"
        "  --max-blocks N     stop after N blocks, 0 = no limit (default 0)\n"
        "  --reps N           encode each block N times, report the fastest pass\n"
        "  --no-apple         skip the Apple-decoder oracle check (faster, less safe)\n",
        argv0, c.acceleration_min, c.acceleration_max,
        c.hc_level_min, c.hc_level_max, 10);
}

int main(int argc, char **argv) {
    const char *manifest_path = NULL;
    size_t block_size = 65536;
    long max_blocks = 0;
    int reps = 1;
    int skip_apple = 0;

    crushlz4_encode_params params;
    crushlz4_params_for_level(CRUSHLZ4_LEVEL_DEFAULT, &params);

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (fprintf(stderr, "%s needs a value\n", a), exit(1), (char *)0))
        if (!strcmp(a, "--mode")) {
            const char *v = NEXT();
            if (!strcmp(v, "fast")) params.mode = CRUSHLZ4_MODE_FAST;
            else if (!strcmp(v, "hc")) params.mode = CRUSHLZ4_MODE_HC;
            else { fprintf(stderr, "--mode takes fast or hc, not %s\n", v); return 1; }
        }
        else if (!strcmp(a, "--acceleration")) params.acceleration = atoi(NEXT());
        else if (!strcmp(a, "--hc-level")) params.hc_level = atoi(NEXT());
        else if (!strcmp(a, "--level")) crushlz4_params_for_level(atoi(NEXT()), &params);
        else if (!strcmp(a, "--block")) block_size = (size_t)atol(NEXT());
        else if (!strcmp(a, "--max-blocks")) max_blocks = atol(NEXT());
        else if (!strcmp(a, "--reps")) reps = atoi(NEXT());
        else if (!strcmp(a, "--no-apple")) skip_apple = 1;
        else if (a[0] != '-' && !manifest_path) manifest_path = a;
        else { fprintf(stderr, "unrecognized arg %s\n", a); usage(argv[0]); return 1; }
        #undef NEXT
    }

    if (!manifest_path || reps < 1 || block_size < 16) { usage(argv[0]); return 1; }

    #ifndef CRUSHLZ4_SWEEP_HAVE_APPLE
    skip_apple = 1;
    #endif

    FILE *mf = fopen(manifest_path, "rb");
    if (!mf) { perror(manifest_path); return 1; }

    size_t cap = crushlz4_encode_bound(block_size);
    /* Sized for the params this run sweeps, which is also what rejects a
     * params set the encoder would refuse: it reports 0 for those. */
    size_t scratch_n = crushlz4_scratch_size(&params);
    void *scratch;
    if (scratch_n == 0) { fprintf(stderr, "params outside crushlz4_get_capabilities()\n"); return 1; }
    scratch = malloc(scratch_n);
    uint8_t *raw = malloc(block_size);
    uint8_t *dst = malloc(cap);
    uint8_t *back = malloc(block_size + 4096);
    if (!scratch || !raw || !dst || !back) { fprintf(stderr, "oom\n"); return 1; }
    memset(scratch, 0, scratch_n);

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
            double best = 0;
            for (int r = 0; r < reps; r++) {
                double t0 = now_secs();
                out = crushlz4_encode_buffer_advanced(dst, cap, raw, got, scratch, scratch_n, &params);
                double dt = now_secs() - t0;
                if (r == 0 || dt < best) best = dt;
            }
            enc_secs += best;

            if (out == 0) { refused++; nblocks++; continue; }

            size_t back_got = 0;
            int ours_ok = (crushlz4_decode_buffer(back, block_size + 4096, dst, out, &back_got) == 0 &&
                           back_got == got && memcmp(back, raw, got) == 0);
            if (!ours_ok) ours_failed++;

            if (!skip_apple) {
                #ifdef CRUSHLZ4_SWEEP_HAVE_APPLE
                memset(back, 0, got);
                size_t alen = compression_decode_buffer(back, block_size + 4096, dst, out, NULL, COMPRESSION_LZ4);
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

    /* Only the knob this mode reads is printed: the other holds a neutral
     * value and printing it would read like a setting that did something. */
    if (params.mode == CRUSHLZ4_MODE_FAST)
        printf("mode=fast acceleration=%d\n", params.acceleration);
    else
        printf("mode=hc hc_level=%d\n", params.hc_level);
    printf("blocks: %ld   refused: %ld   our-decoder-failed: %ld   apple-failed: %ld%s\n",
           nblocks, refused, ours_failed, apple_failed, skip_apple ? " (skipped)" : "");
    printf("ratio: %.4f   saved: %.2f%%   enc MB/s: %.2f\n", ratio, saved_pct, mb_s);

    return (ours_failed || apple_failed) ? 2 : 0;
}
