// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Raw-params sweep driver for the LZBITMAP encoder: hands
 * crushlzbitmap_encode_buffer_advanced() arbitrary params (see
 * crushlzbitmap.h), round-trips every block (through Apple's decoder too on
 * macOS), and reports saved% and encode MB/s.
 *
 *   zbm_sweep <manifest> --strategy row --hash-bits 16 --row-depth 2 --scan-window 16
 *   zbm_sweep <manifest> --strategy dp --row-depth 16 --max-cands 16 --dp-iterations 2
 *
 * The manifest is one file path per line, same format bench uses. Each file
 * is split into --block (default 65536) byte blocks; a short final block is
 * kept.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <compression.h>
#define ZBM_SWEEP_HAVE_APPLE 1
#endif

#include "crushlzbitmap.h"

static double now_secs(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s <manifest> --strategy row|dp [options] [--block N] [--max-blocks N]\n"
        "\n"
        "  row:    --hash-bits N --row-depth N --dist-cache N --accept-diff N\n"
        "          --scan-window N (a multiple of 16, to 256) --lookahead 0|1\n"
        "  dp:     the row options for sourcing, plus --max-cands N --dp-iterations N\n"
        "\n"
        "  --block N       block size in bytes (default 65536)\n"
        "  --max-blocks N  stop after N blocks, 0 = no limit (default 0)\n"
        "  --no-apple      skip the Apple-decoder oracle check (faster, less safe)\n"
        "  --no-decode     skip both decoders; prints only ratio, speed and digest\n",
        argv0);
}

/* The sweep drives hand-built params, so it sizes for the largest it can
 * emit rather than for any level. */
static size_t zbm_sweep_max_scratch(void)
{
    crushlzbitmap_params p;
    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_DP, &p);
    p.p.dp.max_candidates = CRUSHLZBITMAP_MAX_DP_CANDS;
    return crushlzbitmap_scratch_size(&p);
}

int main(int argc, char **argv) {
    const char *manifest_path = NULL;
    size_t block_size = 65536;
    long max_blocks = 0;
    int skip_apple = 0;
    /* FNV-1a over every compressed block, for output-identity checks. */
    unsigned long long digest = 1469598103934665603ULL;

    crushlzbitmap_params params;
    memset(&params, 0, sizeof params);
    params.strategy = -1;

    /* Start from the defaults; flags override fields. */
    crushlzbitmap_params tmp;
    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_DP, &tmp);
    int max_cands = tmp.p.dp.max_candidates, dp_iterations = tmp.p.dp.iterations;
    crushlzbitmap_row_params dprow = tmp.p.dp.row;
    crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_ROW, &tmp);
    crushlzbitmap_row_params row = tmp.p.row;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEXT() (++i < argc ? argv[i] : (fprintf(stderr, "%s needs a value\n", a), exit(1), (char *)0))
        if (!strcmp(a, "--strategy")) {
            const char *v = NEXT();
            if (!strcmp(v, "row")) params.strategy = CRUSHLZBITMAP_STRATEGY_ROW;
            else if (!strcmp(v, "dp")) params.strategy = CRUSHLZBITMAP_STRATEGY_DP;
            else { fprintf(stderr, "unknown strategy %s\n", v); return 1; }
        }
        else if (!strcmp(a, "--hash-bits")) { int v = atoi(NEXT()); row.hash_bits = v; dprow.hash_bits = v; }
        else if (!strcmp(a, "--row-depth")) { int v = atoi(NEXT()); row.depth = v; dprow.depth = v; }
        else if (!strcmp(a, "--lookahead")) { int v = atoi(NEXT()); row.lookahead = v; dprow.lookahead = v; }
        else if (!strcmp(a, "--dist-cache")) { int v = atoi(NEXT()); row.dist_cache_size = v; dprow.dist_cache_size = v; }
        else if (!strcmp(a, "--scan-window")) { int v = atoi(NEXT()); row.scan_window = v; dprow.scan_window = v; }
        else if (!strcmp(a, "--accept-diff")) { int v = atoi(NEXT()); row.accept_diff = v; dprow.accept_diff = v; }
        else if (!strcmp(a, "--max-cands")) { max_cands = atoi(NEXT()); }
        else if (!strcmp(a, "--dp-iterations")) { dp_iterations = atoi(NEXT()); }
        else if (!strcmp(a, "--block")) block_size = (size_t)atol(NEXT());
        else if (!strcmp(a, "--max-blocks")) max_blocks = atol(NEXT());
        else if (!strcmp(a, "--no-apple")) skip_apple = 1;
        else if (!strcmp(a, "--no-decode")) skip_apple = 2;
        else if (a[0] != '-' && !manifest_path) manifest_path = a;
        else { fprintf(stderr, "unrecognized arg %s\n", a); usage(argv[0]); return 1; }
        #undef NEXT
    }

    if (!manifest_path || params.strategy < 0) { usage(argv[0]); return 1; }

    if (params.strategy == CRUSHLZBITMAP_STRATEGY_ROW) params.p.row = row;
    if (params.strategy == CRUSHLZBITMAP_STRATEGY_DP) { params.p.dp.row = dprow; params.p.dp.max_candidates = max_cands; params.p.dp.iterations = dp_iterations; }

    #ifndef ZBM_SWEEP_HAVE_APPLE
    skip_apple = 1;
    #endif

    FILE *mf = fopen(manifest_path, "rb");
    if (!mf) { perror(manifest_path); return 1; }

    uint8_t *raw = malloc(block_size);
    uint8_t *dst = malloc(crushlzbitmap_encode_bound(block_size));
    uint8_t *back = malloc(block_size * 3 + 4096);
    /* Sized for the widest params this sweep will drive: the DP tables scale
     * with max_candidates, so take the cap the sweep is allowed to reach. */
    size_t scratch_bytes = zbm_sweep_max_scratch();
    void *scratch = calloc(1, scratch_bytes);
    if (!raw || !dst || !back || !scratch) { fprintf(stderr, "oom\n"); return 1; }

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

            double t0 = now_secs();
            size_t out = crushlzbitmap_encode_buffer_advanced(dst, crushlzbitmap_encode_bound(block_size),
                                                              raw, got, scratch, scratch_bytes, &params);
            enc_secs += now_secs() - t0;

            if (out == 0) { refused++; nblocks++; continue; }

            for (size_t k = 0; k < out; k++) { digest ^= dst[k]; digest *= 1099511628211ULL; }

            size_t back_got = 0;
            int ours_ok = skip_apple == 2 ||
                          (crushlzbitmap_decode_buffer(back, block_size * 3 + 4096, dst, out, &back_got) == 0 &&
                           back_got == got && memcmp(back, raw, got) == 0);
            if (!ours_ok) ours_failed++;

            if (!skip_apple) {
                #ifdef ZBM_SWEEP_HAVE_APPLE
                memset(back, 0, got);
                size_t alen = compression_decode_buffer(back, block_size * 3 + 4096, dst, out, NULL, COMPRESSION_LZBITMAP);
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

    printf("blocks: %ld   refused: %ld   our-decoder-failed: %ld   apple-failed: %ld%s\n",
           nblocks, refused, ours_failed, apple_failed, skip_apple ? " (skipped)" : "");
    printf("ratio: %.4f   saved: %.2f%%   enc MB/s: %.2f\n", ratio, saved_pct, mb_s);
    printf("digest: %016llx\n", digest);

    return (ours_failed || apple_failed) ? 2 : 0;
}
