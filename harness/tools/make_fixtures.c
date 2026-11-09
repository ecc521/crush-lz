// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Generates the deterministic corpus `make check` runs against: files plus
 * manifest.txt. Usage: make_fixtures <out_dir> [bytes]
 *
 * The size defaults to what the concurrency tests need on this machine
 * (four 64KB chunks per worker); an explicit size is clamped up to that floor.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static uint64_t rng_state = 0x2545F4914F6CDD1DULL;
static uint8_t rng_byte(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint8_t)(rng_state >> 24);
}

static size_t MAXLEN;
static uint8_t *buf;

#define N_FIXTURES 7

static size_t pick_len(void) {
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 2) cores = 2;
    /* cores * 4 chunks over N_FIXTURES files, plus headroom. */
    size_t chunks_per_file = ((size_t)cores * 4 * 2 + N_FIXTURES - 1) / N_FIXTURES;
    size_t len = chunks_per_file * 65536;
    return len < 512 * 1024 ? 512 * 1024 : len;
}

/* Smallest fixture size the concurrency tests accept: cores * 4 chunks. */
static size_t min_len(void) {
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 2) cores = 2;
    size_t chunks_per_file = ((size_t)cores * 4 + N_FIXTURES - 1) / N_FIXTURES + 1;
    return chunks_per_file * 65536;
}

static int emit(const char *dir, FILE *manifest, const char *name, size_t len) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return 1; }
    if (fwrite(buf, 1, len, f) != len) { perror(path); fclose(f); return 1; }
    fclose(f);
    fprintf(manifest, "%s\n", path);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <out_dir>\n", argv[0]); return 1; }
    const char *dir = argv[1];
    MAXLEN = pick_len();
    if (argc > 2 && argv[2][0]) {
        size_t want = (size_t)atol(argv[2]);
        size_t floor_len = min_len();
        MAXLEN = want < floor_len ? floor_len : want;
    }
    buf = malloc(MAXLEN);
    if (!buf) { perror("malloc"); return 1; }

    char mpath[1024];
    snprintf(mpath, sizeof mpath, "%s/manifest.txt", dir);
    FILE *manifest = fopen(mpath, "wb");
    if (!manifest) { perror(mpath); return 1; }

    int rc = 0;

    /* Incompressible. */
    for (size_t i = 0; i < MAXLEN; i++) buf[i] = rng_byte();
    rc |= emit(dir, manifest, "random.bin", MAXLEN);

    /* A single long run. */
    memset(buf, 0x00, MAXLEN);
    rc |= emit(dir, manifest, "zeros.bin", MAXLEN);

    /* Periodic at a multiple of 8, which LZBITMAP can express natively. */
    for (size_t i = 0; i < MAXLEN; i++) buf[i] = (uint8_t)("crushlz!"[i % 8]);
    rc |= emit(dir, manifest, "period8.bin", MAXLEN);

    /* Periodic at 12, which LZBITMAP cannot express natively. */
    for (size_t i = 0; i < MAXLEN; i++) buf[i] = (uint8_t)(i % 12) * 17u;
    rc |= emit(dir, manifest, "period12.bin", MAXLEN);

    /* Text-like: skewed byte distribution with real repetition. */
    {
        static const char *words[] = { "the ", "compression ", "block ", "encoder ",
                                       "a ", "of ", "and ", "decode " };
        size_t n = 0;
        while (n < MAXLEN - 16) {
            const char *w = words[rng_byte() & 7];
            size_t l = strlen(w);
            memcpy(buf + n, w, l);
            n += l;
        }
        rc |= emit(dir, manifest, "textlike.bin", MAXLEN);
    }

    /* Sparse: long zero runs punctuated by data. */
    memset(buf, 0, MAXLEN);
    for (size_t i = 0; i < MAXLEN; i += 4096)
        for (size_t j = 0; j < 64 && i + j < MAXLEN; j++) buf[i + j] = rng_byte();
    rc |= emit(dir, manifest, "sparse.bin", MAXLEN);

    /* Not a multiple of any block size, so the last chunk is partial. */
    for (size_t i = 0; i < MAXLEN; i++) buf[i] = (uint8_t)((i / 7) ^ (i * 31));
    rc |= emit(dir, manifest, "ragged.bin", MAXLEN - 65536 + 137);

    fclose(manifest);

    if (rc) return 1;
    printf("fixtures written to %s (%zu bytes each)\n", dir, MAXLEN);
    return 0;
}
