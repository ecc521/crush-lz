// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * crushlzfse_encode_buffer_chained at every level, over a file of drifting
 * 64 KiB chunks with an incompressible chunk and a short tail among them:
 *
 *   - NULL and zeroed stats give crushlzfse_encode_buffer_advanced's bytes;
 *   - a chain round-trips through our decoder (and Apple's on macOS), is
 *     deterministic, and gives the same bytes and stats whether the struct
 *     is reused in place or each call gets a copy;
 *   - stats follow an LZFSE block only: a raw or LZVN chunk, a rejected
 *     call and an empty input leave them zeroed;
 *   - arbitrary stats (random words, all 0xFF, a genuine header over huge or
 *     empty counts) still round-trip.
 *
 * The garbage cases write word 0 as the header, which is crushlzfse.c's
 * layout, not part of the API.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzfse.h"

#ifdef __APPLE__
#include <compression.h>
#endif

#define CHUNK 65536
#define NCHUNKS 6

static const size_t chunk_len[NCHUNKS] = {CHUNK, CHUNK, CHUNK, CHUNK, CHUNK, 3000};
static uint8_t input[NCHUNKS * CHUNK];
static unsigned checks, failures;

static uint32_t rng_state = 0x2545F491u;
static uint32_t rng(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

/* Words over a vocabulary that shifts chunk by chunk, so neighbouring chunks
 * have similar but not equal statistics. Chunk 3 is random bytes. */
static void fill_input(void) {
    static const char *words[] = {"chain ", "stats ", "seed ", "chunk ", "level ", "parse ",
                                  "table ", "block ", "match ", "literal "};
    for (int c = 0; c < NCHUNKS; c++) {
        uint8_t *p = input + (size_t)c * CHUNK;
        size_t n = chunk_len[c], i = 0;
        if (c == 3) {
            for (; i < n; i++) p[i] = (uint8_t)(rng() >> 24);
            continue;
        }
        while (i < n) {
            uint32_t x = rng();
            const char *w = words[(x % 7) + (uint32_t)c / 2];
            for (; *w && i < n; w++) p[i++] = (uint8_t)*w;
            if ((x >> 8) % 11 == 0 && i < n) p[i++] = (uint8_t)(x >> 16);
            if ((x >> 12) % 29 == 0)
                for (int k = 0; k < 12 && i < n; k++) p[i++] = (uint8_t)('0' + (k + c + (int)(x >> 20)) % 10);
        }
    }
}

static void fail(int level, int chunk, const char *what) {
    printf("level %3d chunk %d: %s\n", level, chunk, what);
    failures++;
}

static int is_zero(const crushlzfse_stats *s) {
    for (int i = 0; i < CRUSHLZFSE_STATS_WORDS; i++)
        if (s->opaque[i]) return 0;
    return 1;
}

static void check_roundtrip(int level, int chunk, const char *what, const uint8_t *src, size_t n,
                            const uint8_t *enc, size_t enc_len) {
    static uint8_t back[CHUNK + 64];
    checks++;
    if (!enc_len) { fail(level, chunk, what); return; }
    size_t got = 0;
    if (crushlzfse_decode_buffer(back, sizeof back, enc, enc_len, &got) != 0 || got != n ||
        memcmp(back, src, n) != 0) {
        printf("  (our decoder)\n");
        fail(level, chunk, what);
        return;
    }
#ifdef __APPLE__
    memset(back, 0, n);
    if (compression_decode_buffer(back, sizeof back, enc, enc_len, NULL, COMPRESSION_LZFSE) != n ||
        memcmp(back, src, n) != 0) {
        printf("  (Apple's decoder)\n");
        fail(level, chunk, what);
    }
#endif
}

int main(void) {
    fill_input();
    crushlzfse_capabilities caps = crushlzfse_get_capabilities();

    for (int level = caps.level_min; level <= caps.level_max; level++) {
        crushlzfse_encode_params p;
        crushlzfse_params_for_level(level, &p);
        size_t ss = crushlzfse_scratch_size(&p), cap = crushlzfse_encode_bound(CHUNK, &p);
        void *scratch = malloc(ss);
        uint8_t *want = malloc(cap), *got = malloc(cap), *again = malloc(cap);
        if (!scratch || !want || !got || !again) abort();

        crushlzfse_stats chain, copy, prev, fresh;
        memset(&chain, 0, sizeof chain);
        int seeded_differs = 0;
        for (int c = 0; c < NCHUNKS; c++) {
            const uint8_t *src = input + (size_t)c * CHUNK;
            size_t n = chunk_len[c];

            /* NULL and zeroed stats are _advanced. */
            size_t want_len = crushlzfse_encode_buffer_advanced(want, cap, src, n, scratch, ss, &p);
            size_t null_len = crushlzfse_encode_buffer_chained(got, cap, src, n, scratch, ss, &p, NULL);
            checks++;
            if (null_len != want_len || memcmp(got, want, want_len) != 0) fail(level, c, "NULL stats changed the output");
            memset(&fresh, 0, sizeof fresh);
            size_t zero_len = crushlzfse_encode_buffer_chained(got, cap, src, n, scratch, ss, &p, &fresh);
            checks++;
            if (zero_len != want_len || memcmp(got, want, want_len) != 0) fail(level, c, "zeroed stats changed the output");
            /* Stats only follow an LZFSE block, magic bvx1 or bvx2, never
             * the LZVN or raw fallback. */
            int lzfse_block = want_len > 4 && (want[3] == '1' || want[3] == '2');
            checks++;
            if (lzfse_block == is_zero(&fresh)) fail(level, c, lzfse_block ? "stats not written" : "fallback left stats");
            checks++;
            if (c == 3 && lzfse_block) fail(level, c, "random chunk not stored raw");

            /* The chain in place, and the same step from a copy. */
            prev = chain;
            size_t len = crushlzfse_encode_buffer_chained(got, cap, src, n, scratch, ss, &p, &chain);
            check_roundtrip(level, c, "chain does not round-trip", src, n, got, len);
            seeded_differs |= len != want_len || memcmp(got, want, len) != 0;
            copy = prev;
            size_t len2 = crushlzfse_encode_buffer_chained(again, cap, src, n, scratch, ss, &p, &copy);
            checks++;
            if (len2 != len || memcmp(again, got, len) != 0 || memcmp(&copy, &chain, sizeof copy) != 0)
                fail(level, c, "in-place and copied stats differ, or the encode is not deterministic");

            /* Arbitrary stats, from the previous step's genuine header. */
            for (int g = 0; g < 5; g++) {
                crushlzfse_stats junk = prev;
                for (int i = 0; i < CRUSHLZFSE_STATS_WORDS; i++) {
                    switch (g) {
                    case 0: junk.opaque[i] = rng(); break;
                    case 1: junk.opaque[i] = 0xFFFFFFFFu; break;
                    case 2: if (i) junk.opaque[i] = 0xFFFFFFFFu - (uint32_t)i; break;
                    case 3: if (i) junk.opaque[i] = (i % 3 == 0) ? 0x80000000u : 0; break;
                    default: if (i > 20) junk.opaque[i] = 0; break; /* empty M and D */
                    }
                }
                if (g >= 2) junk.opaque[0] = fresh.opaque[0] ? fresh.opaque[0] : chain.opaque[0];
                size_t jl = crushlzfse_encode_buffer_chained(got, cap, src, n, scratch, ss, &p, &junk);
                check_roundtrip(level, c, "garbage stats broke the stream", src, n, got, jl);
            }
        }

        /* Only the optimal levels consume the seed. */
        checks++;
        if (seeded_differs != (p.strategy == CRUSHLZFSE_STRATEGY_OPTIMAL))
            fail(level, -1, seeded_differs ? "a non-optimal level used the seed" : "the seed changed nothing");

        /* A rejected call and an empty input both leave zeroed stats. */
        crushlzfse_stats s = chain;
        memset(&s.opaque[1], 0x11, sizeof s.opaque - sizeof s.opaque[0]);
        checks++;
        if (crushlzfse_encode_buffer_chained(got, cap, input, CHUNK + 1, scratch, ss, &p, &s) != 0 || !is_zero(&s))
            fail(level, -1, "oversized input accepted or stats kept");
        s = chain;
        size_t el = crushlzfse_encode_buffer_chained(got, cap, input, 0, scratch, ss, &p, &s);
        check_roundtrip(level, -1, "empty input does not round-trip", input, 0, got, el);
        checks++;
        if (!is_zero(&s)) fail(level, -1, "empty input left stats");

        free(scratch);
        free(want);
        free(got);
        free(again);
    }
    printf("%u chained checks, %u failed\n", checks, failures);
    return failures ? 1 : 0;
}
