// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Asserts that the LZFSE decoder's wide copies never write past dst_end.
// lzfse_decode_lmd copies in fixed-width units and relies on holding
// `remaining_bytes` LZFSE_DECODE_COPY_MARGIN short of the true capacity; if
// the peel width and the margin ever disagree, the last symbol overruns.
// Every destination is allocated at exactly the decoded size so under ASan
// the first stray byte is a heap-buffer-overflow. The truncation sweep is
// exhaustive because the overrun only fires when a symbol straddles the
// margin boundary.

#include "lzfse.h"
#include "lzfse_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// FNV-1a over the decoded prefix, so output can be diffed between builds.
static uint32_t digest(const uint8_t *p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

// Shapes chosen for which decode path they drive.
static size_t make_payload(int which, uint8_t *buf, size_t cap) {
    size_t n = 0;
    uint32_t s = 12345u + (uint32_t)which * 7919u;
#define RND() (s = s * 1103515245u + 12345u, (uint8_t)(s >> 16))
    switch (which) {
    case 0: // short literals alternating with short matches
        // Seed the back-reference distance first so buf[n - 4] is in bounds.
        for (int i = 0; i < 4 && n < cap; i++) buf[n++] = RND();
        while (n + 8 < cap) {
            for (int i = 0; i < 3 && n < cap; i++) buf[n++] = RND();
            for (int i = 0; i < 5 && n < cap; i++) { buf[n] = buf[n - 4]; n++; }
        }
        break;
    case 1: // distance-1 runs: the splat case, D < 8
        while (n + 40 < cap) {
            uint8_t v = RND();
            size_t r = 3 + (RND() % 37);
            for (size_t i = 0; i < r && n < cap; i++) buf[n++] = v;
        }
        break;
    case 2: // small periods 2..15, the materialised-period path
        while (n + 64 < cap) {
            size_t p = 2 + (RND() % 14);
            for (size_t i = 0; i < p && n < cap; i++) buf[n++] = RND();
            for (size_t i = 0; i < 50 && n < cap; i++) { buf[n] = buf[n - p]; n++; }
        }
        break;
    case 3: // long matches at large distance: the wide path, many margins deep
        while (n + 600 < cap) {
            for (size_t i = 0; i < 300 && n < cap; i++) buf[n++] = RND();
            size_t d = 300;
            for (size_t i = 0; i < 280 && n < cap; i++) { buf[n] = buf[n - d]; n++; }
        }
        break;
    case 4: // incompressible: drives the uncompressed-block path
        while (n < cap) buf[n++] = RND();
        break;
    default: // mostly literal with occasional far match
        while (n + 32 < cap) {
            for (int i = 0; i < 20 && n < cap; i++) buf[n++] = RND();
            if (n > 1000) for (int i = 0; i < 9 && n < cap; i++) { buf[n] = buf[n - 999]; n++; }
        }
        break;
    }
#undef RND
    while (n < cap) buf[n++] = 0;
    return n;
}

#define N_PAYLOADS 6
// Several times LZFSE_DECODE_COPY_MARGIN, small enough to sweep exhaustively.
#define PAYLOAD_LEN 9000

int main(void) {
    uint8_t *raw = malloc(PAYLOAD_LEN);
    size_t enc_cap = PAYLOAD_LEN * 2 + 4096;
    uint8_t *enc = malloc(enc_cap);
    void *escratch = malloc(lzfse_encode_scratch_size());
    size_t dss = lzfse_decode_scratch_size();
    void *dscratch = malloc(dss ? dss : 1);
    int failures = 0;
    long decodes = 0;

    printf("LZFSE_DECODE_COPY_MARGIN = %d\n", (int)LZFSE_DECODE_COPY_MARGIN);

    // The LMD loop skips its literal bound check for a run of tuples sized by
    // LZFSE_DECODE_L_MAX_VALUE, so too small a value walks `lit` past the array.
    {
        int l_max = 0;
        for (int i = 0; i < LZFSE_ENCODE_L_SYMBOLS; i++) {
            int v = l_base_value[i] + (1 << l_extra_bits[i]) - 1;
            if (v > l_max) l_max = v;
        }
        printf("LZFSE_DECODE_L_MAX_VALUE = %d (tables say %d)\n",
               (int)LZFSE_DECODE_L_MAX_VALUE, l_max);
        if (l_max != LZFSE_DECODE_L_MAX_VALUE) {
            printf("L MAX MISMATCH: the literal bound run length is wrong\n");
            failures++;
        }
    }

    for (int p = 0; p < N_PAYLOADS; p++) {
        size_t n = make_payload(p, raw, PAYLOAD_LEN);
        size_t enc_len = lzfse_encode_buffer(enc, enc_cap, raw, n, escratch);
        if (enc_len == 0) { printf("payload %d: encoder refused, skipped\n", p); continue; }

        // Full-size destination, allocated at exactly the decoded length.
        uint8_t *exact = malloc(n);
        size_t got = lzfse_decode_buffer(exact, n, enc, enc_len, dscratch);
        int ok = (got == n) && memcmp(exact, raw, n) == 0;
        uint32_t d_full = digest(exact, got);
        free(exact);
        decodes++;
        if (!ok) { printf("payload %d: FULL DECODE MISMATCH got=%zu want=%zu\n", p, got, n); failures++; }

        // Every truncation length, each into an exactly sized destination.
        uint32_t acc = 0;
        for (size_t t = 0; t <= n; t++) {
            uint8_t *dst = malloc(t ? t : 1);
            size_t w = lzfse_decode_buffer(dst, t, enc, enc_len, dscratch);
            decodes++;
            // A truncated decode must fill exactly t bytes, all correct.
            if (w != t || (t && memcmp(dst, raw, t) != 0)) {
                if (failures < 10)
                    printf("payload %d: TRUNCATION t=%zu wrote=%zu %s\n", p, t, w,
                           (w == t) ? "CONTENT MISMATCH" : "SHORT WRITE");
                failures++;
            }
            acc = acc * 31u + digest(dst, w);
            free(dst);
        }
        printf("payload %d len=%-6zu enc=%-6zu full=%s digest=%08x trunc-acc=%08x\n",
               p, n, enc_len, ok ? "ok" : "BAD", d_full, acc);
    }

    free(raw); free(enc); free(escratch); free(dscratch);
    printf("%ld decodes, %d failures\n", decodes, failures);
    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
