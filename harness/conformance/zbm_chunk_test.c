// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * crushlzbitmap_encode_chunk() over chunks 0..N, concatenated, must equal
 * crushlzbitmap_encode_buffer() byte for byte, so chunks can be encoded in
 * parallel or one at a time. Swept over every level, with periods pointing
 * back past chunk boundaries and chunks encoded out of order, and at the
 * fast levels across the 16 MiB wrap of the match table's 24-bit positions.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crushlzbitmap.h"

#define CHUNK   CRUSHLZBITMAP_CHUNK_SIZE
#define SRC_SZ  (12 * CHUNK + 1234)

static size_t zbm_ladder_max_scratch(void)
{
    size_t max = 0;
    for(int lv = CRUSHLZBITMAP_LEVEL_MIN; lv <= CRUSHLZBITMAP_LEVEL_MAX; ++lv) {
        crushlzbitmap_params p;
        size_t n;
        crushlzbitmap_params_for_level(lv, &p);
        n = crushlzbitmap_scratch_size(&p);
        if(n > max) max = n;
    }
    return max;
}

static void fill(uint8_t *b, size_t n)
{
    size_t i;
    uint32_t x = 12345;

    /* Long-period structure plus drift, so periods cross chunk boundaries. */
    for(i = 0; i < n; ++i) {
        x = x * 1103515245u + 12345u;
        b[i] = (uint8_t)((i % 1543) ^ (i / 4099) ^ ((x >> 16) & ((i % 97) ? 0 : 0xff)));
    }
}

/* Repeats straddling 16 MiB, where a stale table entry's distance can look
 * real; only the chunks around it are compared, the rest being covered above. */
static int wrap_case(void *scratch, size_t scratch_bytes)
{
    const size_t wrap = (size_t)1 << 24, n = wrap + 3 * CHUNK;
    const size_t first = wrap / CHUNK - 3, last = n / CHUNK;
    uint8_t *src = malloc(n), *seq = malloc(crushlzbitmap_encode_bound(n));
    uint8_t piece[CRUSHLZBITMAP_MAX_CHUNK_SIZE];
    uint32_t x = 1;
    int all_ok = 1, lvl;
    size_t i;

    for(i = 0; i < n; ++i) {
        x = x * 1103515245u + 12345u;
        src[i] = (uint8_t)(x >> 23);
    }
    for(i = wrap - 2 * CHUNK; i < n; ++i)
        if(i % 4099 < 3000)
            src[i] = src[i - 1001 - (i / CHUNK) % 3];

    for(lvl = CRUSHLZBITMAP_LEVEL_MIN; lvl <= -2; ++lvl) {
        crushlzbitmap_params params;
        size_t seqlen, off = 0, k;
        int ok = 1;

        crushlzbitmap_params_for_level(lvl, &params);
        seqlen = crushlzbitmap_encode_buffer_advanced(seq, crushlzbitmap_encode_bound(n), src, n,
                                                      scratch, scratch_bytes, &params);
        for(k = 0; ok && k <= last; ++k) {
            size_t got = crushlzbitmap_encode_chunk(piece, sizeof piece, src, n, k, scratch, scratch_bytes, &params);

            if(!got || off + got > seqlen || (k >= first && memcmp(piece, seq + off, got)))
                ok = 0;
            off += got;
        }
        if(!seqlen || !ok || off != seqlen) {
            printf("level %-3d across 16 MiB                *** DIVERGED ***\n", lvl);
            all_ok = 0;
            continue;
        }
        printf("level %-3d across 16 MiB, identical to sequential\n", lvl);
    }
    free(src);
    free(seq);
    return all_ok;
}

int main(void)
{
    static uint8_t src[SRC_SZ], seq[SRC_SZ * 2], cat[SRC_SZ * 2], back[SRC_SZ];
    static uint8_t piece[CRUSHLZBITMAP_MAX_CHUNK_SIZE];
    static size_t piece_len[SRC_SZ / CHUNK + 2], piece_off[SRC_SZ / CHUNK + 2];
    const size_t nchunks = SRC_SZ / CHUNK + 2;   /* data chunks plus the terminator */
    crushlzbitmap_params params;
    size_t scratch_bytes = zbm_ladder_max_scratch();
    void *scratch = calloc(1, scratch_bytes);
    int all_ok = 1, lvl;

    fill(src, sizeof src);

    for(lvl = CRUSHLZBITMAP_LEVEL_MIN; lvl <= CRUSHLZBITMAP_LEVEL_MAX; ++lvl) {
        size_t seqlen, catlen = 0, blen = 0, k;
        int ok = 1;

        crushlzbitmap_params_for_level(lvl, &params);
        seqlen = crushlzbitmap_encode_buffer_advanced(seq, sizeof seq, src, sizeof src, scratch, scratch_bytes, &params);
        if(!seqlen) {
            printf("level %-3d sequential encode           *** FAILED ***\n", lvl);
            all_ok = 0;
            continue;
        }

        /* Sizes first, in reverse order. */
        for(k = nchunks; k-- > 0;) {
            piece_len[k] = crushlzbitmap_encode_chunk(piece, sizeof piece, src, sizeof src, k,
                                                      scratch, scratch_bytes, &params);
            if(!piece_len[k]) {
                printf("level %-3d chunk %zu                     *** FAILED ***\n", lvl, k);
                ok = 0;
            }
        }
        if(!ok) { all_ok = 0; continue; }
        for(k = 0; k < nchunks; ++k) {
            piece_off[k] = catlen;
            catlen += piece_len[k];
        }
        if(catlen > sizeof cat) { printf("level %-3d chunks overflow\n", lvl); all_ok = 0; continue; }

        /* Then the bytes, odd chunks before even ones. */
        for(k = 0; k < nchunks; ++k) {
            size_t j = (k < nchunks / 2) ? 2 * k + 1 : 2 * (k - nchunks / 2);
            if(j >= nchunks) continue;
            size_t got = crushlzbitmap_encode_chunk(piece, sizeof piece, src, sizeof src, j, scratch, scratch_bytes, &params);
            if(got != piece_len[j]) {
                printf("level %-3d chunk %zu is %zu bytes, was %zu   *** UNSTABLE ***\n", lvl, j, got, piece_len[j]);
                ok = 0;
                continue;
            }
            memcpy(cat + piece_off[j], piece, got);
        }
        if(!ok) { all_ok = 0; continue; }

        if(piece_len[nchunks - 1] != CRUSHLZBITMAP_LAST_CHUNK_SIZE) {
            printf("level %-3d terminator is %zu bytes        *** WRONG ***\n", lvl, piece_len[nchunks - 1]);
            all_ok = 0;
        }
        if(catlen != seqlen || memcmp(cat, seq, seqlen)) {
            printf("level %-3d chunks %zu vs sequential %zu   *** DIVERGED ***\n", lvl, catlen, seqlen);
            all_ok = 0;
            continue;
        }
        if(crushlzbitmap_decode_buffer(back, sizeof back, cat, catlen, &blen) ||
           blen != sizeof src || memcmp(back, src, sizeof src)) {
            printf("level %-3d round-trip                   *** FAILED ***\n", lvl);
            all_ok = 0;
            continue;
        }
        printf("level %-3d %zu chunks, %zu bytes, identical to sequential\n", lvl, nchunks, catlen);
    }

    all_ok &= wrap_case(scratch, scratch_bytes);
    free(scratch);
    printf("%s\n", all_ok ? "all chunked encodes byte-identical to sequential"
                          : "*** FAILURE ***");
    return all_ok ? 0 : 1;
}
