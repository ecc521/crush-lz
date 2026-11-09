// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * The scratch contract, asserted identically for all four codecs, because it
 * is the part of the API most easily made inconsistent one codec at a time.
 * For each of LZFSE, LZVN, LZBITMAP and LZ4:
 *
 *   1. Every level's params give a non-zero size, and walking the ladder for
 *      the largest of them is what a caller reusing one buffer does. The API
 *      has no "big enough for anything" query: params are required, and a
 *      NULL params pointer is a caller bug that crashes at the call rather
 *      than returning something that silently under-allocates.
 *   2. A buffer of exactly X_scratch_size(params) encodes at that level.
 *   3. An undersized buffer is refused, not overrun. The byte after the
 *      carve is checked, so a one-byte overrun fails here rather than in a
 *      caller's heap.
 *
 * Sizes come from the API, never from a constant repeated here; a test that
 * hard-codes them stops testing the thing that drifts.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzfse.h"
#include "crushlzvn.h"
#include "crushlzbitmap.h"
#include "crushlz4.h"

#define SRC_SZ (96 * 1024)      /* more than one 64 KiB block */
/* LZFSE/LZVN's Optimal-strategy calls now accept at most one 64 KiB piece
 * per call and fail outright above it (the caller, decmpfs, never hands one
 * more); LZBITMAP and crushlz4 still chunk arbitrarily large input
 * internally, so they alone are exercised at SRC_SZ. */
#define LZFSE_LZVN_SRC_SZ (64 * 1024)
#define GUARD  0xA5

static int failures, checks;

static void fail(const char *codec, int level, const char *what)
{
    printf("FAIL %s level %d: %s\n", codec, level, what);
    failures++;
}

static void fill(uint8_t *b, size_t n)
{
    uint32_t x = 0x1234567u;
    for (size_t i = 0; i < n; i++) {
        x = x * 1103515245u + 12345u;
        b[i] = (i % 48 < 40) ? (uint8_t)('a' + (i % 23)) : (uint8_t)(x >> 24);
    }
}

/* One codec's entry points, so the four cases below are the same code. */
typedef struct {
    const char *name;
    int level_min, level_max;
    size_t (*size_for_level)(int level);   /* scratch for this level */
    size_t (*encode)(uint8_t *dst, size_t dcap, const uint8_t *src, size_t slen,
                     void *scratch, size_t scratch_size, int level);
    size_t (*bound)(size_t n);
    size_t src_len;                        /* bytes of `src` this codec is tested with */
} codec;

/* ---- per-codec adapters ---------------------------------------------- */

#define ADAPT(PFX, TYPE)                                                      \
    static size_t PFX##_size_for_level(int level) {                           \
        TYPE p; PFX##_params_for_level(level, &p);                            \
        return PFX##_scratch_size(&p);                                        \
    }

ADAPT(crushlzfse, crushlzfse_encode_params)
ADAPT(crushlzvn,  crushlzvn_encode_params)
ADAPT(crushlz4,   crushlz4_encode_params)

static size_t crushlzbitmap_size_for_level(int level) {
    crushlzbitmap_params p;
    crushlzbitmap_params_for_level(level, &p);
    return crushlzbitmap_scratch_size(&p);
}

/* crushlzfse/crushlzvn's bound takes params (it depends on the strategy:
 * Optimal's block is the fixed 64 KiB constant, Greedy splits only at its
 * own much larger ceiling); this test's `bound` field is called once per
 * codec, ahead of the per-level loop, so the default level's (Greedy)
 * params stand in for the whole ladder: every level's bound only differs
 * by strategy, not by a caller-chosen block size any more. */
static size_t crushlzfse_bound_default(size_t n) {
    crushlzfse_encode_params p;
    crushlzfse_params_for_level(CRUSHLZFSE_LEVEL_DEFAULT, &p);
    return crushlzfse_encode_bound(n, &p);
}
static size_t crushlzvn_bound_default(size_t n) {
    crushlzvn_encode_params p;
    crushlzvn_params_for_level(CRUSHLZVN_LEVEL_DEFAULT, &p);
    return crushlzvn_encode_bound(n, &p);
}

/* The encoders differ only in their dst/src pointer types. */
static size_t enc_lzfse(uint8_t *d, size_t dc, const uint8_t *s, size_t sl, void *sc, size_t scn, int lv)
{ return crushlzfse_encode_buffer(d, dc, s, sl, sc, scn, lv); }
static size_t enc_lzvn(uint8_t *d, size_t dc, const uint8_t *s, size_t sl, void *sc, size_t scn, int lv)
{ return crushlzvn_encode_buffer(d, dc, s, sl, sc, scn, lv); }
static size_t enc_zbm(uint8_t *d, size_t dc, const uint8_t *s, size_t sl, void *sc, size_t scn, int lv)
{ return crushlzbitmap_encode_buffer(d, dc, s, sl, sc, scn, lv); }
static size_t enc_lz4(uint8_t *d, size_t dc, const uint8_t *s, size_t sl, void *sc, size_t scn, int lv)
{ return crushlz4_encode_buffer(d, dc, s, sl, sc, scn, lv); }

/* What a caller reusing one buffer across the ladder must work out itself. */
static size_t ladder_max(const codec *c)
{
    size_t max = 0;
    for (int level = c->level_min; level <= c->level_max; level++) {
        size_t n = c->size_for_level(level);
        if (n > max) max = n;
    }
    return max;
}

static void run(const codec *c, const uint8_t *src, size_t slen)
{
    size_t any = ladder_max(c);
    size_t cap = c->bound(slen);
    uint8_t *dst = malloc(cap);
    /* One guard byte past the carve catches an off-by-one overrun. */
    uint8_t *scratch = malloc(any + 1);

    if (!dst || !scratch) { fail(c->name, 0, "out of memory"); free(dst); free(scratch); return; }

    checks++;
    if (any == 0) fail(c->name, 0, "no level reports a scratch size");

    for (int level = c->level_min; level <= c->level_max; level++) {
        size_t want = c->size_for_level(level);

        /* 1. every level reports a size, inside the ladder's maximum */
        checks++;
        if (want == 0 || want > any)
            fail(c->name, level, "level's scratch size is 0 or above the ladder maximum");

        /* 2. exactly enough encodes, and stays inside its carve */
        checks++;
        memset(scratch, 0, any + 1);
        scratch[want] = GUARD;
        if (c->encode(dst, cap, src, slen, scratch, want, level) == 0)
            fail(c->name, level, "encode refused a scratch of exactly scratch_size(params)");
        else if (scratch[want] != GUARD)
            fail(c->name, level, "encode wrote past scratch_size(params)");

        /* 3. one byte short is refused rather than overrun */
        if (want > 0) {
            checks++;
            memset(scratch, 0, any + 1);
            scratch[want - 1] = GUARD;
            if (c->encode(dst, cap, src, slen, scratch, want - 1, level) != 0)
                fail(c->name, level, "encode accepted an undersized scratch");
            else if (scratch[want - 1] != GUARD)
                fail(c->name, level, "refused encode still wrote into the buffer");
        }
    }
    free(dst);
    free(scratch);
}

int main(void)
{
    uint8_t *src = malloc(SRC_SZ);
    if (!src) { printf("FAIL out of memory\n"); return 1; }
    fill(src, SRC_SZ);

    const codec codecs[] = {
        { "crushlzfse", CRUSHLZFSE_LEVEL_MIN, CRUSHLZFSE_LEVEL_MAX,
          crushlzfse_size_for_level, enc_lzfse, crushlzfse_bound_default, LZFSE_LZVN_SRC_SZ },
        { "crushlzvn", CRUSHLZVN_LEVEL_MIN, CRUSHLZVN_LEVEL_MAX,
          crushlzvn_size_for_level, enc_lzvn, crushlzvn_bound_default, LZFSE_LZVN_SRC_SZ },
        { "lzbitmap", CRUSHLZBITMAP_LEVEL_MIN, CRUSHLZBITMAP_LEVEL_MAX,
          crushlzbitmap_size_for_level, enc_zbm, crushlzbitmap_encode_bound, SRC_SZ },
        { "crushlz4", CRUSHLZ4_LEVEL_MIN, CRUSHLZ4_LEVEL_MAX,
          crushlz4_size_for_level, enc_lz4, crushlz4_encode_bound, SRC_SZ },
    };

    for (size_t i = 0; i < sizeof codecs / sizeof codecs[0]; i++)
        run(&codecs[i], src, codecs[i].src_len);

    free(src);
    printf("\nscratch_contract_test: %d checks, %d failures\n", checks, failures);
    if (!checks) {
        printf("NO CHECKS RAN: treating as failure\n");
        return 1;
    }
    return failures != 0;
}
