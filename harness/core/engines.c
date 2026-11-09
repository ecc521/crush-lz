// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#include "engines.h"

#include <stdlib.h>
#include <string.h>

#include "crushlz4.h"
#include "crushlzbitmap.h"
#include "crushlzfse.h"
#include "crushlzmesh.h"
#include "crushlzvn.h"

#include <zlib.h>

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#ifdef HAVE_ZOPFLI
#include <zopfli.h>
#endif

#ifdef __APPLE__
#include <compression.h>
/* COMPRESSION_LZVN was dropped from the public enum in recent SDKs, but
 * libcompression still implements it at its long-stable value. */
#ifndef COMPRESSION_LZVN
#define COMPRESSION_LZVN ((compression_algorithm)0x900)
#endif
#ifndef COMPRESSION_LZMESH
#define COMPRESSION_LZMESH ((compression_algorithm)0xE05)
#endif
#endif

/* ---------------------------------------------------------------- shared */

/* The per-worker state of every engine of ours: one encoder scratch, sized
 * once for the largest level so any level can be encoded with it. The
 * decoders take no scratch. */
typedef struct {
    void *scratch;
    size_t bytes;   /* the encoders check their carve against this */
} scratch_state;

static void *scratch_state_new(size_t n) {
    scratch_state *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->scratch = calloc(1, n ? n : 1);
    if (!s->scratch) { free(s); return NULL; }
    s->bytes = n;
    return s;
}

static void scratch_state_free(void *st) {
    scratch_state *s = st;
    if (!s) return;
    free(s->scratch);
    free(s);
}

static void *scratch_of(void *st) {
    return st ? ((scratch_state *)st)->scratch : NULL;
}

static size_t scratch_bytes_of(void *st) {
    return st ? ((scratch_state *)st)->bytes : 0;
}

/* ------------------------------------------------------------------ zlib */

static size_t zlib_encode(void *st, uint8_t *dst, size_t dcap,
                          const uint8_t *src, size_t slen, int level) {
    (void)st;
    uLongf out = (uLongf)dcap;
    if (compress2(dst, &out, src, (uLong)slen, level) != Z_OK) return 0;
    return (size_t)out;
}

static size_t zlib_decode(void *st, uint8_t *dst, size_t dcap,
                          const uint8_t *src, size_t slen) {
    (void)st;
    uLongf out = (uLongf)dcap;
    if (uncompress(dst, &out, src, (uLong)slen) != Z_OK) return 0;
    return (size_t)out;
}

/* ---------------------------------------------------------------- zopfli */

#ifdef HAVE_ZOPFLI
/* The same zlib-wrapped DEFLATE bitstream `zlib` emits (decmpfs type 3/4),
 * from an iterative optimal parse instead of a greedy one. Decoding is plain
 * zlib, so it shares FMT_DEFLATE with the zlib row. The level is
 * numiterations; the ratio curve is nearly flat past 5. */
static size_t zopfli_encode(void *st, uint8_t *dst, size_t dcap,
                            const uint8_t *src, size_t slen, int level) {
    (void)st;
    ZopfliOptions opt;
    ZopfliInitOptions(&opt);
    opt.numiterations = level;
    unsigned char *out = NULL;
    size_t out_size = 0;
    ZopfliCompress(&opt, ZOPFLI_FORMAT_ZLIB, src, slen, &out, &out_size);
    if (!out) return 0;
    size_t ret = (out_size <= dcap) ? out_size : 0;
    if (ret) memcpy(dst, out, out_size);
    free(out);
    return ret;
}
#endif

/* ------------------------------------------------------------ crushlzfse */

static void *crushlzfse_state_new(int level) {
    crushlzfse_encode_params params;
    crushlzfse_params_for_level(level, &params);
    return scratch_state_new(crushlzfse_scratch_size(&params));
}

static size_t crushlzfse_encode_e(void *st, uint8_t *dst, size_t dcap,
                                  const uint8_t *src, size_t slen, int level) {
    return crushlzfse_encode_buffer(dst, dcap, src, slen, scratch_of(st), scratch_bytes_of(st), level);
}

static size_t crushlzfse_decode_e(void *st, uint8_t *dst, size_t dcap,
                                  const uint8_t *src, size_t slen) {
    (void)st;
    size_t out = 0;
    if (crushlzfse_decode_buffer(dst, dcap, src, slen, &out) != 0) return 0;
    return out;
}

/* A scratch_state first, so scratch_of and scratch_state_free apply. */
typedef struct {
    scratch_state base;
    crushlzfse_stats stats;
} crushlzfse_chain_state;

static void *crushlzfse_chain_state_new(int level) {
    crushlzfse_encode_params params;
    crushlzfse_params_for_level(level, &params);
    size_t n = crushlzfse_scratch_size(&params);
    crushlzfse_chain_state *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->base.scratch = calloc(1, n ? n : 1);
    if (!s->base.scratch) { free(s); return NULL; }
    s->base.bytes = n;
    return s;
}

static crushlzfse_stats *chain_stats_of(void *st) {
    return &((crushlzfse_chain_state *)st)->stats;
}

static void crushlzfse_chain_reset(void *st) {
    memset(chain_stats_of(st), 0, sizeof(crushlzfse_stats));
}

static size_t crushlzfse_chain_encode_e(void *st, uint8_t *dst, size_t dcap,
                                        const uint8_t *src, size_t slen, int level) {
    crushlzfse_encode_params params;
    crushlzfse_params_for_level(level, &params);
    return crushlzfse_encode_buffer_chained(dst, dcap, src, slen, scratch_of(st), scratch_bytes_of(st), &params,
                                            chain_stats_of(st));
}

/* ------------------------------------------------------------- crushlzvn */

static void *crushlzvn_state_new(int level) {
    crushlzvn_encode_params params;
    crushlzvn_params_for_level(level, &params);
    return scratch_state_new(crushlzvn_scratch_size(&params));
}

static size_t crushlzvn_encode_e(void *st, uint8_t *dst, size_t dcap,
                                 const uint8_t *src, size_t slen, int level) {
    return crushlzvn_encode_buffer(dst, dcap, src, slen, scratch_of(st), scratch_bytes_of(st), level);
}

static size_t crushlzvn_decode_e(void *st, uint8_t *dst, size_t dcap,
                                 const uint8_t *src, size_t slen) {
    (void)st;
    size_t out = 0;
    if (crushlzvn_decode_buffer(dst, dcap, src, slen, &out) != 0) return 0;
    return out;
}

/* -------------------------------------------------------------- lzbitmap */

static void *lzbitmap_state_new(int level) {
    crushlzbitmap_params params;
    crushlzbitmap_params_for_level(level, &params);
    return scratch_state_new(crushlzbitmap_scratch_size(&params));
}

static size_t lzbitmap_encode_e(void *st, uint8_t *dst, size_t dcap,
                                const uint8_t *src, size_t slen, int level) {
    return crushlzbitmap_encode_buffer(dst, dcap, src, slen, scratch_of(st), scratch_bytes_of(st), level);
}

static size_t lzbitmap_decode_e(void *st, uint8_t *dst, size_t dcap,
                                const uint8_t *src, size_t slen) {
    (void)st;
    size_t out = 0;
    if (crushlzbitmap_decode_buffer(dst, dcap, src, slen, &out) != 0) return 0;
    return out;
}

/* -------------------------------------------------------------- crushlz4 */

static void *crushlz4_state_new(int level) {
    crushlz4_encode_params params;
    crushlz4_params_for_level(level, &params);
    return scratch_state_new(crushlz4_scratch_size(&params));
}

static size_t crushlz4_encode_e(void *st, uint8_t *dst, size_t dcap,
                                const uint8_t *src, size_t slen, int level) {
    return crushlz4_encode_buffer(dst, dcap, src, slen, scratch_of(st), scratch_bytes_of(st), level);
}

static size_t crushlz4_decode_e(void *st, uint8_t *dst, size_t dcap,
                                const uint8_t *src, size_t slen) {
    (void)st;
    size_t out = 0;
    if (crushlz4_decode_buffer(dst, dcap, src, slen, &out) != 0) return 0;
    return out;
}

/* ---------------------------------------------------------------- lzmesh */

static void *lzmesh_state_new(int level) {
    crushlzmesh_params params;
    crushlzmesh_params_for_level(level, &params);
    return scratch_state_new(crushlzmesh_encode_scratch_buffer_size(&params));
}

static size_t lzmesh_encode_e(void *st, uint8_t *dst, size_t dcap,
                              const uint8_t *src, size_t slen, int level) {
    crushlzmesh_params params;
    crushlzmesh_params_for_level(level, &params);
    return crushlzmesh_encode_buffer(dst, dcap, src, slen, scratch_of(st), &params);
}

static size_t lzmesh_decode_e(void *st, uint8_t *dst, size_t dcap,
                              const uint8_t *src, size_t slen) {
    (void)st;
    size_t out = 0;
    if (crushlzmesh_decode_buffer(dst, dcap, src, slen, &out) != 0) return 0;
    return out;
}

/* ----------------------------------------------------------------- apple */

#ifdef __APPLE__
static size_t apple_encode(uint8_t *dst, size_t dcap, const uint8_t *src,
                           size_t slen, compression_algorithm algo) {
    return compression_encode_buffer(dst, dcap, src, slen, NULL, algo);
}

static size_t apple_decode(uint8_t *dst, size_t dcap, const uint8_t *src,
                           size_t slen, compression_algorithm algo) {
    return compression_decode_buffer(dst, dcap, src, slen, NULL, algo);
}

#define APPLE_ENGINE(fn, algo)                                                \
    static size_t fn##_encode_e(void *st, uint8_t *dst, size_t dcap,          \
                                const uint8_t *src, size_t slen, int level) { \
        (void)st; (void)level;                                                \
        return apple_encode(dst, dcap, src, slen, algo);                      \
    }                                                                         \
    static size_t fn##_decode_e(void *st, uint8_t *dst, size_t dcap,          \
                                const uint8_t *src, size_t slen) {            \
        (void)st;                                                             \
        return apple_decode(dst, dcap, src, slen, algo);                      \
    }

APPLE_ENGINE(apple_lzfse, COMPRESSION_LZFSE)
APPLE_ENGINE(apple_lzvn, COMPRESSION_LZVN)
APPLE_ENGINE(apple_lzbitmap, COMPRESSION_LZBITMAP)
APPLE_ENGINE(apple_lz4, COMPRESSION_LZ4)
APPLE_ENGINE(apple_lzmesh, COMPRESSION_LZMESH)
#endif

/* ------------------------------------------------------------------ zstd */

#ifdef HAVE_ZSTD
/* One context per worker: ZSTD_compress allocates and frees one per call,
 * which at the high levels is a large share of a 64 KiB block's time. */
static void *zstd_state_new(int level) {
    (void)level;
    return ZSTD_createCCtx();
}

static void zstd_state_free(void *st) {
    ZSTD_freeCCtx((ZSTD_CCtx *)st);
}

static size_t zstd_encode_e(void *st, uint8_t *dst, size_t dcap,
                            const uint8_t *src, size_t slen, int level) {
    size_t r = ZSTD_compressCCtx((ZSTD_CCtx *)st, dst, dcap, src, slen, level);
    return ZSTD_isError(r) ? 0 : r;
}

static size_t zstd_decode_e(void *st, uint8_t *dst, size_t dcap,
                            const uint8_t *src, size_t slen) {
    (void)st;
    size_t r = ZSTD_decompress(dst, dcap, src, slen);
    return ZSTD_isError(r) ? 0 : r;
}
#endif

/* -------------------------------------------------------------- registry */

#define UNAVAILABLE(nm, fmt, org, type)                                       \
    { nm, fmt, org, 0, 0, 0, type, 0, NULL, NULL, NULL, NULL, NULL }

static const engine ENGINES[] = {
    { "zlib", FMT_DEFLATE, ORIGIN_REFERENCE, 1, 9, 9, 3, 1,
      NULL, NULL, zlib_encode, zlib_decode, NULL },
#ifdef HAVE_ZOPFLI
    { "zopfli", FMT_DEFLATE, ORIGIN_REFERENCE, 1, 50, 5, 3, 1,
      NULL, NULL, zopfli_encode, zlib_decode, NULL },
#else
    UNAVAILABLE("zopfli", FMT_DEFLATE, ORIGIN_REFERENCE, 3),
#endif

    { "crushlzvn", FMT_LZVN, ORIGIN_OURS, CRUSHLZVN_LEVEL_MIN, CRUSHLZVN_LEVEL_MAX,
      CRUSHLZVN_LEVEL_DEFAULT, 7, 1,
      crushlzvn_state_new, scratch_state_free, crushlzvn_encode_e, crushlzvn_decode_e, NULL },

    { "crushlzfse", FMT_LZFSE, ORIGIN_OURS, CRUSHLZFSE_LEVEL_MIN, CRUSHLZFSE_LEVEL_MAX,
      CRUSHLZFSE_LEVEL_DEFAULT, 11, 1,
      crushlzfse_state_new, scratch_state_free, crushlzfse_encode_e, crushlzfse_decode_e, NULL },

    /* Chained within each file (crushlzfse_encode_buffer_chained). Not in
     * the default selection, and leaves decoding to the crushlzfse row. */
    { "crushlzfse-chain", FMT_LZFSE, ORIGIN_OURS, CRUSHLZFSE_LEVEL_MIN, CRUSHLZFSE_LEVEL_MAX,
      CRUSHLZFSE_LEVEL_DEFAULT, 11, 1,
      crushlzfse_chain_state_new, scratch_state_free, crushlzfse_chain_encode_e, NULL,
      crushlzfse_chain_reset },

    { "lzbitmap", FMT_LZBITMAP, ORIGIN_OURS, CRUSHLZBITMAP_LEVEL_MIN, CRUSHLZBITMAP_LEVEL_MAX,
      CRUSHLZBITMAP_LEVEL_DEFAULT, 13, 1,
      lzbitmap_state_new, scratch_state_free, lzbitmap_encode_e, lzbitmap_decode_e, NULL },

    { "crushlz4", FMT_LZ4, ORIGIN_OURS, CRUSHLZ4_LEVEL_MIN, CRUSHLZ4_LEVEL_MAX,
      CRUSHLZ4_LEVEL_DEFAULT, 15, 1,
      crushlz4_state_new, scratch_state_free, crushlz4_encode_e, crushlz4_decode_e, NULL },

    /* No decmpfs type: LZMESH is a libcompression format only. */
    { "lzmesh", FMT_LZMESH, ORIGIN_OURS, CRUSHLZMESH_LEVEL_MIN, CRUSHLZMESH_LEVEL_MAX,
      CRUSHLZMESH_LEVEL_DEFAULT, 0, 1,
      lzmesh_state_new, scratch_state_free, lzmesh_encode_e, lzmesh_decode_e, NULL },

#ifdef __APPLE__
    { "apple-lzvn", FMT_LZVN, ORIGIN_APPLE, 0, 0, 0, 7, 1,
      NULL, NULL, apple_lzvn_encode_e, apple_lzvn_decode_e, NULL },
    { "apple-lzfse", FMT_LZFSE, ORIGIN_APPLE, 0, 0, 0, 11, 1,
      NULL, NULL, apple_lzfse_encode_e, apple_lzfse_decode_e, NULL },
    { "apple-lzbitmap", FMT_LZBITMAP, ORIGIN_APPLE, 0, 0, 0, 13, 1,
      NULL, NULL, apple_lzbitmap_encode_e, apple_lzbitmap_decode_e, NULL },
    { "apple-lz4", FMT_LZ4, ORIGIN_APPLE, 0, 0, 0, 15, 1,
      NULL, NULL, apple_lz4_encode_e, apple_lz4_decode_e, NULL },
    { "apple-lzmesh", FMT_LZMESH, ORIGIN_APPLE, 0, 0, 0, 0, 1,
      NULL, NULL, apple_lzmesh_encode_e, apple_lzmesh_decode_e, NULL },
#else
    UNAVAILABLE("apple-lzvn", FMT_LZVN, ORIGIN_APPLE, 7),
    UNAVAILABLE("apple-lzfse", FMT_LZFSE, ORIGIN_APPLE, 11),
    UNAVAILABLE("apple-lzbitmap", FMT_LZBITMAP, ORIGIN_APPLE, 13),
    UNAVAILABLE("apple-lz4", FMT_LZ4, ORIGIN_APPLE, 15),
    UNAVAILABLE("apple-lzmesh", FMT_LZMESH, ORIGIN_APPLE, 0),
#endif

    /* decmpfs type 0: not a kernel-decodable format, so never a shippable
     * option. Present as calibration against the wider compression world,
     * which is what shows what the decmpfs format constraint costs. */
#ifdef HAVE_ZSTD
    { "zstd", FMT_ZSTD, ORIGIN_REFERENCE, 1, 22, 19, 0, 1,
      zstd_state_new, zstd_state_free, zstd_encode_e, zstd_decode_e, NULL },
#else
    UNAVAILABLE("zstd", FMT_ZSTD, ORIGIN_REFERENCE, 0),
#endif
};

static const char *FORMAT_NAMES[FMT_COUNT] = {
    "deflate", "lzvn", "lzfse", "lzbitmap", "lz4", "lzmesh", "zstd",
};

const engine *engines_all(size_t *count) {
    *count = sizeof(ENGINES) / sizeof(ENGINES[0]);
    return ENGINES;
}

const engine *engine_by_name(const char *name) {
    size_t n;
    const engine *all = engines_all(&n);
    for (size_t i = 0; i < n; i++)
        if (strcmp(all[i].name, name) == 0) return &all[i];
    return NULL;
}

const char *origin_name(origin_id o) {
    switch (o) {
        case ORIGIN_OURS:      return "ours";
        case ORIGIN_APPLE:     return "APPLE";
        case ORIGIN_REFERENCE: return "reference";
    }
    return "?";
}

const char *format_name(format_id f) {
    return (f >= 0 && f < FMT_COUNT) ? FORMAT_NAMES[f] : "?";
}

size_t engines_decoders_for_format(format_id f, const engine **out, size_t cap) {
    size_t n, found = 0;
    const engine *all = engines_all(&n);
    for (size_t i = 0; i < n && found < cap; i++)
        if (all[i].format == f && all[i].available && all[i].decode)
            out[found++] = &all[i];
    return found;
}
