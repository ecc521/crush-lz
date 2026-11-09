// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#ifndef CRUSHLZ_HARNESS_ENGINES_H
#define CRUSHLZ_HARNESS_ENGINES_H

#include <stddef.h>
#include <stdint.h>

/* A codec as the harness sees it: encode at a level, decode, and a reusable
 * per-thread state. The bench and the oracle drive every codec through this
 * table, so adding one means adding a table entry in engines.c. */

typedef struct engine engine;

/* Engines sharing a format emit interchangeable bitstreams, which is what
 * lets the oracle decode one engine's output with another's decoder. */
typedef enum {
    FMT_DEFLATE,
    FMT_LZVN,
    FMT_LZFSE,
    FMT_LZBITMAP,
    FMT_LZ4,
    FMT_LZMESH,
    FMT_ZSTD,
    FMT_COUNT
} format_id;

/* Who wrote the encoder. Engine names are unprefixed for ours and prefixed
 * for anyone else's (`apple-`). */
typedef enum {
    ORIGIN_OURS,
    ORIGIN_APPLE,     /* libcompression */
    ORIGIN_REFERENCE  /* calibration only, not a decmpfs option */
} origin_id;

struct engine {
    const char *name;
    format_id   format;
    origin_id   origin;

    int level_min;
    int level_max;
    int level_default;

    /* decmpfs compression type for the xattr form, or 0 for formats the
     * kernel cannot decode. */
    int decmpfs_type;

    /* Non-zero when this engine was compiled in; absent ones stay in the
     * table as inactive rows. */
    int available;

    /* Scratch is sized for the level this state will encode at, so the
     * level comes in here rather than at encode time. Decoders take no
     * scratch, so a decode-only state can be made at any level. */
    void *(*state_new)(int level);
    void  (*state_free)(void *state);

    /* Compressed size, or 0 if the input did not compress or encoding
     * failed. */
    size_t (*encode)(void *state, uint8_t *dst, size_t dcap,
                     const uint8_t *src, size_t slen, int level);

    /* Decompressed size, or 0 on failure. */
    size_t (*decode)(void *state, uint8_t *dst, size_t dcap,
                     const uint8_t *src, size_t slen);

    /* For an encoder that carries state from one block to the next: called
     * before each file's first block. NULL for independent blocks. */
    void (*reset)(void *state);
};

const engine *engines_all(size_t *count);
const engine *engine_by_name(const char *name);
const char   *format_name(format_id f);
const char   *origin_name(origin_id o);

/* Every engine that can decode `f`, for cross-decoder verification. Writes
 * at most `cap` pointers, returns how many were written. */
size_t engines_decoders_for_format(format_id f, const engine **out, size_t cap);

#endif /* CRUSHLZ_HARNESS_ENGINES_H */
