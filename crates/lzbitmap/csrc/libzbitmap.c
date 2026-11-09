// SPDX-License-Identifier: MPL-2.0 AND MIT
/*
 * Copyright (c) 2022 Corellium LLC
 *
 * Author: Ernesto A. Fernández <ernesto@corellium.com>
 */
// Modifications copyright (c) 2026 Tucker Willenborg


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "crushlzbitmap.h"

/* The encoder reads byte lanes out of native-order words throughout, so it
 * writes invalid streams on a big-endian host; refuse to build there rather
 * than corrupt data quietly. Every Apple and x86 target is little-endian. */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#error "libzbitmap supports little-endian hosts only"
#endif

/* Internal status codes; the public entry points map them. */
#define ZBM_NOMEM       (-1)
#define ZBM_INVAL       (-2)
#define ZBM_RANGE       (-3)
#define ZBM_OVERFLOW    (-4)

#define MIN(x, y)   ((x) > (y) ? (y) : (x))

#define ZBM_MAGIC       "ZBM\x09"
#define ZBM_MAGIC_SZ    4

/*
 * This encoder takes a vector fast path on ARM NEON and x86 SSE4.1+POPCNT;
 * every other target, and CRUSH_SIMD_PORTABLE builds requesting it
 * explicitly, get the scalar branch of crush_simd.h instead. No #error here:
 * crush_simd.h itself decides, and by the time it is included below,
 * CRUSH_SIMD_PORTABLE reflects that decision for the rest of this file.
 */

/*
 * ZBM_TEST_DECODER_FALLBACK compiles out the per-block and per-run fast paths,
 * leaving the generic per-byte loop that defines the format;
 * harness/conformance/zbm_decoder_diff_test.c compares the two decoders.
 */
#ifdef ZBM_TEST_DECODER_FALLBACK
#define ZBM_DECODER_FAST_PATHS 0
#else
#define ZBM_DECODER_FAST_PATHS 1
#endif

/*
 * Lift the trailing bitmap table with two 64-bit loads instead of 120 bit
 * reads. Tied to ZBM_DECODER_FAST_PATHS so the fallback build keeps the
 * bit-at-a-time reader for the diff test.
 */
#if ZBM_DECODER_FAST_PATHS
#define ZBM_FAST_BITMAP_TABLE 1
#else
#define ZBM_FAST_BITMAP_TABLE 0
#endif

/*
 * Function and loop contracts for the CBMC proofs in harness/proofs. Outside
 * a proof build they expand to nothing. Clause order is fixed by CBMC:
 * requires, assigns, ensures on a function; assigns, invariant, decreases on
 * a loop. crush_simd.h uses them on its portable helpers, so they are
 * defined before it is included.
 */
#ifdef ZBM_PROOF
#define ZBM_REQUIRES(x)         __CPROVER_requires(x)
#define ZBM_ENSURES(x)          __CPROVER_ensures(x)
#define ZBM_ASSIGNS(...)        __CPROVER_assigns(__VA_ARGS__)
#define ZBM_LOOP_ASSIGNS(...)   __CPROVER_assigns(__VA_ARGS__)
#define ZBM_LOOP_INVARIANT(x)   __CPROVER_loop_invariant(x)
#define ZBM_LOOP_DECREASES(x)   __CPROVER_decreases(x)
#define ZBM_LOOP_ENTRY(x)       __CPROVER_loop_entry(x)
#define ZBM_OLD(x)              __CPROVER_old(x)
#else
#define ZBM_REQUIRES(x)
#define ZBM_ENSURES(x)
#define ZBM_ASSIGNS(...)
#define ZBM_LOOP_ASSIGNS(...)
#define ZBM_LOOP_INVARIANT(x)
#define ZBM_LOOP_DECREASES(x)
#endif

/*
 * Branch-free literal blend and the block loop that uses it. Both rely on
 * `period >= 8`: the 8-byte copy source then lies strictly before the block,
 * so a block is a bulk load of the periodic baseline with the literals blended
 * over it. zbm_blend_row[bmp] holds eight TBL selectors and the literal count
 * in byte 8. The blend reads a full 8 literal bytes regardless of how many the
 * bitmap consumes, so every caller must first establish that 8 are readable.
 */
#include "crush_simd.h"
#include "zbm_blend_tables.h"

static inline void zbm_blend8(uint8_t *dst, const uint8_t *base,
                               const uint8_t *lits, uint8_t bmp)
ZBM_REQUIRES(__CPROVER_r_ok(base, 8) && __CPROVER_r_ok(lits, 8))
ZBM_REQUIRES(__CPROVER_w_ok(dst, 8))
ZBM_ASSIGNS(__CPROVER_object_upto(dst, 8))
{
    zbm_blend8_row(dst, base, lits, zbm_blend_row[bmp]);
}


/*
 * Forward copy of @n bytes from a source that does not overlap the
 * destination (before it, after it or in another buffer). The overlapping tail stores rewrite
 * bytes already written with the same values; nothing outside [d, d+n) is
 * written and nothing outside [s, s+n) is read. @n is at most one chunk:
 * within 32 of 2^32, `i + 32` would wrap and the loop would not stop.
 */
static inline void zbm_copy_fwd(uint8_t *d, const uint8_t *s, uint32_t n)
ZBM_REQUIRES(n <= CRUSHLZBITMAP_CHUNK_SIZE)
ZBM_REQUIRES(__CPROVER_w_ok(d, n) && __CPROVER_r_ok(s, n))
ZBM_REQUIRES(!__CPROVER_same_object(d, s) || s + n <= d || d + n <= s)
ZBM_ASSIGNS(__CPROVER_object_upto(d, n))
{
    uint32_t i = 0;

    if(n <= 64) {
        if(n >= 32) {
            zbm_cpy16(d, s);
            zbm_cpy16(d + 16, s + 16);
            zbm_cpy16(d + n - 32, s + n - 32);
            zbm_cpy16(d + n - 16, s + n - 16);
            return;
        }
        if(n >= 16) {
            zbm_cpy16(d, s);
            zbm_cpy16(d + n - 16, s + n - 16);
            return;
        }
        if(n >= 8) {
            zbm_cpy8(d, s);
            zbm_cpy8(d + n - 8, s + n - 8);
            return;
        }
        for(; i < n; ++i)
            ZBM_LOOP_ASSIGNS(i, __CPROVER_object_upto(d, n))
            ZBM_LOOP_INVARIANT(i <= n)
            ZBM_LOOP_DECREASES(n - i)
            d[i] = s[i];
        return;
    }
    for(; i + 32 <= n; i += 32)
        ZBM_LOOP_ASSIGNS(i, __CPROVER_object_upto(d, n))
        ZBM_LOOP_INVARIANT(i <= n)
        ZBM_LOOP_DECREASES(n - i)
        zbm_cpy32(d + i, s + i);
    if(i < n) {
        zbm_cpy16(d + n - 32, s + n - 32);
        zbm_cpy16(d + n - 16, s + n - 16);
    }
}

struct uint24 {
    uint8_t     low;
    uint8_t     mid;
    uint8_t     hig;
};

/* This header is shared by both compressed and decompressed chunks */
struct zbm_chunk_hdr {
    struct uint24   len;        /* Length of the chunk */
    struct uint24   decmp_len;  /* Length of the chunk after decompression */
};

/* The full header for compressed chunks */
struct zbm_cmp_chunk_hdr {
    /* Shared with decompressed chunks */
    struct zbm_chunk_hdr hdr;

    /* Offset for each of the three metadata areas */
    struct uint24   meta_off_1;
    struct uint24   meta_off_2;
    struct uint24   meta_off_3;
};

/* Pointer to a half-byte */
struct nybl_ptr {
    uint8_t         *addr;  /* Address of the byte */
    int             nibble; /* Which of the two nibbles? */
};

/* 0-2 and 0xf are not real bitmap indexes */
#define ZBM_BITMAP_COUNT        (16 - 1 - 3)
#define ZBM_BITMAP_BASE         3
#define ZBM_BITMAP_BYTECNT      17
#define ZBM_MAX_PERIOD_BYTECNT  2

struct zbm_bmap {
    uint8_t     bitmap;         /* The bitmap */
    uint8_t     period_bytecnt; /* Read this many bytes to get the new period */
};

struct zbm_state {
    /* Updated during a chunk read */
    uint8_t         *dest;      /* Write the next byte here */
    size_t          dest_left;  /* Room left in destination buffer */
    uint32_t        written;    /* Bytes written so far for current chunk */
    uint16_t        period;     /* Repetition period for decompression, in bytes */

    /* Updated right before a chunk read */
    const uint8_t   *src_end;   /* End of current chunk */
    uint32_t        len;        /* Length of the chunk */
    uint32_t        decmp_len;  /* Expected chunk length after decompression */

    /* Updated after a chunk read */
    const uint8_t   *src;       /* Start of buffer, or current chunk if any */
    size_t          src_left;   /* Room left in the source buffer */
    size_t          prewritten; /* Bytes written for previous chunks */

    /* Current position in data and metadata areas for this chunk */
    const uint8_t   *data;
    const uint8_t   *meta_1;
    const uint8_t   *meta_2;
    struct nybl_ptr meta_3;

    /* Array of bitmaps for the current chunk */
    struct zbm_bmap bitmaps[ZBM_BITMAP_COUNT];
};

#ifdef ZBM_PROOF
/*
 * What the proofs know about a state while a compressed chunk decodes: the
 * chunk src[0, len) is readable and every cursor lies inside it; the output
 * so far, prewritten + written bytes, is readable just before dest; and
 * dest has room for the rest of the chunk.
 */
/* Ranges a[0, an) and b[0, bn) share no byte: the API's "separate storage
 * ranges", which need not be separate objects. */
#define ZBM_DISJOINT(a, an, b, bn)                                           \
    (!__CPROVER_same_object((a), (b)) ||                                      \
     (size_t)__CPROVER_POINTER_OFFSET(a) + (an) <=                            \
         (size_t)__CPROVER_POINTER_OFFSET(b) ||                               \
     (size_t)__CPROVER_POINTER_OFFSET(b) + (bn) <=                            \
         (size_t)__CPROVER_POINTER_OFFSET(a))
#define ZBM_IN_CHUNK(st, p)                                                  \
    (__CPROVER_same_object((p), (st)->src) &&                                 \
     __CPROVER_POINTER_OFFSET(p) >= __CPROVER_POINTER_OFFSET((st)->src) &&     \
     __CPROVER_POINTER_OFFSET(p) <= __CPROVER_POINTER_OFFSET((st)->src_end))
#define ZBM_OUT_OK(st)                                                       \
    ((st)->written <= (st)->decmp_len &&                                      \
     (st)->decmp_len <= CRUSHLZBITMAP_CHUNK_SIZE &&                           \
     __CPROVER_w_ok((st)->dest, (st)->decmp_len - (st)->written) &&           \
     (st)->prewritten + (st)->written <=                                      \
         (size_t)__CPROVER_POINTER_OFFSET((st)->dest) &&                      \
     __CPROVER_r_ok((st)->dest - ((st)->prewritten + (st)->written),          \
                    (st)->prewritten + (st)->written))
#define ZBM_STATE_OK(st)                                                     \
    (__CPROVER_r_ok((st)->src, (st)->len) &&                                  \
     (st)->src_end == (st)->src + (st)->len &&                                \
     ZBM_IN_CHUNK(st, (st)->data) && ZBM_IN_CHUNK(st, (st)->meta_1) &&        \
     ZBM_IN_CHUNK(st, (st)->meta_2) && ZBM_IN_CHUNK(st, (st)->meta_3.addr) && \
     ((st)->meta_3.nibble == 0 || (st)->meta_3.nibble == 1) &&                \
     (st)->period >= 8 && ZBM_OUT_OK(st) &&                                   \
     ZBM_DISJOINT((st)->src, (st)->len, (st)->dest,                           \
                  (st)->decmp_len - (st)->written))
/* dest and dest_left move in step with written. */
#define ZBM_OUT_ADVANCED(st)                                                 \
    ((st)->written >= __CPROVER_old((st)->written) &&                         \
     (st)->dest == __CPROVER_old((st)->dest) +                                \
                   ((st)->written - __CPROVER_old((st)->written)) &&          \
     (st)->dest_left + (st)->written ==                                       \
         __CPROVER_old((st)->dest_left) + __CPROVER_old((st)->written))
/* A call that succeeds with output left to produce produces some. */
#define ZBM_PROGRESS(st)                                                     \
    (__CPROVER_return_value != 0 ||                                           \
     __CPROVER_old((st)->written) == (st)->decmp_len ||                       \
     (st)->written > __CPROVER_old((st)->written))
#define ZBM_STATUS                                                           \
    (__CPROVER_return_value == 0 || __CPROVER_return_value == ZBM_INVAL)
#define ZBM_TABLE_OK(st) \
    ((st)->bitmaps[0].period_bytecnt <= 2 && \
     (st)->bitmaps[1].period_bytecnt <= 2 && \
     (st)->bitmaps[2].period_bytecnt <= 2 && \
     (st)->bitmaps[3].period_bytecnt <= 2 && \
     (st)->bitmaps[4].period_bytecnt <= 2 && \
     (st)->bitmaps[5].period_bytecnt <= 2 && \
     (st)->bitmaps[6].period_bytecnt <= 2 && \
     (st)->bitmaps[7].period_bytecnt <= 2 && \
     (st)->bitmaps[8].period_bytecnt <= 2 && \
     (st)->bitmaps[9].period_bytecnt <= 2 && \
     (st)->bitmaps[10].period_bytecnt <= 2 && \
     (st)->bitmaps[11].period_bytecnt <= 2)
#define ZBM_PBC_PREFIX_OK(p, n) \
    (((n) <= 0 || (p)[0] <= 2) && \
     ((n) <= 1 || (p)[1] <= 2) && \
     ((n) <= 2 || (p)[2] <= 2) && \
     ((n) <= 3 || (p)[3] <= 2) && \
     ((n) <= 4 || (p)[4] <= 2) && \
     ((n) <= 5 || (p)[5] <= 2) && \
     ((n) <= 6 || (p)[6] <= 2) && \
     ((n) <= 7 || (p)[7] <= 2) && \
     ((n) <= 8 || (p)[8] <= 2) && \
     ((n) <= 9 || (p)[9] <= 2) && \
     ((n) <= 10 || (p)[10] <= 2) && \
     ((n) <= 11 || (p)[11] <= 2) && \
     ((n) <= 12 || (p)[12] <= 2) && \
     ((n) <= 13 || (p)[13] <= 2) && \
     ((n) <= 14 || (p)[14] <= 2) && \
     ((n) <= 15 || (p)[15] <= 2))
#define ZBM_SELECTOR_OK(st, begin) \
    (ZBM_IN_CHUNK(st, begin) && \
     __CPROVER_POINTER_OFFSET((st)->meta_3.addr) >= __CPROVER_POINTER_OFFSET(begin))
#define ZBM_LOCAL_OK(st, d, lit, m1, m2, m3, per, a, start, finish, dstart, selector_off) \
    ((selector_off) < (st)->len &&                                  \
     (start) <= (a) && (a) <= (finish) &&                                    \
     (d) == (dstart) + ((a) - (start)) &&                                    \
     ZBM_IN_CHUNK(st, lit) && ZBM_IN_CHUNK(st, m1) &&                        \
     ZBM_IN_CHUNK(st, m2) && ZBM_IN_CHUNK(st, (m3).addr) &&                   \
     ((m3).nibble == 0 || (m3).nibble == 1) &&                               \
     __CPROVER_POINTER_OFFSET((m3).addr) >=                                 \
         (__CPROVER_POINTER_OFFSET((st)->src) + (selector_off)) &&                \
     8 <= (per) && (per) <= UINT16_MAX)
#define ZBM_SAME_INPUT(st, previous)                                        \
    ((st)->src == previous((st)->src) &&                                    \
     (st)->src_end == previous((st)->src_end) &&                             \
     (st)->src_left == previous((st)->src_left) &&                           \
     (st)->len == previous((st)->len) &&                                     \
     (st)->decmp_len == previous((st)->decmp_len) &&                          \
     (st)->prewritten == previous((st)->prewritten))
#endif

/* The two period bytes as one little-endian load. Both call sites have
 * already established that two bytes are readable. */
static inline uint32_t zbm_load_u16le(const uint8_t *p)
{
    uint16_t v;

    memcpy(&v, p, sizeof(v));
    return v;
}

/*
 * Whether fewer than @n bytes remain between @p and @end. Compares addresses
 * as integers: `p + n > end` would form a pointer past the end of the input
 * whenever p is near it, which C leaves undefined even if nothing reads it.
 */
#define ZBM_SHORT(p, n, end)  ((uintptr_t)(p) + (n) > (uintptr_t)(end))

/*
 * One byte read through a cursor that a loop advances. The decoder's proofs
 * replace this by its contract, which returns an arbitrary byte: safety does
 * not depend on what the input says, and CBMC's loop contracts cannot afford
 * a direct read through a pointer the loop moves. It inlines to a plain load.
 */
static inline uint8_t zbm_rd8(const uint8_t *p)
ZBM_REQUIRES(__CPROVER_r_ok(p, 1))
ZBM_ASSIGNS()
{
    return *p;
}

static int zbm_check_magic(struct zbm_state *state)
{
    if(state->src_left < ZBM_MAGIC_SZ)
        return ZBM_INVAL;

    if(memcmp(state->src, ZBM_MAGIC, ZBM_MAGIC_SZ))
        return ZBM_INVAL;

    state->src += ZBM_MAGIC_SZ;
    state->src_left -= ZBM_MAGIC_SZ;
    return 0;
}

static uint32_t zbm_u24_to_u32(struct uint24 n)
{
    uint32_t res;

    res = n.hig;
    res <<= 8;
    res += n.mid;
    res <<= 8;
    res += n.low;
    return res;
}

/* Some chunks just have regular uncompressed data, but with a header */
static int zbm_chunk_is_uncompressed(struct zbm_state *state)
{
    return state->len == state->decmp_len + sizeof(struct zbm_chunk_hdr);
}

static int zbm_handle_uncompressed_chunk(struct zbm_state *state)
{
    state->meta_1 = state->meta_2 = NULL;
    state->meta_3.addr = NULL;
    state->meta_3.nibble = 0;
    state->data = state->src + sizeof(struct zbm_chunk_hdr);
    memcpy(state->dest, state->data, state->decmp_len);

    state->dest += state->decmp_len;
    state->dest_left -= state->decmp_len;
    state->written = state->decmp_len;
    return 0;
}

static int zbm_read_nibble(struct nybl_ptr *nybl, const uint8_t *limit, uint8_t *result)
{
    if(nybl->addr >= limit)
        return ZBM_INVAL;

    if(nybl->nibble == 0) {
        *result = zbm_rd8(nybl->addr) & 0xf;
        nybl->nibble = 1;
    } else {
        *result = (zbm_rd8(nybl->addr) >> 4) & 0xf;
        nybl->nibble = 0;
        ++nybl->addr;
    }
    return 0;
}

static void zbm_rewind_nibble(struct nybl_ptr *nybl)
{
    if(nybl->nibble == 0) {
        nybl->nibble = 1;
        --nybl->addr;
    } else {
        nybl->nibble = 0;
    }
}

/* Only the unusual standalone-0xf path needs history. Scan consumed selector
 * bytes instead of tracking an extra field through every optimized block. */
static uint8_t zbm_last_nonrepeat_nibble(struct nybl_ptr scan, const uint8_t *start)
ZBM_REQUIRES(scan.nibble == 0 || scan.nibble == 1)
ZBM_REQUIRES(__CPROVER_same_object(scan.addr, start) && scan.addr >= start)
ZBM_REQUIRES(__CPROVER_r_ok(start, (size_t)(scan.addr - start) + scan.nibble))
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value < 15)
{
    uint8_t n;
    while(scan.addr > start || scan.nibble)
        ZBM_LOOP_ASSIGNS(scan.addr, scan.nibble, n)
        ZBM_LOOP_INVARIANT(__CPROVER_same_object(scan.addr, start))
        ZBM_LOOP_INVARIANT(__CPROVER_POINTER_OFFSET(scan.addr) >= __CPROVER_POINTER_OFFSET(start))
        ZBM_LOOP_INVARIANT(__CPROVER_POINTER_OFFSET(scan.addr) <= __CPROVER_POINTER_OFFSET(ZBM_LOOP_ENTRY(scan.addr)))
        ZBM_LOOP_INVARIANT(scan.nibble == 0 || scan.nibble == 1)
        ZBM_LOOP_INVARIANT(scan.addr < ZBM_LOOP_ENTRY(scan.addr) || scan.nibble <= ZBM_LOOP_ENTRY(scan.nibble))
        ZBM_LOOP_DECREASES((size_t)(scan.addr - start) * 2 + scan.nibble)
    {
        zbm_rewind_nibble(&scan);
        n = (uint8_t)((zbm_rd8(scan.addr) >> (4 * scan.nibble)) & 15);
        if(n != 15)
            return n;
    }
    return 0;
}

/* Contract proved in harness/proofs/zbm_apply_bitmap.c. Its loops run at
 * most 8 times and are unrolled there, so they carry no loop contracts. */
static int zbm_apply_bitmap(struct zbm_state *state, struct zbm_bmap *bitmap)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)) &&
             __CPROVER_r_ok(bitmap, sizeof(*bitmap)))
ZBM_REQUIRES(bitmap->period_bytecnt <= ZBM_MAX_PERIOD_BYTECNT)
ZBM_REQUIRES(ZBM_STATE_OK(state))
ZBM_ASSIGNS(state->dest, state->dest_left, state->written, state->period,
            state->data, state->meta_1,
            __CPROVER_object_upto(state->dest, state->decmp_len - state->written))
ZBM_ENSURES(ZBM_STATUS)
ZBM_ENSURES(state->written <= state->decmp_len && ZBM_OUT_ADVANCED(state) &&
            ZBM_STATE_OK(state) && ZBM_PROGRESS(state))
{
    uint32_t count;
    int i;

    /* The periods are stored in the first metadata area */
    if(bitmap->period_bytecnt) {
        uint16_t new_period = 0;

        for(i = 0; i < bitmap->period_bytecnt; ++i) {
            if(state->meta_1 >= state->src_end)
                return ZBM_INVAL;
            new_period |= *state->meta_1 << i * 8;
            ++state->meta_1;
        }
        /*
         * Periods below 8 are outside the format's correctness guarantee:
         * Apple's behavior varies across OS versions. Crush currently rejects
         * them, while all-input memory-safety requirements still apply.
         */
        if(new_period < 8)
            return ZBM_INVAL;
        state->period = new_period;
    }

    /* Only a trailing block near the end of a chunk applies to fewer than 8
     * bytes. */
    count = state->decmp_len - state->written;
    if(count > 8)
        count = 8;

    if(ZBM_DECODER_FAST_PATHS && count == 8) {
        uint8_t bmp = bitmap->bitmap;

        /* All-literal block: a straight copy, no dependency on period. */
        if(bmp == 0xff) {
            if(ZBM_SHORT(state->data, 8, state->src_end))
                return ZBM_INVAL;
            memcpy(state->dest, state->data, 8);
            state->data += 8;
            state->dest += 8;
            state->dest_left -= 8;
            state->written += 8;
            return 0;
        }

        /*
         * Blend path. `period >= 8` puts the whole 8-byte source before the
         * block, so copy-then-patch is exact; below 8 a literal could feed a
         * later copy inside the block, and those periods take the per-byte
         * loop. `prewritten + written >= period` puts the source inside
         * written memory.
         */
        if(state->period >= 8 &&
           state->prewritten + state->written >= state->period) {
            int nlit = __builtin_popcount(bmp);

            if(nlit && ZBM_SHORT(state->data, (size_t)nlit, state->src_end))
                return ZBM_INVAL;
            /* The 8-byte literal read needs 8 readable bytes; the tail keeps
             * the scalar form. */
            if(!ZBM_SHORT(state->data, 8, state->src_end)) {
                zbm_blend8(state->dest, state->dest - state->period,
                           state->data, bmp);
                state->data += nlit;
            } else
            {
                memcpy(state->dest, state->dest - state->period, 8);
                for(i = 0; i < 8; ++i) {
                    if(bmp & 1 << i) {
                        state->dest[i] = *state->data;
                        ++state->data;
                    }
                }
            }
            state->dest += 8;
            state->dest_left -= 8;
            state->written += 8;
            return 0;
        }
    }

    for(i = 0; i < (int)count; ++i) {
        if(bitmap->bitmap & 1 << i) {
            if(state->data >= state->src_end)
                return ZBM_INVAL;
            *state->dest = *state->data;
            ++state->data;
        } else {
            /* Check the actual copy position. A literal prefix can make a
             * copy valid even when the block started less than period bytes
             * from the beginning of produced output. The bulk blend above
             * still requires its whole baseline to be readable. */
            if(state->prewritten + state->written < state->period)
                return ZBM_INVAL;
            *state->dest = *(state->dest - state->period);
        }
        ++state->dest;
        --state->dest_left;
        ++state->written;
    }

    return 0;
}

static int zbm_apply_bitmap_number(struct zbm_state *state, uint8_t bmp_num)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)) && ZBM_STATE_OK(state))
ZBM_REQUIRES(bmp_num <= 15)
ZBM_REQUIRES(bmp_num <= 2 || bmp_num == 15 ||
             state->bitmaps[bmp_num - ZBM_BITMAP_BASE].period_bytecnt <= 2)
ZBM_ASSIGNS(state->dest, state->dest_left, state->written, state->period,
            state->data, state->meta_1, state->meta_2,
            __CPROVER_object_upto(state->dest, state->decmp_len - state->written))
ZBM_ENSURES(ZBM_STATUS)
ZBM_ENSURES(state->written <= state->decmp_len && ZBM_OUT_ADVANCED(state) &&
            ZBM_STATE_OK(state) && ZBM_PROGRESS(state))
ZBM_ENSURES(state->meta_2 >= ZBM_OLD(state->meta_2))
{
    struct zbm_bmap next = {0};

    /* Not a valid bitmap number (it signals a repetition) */
    if(bmp_num == 0xf)
        return ZBM_INVAL;

    /* An actual index in the bitmap array */
    if(bmp_num > ZBM_MAX_PERIOD_BYTECNT)
        return zbm_apply_bitmap(state, &state->bitmaps[bmp_num - ZBM_BITMAP_BASE]);

    /* For < 2, use the next bitmap in the second metadata area */
    if(state->meta_2 >= state->src_end)
        return ZBM_INVAL;
    next.bitmap = *state->meta_2;
    next.period_bytecnt = bmp_num;
    ++state->meta_2;
    return zbm_apply_bitmap(state, &next);
}

/*
 * Whether a whole run of @bmp at @period can be filled with the periodic
 * pattern first and the literals patched in afterwards. The fill propagates
 * only bytes from before the run, so a copy whose source is a literal position
 * inside the run would read the stale byte. Safe cases: no mixed bitmap,
 * period >= total, or period % 8 == 0 (a copy position then only ever reads
 * another copy position, since every block in the run shares one bitmap).
 */
static int zbm_run_is_fusable(uint8_t bmp, uint16_t period, uint32_t total)
{
    if(bmp == 0x00 || bmp == 0xff)
        return 1;
    if((uint32_t)period >= total)
        return 1;
    return period % 8 == 0;
}

/* These inline helpers retain the fused run's loops while letting their
 * memory bounds be proved independently of state-machine dispatch. */
static __attribute__((always_inline)) inline void zbm_fill_periodic(uint8_t *dest, uint16_t period, uint32_t total)
ZBM_REQUIRES(period >= 8 && total >= 8 && total <= CRUSHLZBITMAP_CHUNK_SIZE)
ZBM_REQUIRES(__CPROVER_w_ok(dest, total) &&
             (size_t)__CPROVER_POINTER_OFFSET(dest) >= period &&
             __CPROVER_r_ok(dest - period, period < total ? period : total))
ZBM_ASSIGNS(__CPROVER_object_upto(dest, total))
{
    uint32_t filled = period < total ? period : total;

    zbm_copy_fwd(dest, dest - period, filled);
    while(filled < total)
        ZBM_LOOP_ASSIGNS(filled, __CPROVER_object_upto(dest, total))
        ZBM_LOOP_INVARIANT(filled >= 8 && filled <= total)
        ZBM_LOOP_DECREASES(total - filled)
    {
        uint32_t chunk = filled < total - filled ? filled : total - filled;
        zbm_copy_fwd(dest + filled, dest, chunk);
        filled += chunk;
    }
}

static __attribute__((always_inline)) inline const uint8_t *zbm_patch_literals(
    uint8_t *dest, const uint8_t *data, const uint8_t *src_end, uint8_t bmp, uint32_t n_blocks)
ZBM_REQUIRES(n_blocks >= 1 && n_blocks <= CRUSHLZBITMAP_CHUNK_SIZE / 8)
ZBM_REQUIRES(__builtin_popcount(bmp) > 0)
ZBM_REQUIRES(__CPROVER_same_object(data, src_end) && data <= src_end)
ZBM_REQUIRES(__CPROVER_r_ok(data, (size_t)(src_end - data)))
ZBM_REQUIRES((size_t)__builtin_popcount(bmp) * n_blocks <= (size_t)(src_end - data))
ZBM_REQUIRES(__CPROVER_w_ok(dest, n_blocks * 8))
ZBM_REQUIRES(ZBM_DISJOINT(data, (size_t)(src_end - data), dest, (size_t)n_blocks * 8))
ZBM_ASSIGNS(__CPROVER_object_upto(dest, n_blocks * 8))
ZBM_ENSURES(__CPROVER_return_value == ZBM_OLD(data) + (size_t)__builtin_popcount(bmp) * n_blocks)
{
    int nlit = __builtin_popcount(bmp);
#ifdef ZBM_PROOF
    uint32_t total = n_blocks * 8;
#endif
    uint32_t b = 0, i;
    /* One bitmap for the whole run, so the selector row loads
     * once. The blend reads 8 literal bytes but consumes only
     * nlit, so a run that ends flush against the literal area
     * takes the checked loop. */
    zbm_sel_t selv = zbm_sel_load(zbm_blend_row[bmp]);
    uint8_t *d = dest;
    const uint8_t *lit = data;

    if(!ZBM_SHORT(lit, (size_t)nlit * (n_blocks - 1) + 8, src_end)) {
        for(; b < n_blocks; ++b, d += 8, lit += nlit)
            ZBM_LOOP_ASSIGNS(b, d, lit, __CPROVER_object_upto(dest, total))
            ZBM_LOOP_INVARIANT(b <= n_blocks)
            ZBM_LOOP_INVARIANT(d == dest + b * 8)
            ZBM_LOOP_INVARIANT(lit == data + b * nlit)
            ZBM_LOOP_DECREASES(n_blocks - b)
            zbm_blend8_sel(d, d, lit, selv);
    } else {
        for(; b < n_blocks; ++b, d += 8, lit += nlit)
            ZBM_LOOP_ASSIGNS(b, d, lit, __CPROVER_object_upto(dest, total))
            ZBM_LOOP_INVARIANT(b <= n_blocks)
            ZBM_LOOP_INVARIANT(d == dest + b * 8)
            ZBM_LOOP_INVARIANT(lit == data + b * nlit)
            ZBM_LOOP_DECREASES(n_blocks - b)
        {
            if(ZBM_SHORT(lit, 8, src_end))
                break;
            zbm_blend8_sel(d, d, lit, selv);
        }
    }
    data = lit;
#ifdef ZBM_PROOF
    const uint8_t *patch_start = lit;
    uint32_t patch_block = b;
#endif
    for(; b < n_blocks; ++b)
        ZBM_LOOP_ASSIGNS(b, i, data, __CPROVER_object_upto(dest, total))
        ZBM_LOOP_INVARIANT(patch_block <= b && b <= n_blocks)
        ZBM_LOOP_INVARIANT(data == patch_start + (b - patch_block) * nlit)
        ZBM_LOOP_DECREASES(n_blocks - b)
    {
        for(i = 0; i < 8; ++i)
            ZBM_LOOP_ASSIGNS(i, data, __CPROVER_object_upto(dest, total))
            ZBM_LOOP_INVARIANT(i <= 8)
            ZBM_LOOP_INVARIANT(data == patch_start + (b - patch_block) * nlit +
                              __builtin_popcount((unsigned)bmp & ((1u << i) - 1)))
            ZBM_LOOP_DECREASES(8 - i)
        {
            if(bmp & 1 << i) {
                dest[b * 8 + i] = zbm_rd8(data);
                ++data;
            }
        }
    }
    return data;
}

static __attribute__((always_inline)) inline int zbm_apply_bitmap_run_slow(struct zbm_state *state, struct zbm_bmap *bitmap, uint16_t repeat)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)) &&
             __CPROVER_r_ok(bitmap, sizeof(*bitmap)))
ZBM_REQUIRES(ZBM_STATE_OK(state) && bitmap->period_bytecnt == 0)
ZBM_REQUIRES(repeat <= CRUSHLZBITMAP_CHUNK_SIZE / 8)
ZBM_ASSIGNS(state->dest, state->dest_left, state->written, state->period,
            state->data, state->meta_1,
            __CPROVER_object_upto(state->dest, state->decmp_len - state->written))
ZBM_ENSURES(ZBM_STATUS)
ZBM_ENSURES(state->written <= state->decmp_len && ZBM_OUT_ADVANCED(state) &&
            ZBM_STATE_OK(state) && (ZBM_OLD(repeat) == 0 || ZBM_PROGRESS(state)))
{
    int err;
    /*
     * Anything the bulk path did not cover goes through the per-block path.
     * The `written` test retires an over-long run's surplus blocks: they
     * consume no metadata (period_bytecnt is 0 here), so stopping equals
     * iterating.
     */
    while(repeat > 0)
        ZBM_LOOP_ASSIGNS(repeat, err, state->dest, state->dest_left,
                        state->written, state->period, state->data, state->meta_1,
                        __CPROVER_object_upto(state->dest, state->decmp_len - state->written))
        ZBM_LOOP_INVARIANT(repeat <= CRUSHLZBITMAP_CHUNK_SIZE / 8)
        ZBM_LOOP_INVARIANT(repeat == ZBM_LOOP_ENTRY(repeat) ||
                          state->written > ZBM_LOOP_ENTRY(state->written) ||
                          state->written == state->decmp_len)
        ZBM_LOOP_INVARIANT(state->written <= state->decmp_len)
        ZBM_LOOP_INVARIANT(state->written >= ZBM_LOOP_ENTRY(state->written))
        ZBM_LOOP_INVARIANT(state->dest == ZBM_LOOP_ENTRY(state->dest) +
                          (state->written - ZBM_LOOP_ENTRY(state->written)))
        ZBM_LOOP_INVARIANT(state->dest_left + state->written ==
                          ZBM_LOOP_ENTRY(state->dest_left) + ZBM_LOOP_ENTRY(state->written))
        ZBM_LOOP_INVARIANT(ZBM_STATE_OK(state))
        ZBM_LOOP_DECREASES(repeat)
    {
        --repeat;
        if(state->written >= state->decmp_len)
            break;
        err = zbm_apply_bitmap(state, bitmap);
        if(err)
            return err;
    }
    return 0;
}

static int zbm_apply_bitmap_run(struct zbm_state *state, struct zbm_bmap *bitmap, uint16_t repeat)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)) &&
             __CPROVER_r_ok(bitmap, sizeof(*bitmap)))
ZBM_REQUIRES(ZBM_STATE_OK(state) && bitmap->period_bytecnt == 0)
ZBM_REQUIRES(repeat >= 1 && repeat <= CRUSHLZBITMAP_CHUNK_SIZE / 8)
ZBM_ASSIGNS(state->dest, state->dest_left, state->written, state->period,
            state->data, state->meta_1,
            __CPROVER_object_upto(state->dest, state->decmp_len - state->written))
ZBM_ENSURES(ZBM_STATUS)
ZBM_ENSURES(state->written <= state->decmp_len && ZBM_OUT_ADVANCED(state) &&
            ZBM_STATE_OK(state) && ZBM_PROGRESS(state))
{
    uint8_t bmp = bitmap->bitmap;
    uint32_t remaining = state->decmp_len - state->written;
    uint32_t total = (uint32_t)repeat * 8;
    uint32_t n_blocks;

    /* A run has no period of its own; it inherits state->period, which must
     * not be 0. */
    if(state->period == 0)
        return ZBM_INVAL;
    /*
     * A run may name more blocks than the chunk has output left; the surplus
     * produces nothing. Apple's encoder emits over-long final runs routinely,
     * so rejecting `total >= remaining + 8` would refuse conforming streams.
     */
    if(total > remaining)
        total = remaining;
    n_blocks = total / 8;
    total = n_blocks * 8;

    /*
     * Bulk path: an all-literal run has no period dependency; otherwise the
     * same distance gate as zbm_apply_bitmap's fast path, checked once at the
     * start since every later position is further from the start of output.
     */
    if(ZBM_DECODER_FAST_PATHS && n_blocks > 0 && (bmp == 0xff ||
       state->prewritten + state->written >= state->period) &&
       zbm_run_is_fusable(bmp, state->period, total)) {
        int nlit = __builtin_popcount(bmp);

        if(nlit && ZBM_SHORT(state->data, (size_t)nlit * n_blocks, state->src_end))
            return ZBM_INVAL;

        if(bmp == 0xff) {
            zbm_copy_fwd(state->dest, state->data, total);
            state->data += total;
        } else {
            /*
             * Fill the run with the periodic pattern by doubling: each step
             * copies the already-correct prefix into the not-yet-written range
             * right after it, so source and destination never overlap within
             * one copy.
             */
            zbm_fill_periodic(state->dest, state->period, total);
            if(nlit)
                state->data = zbm_patch_literals(state->dest, state->data, state->src_end, bmp, n_blocks);
        }

        state->dest += total;
        state->dest_left -= total;
        state->written += total;
        repeat -= n_blocks;
    }

    return zbm_apply_bitmap_run_slow(state, bitmap, repeat);
}

/* Find out how many times we need to repeat the current bitmap operation */
static int zbm_read_repetition_count(struct zbm_state *state, uint16_t *repeat, uint16_t base)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)) && ZBM_STATE_OK(state))
ZBM_REQUIRES(__CPROVER_is_fresh(repeat, sizeof(*repeat)))
ZBM_REQUIRES(base == 3 || base == 4)
ZBM_ASSIGNS(state->meta_3, *repeat)
ZBM_ENSURES(ZBM_STATUS && ZBM_STATE_OK(state))
ZBM_ENSURES(state->meta_3.addr >= ZBM_OLD(state->meta_3.addr))
ZBM_ENSURES(__CPROVER_return_value != 0 ||
             (*repeat >= 1 && *repeat <= CRUSHLZBITMAP_CHUNK_SIZE / 8))
{
    uint8_t nibble;
    uint16_t total;
    int err;

    /* Don't confuse the trailing bitmaps with a repetition count */
    if(state->decmp_len - state->written <= 8) {
        *repeat = 1;
        return 0;
    }

    err = zbm_read_nibble(&state->meta_3, state->src_end, &nibble);
    if(err)
        return err;

    if(nibble != 0xf) {
        /* No repetition count: the previous bitmap number gets applied once */
        zbm_rewind_nibble(&state->meta_3);
        *repeat = 1;
        return 0;
    }

    /*
     * Under this scheme, repeating a bitmap number 3 times wouldn't save any
     * space, so the normal count starts from 4. A standalone 0xf reuses the
     * preceding non-0xf nibble and starts from 3.
     */
    total = base;
    while(nibble == 0xf)
        ZBM_LOOP_ASSIGNS(nibble, total, err, state->meta_3)
        ZBM_LOOP_INVARIANT(ZBM_STATE_OK(state))
        ZBM_LOOP_INVARIANT(total >= base && total <= CRUSHLZBITMAP_CHUNK_SIZE / 8)
        ZBM_LOOP_INVARIANT(state->meta_3.addr >= ZBM_LOOP_ENTRY(state->meta_3.addr))
        ZBM_LOOP_INVARIANT(state->meta_3.addr < state->src_end || state->meta_3.nibble == 0)
        ZBM_LOOP_DECREASES((size_t)(state->src_end - state->meta_3.addr) * 2 - state->meta_3.nibble)
    {
        err = zbm_read_nibble(&state->meta_3, state->src_end, &nibble);
        if(err)
            return err;
        total += nibble;
        /* A chunk needs at most 4096 blocks. Larger counts have the same
         * output semantics; still consume every count nibble, but keep no
         * unusable excess and never let the 16-bit counter wrap. */
        if(total > CRUSHLZBITMAP_CHUNK_SIZE / 8)
            total = CRUSHLZBITMAP_CHUNK_SIZE / 8;
    }

    *repeat = total;
    return 0;
}

static int zbm_decompress_single_bitmap(struct zbm_state *state, const uint8_t *selector_start)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)) && ZBM_STATE_OK(state))
ZBM_REQUIRES(ZBM_TABLE_OK(state) && ZBM_SELECTOR_OK(state, selector_start))
ZBM_ASSIGNS(*state, __CPROVER_object_upto(state->dest, state->decmp_len - state->written))
ZBM_ENSURES(ZBM_STATUS)
ZBM_ENSURES(ZBM_SAME_INPUT(state, ZBM_OLD) && ZBM_TABLE_OK(state))
ZBM_ENSURES(state->written <= state->decmp_len && ZBM_OUT_ADVANCED(state) &&
            ZBM_STATE_OK(state) && ZBM_PROGRESS(state) && ZBM_SELECTOR_OK(state, selector_start))
{
    uint8_t bmp_num;
    uint16_t repeat;
    int i;
    int err;
    uint16_t count_base = 4;
#ifdef ZBM_PROOF
    uint8_t *const run_dest_start = state->dest;
    const uint32_t run_room = state->decmp_len - state->written;
#endif

    /* The current nibble is the offset of the next bitmap to apply */
    err = zbm_read_nibble(&state->meta_3, state->src_end, &bmp_num);
    if(err)
        return err;

    if(bmp_num == 15) {
        bmp_num = zbm_last_nonrepeat_nibble(state->meta_3, selector_start);
        count_base = 3;
        /* Reuse the consumed marker as the count parser's introducer.
         * A final partial block consumes no count, so leave it consumed. */
        if(state->decmp_len - state->written > 8)
            zbm_rewind_nibble(&state->meta_3);
    }
    err = zbm_read_repetition_count(state, &repeat, count_base);
    if(err)
        return err;

    /* A run of one top-12 bitmap whose period never changes mid-run can be
     * batched. */
    if(repeat > 1 && bmp_num > ZBM_MAX_PERIOD_BYTECNT && bmp_num < ZBM_BITMAP_BASE + ZBM_BITMAP_COUNT) {
        struct zbm_bmap *bm = &state->bitmaps[bmp_num - ZBM_BITMAP_BASE];
        if(bm->period_bytecnt == 0)
            return zbm_apply_bitmap_run(state, bm, repeat);
    }

    for(i = 0; i < repeat; ++i)
        ZBM_LOOP_ASSIGNS(i, err, *state, __CPROVER_object_upto(run_dest_start, run_room))
        ZBM_LOOP_INVARIANT(0 <= i && i <= repeat)
        ZBM_LOOP_INVARIANT(ZBM_SAME_INPUT(state, ZBM_LOOP_ENTRY) && ZBM_TABLE_OK(state))
        ZBM_LOOP_INVARIANT(state->written <= state->decmp_len)
        ZBM_LOOP_INVARIANT(state->written >= ZBM_LOOP_ENTRY(state->written))
        ZBM_LOOP_INVARIANT(i == 0 || state->written > ZBM_LOOP_ENTRY(state->written) ||
                          state->written == state->decmp_len)
        ZBM_LOOP_INVARIANT(state->dest == ZBM_LOOP_ENTRY(state->dest) +
                          (state->written - ZBM_LOOP_ENTRY(state->written)))
        ZBM_LOOP_INVARIANT(state->dest_left + state->written ==
                          ZBM_LOOP_ENTRY(state->dest_left) + ZBM_LOOP_ENTRY(state->written))
        ZBM_LOOP_INVARIANT(ZBM_STATE_OK(state))
        ZBM_LOOP_INVARIANT(state->meta_3.addr == ZBM_LOOP_ENTRY(state->meta_3.addr) &&
                          state->meta_3.nibble == ZBM_LOOP_ENTRY(state->meta_3.nibble))
        ZBM_LOOP_DECREASES(repeat - i)
    {
        /* The run describes output blocks, not mandatory metadata reads.
         * Once the chunk is full, surplus blocks consume nothing. */
        if(state->written >= state->decmp_len)
            break;
        err = zbm_apply_bitmap_number(state, bmp_num);
        if(err)
            return err;
    }
    return 0;
}

/* Pointer to a bit */
struct bit_ptr {
    uint8_t         *addr;  /* Address of the byte */
    int             offset; /* Bit number */
};

#if !ZBM_FAST_BITMAP_TABLE
/* This function does not perform boundary checks, the caller must do it */
static int zbm_read_single_bit(struct bit_ptr *bit)
{
    int res = *bit->addr >> bit->offset & 1;

    ++bit->offset;
    if(bit->offset != 8)
        return res;
    bit->offset = 0;
    ++bit->addr;
    return res;
}

static int zbm_read_single_bitmap(struct bit_ptr *bit, const uint8_t *limit, struct zbm_bmap *result)
{
    int i;

    result->bitmap = 0;
    result->period_bytecnt = 0;

    /* The bitmap itself */
    for(i = 0; i < 8; ++i) {
        if(bit->addr >= limit)
            return ZBM_INVAL;
        result->bitmap |= zbm_read_single_bit(bit) << i;
    }

    /*
     * The two trailing bits tell us how many bytes to read for the next
     * repetition period
     */
    for(i = 0; i < 2; ++i) {
        if(bit->addr >= limit)
            return ZBM_INVAL;
        result->period_bytecnt |= zbm_read_single_bit(bit) << i;
    }

    return 0;
}
#endif /* !ZBM_FAST_BITMAP_TABLE */

/*
 * The trailing bitmap table is a flat little-endian bit stream: bitmap i
 * occupies bits [10i, 10i+10), the low 8 the bitmap and the high 2 the period
 * byte count. Twelve of them are 120 bits, so the table is the first 15 of the
 * 17 trailing bytes. w0 carries bits 0..63 and w1, loaded seven bytes in, bits
 * 56..119, so every field lies wholly inside one of them; both loads stay
 * inside the 17 bytes the length check guarantees.
 */
static int zbm_read_bitmaps(struct zbm_state *state)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_REQUIRES(__CPROVER_r_ok(state->src, state->len) &&
             state->src_end == state->src + state->len)
ZBM_ASSIGNS(state->bitmaps)
ZBM_ENSURES(ZBM_STATUS)
ZBM_ENSURES(__CPROVER_return_value != 0 || ZBM_TABLE_OK(state))
{
    if(state->len < ZBM_BITMAP_BYTECNT)
        return ZBM_INVAL;

#if ZBM_FAST_BITMAP_TABLE
    {
        const uint8_t *tbl = state->src_end - ZBM_BITMAP_BYTECNT;
        uint64_t w0, w1;
        int i;

        memcpy(&w0, tbl, 8);
        memcpy(&w1, tbl + 7, 8);

        for(i = 0; i < ZBM_BITMAP_COUNT; ++i) {
            uint32_t v = (uint32_t)((i < 6 ? w0 >> (10 * i)
                                           : w1 >> (10 * i - 56)) & 0x3ff);

            if(v >> 8 > ZBM_MAX_PERIOD_BYTECNT)
                return ZBM_INVAL;
            state->bitmaps[i].bitmap = (uint8_t)v;
            state->bitmaps[i].period_bytecnt = (uint8_t)(v >> 8);
        }
        return 0;
    }
#else
    {
        struct bit_ptr bmap = {0};
        int err, i;

        bmap.addr = (uint8_t *)state->src_end - ZBM_BITMAP_BYTECNT;
        bmap.offset = 0;

        for(i = 0; i < ZBM_BITMAP_COUNT; ++i) {
            err = zbm_read_single_bitmap(&bmap, state->src_end, &state->bitmaps[i]);
            if(err)
                return err;
            if(state->bitmaps[i].period_bytecnt > ZBM_MAX_PERIOD_BYTECNT)
                return ZBM_INVAL;
        }
        return 0;
    }
#endif /* ZBM_FAST_BITMAP_TABLE */
}

/*
 * How many two-block iterations the pair path may run with no margin checks.
 * Each margin moves at a known maximum rate per iteration: 16 output bytes,
 * 16 literal bytes, 4 period bytes, 2 explicit-bitmap bytes, 1 meta_3 byte.
 * Returning 0 is always safe: the caller falls back to the per-block path.
 */
static uint32_t zbm_pair_budget(size_t avail, size_t avail_end,
                                const uint8_t *data, const uint8_t *m1,
                                const uint8_t *m2, const uint8_t *m3a,
                                const uint8_t *src_end)
ZBM_REQUIRES(avail <= avail_end && avail <= SIZE_MAX - 16 &&
             avail_end - avail <= CRUSHLZBITMAP_CHUNK_SIZE)
ZBM_REQUIRES(__CPROVER_same_object(data, src_end) && data <= src_end)
ZBM_REQUIRES(__CPROVER_same_object(m1, src_end) && m1 <= src_end)
ZBM_REQUIRES(__CPROVER_same_object(m2, src_end) && m2 <= src_end)
ZBM_REQUIRES(__CPROVER_same_object(m3a, src_end) && m3a <= src_end)
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value <= CRUSHLZBITMAP_CHUNK_SIZE / 16)
ZBM_ENSURES(__CPROVER_return_value == 0 ||
             (size_t)__CPROVER_return_value * 16 < avail_end - avail)
ZBM_ENSURES((size_t)__CPROVER_return_value * 16 <= (size_t)(src_end - data))
ZBM_ENSURES((size_t)__CPROVER_return_value * 4 <= (size_t)(src_end - m1))
ZBM_ENSURES((size_t)__CPROVER_return_value * 2 <= (size_t)(src_end - m2))
ZBM_ENSURES(__CPROVER_return_value == 0 ||
             (size_t)__CPROVER_return_value + 1 <= (size_t)(src_end - m3a))
{
    ptrdiff_t d;
    size_t k;

    if(avail + 16 >= avail_end)
        return 0;
    k = (avail_end - avail - 1) / 16;

    d = src_end - data;
    if(d <= 0)
        return 0;
    if((size_t)d / 16 < k)
        k = (size_t)d / 16;

    d = src_end - m1;
    if(d <= 0)
        return 0;
    if((size_t)d / 4 < k)
        k = (size_t)d / 4;

    d = src_end - m2;
    if(d <= 0)
        return 0;
    if((size_t)d / 2 < k)
        k = (size_t)d / 2;

    d = src_end - m3a - 1;
    if(d <= 0)
        return 0;
    if((size_t)d < k)
        k = (size_t)d;

    return (uint32_t)k;
}

struct zbm_pair_state {
    uint8_t *dest;
    const uint8_t *data, *m1, *m2;
    struct nybl_ptr m3;
    uint32_t period;
    size_t avail;
};

#ifdef ZBM_PROOF
#define ZBM_PAIR_SOURCE_PTR(src, end, p)                                    \
    (__CPROVER_same_object(p, src) &&                                      \
     __CPROVER_POINTER_OFFSET(p) >= __CPROVER_POINTER_OFFSET(src) &&         \
     __CPROVER_POINTER_OFFSET(p) <= __CPROVER_POINTER_OFFSET(end))
#define ZBM_PAIR_OK(cur, src, end, dstart, astart, aend)                     \
    ((astart) <= (cur)->avail && (cur)->avail < (aend) &&                     \
     (cur)->dest == (dstart) + ((cur)->avail - (astart)) &&                   \
     ZBM_PAIR_SOURCE_PTR(src, end, (cur)->data) &&                            \
     ZBM_PAIR_SOURCE_PTR(src, end, (cur)->m1) &&                              \
     ZBM_PAIR_SOURCE_PTR(src, end, (cur)->m2) &&                              \
     ZBM_PAIR_SOURCE_PTR(src, end, (cur)->m3.addr) &&                         \
     ((cur)->m3.nibble == 0 || (cur)->m3.nibble == 1) &&                       \
     8 <= (cur)->period && (cur)->period <= UINT16_MAX)

#endif

/* Return the unused pair budget. Odd selector parity means its first block
 * committed before a bailout, so the second block needs the slow path.
 * Always inline: the shipping compiler keeps these cursors in registers. */
static __attribute__((always_inline)) inline uint32_t zbm_decode_pairs(
    struct zbm_pair_state *cur, const uint8_t *src, const uint8_t *src_end,
    size_t avail_end, const uint8_t *bmpbase, const uint8_t *pbcbase,
    const uint8_t *rowbase, uint32_t k)
ZBM_REQUIRES(__CPROVER_rw_ok(cur, sizeof(*cur)))
ZBM_REQUIRES(__CPROVER_same_object(src, src_end) && src <= src_end &&
             __CPROVER_r_ok(src, (size_t)(src_end - src)))
ZBM_REQUIRES(cur->avail < avail_end && k >= 1 && k <= CRUSHLZBITMAP_CHUNK_SIZE / 16)
ZBM_REQUIRES(avail_end - cur->avail <= CRUSHLZBITMAP_CHUNK_SIZE)
ZBM_REQUIRES(ZBM_PAIR_OK(cur, src, src_end, cur->dest, cur->avail, avail_end) && cur->m3.nibble == 0)
ZBM_REQUIRES(__CPROVER_w_ok(cur->dest, avail_end - cur->avail) &&
             cur->avail <= (size_t)__CPROVER_POINTER_OFFSET(cur->dest) &&
             __CPROVER_r_ok(cur->dest - cur->avail, cur->avail))
ZBM_REQUIRES((size_t)k * 16 < avail_end - cur->avail &&
             (size_t)k * 16 <= (size_t)(src_end - cur->data) &&
             (size_t)k * 4 <= (size_t)(src_end - cur->m1) &&
             (size_t)k * 2 <= (size_t)(src_end - cur->m2) &&
             (size_t)k + 1 <= (size_t)(src_end - cur->m3.addr))
ZBM_REQUIRES(__CPROVER_r_ok(bmpbase, 16) && __CPROVER_r_ok(pbcbase, 16))
ZBM_REQUIRES(ZBM_PBC_PREFIX_OK(pbcbase, 16))
ZBM_REQUIRES(rowbase == zbm_blend_row[0])
ZBM_REQUIRES(ZBM_DISJOINT(src, (size_t)(src_end - src), cur->dest, avail_end - cur->avail))
ZBM_ASSIGNS(*cur, __CPROVER_object_upto(cur->dest, avail_end - cur->avail))
ZBM_ENSURES(__CPROVER_return_value <= ZBM_OLD(k))
ZBM_ENSURES(ZBM_PAIR_OK(cur, src, src_end, ZBM_OLD(cur->dest), ZBM_OLD(cur->avail), avail_end))
ZBM_ENSURES(cur->data >= ZBM_OLD(cur->data) && cur->m1 >= ZBM_OLD(cur->m1) &&
             cur->m2 >= ZBM_OLD(cur->m2) && cur->m3.addr >= ZBM_OLD(cur->m3.addr))
ZBM_ENSURES(__CPROVER_return_value != 0 || cur->avail > ZBM_OLD(cur->avail))
ZBM_ENSURES(__CPROVER_return_value != 0 || cur->m3.nibble == 0)
{
    (void)src; (void)src_end; (void)avail_end;
#ifdef ZBM_PROOF
    uint8_t *const dest_start = cur->dest;
    uint32_t k_start = k;
    size_t avail_start = cur->avail;
#endif
    /* A local copy: through `cur` the compiler must assume the blend stores
     * alias the cursors, and spills them on x86-64. */
    struct zbm_pair_state c = *cur;
#if defined(__aarch64__)
#define ZBM_PAIR_PIN_CURSORS __asm__("" : "+r"(c.dest), "+r"(c.avail));
#else
#define ZBM_PAIR_PIN_CURSORS
#endif
#define ZBM_RESOLVE(nsel, bailstmt)                                               \
            {                                                                     \
                uint32_t pbc_;                                                    \
                uint8_t bmp_;                                                     \
                const uint8_t *row_;                                              \
                int explicit_ = ((nsel) < ZBM_BITMAP_BASE);                       \
                {                                                                 \
                    const uint8_t *bmpptr_ = explicit_ ? c.m2 : &bmpbase[(nsel)]; \
                    bmp_ = zbm_rd8(bmpptr_);                                      \
                    pbc_ = pbcbase[(nsel)];                                       \
                }                                                                 \
                {                                                                 \
                    uint32_t raw_ = zbm_load_u16le(c.m1);                         \
                    uint32_t np_ = pbc_ > 1 ? raw_ : (raw_ & 0xffu);              \
                    uint32_t new_ = pbc_ ? np_ : c.period;                        \
                                                                                  \
                    if(new_ < 8 || c.avail < new_) { bailstmt; }                  \
                    c.period = new_;                                              \
                    c.m1 += pbc_;                                                 \
                }                                                                 \
                c.m2 += (unsigned)explicit_;                                      \
                row_ = rowbase + ((size_t)bmp_ << 4);                             \
                zbm_blend8_row(c.dest, c.dest - c.period, c.data, row_);          \
                c.data += row_[ZBM_BLEND_ROW_CNT];                                \
                c.dest += 8;                                                      \
                c.avail += 8;                                                     \
                ZBM_PAIR_PIN_CURSORS                                              \
            }

    uint8_t byte0 = zbm_rd8(c.m3.addr);
    while(k)
        ZBM_LOOP_ASSIGNS(k, byte0, c,
                        __CPROVER_object_upto(dest_start, avail_end - avail_start))
        ZBM_LOOP_INVARIANT(k <= k_start)
        ZBM_LOOP_INVARIANT(c.avail == avail_start + (size_t)(k_start - k) * 16)
        ZBM_LOOP_INVARIANT(ZBM_PAIR_OK(&c, src, src_end, dest_start, avail_start, avail_end))
        ZBM_LOOP_INVARIANT(c.data >= ZBM_LOOP_ENTRY(c.data) && c.m1 >= ZBM_LOOP_ENTRY(c.m1) &&
                          c.m2 >= ZBM_LOOP_ENTRY(c.m2) && c.m3.addr >= ZBM_LOOP_ENTRY(c.m3.addr))
        ZBM_LOOP_INVARIANT(c.m3.nibble == 0)
        ZBM_LOOP_INVARIANT((size_t)k * 16 < avail_end - c.avail)
        ZBM_LOOP_INVARIANT((size_t)k * 16 <= (size_t)(src_end - c.data))
        ZBM_LOOP_INVARIANT((size_t)k * 4 <= (size_t)(src_end - c.m1))
        ZBM_LOOP_INVARIANT((size_t)k * 2 <= (size_t)(src_end - c.m2))
        ZBM_LOOP_INVARIANT((size_t)k + 1 <= (size_t)(src_end - c.m3.addr))
        ZBM_LOOP_DECREASES(k)
    {
        uint8_t n0 = byte0 & 0xf, n1 = (byte0 >> 4) & 0xf;
        /* Block 1's repetition peek is block 0 of the next
         * iteration, so the byte is read once and carried. */
        uint8_t byte1 = zbm_rd8(c.m3.addr + 1);

        if(n1 == 0xf ||
           n0 >= ZBM_BITMAP_BASE + ZBM_BITMAP_COUNT)
            goto out;
        ZBM_RESOLVE(n0, goto out);
        /* Block 0 committed. n1 needs no range check: a nibble
         * is out of range exactly when it is 0xf, already
         * rejected above. */
        if((byte1 & 0xf) == 0xf) {
            c.m3.nibble = 1;
            goto out;
        }
        ZBM_RESOLVE(n1, { c.m3.nibble = 1; goto out; });
        ++c.m3.addr;
        byte0 = byte1;
        --k;
    }
#undef ZBM_RESOLVE
#undef ZBM_PAIR_PIN_CURSORS
out:
    *cur = c;
    return k;
}

static int zbm_handle_compressed_chunk(struct zbm_state *state)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_REQUIRES(__CPROVER_r_ok(state->src, state->len) &&
             state->src_end == state->src + state->len)
ZBM_REQUIRES(state->decmp_len <= CRUSHLZBITMAP_CHUNK_SIZE &&
             __CPROVER_w_ok(state->dest, state->decmp_len))
ZBM_REQUIRES(state->prewritten <= (size_t)__CPROVER_POINTER_OFFSET(state->dest) &&
             __CPROVER_r_ok(state->dest - state->prewritten, state->prewritten))
ZBM_REQUIRES(ZBM_DISJOINT(state->src, state->len, state->dest, state->decmp_len))
ZBM_ASSIGNS(*state, __CPROVER_object_upto(state->dest, state->decmp_len))
ZBM_ENSURES(ZBM_STATUS)
ZBM_ENSURES(ZBM_SAME_INPUT(state, ZBM_OLD))
ZBM_ENSURES(state->written <= state->decmp_len &&
             state->dest == ZBM_OLD(state->dest) + state->written &&
             state->dest_left + state->written == ZBM_OLD(state->dest_left))
ZBM_ENSURES(ZBM_OUT_OK(state))
ZBM_ENSURES(__CPROVER_return_value != 0 || state->written == state->decmp_len)
{
    const struct zbm_cmp_chunk_hdr *hdr = NULL;
    uint32_t meta_off_1, meta_off_2, meta_off_3;
    int err;

    state->written = 0;
    state->period = 8;

    if(state->len < sizeof(*hdr))
        return ZBM_INVAL;
    hdr = (struct zbm_cmp_chunk_hdr *)state->src;
    state->data = state->src + sizeof(*hdr);

    meta_off_1 = zbm_u24_to_u32(hdr->meta_off_1);
    meta_off_2 = zbm_u24_to_u32(hdr->meta_off_2);
    meta_off_3 = zbm_u24_to_u32(hdr->meta_off_3);
    if(meta_off_1 >= state->len || meta_off_2 >= state->len || meta_off_3 >= state->len)
        return ZBM_INVAL;
    state->meta_1 = state->src + meta_off_1;
    state->meta_2 = state->src + meta_off_2;
    state->meta_3.addr = (uint8_t *)state->src + meta_off_3;
    state->meta_3.nibble = 0;

    err = zbm_read_bitmaps(state);
    if(err)
        return err;

    /*
     * The block loop, with every cursor in a register. Singleton blocks are
     * handled inline; anything else (a repetition run, an explicit bitmap, a
     * period change, the trailing partial block) syncs to `state`, calls the
     * general path, and reloads. Preconditions are margins: staying off the
     * trailing block, 8 readable literal bytes, two readable nibbles,
     * period >= 8 and prewritten + written >= period.
     */
    {
        struct zbm_pair_state cur = {state->dest, state->data, state->meta_1,
                                     state->meta_2, state->meta_3, state->period,
                                     state->prewritten + state->written};
        const uint8_t *src_end = state->src_end;
        const size_t dl_sum = state->dest_left + cur.avail;
        const size_t prewritten = state->prewritten;
        const size_t avail_end = state->prewritten + state->decmp_len;
#ifdef ZBM_PROOF
        uint8_t *const dest_start = cur.dest;
#endif
        /* per-chunk 16-entry resolve table, indexed by the raw nibble */
        uint8_t rtab_bmp[16], rtab_pbc[16];
        for(int ri = 0; ri < 16; ri++)
            ZBM_LOOP_ASSIGNS(ri, rtab_bmp, rtab_pbc)
            ZBM_LOOP_INVARIANT(0 <= ri && ri <= 16)
            ZBM_LOOP_INVARIANT(ZBM_PBC_PREFIX_OK(rtab_pbc, ri))
            ZBM_LOOP_DECREASES(16 - ri)
        {
            if(ri >= ZBM_BITMAP_BASE && ri < ZBM_BITMAP_BASE + ZBM_BITMAP_COUNT) {
                rtab_bmp[ri] = state->bitmaps[ri - ZBM_BITMAP_BASE].bitmap;
                rtab_pbc[ri] = state->bitmaps[ri - ZBM_BITMAP_BASE].period_bytecnt;
            } else {
                rtab_bmp[ri] = 0;
                rtab_pbc[ri] = (uint8_t)(ri < ZBM_BITMAP_BASE ? ri : 0);
            }
        }
        const uint8_t *rowbase = zbm_blend_row[0];
        const uint8_t *bmpbase = rtab_bmp;
        const uint8_t *pbcbase = rtab_pbc;

        /* Keep the three loop-invariant base addresses in registers: an empty
         * asm with the pointer as an in-out operand stops clang
         * rematerialising them. aarch64 only, where the registers are spare. */
#if defined(__aarch64__)
        __asm__("" : "+r"(rowbase), "+r"(bmpbase), "+r"(pbcbase));
#endif

        while(cur.avail < avail_end)
            ZBM_LOOP_ASSIGNS(cur, err, *state,
                            __CPROVER_object_upto(dest_start, state->decmp_len))
            ZBM_LOOP_INVARIANT(ZBM_SAME_INPUT(state, ZBM_LOOP_ENTRY) && ZBM_TABLE_OK(state))
            ZBM_LOOP_INVARIANT(ZBM_LOCAL_OK(state, cur.dest, cur.data, cur.m1, cur.m2, cur.m3, cur.period,
                                            cur.avail, prewritten, avail_end, dest_start, meta_off_3))
            ZBM_LOOP_INVARIANT(dl_sum == ZBM_LOOP_ENTRY(dl_sum))
            ZBM_LOOP_DECREASES(avail_end - cur.avail)
        {
            struct nybl_ptr save;

            /* One meta_3 byte carries two block selectors. Entering at odd
             * parity falls through to the single-block path, which realigns. */
            if(cur.m3.nibble == 0) {
                uint32_t k = zbm_pair_budget(cur.avail, avail_end, cur.data, cur.m1, cur.m2,
                                             cur.m3.addr, src_end);

                /* The budget has proved every cursor has room for k iterations,
                 * so nothing inside the loop checks a margin. A zero budget
                 * must fall through to the per-block path: nothing in between
                 * advances a cursor. */
                if(k) {
                    uint32_t unused = zbm_decode_pairs(&cur, state->src, src_end, avail_end,
                                                       bmpbase, pbcbase, rowbase, k);
                    if(cur.m3.nibble)
                        goto slow;
                    if(!unused)
                        continue;
                }
            }
            /* Saved so a bail out of the per-block path can put the cursor
             * back. */
            save = cur.m3;
            uint8_t bmp_num, peek, bmp;

            uint32_t pbc;

            if(cur.avail + 8 >= avail_end || ZBM_SHORT(cur.data, 8, src_end) ||
               (uintptr_t)cur.m3.addr + 1 >= (uintptr_t)src_end ||
               ZBM_SHORT(cur.m1, 2, src_end) ||
               cur.m2 >= src_end)
                goto slow;

            /* Consume the bitmap number, then peek the next nibble without
             * consuming it; the unconsumed peek is what
             * zbm_read_repetition_count's rewind leaves for repeat == 1. */
            if(cur.m3.nibble == 0) {
                bmp_num = zbm_rd8(cur.m3.addr) & 0xf;
                cur.m3.nibble = 1;
            } else {
                bmp_num = (zbm_rd8(cur.m3.addr) >> 4) & 0xf;
                cur.m3.nibble = 0;
                ++cur.m3.addr;
            }
            peek = (cur.m3.nibble == 0) ? (zbm_rd8(cur.m3.addr) & 0xf) : ((zbm_rd8(cur.m3.addr) >> 4) & 0xf);

            /* 0xf introduces a repetition count. Below ZBM_BITMAP_BASE is an
             * explicit bitmap out of meta_2, which carries its own cur.period
             * bytes and can move the cur.period. */
            if(peek == 0xf || bmp_num >= ZBM_BITMAP_BASE + ZBM_BITMAP_COUNT) {
                cur.m3 = save;
                goto slow;
            }

            {
                uint8_t tb = bmpbase[bmp_num];
                bmp = bmp_num >= ZBM_BITMAP_BASE ? tb : zbm_rd8(cur.m2);
                pbc = pbcbase[bmp_num];
            }

            /* Nothing above this point has advanced cur.m1, cur.m2 or cur.period, so a
             * bail here needs only the nibble rewound. */
            {
                uint32_t raw = zbm_load_u16le(cur.m1);
                uint32_t np = raw & (pbc > 1 ? 0xffffu : 0xffu);
                uint32_t newp = pbc ? np : cur.period;

                if(newp < 8 || cur.avail < newp) {
                    cur.m3 = save;
                    goto slow;
                }
                cur.period = newp;
                cur.m1 += pbc;
            }
            if(bmp_num < ZBM_BITMAP_BASE)
                ++cur.m2;

            {
                const uint8_t *row = rowbase + ((size_t)bmp << 4);

                zbm_blend8_row(cur.dest, cur.dest - cur.period, cur.data, row);
                cur.data += row[ZBM_BLEND_ROW_CNT];
            }
            cur.dest += 8;
            cur.avail += 8;
            continue;

slow:
            state->dest = cur.dest;
            state->data = cur.data;
            state->meta_1 = cur.m1;
            state->meta_2 = cur.m2;
            state->meta_3 = cur.m3;
            state->written = (uint32_t)(cur.avail - prewritten);
            state->period = cur.period;
            state->dest_left = dl_sum - cur.avail;

            err = zbm_decompress_single_bitmap(state, state->src + meta_off_3);
            if(err)
                return err;

            cur.dest = state->dest;
            cur.data = state->data;
            cur.m1 = state->meta_1;
            cur.m2 = state->meta_2;
            cur.m3 = state->meta_3;
            cur.period = state->period;
            cur.avail = prewritten + state->written;
        }

        state->dest = cur.dest;
        state->data = cur.data;
        state->meta_1 = cur.m1;
        state->meta_2 = cur.m2;
        state->meta_3 = cur.m3;
        state->written = (uint32_t)(cur.avail - prewritten);
        state->period = cur.period;
        state->dest_left = dl_sum - cur.avail;
    }

    /*
     * Literals and period bytes must land exactly on their declared ends.
     * The explicit bitmap and selector cursors may reuse later areas,
     * including the trailing table: Apple's decoder accepts those layouts
     * with the usual bitmap semantics. Every read is still bounded by the
     * chunk, independently of its role as metadata or table storage.
     */
    if((uint32_t)(state->data - state->src) != meta_off_1 ||
       (uint32_t)(state->meta_1 - state->src) != meta_off_2)
        return ZBM_INVAL;

    return 0;
}

static int zbm_handle_chunk(struct zbm_state *state)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_REQUIRES(state->src_left == 0 || __CPROVER_r_ok(state->src, state->src_left))
ZBM_REQUIRES(state->dest == NULL ||
             (__CPROVER_w_ok(state->dest, state->dest_left) &&
              state->prewritten <= (size_t)__CPROVER_POINTER_OFFSET(state->dest) &&
              __CPROVER_r_ok(state->dest - state->prewritten, state->prewritten) &&
              ZBM_DISJOINT(state->src, state->src_left, state->dest, state->dest_left)))
ZBM_ASSIGNS(*state; state->dest != NULL: __CPROVER_object_upto(state->dest, state->dest_left))
ZBM_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == ZBM_INVAL ||
             __CPROVER_return_value == ZBM_RANGE)
ZBM_ENSURES(state->src == ZBM_OLD(state->src) &&
             state->src_left == ZBM_OLD(state->src_left) &&
             state->prewritten == ZBM_OLD(state->prewritten))
ZBM_ENSURES(state->dest_left <= ZBM_OLD(state->dest_left))
ZBM_ENSURES(__CPROVER_return_value != 0 ||
             (state->len >= sizeof(struct zbm_chunk_hdr) && state->len <= state->src_left &&
              state->decmp_len <= CRUSHLZBITMAP_CHUNK_SIZE &&
              state->decmp_len <= ZBM_OLD(state->dest_left) &&
              state->dest_left == ZBM_OLD(state->dest_left) - state->decmp_len &&
              (ZBM_OLD(state->dest) == NULL ? state->dest == NULL :
               state->dest == ZBM_OLD(state->dest) + state->decmp_len)))
{
    const struct zbm_chunk_hdr *decmp_hdr = NULL;

    if(state->src_left < sizeof(*decmp_hdr))
        return ZBM_INVAL;
    decmp_hdr = (struct zbm_chunk_hdr *)state->src;

    state->len = zbm_u24_to_u32(decmp_hdr->len);
    if(state->len > state->src_left)
        return ZBM_INVAL;
    /* A chunk shorter than its own header can never be valid. */
    if(state->len < sizeof(*decmp_hdr))
        return ZBM_INVAL;
    state->src_end = state->src + state->len;

    state->decmp_len = zbm_u24_to_u32(decmp_hdr->decmp_len);
    if(state->decmp_len > CRUSHLZBITMAP_CHUNK_SIZE)
        return ZBM_INVAL;
    /* dest_size is honored as a ceiling on the total decoded length even
     * with dest == NULL, so a probe call can refuse a stream past a caller
     * chosen bound instead of only ever reporting "unlimited". */
    if(state->decmp_len > state->dest_left)
        return ZBM_RANGE;
    if(!state->dest) { /* We just wanted the length, so we are done */
        state->dest_left -= state->decmp_len;
        return 0;
    }

    if(zbm_chunk_is_uncompressed(state))
        return zbm_handle_uncompressed_chunk(state);

    return zbm_handle_compressed_chunk(state);
}

static int zbm_decompress_raw(void *dest, size_t dest_size, const void *src, size_t src_size, size_t *out_len)
{
    struct zbm_state state = {0};
    int err;

    state.src = src;
    state.src_left = src_size;
    state.dest = dest;
    state.dest_left = dest_size;
    state.prewritten = 0;

    err = zbm_check_magic(&state);
    if(err) {
        *out_len = state.prewritten; /* always 0 here; no chunk has run yet */
        return err;
    }

    /* The final chunk has zero decompressed length */
    do
        ZBM_LOOP_ASSIGNS(state, err; dest != NULL: __CPROVER_object_upto(dest, dest_size))
        ZBM_LOOP_INVARIANT(state.src_left <= src_size)
        ZBM_LOOP_INVARIANT(state.src == (const uint8_t *)src + (src_size - state.src_left))
        ZBM_LOOP_INVARIANT(state.src_left == 0 || __CPROVER_r_ok(state.src, state.src_left))
        ZBM_LOOP_INVARIANT(state.prewritten <= dest_size)
        ZBM_LOOP_INVARIANT(state.dest_left == dest_size - state.prewritten)
        ZBM_LOOP_INVARIANT(dest == NULL ? state.dest == NULL :
                          state.dest == (uint8_t *)dest + state.prewritten)
        ZBM_LOOP_INVARIANT(dest == NULL ||
                          (__CPROVER_w_ok(state.dest, state.dest_left) &&
                           __CPROVER_r_ok(dest, state.prewritten) &&
                           ZBM_DISJOINT(state.src, state.src_left,
                                        state.dest, state.dest_left)))
        ZBM_LOOP_DECREASES(state.src_left)
    {
        err = zbm_handle_chunk(&state);
        if(err) {
            /* Every fully completed chunk before this one is real, correct
             * decoded output; the chunk that failed contributes nothing,
             * whether or not it partially wrote into dest. */
            *out_len = state.prewritten;
            return err;
        }
        state.src += state.len;
        state.src_left -= state.len;
        state.prewritten += state.decmp_len;
    } while(state.decmp_len != 0);

    *out_len = state.prewritten;
    return 0;
}

/* Decodes a whole stream. Returns 0, CRUSHLZBITMAP_OUTPUT_TOO_SMALL when dst
 * cannot hold the output, or CRUSHLZBITMAP_INVALID for a malformed stream. */
int crushlzbitmap_decode_buffer(void *dst, size_t dst_size, const void *src, size_t src_size, size_t *out_len)
{
    if(!out_len)
        return CRUSHLZBITMAP_INVALID;
    /* zbm_decompress_raw only writes *out_len on success; a caller reading
     * it after a reported failure must not see an uninitialized value. */
    *out_len = 0;
    if(src_size && !src)
        return CRUSHLZBITMAP_INVALID;
    int err = zbm_decompress_raw(dst, dst_size, src, src_size, out_len);
    if(err == 0)
        return 0;
    return err == ZBM_RANGE ? CRUSHLZBITMAP_OUTPUT_TOO_SMALL : CRUSHLZBITMAP_INVALID;
}

#define ZBM_MAX_BITMAP_COUNT    (CRUSHLZBITMAP_CHUNK_SIZE >> 3)
#define ZBM_POSSIBLE_BMPROTS    (1 << 10)

/* A use count never exceeds one chunk's block count (4096), so 16 bits
 * suffice. */
typedef uint16_t zbm_usecnt_t;

/* Every tuning knob is a runtime field of crushlzbitmap_params; this
 * file fixes only the ceilings for array sizing, and zbm_validate_params()
 * rejects anything past them. */

#define ZBM_GREEDY_REACH        65535u  /* largest legal period, so the largest useful reach */
/* Candidates handed to the exact scorer per block. */
#define ZBM_GREEDY_MAX_CANDS    CRUSHLZBITMAP_MAX_DP_CANDS

/*
 * dp_ncand[] and dp_parent[][] are uint8_t, so a candidate count above 255
 * would truncate silently; this is the real ceiling. The DP tables are also
 * dimensioned per block, so each extra slot costs 12 KiB of state.
 */
typedef char zbm_dp_cands_fit_in_u8[(CRUSHLZBITMAP_MAX_DP_CANDS <= 255) ? 1 : -1];

/* Extra bits charged against a period change in the probe cost, beyond the
 * meta_1 bytes. Negative: the probe cost only decides what is seen, and a
 * candidate is admitted only when it strictly improves on the continuation,
 * so charging the true cost would discard every candidate that saves exactly
 * one literal at a changed period. The scorer settles the real price. */
#define ZBM_GREEDY_PERIOD_CHANGE_PENALTY (-8)
#define ZBM_PROBE_PEN_1B (8 + ZBM_GREEDY_PERIOD_CHANGE_PENALTY)
#define ZBM_PROBE_PEN_2B (16 + ZBM_GREEDY_PERIOD_CHANGE_PENALTY)

/*
 * Row tier. Each bucket has the configured depth of 32-bit entries. An
 * entry is a 24-bit position under an 8-bit epoch. An insert is one store
 * into the slot a hash of the position names: nothing is read, so the
 * bucket never serialises on itself. An entry is used only if its epoch
 * is current and the distance it implies is in reach. Candidates are
 * checked against the current input's bytes. Rebuilding the index advances
 * the epoch through 1..255; wrap clears the active table layout.
 */
#define ZBM_ROW_WAYS            4       /* table entries per bucket the state reserves at 16 hash bits */
#define ZBM_ROW_EPOCH_BITS      8
#define ZBM_ROW_POS_MASK        0xffffffu

#define ZBM_DEFAULT_ROW_HASH_BITS           16
#define ZBM_DEFAULT_ROW_DEPTH                2
#define ZBM_DEFAULT_ROW_DIST_CACHE_SIZE      4
#define ZBM_DEFAULT_ROW_ACCEPT_DIFF          1
#define ZBM_DEFAULT_ROW_SCAN_WINDOW          0
#define ZBM_DEFAULT_ROW_LOOKAHEAD            0
/* Defaults for CRUSHLZBITMAP_STRATEGY_FAST: level -3's settings. */
#define ZBM_DEFAULT_FAST_HASH_BITS          16
#define ZBM_DEFAULT_FAST_WINDOWS             8
#define ZBM_DEFAULT_FAST_DIST_CACHE_SIZE     2
#define ZBM_DEFAULT_FAST_ACCEPT_DIFF         1
#define ZBM_DEFAULT_FAST_SKIP_SHIFT          4
/* Defaults for CRUSHLZBITMAP_STRATEGY_DP: level 7's sourcing. */
#define ZBM_DEFAULT_DP_HASH_BITS            15
#define ZBM_DEFAULT_DP_DEPTH                 8
#define ZBM_DEFAULT_DP_DIST_CACHE_SIZE       8
#define ZBM_DEFAULT_DP_SCAN_WINDOW         256
#define ZBM_DEFAULT_DP_MAX_CANDIDATES       16
#define ZBM_DEFAULT_DP_ITERATIONS            2

#define ZBM_META_SCRATCH_SIZE   16384 /* bound on one chunk's metadata; the worst case is about 14.3 KB */

/* A full candidate (period, bitmap) sequence for one chunk, snapshotted so it
 * can be scored and kept or discarded. */
struct zbm_bitmap_snapshot {
    struct zbm_bmap bitmaps[ZBM_MAX_BITMAP_COUNT];
    uint16_t        periods[ZBM_MAX_BITMAP_COUNT];
    int             bmp_cnt;
    zbm_usecnt_t    usecnts[ZBM_POSSIBLE_BMPROTS];
};

struct zbm_beam_trace {
    uint16_t period;
    uint8_t parent;
};

/* Candidate deduplication: an open-addressed set of the periods seen in the
 * current block, which a block's stamp marks live. A block offers at most
 * 255 + 64 candidates, so the table stays under a third full. */
#define ZBM_BEAM_SEEN_BITS 10
/* Beams this narrow pick survivors by insertion; wider ones by selection. */
#define ZBM_BEAM_INSERT_MAX_WIDTH 16
struct zbm_beam_seen {
    uint16_t period, stamp;
};

struct zbm_compress_state {
    /* Set once per top-level call, read-only from then on. */
    crushlzbitmap_params params;

    /* Updated during a chunk write */
    const uint8_t   *src;       /* Next byte to read */
    uint32_t        read;       /* Bytes processed so far for current chunk */
    uint32_t        written;    /* Bytes written so far for current chunk */
    uint8_t         *dest;      /* Write the next byte here */
    uint16_t        period;     /* Repetition period for compression, in bytes */

    /* Updated right before a chunk write */
    const uint8_t   *dest_end;  /* Maximum limit for the current chunk */
    const uint8_t   *src_end;   /* End of current decompressed chunk */
    uint32_t        decmp_len;  /* Decompressed length of the chunk */

    /* Updated after a chunk write */
    size_t          dest_left;  /* Room left in destination buffer */
    size_t          preread;    /* Bytes processed for previous chunks */
    size_t          prewritten; /* Bytes written for previous chunks */
    size_t          src_left;   /* Room left in the source buffer */

    /* Array of all bitmaps applied for the current chunk */
    struct zbm_bmap bitmaps[ZBM_MAX_BITMAP_COUNT];
    uint16_t        periods[ZBM_MAX_BITMAP_COUNT];
    int             bmp_cnt;

    /* How many times was each bitmap-rotation combination applied? */
    zbm_usecnt_t    usecnts[ZBM_POSSIBLE_BMPROTS];

    /* The fast tier's use counts while a chunk is decided, keyed by
     * zbm_bmkey() (bitmap | period_bytecnt << 8) so the loop indexes them
     * with the key it stores anyway; folded into usecnts[] afterwards. */
    zbm_usecnt_t    key_usecnts[3 << 8];

    /* Array of bitmaps applied most often */
    struct zbm_bmap top_bitmaps[ZBM_BITMAP_COUNT];

    /* Which bitmap number (the meta_3 nibble) each (bitmap, period_bytecnt)
     * pair encodes to given top_bitmaps, keyed by zbm_bmkey() (at most 767,
     * so it fits the same 1024 entries), and that number resolved per block. */
    uint8_t         bmap_num_tbl[ZBM_POSSIBLE_BMPROTS];
    uint8_t         bmap_nums[ZBM_MAX_BITMAP_COUNT + 16];

    /* One bit per block, set when the block ends a run of equal bitmap
     * numbers. The 16 bytes of slack above let zbm_build_run_boundaries()
     * read past the last block. */
    uint64_t        run_bnd[ZBM_MAX_BITMAP_COUNT / 64 + 1];
    /* One bit per block, set when the block belongs to a run of four or
     * more, the only runs the third area does not store a nibble per block
     * for. The extra word reads as zero. */
    uint64_t        run_long[ZBM_MAX_BITMAP_COUNT / 64 + 1];

    /* Best-scoring iteration so far this chunk and its total compressed size
     * (0 = none yet). */
    struct zbm_bitmap_snapshot best;
    size_t          best_size;

    /* Steering for iterations 2+: which tuples the previous iteration's
     * top-12 table held, and a ring of recently used periods. */
    uint8_t         is_top_estimate[ZBM_POSSIBLE_BMPROTS];

    /* Scratch destination for scoring a trial iteration's metadata size
     * without touching the real state->dest/written. */
    uint8_t         meta_scratch[ZBM_META_SCRATCH_SIZE];

    /* The row tier's bucket table: 2^18 entries, the buckets' ways times
     * 2^hash_bits of them. Absolute positions under an epoch. */
    const uint8_t   *buf_base;  /* start of the caller's whole source buffer */
    size_t          buf_len;    /* its length, bounds the 8-byte needle loads */
    uint32_t        index_pos;  /* absolute offset the index is populated up to (exclusive) */
    int             index_live; /* the table has been initialized at least once this call */
    uint32_t        row_tab[(1u << CRUSHLZBITMAP_MAX_ROW_HASH_BITS) * ZBM_ROW_WAYS] __attribute__((aligned(16)));
    uint32_t        row_epoch;  /* stamps entries; one from another epoch is dead */
    uint64_t        row_mru;    /* four recent periods, 16 bits each, lane 0 in force */
    uint64_t        row_mru2;   /* the four behind them */
    int8_t          row_next_diff; /* the next block's literal count at the period in force, or -1 */
    uint8_t         row_sh;     /* 32 - hash_bits */
    uint8_t         row_ways;   /* entries per bucket: the depth */
    /* The DP and beam seeding pass's second index, keyed by
     * zbm_row_key2(), ZBM_ROW2_WAYS entries a bucket, in caller scratch;
     * NULL for the row and fast strategies. Same epoch as row_tab. */
    uint32_t        *row_tab2;
    uint8_t         row_sh2;

    /* CRUSHLZBITMAP_STRATEGY_DP tables, sized from max_candidates at first
     * use. dp_parent[i][k] is the index into block i-1's list that cell k came
     * from, or ZBM_DP_FROM_MIN when it jumped from that row's best. */
    uint16_t        *dp_cand;    /* [ZBM_MAX_BITMAP_COUNT][dp_cand_stride] */
    uint8_t         *dp_parent;  /* [ZBM_MAX_BITMAP_COUNT][dp_cand_stride] */
    int             dp_cand_stride;
    uint8_t         dp_ncand[ZBM_MAX_BITMAP_COUNT];
    uint16_t        dp_chosen[ZBM_MAX_BITMAP_COUNT];
    uint8_t         dp_argmin_row[ZBM_MAX_BITMAP_COUNT];
    int             dp_recording; /* set only during the seeding pass */
    int             dp_lists_ready; /* this chunk's candidate lists are recorded */
    struct zbm_beam_trace *beam_trace; /* caller scratch, [blocks][beam_width] */
    struct zbm_beam_seen *beam_seen; /* candidate deduplication, [1 << ZBM_BEAM_SEEN_BITS] */
    int             dp_nblocks;     /* blocks the recorded lists cover */
};

#define ZBM_DP_CAND(st, blk)    ((st)->dp_cand + (size_t)(blk) * (st)->dp_cand_stride)
#define ZBM_DP_PARENT(st, blk)  ((st)->dp_parent + (size_t)(blk) * (st)->dp_cand_stride)

/* Internal error used when a compression attempt was ineffective */
#define ZBM_CANT_COMPRESS   (-1024)

/* The (bitmap, period_bytecnt) pair as one small integer, read as the two
 * bytes the struct holds. */
static unsigned zbm_bmkey(const struct zbm_bmap *bmap)
ZBM_REQUIRES(__CPROVER_r_ok(bmap, sizeof(*bmap)))
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value == ((unsigned)bmap->bitmap | (unsigned)bmap->period_bytecnt << 8))
{
    uint16_t v;

    memcpy(&v, bmap, sizeof(v));
    return v;
}

static int zbm_bmprot(struct zbm_bmap *bmap)
{
    return (int)bmap->bitmap << 2 | (int)bmap->period_bytecnt;
}

#ifdef ZBM_PROOF
/* Explicit finite conjunction: DFCC does not support forall predicates. */
#define ZBM_ENCODER_PBC_AT(st, q) \
    (((q) >= (st)->bmp_cnt) | ((st)->bitmaps[q].period_bytecnt <= 2))
#define ZBM_PROOF_ALL16(F, st, q, step) \
    (F(st, (q)) & F(st, (q) + (step)) & F(st, (q) + 2 * (step)) & F(st, (q) + 3 * (step)) & \
     F(st, (q) + 4 * (step)) & F(st, (q) + 5 * (step)) & F(st, (q) + 6 * (step)) & F(st, (q) + 7 * (step)) & \
     F(st, (q) + 8 * (step)) & F(st, (q) + 9 * (step)) & F(st, (q) + 10 * (step)) & F(st, (q) + 11 * (step)) & \
     F(st, (q) + 12 * (step)) & F(st, (q) + 13 * (step)) & F(st, (q) + 14 * (step)) & F(st, (q) + 15 * (step)))
#define ZBM_ENCODER_PBC16(st, q) ZBM_PROOF_ALL16(ZBM_ENCODER_PBC_AT, st, q, 1)
#define ZBM_ENCODER_PBC256(st, q) (ZBM_ENCODER_PBC16(st, (q) + 0) & \
    ZBM_ENCODER_PBC16(st, (q) + 16) & \
    ZBM_ENCODER_PBC16(st, (q) + 32) & \
    ZBM_ENCODER_PBC16(st, (q) + 48) & \
    ZBM_ENCODER_PBC16(st, (q) + 64) & \
    ZBM_ENCODER_PBC16(st, (q) + 80) & \
    ZBM_ENCODER_PBC16(st, (q) + 96) & \
    ZBM_ENCODER_PBC16(st, (q) + 112) & \
    ZBM_ENCODER_PBC16(st, (q) + 128) & \
    ZBM_ENCODER_PBC16(st, (q) + 144) & \
    ZBM_ENCODER_PBC16(st, (q) + 160) & \
    ZBM_ENCODER_PBC16(st, (q) + 176) & \
    ZBM_ENCODER_PBC16(st, (q) + 192) & \
    ZBM_ENCODER_PBC16(st, (q) + 208) & \
    ZBM_ENCODER_PBC16(st, (q) + 224) & \
    ZBM_ENCODER_PBC16(st, (q) + 240))
#define ZBM_ENCODER_PBC_OK(st) (ZBM_ENCODER_PBC256(st, 0) & \
    ZBM_ENCODER_PBC256(st, 256) & \
    ZBM_ENCODER_PBC256(st, 512) & \
    ZBM_ENCODER_PBC256(st, 768) & \
    ZBM_ENCODER_PBC256(st, 1024) & \
    ZBM_ENCODER_PBC256(st, 1280) & \
    ZBM_ENCODER_PBC256(st, 1536) & \
    ZBM_ENCODER_PBC256(st, 1792) & \
    ZBM_ENCODER_PBC256(st, 2048) & \
    ZBM_ENCODER_PBC256(st, 2304) & \
    ZBM_ENCODER_PBC256(st, 2560) & \
    ZBM_ENCODER_PBC256(st, 2816) & \
    ZBM_ENCODER_PBC256(st, 3072) & \
    ZBM_ENCODER_PBC256(st, 3328) & \
    ZBM_ENCODER_PBC256(st, 3584) & \
    ZBM_ENCODER_PBC256(st, 3840))
#endif

static int zbm_write_magic(struct zbm_compress_state *state)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_REQUIRES(state->dest_left <= ((size_t)1 << 48) && state->prewritten <= ((size_t)1 << 48))
ZBM_REQUIRES(__CPROVER_w_ok(state->dest, state->dest_left))
ZBM_REQUIRES(!__CPROVER_same_object(state, state->dest))
ZBM_ASSIGNS(state->dest, state->dest_left, state->prewritten;
            state->dest_left >= ZBM_MAGIC_SZ: __CPROVER_object_upto(state->dest, ZBM_MAGIC_SZ))
ZBM_ENSURES(__CPROVER_return_value == (ZBM_OLD(state->dest_left) < ZBM_MAGIC_SZ ? ZBM_INVAL : 0))
ZBM_ENSURES(state->dest == ZBM_OLD(state->dest) + (__CPROVER_return_value == 0 ? ZBM_MAGIC_SZ : 0))
ZBM_ENSURES(state->dest_left == ZBM_OLD(state->dest_left) - (__CPROVER_return_value == 0 ? ZBM_MAGIC_SZ : 0))
ZBM_ENSURES(state->prewritten == ZBM_OLD(state->prewritten) + (__CPROVER_return_value == 0 ? ZBM_MAGIC_SZ : 0))
{
    if(state->dest_left < ZBM_MAGIC_SZ)
        return ZBM_INVAL;

    memcpy(state->dest, ZBM_MAGIC, ZBM_MAGIC_SZ);

    state->dest += ZBM_MAGIC_SZ;
    state->dest_left -= ZBM_MAGIC_SZ;
    state->prewritten += ZBM_MAGIC_SZ;
    return 0;
}

static int zbm_build_uncompressed_chunk(struct zbm_compress_state *state)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_REQUIRES(state->decmp_len <= CRUSHLZBITMAP_CHUNK_SIZE && state->read <= state->decmp_len)
ZBM_REQUIRES(state->written >= sizeof(struct zbm_chunk_hdr) &&
             state->written <= state->decmp_len + sizeof(struct zbm_chunk_hdr))
ZBM_REQUIRES(__CPROVER_POINTER_OFFSET(state->src) >= state->read &&
             __CPROVER_POINTER_OFFSET(state->dest) >= state->written)
ZBM_REQUIRES(__CPROVER_r_ok(state->src - state->read, state->decmp_len))
ZBM_REQUIRES(__CPROVER_w_ok(state->dest - state->written,
                          state->decmp_len + sizeof(struct zbm_chunk_hdr)))
ZBM_REQUIRES(!__CPROVER_same_object(state, state->src) &&
             !__CPROVER_same_object(state, state->dest) &&
             !__CPROVER_same_object(state->src, state->dest))
ZBM_ASSIGNS(state->src, state->read, state->dest, state->written,
            __CPROVER_object_upto(state->dest - state->written + sizeof(struct zbm_chunk_hdr), state->decmp_len))
ZBM_ENSURES(__CPROVER_return_value == 0 && state->read == state->decmp_len &&
             state->written == state->decmp_len + sizeof(struct zbm_chunk_hdr))
ZBM_ENSURES(state->src == ZBM_OLD(state->src) - ZBM_OLD(state->read) + state->decmp_len)
ZBM_ENSURES(state->dest == ZBM_OLD(state->dest) - ZBM_OLD(state->written) + sizeof(struct zbm_chunk_hdr) + state->decmp_len)
{
    /* Undo the previous compression attempt */
    state->src -= state->read;
    state->read = 0;
    state->dest -= state->written - sizeof(struct zbm_chunk_hdr);
    state->written = sizeof(struct zbm_chunk_hdr);

    memcpy(state->dest, state->src, state->decmp_len);

    state->src += state->decmp_len;
    state->read += state->decmp_len;
    state->written += state->decmp_len;
    state->dest += state->decmp_len;
    return 0;
}

/* memcpy rather than a cast: candidate positions are not aligned. */
static uint64_t zbm_load_u64(const uint8_t *ptr)
{
    uint64_t v;

    memcpy(&v, ptr, sizeof(v));
    return v;
}

static void zbm_append_new_bitmap(struct zbm_compress_state *state, uint8_t bitmap, uint16_t period)
{
    struct zbm_bmap *new_bmp = NULL;

    /* See zbm_commit_block_pbc: the same invariant, a second commit path. */
    assert(period >= 8);

    new_bmp = &state->bitmaps[state->bmp_cnt];
    new_bmp->bitmap = bitmap;
    state->periods[state->bmp_cnt] = period;
    if(period == state->period)
        new_bmp->period_bytecnt = 0;
    else if(period <= 0xff)
        new_bmp->period_bytecnt = 1;
    else
        new_bmp->period_bytecnt = 2;
    ++state->bmp_cnt;

    ++state->usecnts[zbm_bmprot(new_bmp)];

    state->period = period;
}

/*
 * The encoder's period floor: no copy is emitted at a period below 8, because
 * libcompression mishandles these periods on all macOS versions.
 * Expressed as a clamp to all-literal, which makes such a period cost strictly
 * more than any period at or above 8, so every cost model declines it. The
 * candidate searches also refuse a distance below 8; this is the backstop.
 */
static uint8_t zbm_period_floor_bitmap(uint8_t bitmap, uint16_t period, uint8_t size)
{
    uint8_t all_literal = (uint8_t)((1u << size) - 1);

    if(period > 0 && period < 8 && bitmap != all_literal)
        return all_literal;
    return bitmap;
}

/* Which lanes of a full block differ, branch-free: the multiply packs the
 * eight flag bits into one byte (8k - 7j is injective, so nothing carries). */
static __attribute__((always_inline)) inline uint8_t zbm_diff_bitmap(uint64_t xor)
{
    uint64_t t = (xor & 0x7f7f7f7f7f7f7f7fULL) + 0x7f7f7f7f7f7f7f7fULL;

    t = ((t | xor) & 0x8080808080808080ULL) >> 7;
    return (uint8_t)(t * 0x0102040810204080ULL >> 56);
}

/* A partial trailing block keeps the byte loop: loading eight bytes could
 * read past the buffer. */
static uint8_t zbm_calculate_bitmap(const uint8_t *bytes1, const uint8_t *bytes2, uint8_t size, uint16_t period)
ZBM_REQUIRES(size <= 8)
ZBM_REQUIRES(__CPROVER_r_ok(bytes1, size) && __CPROVER_r_ok(bytes2, size))
ZBM_ASSIGNS()
ZBM_ENSURES(((unsigned)__CPROVER_return_value >> size) == 0)
{
    uint8_t bitmap;
    uint8_t i;

    if(size == 8)
        return zbm_period_floor_bitmap(zbm_diff_bitmap(zbm_load_u64(bytes1) ^ zbm_load_u64(bytes2)),
                                      period, size);

    bitmap = 0;
    for(i = 0; i < size; ++i) {
        if(bytes1[i] != bytes2[i])
            bitmap |= 1 << i;
    }
    return zbm_period_floor_bitmap(bitmap, period, size);
}

/*
 * One 16-byte row per bitmap value, the mirror of zbm_blend_row: bytes 0..7
 * are shuffle selectors gathering the literal lanes to the bottom (lanes past
 * the popcount repeat lane 0), byte 8 is popcount(bmp). Every selector is in
 * 0..7, so TBL and PSHUFB agree.
 */
static const uint8_t zbm_pack_row[256][16] = {
  {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
  {0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0},
  {1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0},
  {0,1,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {2,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0},
  {0,2,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {1,2,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,1,2,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {3,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0},
  {0,3,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {1,3,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,1,3,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {2,3,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,2,3,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,2,3,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,2,3,0,0,0,0,4,0,0,0,0,0,0,0},
  {4,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0},
  {0,4,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {1,4,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,1,4,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {2,4,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,2,4,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,2,4,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,2,4,0,0,0,0,4,0,0,0,0,0,0,0},
  {3,4,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,3,4,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,3,4,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,3,4,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,3,4,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,3,4,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,3,4,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,3,4,0,0,0,5,0,0,0,0,0,0,0},
  {5,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0},
  {0,5,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {1,5,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,1,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {2,5,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,2,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,2,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,2,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {3,5,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,3,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,3,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,3,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,3,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,3,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,3,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,3,5,0,0,0,5,0,0,0,0,0,0,0},
  {4,5,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,4,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,4,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,4,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,4,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,4,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,4,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,4,5,0,0,0,5,0,0,0,0,0,0,0},
  {3,4,5,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,3,4,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,3,4,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,3,4,5,0,0,0,5,0,0,0,0,0,0,0},
  {2,3,4,5,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,3,4,5,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,3,4,5,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,3,4,5,0,0,6,0,0,0,0,0,0,0},
  {6,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0},
  {0,6,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {1,6,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,1,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {2,6,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,2,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,2,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,2,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {3,6,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,3,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,3,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,3,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,3,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,3,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,3,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,3,6,0,0,0,5,0,0,0,0,0,0,0},
  {4,6,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,4,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,4,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,4,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,4,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,4,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,4,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,4,6,0,0,0,5,0,0,0,0,0,0,0},
  {3,4,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,3,4,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,3,4,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,3,4,6,0,0,0,5,0,0,0,0,0,0,0},
  {2,3,4,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,3,4,6,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,3,4,6,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,3,4,6,0,0,6,0,0,0,0,0,0,0},
  {5,6,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,5,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,5,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,5,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {3,5,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,3,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,3,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,3,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {2,3,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,3,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,3,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,3,5,6,0,0,6,0,0,0,0,0,0,0},
  {4,5,6,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,4,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,4,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,4,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {2,4,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,4,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,4,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,4,5,6,0,0,6,0,0,0,0,0,0,0},
  {3,4,5,6,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,3,4,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {1,3,4,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,3,4,5,6,0,0,6,0,0,0,0,0,0,0},
  {2,3,4,5,6,0,0,0,5,0,0,0,0,0,0,0},
  {0,2,3,4,5,6,0,0,6,0,0,0,0,0,0,0},
  {1,2,3,4,5,6,0,0,6,0,0,0,0,0,0,0},
  {0,1,2,3,4,5,6,0,7,0,0,0,0,0,0,0},
  {7,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0},
  {0,7,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {1,7,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,1,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {2,7,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,2,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,2,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,2,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {3,7,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,3,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,3,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,3,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,3,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,3,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,3,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,3,7,0,0,0,5,0,0,0,0,0,0,0},
  {4,7,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,4,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,4,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,4,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,4,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,4,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,4,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,4,7,0,0,0,5,0,0,0,0,0,0,0},
  {3,4,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,3,4,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,3,4,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,3,4,7,0,0,0,5,0,0,0,0,0,0,0},
  {2,3,4,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,3,4,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,3,4,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,3,4,7,0,0,6,0,0,0,0,0,0,0},
  {5,7,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,5,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,5,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,5,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {3,5,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,3,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,3,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,3,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {2,3,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,3,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,3,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,3,5,7,0,0,6,0,0,0,0,0,0,0},
  {4,5,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,4,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,4,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,4,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {2,4,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,4,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,4,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,4,5,7,0,0,6,0,0,0,0,0,0,0},
  {3,4,5,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,3,4,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,3,4,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,3,4,5,7,0,0,6,0,0,0,0,0,0,0},
  {2,3,4,5,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,2,3,4,5,7,0,0,6,0,0,0,0,0,0,0},
  {1,2,3,4,5,7,0,0,6,0,0,0,0,0,0,0},
  {0,1,2,3,4,5,7,0,7,0,0,0,0,0,0,0},
  {6,7,0,0,0,0,0,0,2,0,0,0,0,0,0,0},
  {0,6,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {1,6,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,1,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {2,6,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,2,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,2,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,2,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {3,6,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,3,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,3,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,3,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {2,3,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,3,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,3,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,3,6,7,0,0,6,0,0,0,0,0,0,0},
  {4,6,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,4,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,4,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,4,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {2,4,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,4,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,4,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,4,6,7,0,0,6,0,0,0,0,0,0,0},
  {3,4,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,3,4,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,3,4,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,3,4,6,7,0,0,6,0,0,0,0,0,0,0},
  {2,3,4,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,2,3,4,6,7,0,0,6,0,0,0,0,0,0,0},
  {1,2,3,4,6,7,0,0,6,0,0,0,0,0,0,0},
  {0,1,2,3,4,6,7,0,7,0,0,0,0,0,0,0},
  {5,6,7,0,0,0,0,0,3,0,0,0,0,0,0,0},
  {0,5,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {1,5,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,1,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {2,5,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,2,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,2,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,2,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {3,5,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,3,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,3,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,3,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {2,3,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,2,3,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {1,2,3,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {0,1,2,3,5,6,7,0,7,0,0,0,0,0,0,0},
  {4,5,6,7,0,0,0,0,4,0,0,0,0,0,0,0},
  {0,4,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {1,4,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,1,4,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {2,4,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,2,4,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {1,2,4,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {0,1,2,4,5,6,7,0,7,0,0,0,0,0,0,0},
  {3,4,5,6,7,0,0,0,5,0,0,0,0,0,0,0},
  {0,3,4,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {1,3,4,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {0,1,3,4,5,6,7,0,7,0,0,0,0,0,0,0},
  {2,3,4,5,6,7,0,0,6,0,0,0,0,0,0,0},
  {0,2,3,4,5,6,7,0,7,0,0,0,0,0,0,0},
  {1,2,3,4,5,6,7,0,7,0,0,0,0,0,0,0},
  {0,1,2,3,4,5,6,7,8,0,0,0,0,0,0,0},
};

/* Popcount of every 8-bit value; the file is built without -mpopcnt. */
static const uint8_t zbm_popcount8_table[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
};

static inline uint8_t zbm_popcount8(uint8_t v)
{
    return zbm_popcount8_table[v];
}

/* Deinterleave selector shared by zbm_literal_total() and
 * zbm_period_bytes_total(): applied to 16 bytes holding 8 {bitmap,
 * period_bytecnt} pairs, it sorts the even (bitmap) bytes into the low 8
 * lanes and the odd (period_bytecnt) bytes into the high 8, mirroring what
 * NEON's VLD2 does for both fields in one load. */
#if defined(__SSSE3__) && !defined(__ARM_NEON) && !defined(CRUSH_SIMD_PORTABLE)
#define ZBM_BMAP_DEINTERLEAVE _mm_setr_epi8(0, 2, 4, 6, 8, 10, 12, 14, 1, 3, 5, 7, 9, 11, 13, 15)
#endif

/* Sum of the chunk's popcounts, i.e. the literal bytes to write. The u16
 * lanes cannot overflow: at most 4096 blocks of 8 literals, a sixteenth per
 * lane. */
static long zbm_literal_total(const struct zbm_bmap *bmaps, int cnt)
ZBM_REQUIRES(cnt >= 0 && cnt <= ZBM_MAX_BITMAP_COUNT)
ZBM_REQUIRES(__CPROVER_r_ok(bmaps, (size_t)cnt * sizeof(*bmaps)))
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value >= 0 && __CPROVER_return_value <= 8 * cnt)
{
    long total = 0;
    int i = 0;

#ifdef ZBM_PROOF
    /* Both native vector branches read 16 two-byte pairs per iteration:
     * NEON uses one deinterleaving load; x86 uses two adjacent 16-byte loads.
     * Check that footprint even though the portable arithmetic below is used. */
    for(int v = 0; v + 16 <= cnt; v += 16)
        ZBM_LOOP_ASSIGNS(v)
        ZBM_LOOP_INVARIANT(v >= 0 && v <= cnt)
        ZBM_LOOP_DECREASES(cnt - v)
        __CPROVER_assert(__CPROVER_r_ok(bmaps + v, 16 * sizeof(*bmaps)),
                         "native literal sum vector footprint is readable");
#endif

#if defined(__ARM_NEON) && !defined(CRUSH_SIMD_PORTABLE)
    if(cnt >= 16) {
        uint16x8_t acc = vdupq_n_u16(0);

        for(; i + 16 <= cnt; i += 16)
            acc = vpadalq_u8(acc, vcntq_u8(vld2q_u8((const uint8_t *)(const void *)&bmaps[i]).val[0]));
        total = (long)vaddvq_u16(acc);
    }
#elif defined(__SSSE3__) && !defined(CRUSH_SIMD_PORTABLE)
    /*
     * x86 arm of the same idea: PSHUFB deinterleaves the bitmap bytes out of
     * the {bitmap, period_bytecnt} pairs (NEON does this with one VLD2), a
     * nibble-LUT PSHUFB popcounts them (same table as vcnt_u8() further
     * down), and PSADBW sums the 16 popcounts straight into a 64-bit lane,
     * so unlike the ARM arm there is no u16 lane width to reason about
     * overflowing.
     */
    if(cnt >= 16) {
        const __m128i deint = ZBM_BMAP_DEINTERLEAVE;
        const __m128i lut = _mm_setr_epi8(0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4);
        const __m128i nib = _mm_set1_epi8(0x0f);
        __m128i acc = _mm_setzero_si128();

        for(; i + 16 <= cnt; i += 16) {
            __m128i lo = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)&bmaps[i]), deint);
            __m128i hi = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)&bmaps[i + 8]), deint);
            __m128i bm = _mm_unpacklo_epi64(lo, hi); /* 16 bitmap bytes */
            __m128i pc = _mm_add_epi8(_mm_shuffle_epi8(lut, _mm_and_si128(bm, nib)),
                                       _mm_shuffle_epi8(lut, _mm_and_si128(_mm_srli_epi16(bm, 4), nib)));

            acc = _mm_add_epi64(acc, _mm_sad_epu8(pc, _mm_setzero_si128()));
        }
        total = (long)(uint64_t)_mm_cvtsi128_si64(_mm_add_epi64(acc, _mm_unpackhi_epi64(acc, acc)));
    }
#endif
    for(; i < cnt; ++i)
        ZBM_LOOP_ASSIGNS(i, total)
        ZBM_LOOP_INVARIANT(i >= 0 && i <= cnt)
        ZBM_LOOP_INVARIANT(total >= 0 && total <= 8L * i)
        ZBM_LOOP_DECREASES(cnt - i)
        total += zbm_popcount8(bmaps[i].bitmap);
    return total;
}

/*
 * Writes every committed block's literal bytes to the destination in block
 * order and leaves state->src/read/dest/written as a block-at-a-time walk
 * would. @known_total is the literal total if the caller has it, else -1.
 * The bulk loop's store reaches up to eight bytes past the final literal,
 * which the `total + 8` reservation covers; a tighter destination takes the
 * exact path. Only the final block can be short, and it always takes the
 * exact path, which keeps the bulk loop's 8-byte reads in bounds.
 */
static int zbm_emit_literals(struct zbm_compress_state *state, const uint8_t *chunk_src, long known_total)
{
    const struct zbm_bmap *bmaps = state->bitmaps;
    const uint8_t *s = chunk_src;
    uint8_t *d = state->dest;
    ptrdiff_t room = state->dest_end - d;
    int cnt = state->bmp_cnt;
    long total;
    int i, j;

    total = known_total >= 0 ? known_total : zbm_literal_total(bmaps, cnt);
    if(total > room)
        return ZBM_CANT_COMPRESS;

    /* Leaves i at the last block, which the exact loop finishes. */
    i = 0;
    if(total + 8 <= room) {
        for(; i + 1 < cnt; ++i) {
            const uint8_t *row = zbm_pack_row[bmaps[i].bitmap];

            zbm_pack8(d, s, row);
            d += row[8];
            s += 8;
        }
    }

    for(; i < cnt; ++i) {
        uint8_t bm = bmaps[i].bitmap;

        for(j = 0; j < 8 && s != state->src_end; ++j, ++s)
            if(bm >> j & 1)
                *d++ = *s;
    }

    state->written += (uint32_t)(d - state->dest);
    state->dest = d;
    state->src = s;
    state->read = (uint32_t)(s - chunk_src);
    return 0;
}

#if defined(ZBM_PROOF) && defined(ZBM_PROOF_SELECTOR_VALUES)
/* One arbitrary, read-only query proves the range at every table position
 * without materializing a 1024-term postcondition in the symbolic heap. */
unsigned zbm_proof_selector_index;
unsigned zbm_proof_block_index;
#endif

/* A block's bitmap number depends only on its bmkey and the top table, so it
 * is resolved once per chunk over all 1024 keys. */
static void zbm_build_bmap_num_table(struct zbm_compress_state *state)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_REQUIRES((state->top_bitmaps[0].period_bytecnt <= 2) & (state->top_bitmaps[1].period_bytecnt <= 2) & (state->top_bitmaps[2].period_bytecnt <= 2) & (state->top_bitmaps[3].period_bytecnt <= 2) & (state->top_bitmaps[4].period_bytecnt <= 2) & (state->top_bitmaps[5].period_bytecnt <= 2) & (state->top_bitmaps[6].period_bytecnt <= 2) & (state->top_bitmaps[7].period_bytecnt <= 2) & (state->top_bitmaps[8].period_bytecnt <= 2) & (state->top_bitmaps[9].period_bytecnt <= 2) & (state->top_bitmaps[10].period_bytecnt <= 2) & (state->top_bitmaps[11].period_bytecnt <= 2))
ZBM_ASSIGNS(state->bmap_num_tbl)
#ifdef ZBM_PROOF_SELECTOR_VALUES
ZBM_REQUIRES(zbm_proof_selector_index < ZBM_POSSIBLE_BMPROTS)
ZBM_ENSURES(state->bmap_num_tbl[zbm_proof_selector_index] <= 14)
#endif
{
    unsigned key;
    int bmprot, i;

    /* Default: a regular bitmap from the second metadata area, numbered by
     * its period bytecount (the key's high byte). */
    for(key = 0; key < ZBM_POSSIBLE_BMPROTS; ++key)
        ZBM_LOOP_ASSIGNS(key, state->bmap_num_tbl)
        ZBM_LOOP_INVARIANT(key <= ZBM_POSSIBLE_BMPROTS)
#ifdef ZBM_PROOF_SELECTOR_VALUES
        ZBM_LOOP_INVARIANT(zbm_proof_selector_index >= key || state->bmap_num_tbl[zbm_proof_selector_index] <= 14)
#endif
        ZBM_LOOP_DECREASES(ZBM_POSSIBLE_BMPROTS - key)
        state->bmap_num_tbl[key] = (uint8_t)(key >> 8);

    /* Overwrite the keys that made the top table. Walking in reverse leaves
     * the lowest-numbered matching slot in place, which matters for the
     * duplicate (0,0) pairs of unfilled slots. */
    for(i = ZBM_BITMAP_COUNT - 1; i >= 0; --i)
        ZBM_LOOP_ASSIGNS(i, bmprot, state->bmap_num_tbl)
        ZBM_LOOP_INVARIANT(i >= -1 && i < ZBM_BITMAP_COUNT)
#ifdef ZBM_PROOF_SELECTOR_VALUES
        ZBM_LOOP_INVARIANT(state->bmap_num_tbl[zbm_proof_selector_index] <= 14)
#endif
        ZBM_LOOP_DECREASES(i + 1)
    {
        bmprot = zbm_bmprot(&state->top_bitmaps[i]);
        if(state->usecnts[bmprot] == 0)
            state->bmap_num_tbl[zbm_bmkey(&state->top_bitmaps[i])] = (uint8_t)(i + 3);
    }
}

/* Resolve every block's bitmap number once into a byte array. */
static void zbm_build_bmap_nums(struct zbm_compress_state *state)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_REQUIRES(state->bmp_cnt >= 0 && state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT)
ZBM_REQUIRES(ZBM_ENCODER_PBC_OK(state))
ZBM_ASSIGNS(state->bmap_nums)
#ifdef ZBM_PROOF_SELECTOR_VALUES
ZBM_REQUIRES(state->bmp_cnt == 0 || zbm_proof_block_index < (unsigned)state->bmp_cnt)
ZBM_REQUIRES(state->bmp_cnt == 0 ||
    state->bmap_num_tbl[(unsigned)state->bitmaps[zbm_proof_block_index].bitmap |
        (unsigned)state->bitmaps[zbm_proof_block_index].period_bytecnt << 8] <= 14)
ZBM_ENSURES(state->bmp_cnt == 0 || state->bmap_nums[zbm_proof_block_index] <= 14)
#endif
{
    int i, cnt = state->bmp_cnt;

    for(i = 0; i < cnt; ++i)
        ZBM_LOOP_ASSIGNS(i, state->bmap_nums)
        ZBM_LOOP_INVARIANT(i >= 0 && i <= cnt)
#ifdef ZBM_PROOF_SELECTOR_VALUES
        ZBM_LOOP_INVARIANT(zbm_proof_block_index >= (unsigned)i || state->bmap_nums[zbm_proof_block_index] <= 14)
#endif
        ZBM_LOOP_DECREASES(cnt - i)
    {
        struct zbm_bmap entry = state->bitmaps[i];
        unsigned key = zbm_bmkey(&entry);
#ifdef ZBM_PROOF
        __CPROVER_assert(key < ZBM_POSSIBLE_BMPROTS,
                         "bitmap key stays within the selector table");
#endif
        state->bmap_nums[i] = state->bmap_num_tbl[key];
    }
}

static int zbm_bmap_num_for_index(struct zbm_compress_state *state, int idx)
ZBM_REQUIRES(__CPROVER_r_ok(state, sizeof(*state)))
ZBM_REQUIRES(state->bmp_cnt >= 0 && state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT)
ZBM_REQUIRES(idx >= 0 && idx < state->bmp_cnt)
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value == state->bmap_nums[idx])
{
    return state->bmap_nums[idx];
}

static int zbm_write_metadata_1(struct zbm_compress_state *state)
{
    struct zbm_bmap *bmap = NULL;
    uint16_t period;
    ptrdiff_t room;
    uint8_t *d;
    int i;

    /*
     * One room check for the area, and a bulk loop that stores unconditionally
     * and advances only when the byte counts. Speculative stores need room for
     * a block that contributes nothing, hence two bytes more than the
     * 2 * bmp_cnt bound; a tighter destination takes the exact loop.
     */
    room = state->dest_end - state->dest;
    d = state->dest;

    /* The first metadata area stores the periods, when they change */
    if(2 * state->bmp_cnt + 2 <= room) {
        /* The two bytes of the period as one 16-bit store, advanced by
         * period_bytecnt; the last block's overhang reaches one byte past the
         * area, which the `+ 2` above covers. */
        for(i = 0; i < state->bmp_cnt; ++i) {
            uint16_t p = state->periods[i];

            memcpy(d, &p, sizeof(p));
            d += state->bitmaps[i].period_bytecnt;
        }
    } else {
        ptrdiff_t exact = 0;

        for(i = 0; i < state->bmp_cnt; ++i)
            exact += state->bitmaps[i].period_bytecnt;
        if(exact > room)
            return ZBM_CANT_COMPRESS;

        for(i = 0; i < state->bmp_cnt; ++i) {
            bmap = &state->bitmaps[i];
            period = state->periods[i];

            if(bmap->period_bytecnt == 0)
                continue;

            *d++ = (uint8_t)period;

            if(bmap->period_bytecnt == 1)
                continue;

            *d++ = (uint8_t)(period >> 8);
        }
    }
    state->written += (uint32_t)(d - state->dest);
    state->dest = d;
    return 0;
}

static int zbm_write_metadata_2(struct zbm_compress_state *state)
{
    ptrdiff_t room;
    uint8_t *d;
    int i;

    room = state->dest_end - state->dest;
    d = state->dest;

    /* The second metadata area stores the bitmaps that did not make the top
     * table; `bmap_nums[i] < ZBM_BITMAP_BASE` is that test. Same
     * store-then-maybe-advance shape as above. */
    if(state->bmp_cnt + 1 <= room) {
        const struct zbm_bmap *bmaps = state->bitmaps;
        const uint8_t *tbl = state->bmap_num_tbl;
        uint8_t *nums = state->bmap_nums;

        for(i = 0; i < state->bmp_cnt; ++i) {
            unsigned num = tbl[zbm_bmkey(&bmaps[i])];

            nums[i] = (uint8_t)num;
            d[0] = bmaps[i].bitmap;
            d += num < ZBM_BITMAP_BASE;
        }
    } else {
        ptrdiff_t exact = 0;

        zbm_build_bmap_nums(state);

        for(i = 0; i < state->bmp_cnt; ++i)
            exact += state->bmap_nums[i] < ZBM_BITMAP_BASE;
        if(exact > room)
            return ZBM_CANT_COMPRESS;

        for(i = 0; i < state->bmp_cnt; ++i) {
            if(state->bmap_nums[i] >= ZBM_BITMAP_BASE)
                continue;

            *d++ = state->bitmaps[i].bitmap;
        }
    }
    state->written += (uint32_t)(d - state->dest);
    state->dest = d;
    return 0;
}

#if defined(ZBM_PROOF) && defined(ZBM_PROOF_RUN_VALUES)
unsigned zbm_proof_run_index;
#endif

/* How many consecutive blocks from @idx share @bmap_num; *next_num receives
 * the number that ends the run (left alone when the run reaches the last
 * block). */
static int zbm_run_length(struct zbm_compress_state *state, int idx, int bmap_num, int *next_num)
ZBM_REQUIRES(__CPROVER_r_ok(state, sizeof(*state)))
ZBM_REQUIRES(state->bmp_cnt >= 1 && state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT)
ZBM_REQUIRES(idx >= 0 && idx < state->bmp_cnt)
ZBM_REQUIRES(__CPROVER_w_ok(next_num, sizeof(*next_num)) && !__CPROVER_same_object(state, next_num))
ZBM_ASSIGNS(*next_num)
ZBM_ENSURES(__CPROVER_return_value >= 1 && __CPROVER_return_value <= state->bmp_cnt - idx)
ZBM_ENSURES(__CPROVER_return_value < state->bmp_cnt - idx || *next_num == ZBM_OLD(*next_num))
#ifdef ZBM_PROOF_RUN_VALUES
ZBM_REQUIRES(zbm_proof_run_index < (unsigned)state->bmp_cnt)
ZBM_ENSURES(zbm_proof_run_index <= (unsigned)idx ||
    zbm_proof_run_index >= (unsigned)(idx + __CPROVER_return_value) ||
    state->bmap_nums[zbm_proof_run_index] == bmap_num)
ZBM_ENSURES(__CPROVER_return_value == state->bmp_cnt - idx ||
    (*next_num == state->bmap_nums[idx + __CPROVER_return_value] && *next_num != bmap_num))
#endif
{
    int i;

    for(i = idx + 1; i < state->bmp_cnt; ++i)
        ZBM_LOOP_ASSIGNS(i, *next_num)
        ZBM_LOOP_INVARIANT(i >= idx + 1 && i <= state->bmp_cnt)
        ZBM_LOOP_INVARIANT(*next_num == ZBM_LOOP_ENTRY(*next_num))
#ifdef ZBM_PROOF_RUN_VALUES
        ZBM_LOOP_INVARIANT(zbm_proof_run_index <= (unsigned)idx ||
            zbm_proof_run_index >= (unsigned)i || state->bmap_nums[zbm_proof_run_index] == bmap_num)
#endif
        ZBM_LOOP_DECREASES(state->bmp_cnt - i)
    {
        int n = zbm_bmap_num_for_index(state, i);

        if(n != bmap_num) {
            *next_num = n;
            break;
        }
    }
    return i - idx;
}

/*
 * Nibble sink for the third metadata area. It takes no limit because the
 * area's size is known up front: zbm_nibble_cost_for_run() never exceeds the
 * run length it prices, so a chunk's nibble count is bounded by its block
 * count. Sixteen nibbles are accumulated in a register and stored at once.
 */
struct zbm_nybl_out {
    uint8_t  *addr; /* next byte to store into */
    uint64_t acc;   /* pending nibbles, lowest-numbered in the low bits */
    int      n;     /* how many nibbles are pending, 0..15 */
};

/* Nibble k goes in byte k/2, low half for even k. */
static void zbm_nybl_store8(uint8_t *addr, uint64_t acc)
{
    memcpy(addr, &acc, sizeof(acc));
}

/* Append a full vector while retaining the pending partial vector. */
static __attribute__((always_inline)) inline void zbm_write_16_nibbles(struct zbm_nybl_out *out, uint64_t packed)
ZBM_REQUIRES(__CPROVER_rw_ok(out, sizeof(*out)))
ZBM_REQUIRES(out->n >= 0 && out->n < 16 && (out->acc >> (4 * out->n)) == 0)
ZBM_REQUIRES(__CPROVER_w_ok(out->addr, 8) && !__CPROVER_same_object(out, out->addr))
ZBM_ASSIGNS(out->addr, out->acc, __CPROVER_object_upto(out->addr, 8))
ZBM_ENSURES(out->n == ZBM_OLD(out->n))
ZBM_ENSURES(out->addr == ZBM_OLD(out->addr) + 8)
ZBM_ENSURES(out->acc == (packed >> 1) >> (63 - 4 * out->n))
ZBM_ENSURES((out->acc >> (4 * out->n)) == 0)
{
    zbm_nybl_store8(out->addr, out->acc | packed << (4 * out->n));
    out->acc = (packed >> 1) >> (63 - 4 * out->n);
    out->addr += 8;
}

/* Up to four nibbles at once, packed low-to-high in @pat. Whatever did not
 * fit is the top @n nibbles of @pat; when nothing carried the shift is 4 * k,
 * at most 16, and yields zero. */
static void zbm_write_nibbles(struct zbm_nybl_out *out, uint64_t pat, int k)
ZBM_REQUIRES(__CPROVER_rw_ok(out, sizeof(*out)))
ZBM_REQUIRES(out->n >= 0 && out->n < 16 && k >= 1 && k <= 4)
ZBM_REQUIRES((out->acc >> (4 * out->n)) == 0 && (pat >> (4 * k)) == 0)
ZBM_REQUIRES(__CPROVER_w_ok(out->addr, 0) && !__CPROVER_same_object(out, out->addr))
ZBM_REQUIRES(out->n + k < 16 || __CPROVER_w_ok(out->addr, 8))
ZBM_ASSIGNS(out->addr, out->acc, out->n;
            out->n + k >= 16: __CPROVER_object_upto(out->addr, 8))
ZBM_ENSURES(out->n == (ZBM_OLD(out->n) + k) % 16)
ZBM_ENSURES(out->addr == ZBM_OLD(out->addr) + (ZBM_OLD(out->n) + k >= 16 ? 8 : 0))
ZBM_ENSURES((out->acc >> (4 * out->n)) == 0)
{
    out->acc |= pat << 4 * out->n;
    out->n += k;
    if(out->n >= 16) {
        zbm_nybl_store8(out->addr, out->acc);
        out->addr += 8;
        out->n -= 16;
        out->acc = pat >> 4 * (k - out->n);
    }
}

/* val repeated r times, r in 1..3, as a nibble pattern. */
static const uint16_t zbm_nybl_rep_pat[4] = { 0, 0x001, 0x011, 0x111 };

static void zbm_write_nibble(struct zbm_nybl_out *out, uint8_t val)
ZBM_REQUIRES(__CPROVER_rw_ok(out, sizeof(*out)))
ZBM_REQUIRES(out->n >= 0 && out->n < 16 && val < 16)
ZBM_REQUIRES((out->acc >> (4 * out->n)) == 0)
ZBM_REQUIRES(__CPROVER_w_ok(out->addr, 0) && !__CPROVER_same_object(out, out->addr))
ZBM_REQUIRES(out->n < 15 || __CPROVER_w_ok(out->addr, 8))
ZBM_ASSIGNS(out->addr, out->acc, out->n;
            out->n == 15: __CPROVER_object_upto(out->addr, 8))
ZBM_ENSURES(out->n == (ZBM_OLD(out->n) + 1) % 16)
ZBM_ENSURES(out->addr == ZBM_OLD(out->addr) + (ZBM_OLD(out->n) == 15 ? 8 : 0))
ZBM_ENSURES((out->acc >> (4 * out->n)) == 0)
{
    out->acc |= (uint64_t)val << 4 * out->n;
    if(++out->n == 16) {
        zbm_nybl_store8(out->addr, out->acc);
        out->addr += 8;
        out->acc = 0;
        out->n = 0;
    }
}

/* Flushes the partial accumulator and returns the end of the area; a
 * half-written trailing byte is padded with a zero nibble. */
static uint8_t *zbm_nybl_finish(struct zbm_nybl_out *out)
ZBM_REQUIRES(__CPROVER_r_ok(out, sizeof(*out)))
ZBM_REQUIRES(out->n >= 0 && out->n < 16)
ZBM_REQUIRES((out->acc >> (4 * out->n)) == 0)
ZBM_REQUIRES(__CPROVER_w_ok(out->addr, (out->n + 1) / 2) && !__CPROVER_same_object(out, out->addr))
ZBM_ASSIGNS(__CPROVER_object_upto(out->addr, (out->n + 1) / 2))
ZBM_ENSURES(__CPROVER_return_value == out->addr + (out->n + 1) / 2)
{
    int bytes = (out->n + 1) / 2;
    int i;

    for(i = 0; i < bytes; ++i)
        out->addr[i] = (uint8_t)(out->acc >> 8 * i);
    return out->addr + bytes;
}

static void zbm_write_repetition_count(struct zbm_nybl_out *out, int repeat)
ZBM_REQUIRES(__CPROVER_rw_ok(out, sizeof(*out)))
ZBM_REQUIRES(repeat >= 4 && repeat <= ZBM_MAX_BITMAP_COUNT)
ZBM_REQUIRES(out->n >= 0 && out->n < 16 && (out->acc >> (4 * out->n)) == 0)
ZBM_REQUIRES(__CPROVER_w_ok(out->addr, (out->n + 2 + (repeat - 4) / 15 + 1) / 2))
ZBM_REQUIRES(!__CPROVER_same_object(out, out->addr))
ZBM_ASSIGNS(*out,
            __CPROVER_object_upto(out->addr, (out->n + 2 + (repeat - 4) / 15 + 1) / 2))
ZBM_ENSURES(out->n == (ZBM_OLD(out->n) + 2 + (ZBM_OLD(repeat) - 4) / 15) % 16)
ZBM_ENSURES(out->addr == ZBM_OLD(out->addr) + 8 * ((ZBM_OLD(out->n) + 2 + (ZBM_OLD(repeat) - 4) / 15) / 16))
ZBM_ENSURES((out->acc >> (4 * out->n)) == 0)
{
    int nibble = 0xf;
#ifdef ZBM_PROOF
    const int initial = repeat, pending = out->n;
    const int budget = 2 + (repeat - 4) / 15;
    const int room = (pending + budget + 1) / 2;
    uint8_t *const base = out->addr;
    int count = 1;
#endif

    /* 0xf marks that this is a repetition */
    zbm_write_nibble(out, 0xf);

    /* We count from the minimum possible repetition count */
    repeat -= 4;

    while(repeat > 0)
        ZBM_LOOP_ASSIGNS(repeat, nibble, count, *out, __CPROVER_object_upto(base, room))
        ZBM_LOOP_INVARIANT(repeat >= 0 && repeat <= initial - 4)
        ZBM_LOOP_INVARIANT(count >= 1 && count <= budget)
        ZBM_LOOP_INVARIANT(count + (repeat + 14) / 15 == 1 + (initial - 4 + 14) / 15)
        ZBM_LOOP_INVARIANT(nibble >= 0 && nibble <= 15)
        ZBM_LOOP_INVARIANT(nibble != 15 || initial - 4 - repeat == 15 * (count - 1))
        ZBM_LOOP_INVARIANT(repeat == 0 || initial - 4 - repeat == 15 * (count - 1))
        ZBM_LOOP_INVARIANT(nibble == 15 || (repeat == 0 && nibble > 0 && nibble == (initial - 4) % 15))
        ZBM_LOOP_INVARIANT(out->n == (pending + count) % 16)
        ZBM_LOOP_INVARIANT(out->addr == base + 8 * ((pending + count) / 16))
        ZBM_LOOP_INVARIANT((out->acc >> (4 * out->n)) == 0)
        ZBM_LOOP_DECREASES(repeat)
    {
        nibble = MIN(repeat, 0xf);
        zbm_write_nibble(out, (uint8_t)nibble);
        repeat -= nibble;
#ifdef ZBM_PROOF
        ++count;
#endif
    }

    /* The repetition must always end in a non-0xf nibble */
    if(nibble == 0xf)
        zbm_write_nibble(out, 0);
}

/*
 * Where each run of equal bitmap numbers ends, one bit per block. The
 * comparison is equality with the word complemented once (there is no vector
 * not-equal on arm64 or x86). The last block always ends a run, which bounds
 * the search. Skip comparison groups wholly past the last block. The
 * initialized tail covers the final live group's padding and lookahead.
 */
#if defined(ZBM_PROOF) && defined(ZBM_PROOF_BOUNDARY_VALUES)
unsigned zbm_proof_boundary_index;
#endif

/* Separate arrays keep this layout-independent calculation small enough for
 * the value proof; the state wrapper below retains the encoder call site. */
static __attribute__((always_inline)) inline void zbm_build_run_boundaries_arrays(
    uint8_t (*nums_array)[ZBM_MAX_BITMAP_COUNT + 16],
    uint64_t (*bnd_array)[ZBM_MAX_BITMAP_COUNT / 64 + 1], int cnt)
ZBM_REQUIRES(cnt >= 0 && cnt <= ZBM_MAX_BITMAP_COUNT)
ZBM_REQUIRES(__CPROVER_rw_ok(nums_array, sizeof(*nums_array)))
ZBM_REQUIRES(__CPROVER_rw_ok(bnd_array, sizeof(*bnd_array)))
ZBM_REQUIRES(!__CPROVER_same_object(nums_array, bnd_array) ||
    (uint8_t *)nums_array + sizeof(*nums_array) <= (uint8_t *)bnd_array ||
    (uint8_t *)bnd_array + sizeof(*bnd_array) <= (uint8_t *)nums_array)
ZBM_ASSIGNS(*nums_array, *bnd_array)
ZBM_ENSURES(cnt == 0 || ((*bnd_array)[(cnt - 1) >> 6] & ((uint64_t)1 << ((cnt - 1) & 63))) != 0)
#ifdef ZBM_PROOF_BOUNDARY_VALUES
ZBM_REQUIRES(cnt == 0 || zbm_proof_boundary_index < (unsigned)cnt)
ZBM_ENSURES(cnt == 0 ||
    (((*bnd_array)[zbm_proof_boundary_index >> 6] >> (zbm_proof_boundary_index & 63u)) & 1u) ==
    (zbm_proof_boundary_index == (unsigned)(cnt - 1) ||
     (*nums_array)[zbm_proof_boundary_index] != (*nums_array)[zbm_proof_boundary_index + 1]))
ZBM_ENSURES(cnt == 0 || (*nums_array)[zbm_proof_boundary_index] ==
    ZBM_OLD((*nums_array)[cnt == 0 ? 0 : zbm_proof_boundary_index]))
ZBM_ENSURES(cnt == 0 || zbm_proof_boundary_index == (unsigned)(cnt - 1) ||
    (*nums_array)[zbm_proof_boundary_index + 1] == ZBM_OLD((*nums_array)[cnt <= 1 || zbm_proof_boundary_index == (unsigned)(cnt - 1) ? 0 : zbm_proof_boundary_index + 1]))
#endif
{
    uint8_t *const nums = *nums_array;
    uint64_t *const bnd = *bnd_array;
    int words = (cnt + 63) >> 6;
    int g, k;

    if(cnt <= 0)
        return;
    for(k = 0; k < 16; ++k)
        ZBM_LOOP_ASSIGNS(k, *nums_array)
        ZBM_LOOP_INVARIANT(k >= 0 && k <= 16)
#ifdef ZBM_PROOF_BOUNDARY_VALUES
        ZBM_LOOP_INVARIANT(nums[zbm_proof_boundary_index] == ZBM_LOOP_ENTRY(nums[zbm_proof_boundary_index]))
        ZBM_LOOP_INVARIANT(zbm_proof_boundary_index == (unsigned)(cnt - 1) ||
            nums[zbm_proof_boundary_index + 1] == ZBM_LOOP_ENTRY(nums[zbm_proof_boundary_index + 1]))
#endif
        ZBM_LOOP_DECREASES(16 - k)
        nums[cnt + k] = 0;

    for(g = 0; g < words; ++g)
        ZBM_LOOP_ASSIGNS(g, k, *bnd_array)
        ZBM_LOOP_INVARIANT(g >= 0 && g <= words)
#ifdef ZBM_PROOF_BOUNDARY_VALUES
        ZBM_LOOP_INVARIANT((zbm_proof_boundary_index >> 6) >= (unsigned)g ||
            zbm_proof_boundary_index == (unsigned)(cnt - 1) ||
            ((bnd[zbm_proof_boundary_index >> 6] >> (zbm_proof_boundary_index & 63u)) & 1u) ==
            (nums[zbm_proof_boundary_index] != nums[zbm_proof_boundary_index + 1]))
#endif
        ZBM_LOOP_DECREASES(words - g)
    {
        uint64_t eq = 0;
        int groups = g + 1 == words ? (cnt - (g << 6) + 15) >> 4 : 4;

        for(k = 0; k < groups; ++k)
            ZBM_LOOP_ASSIGNS(k, eq)
            ZBM_LOOP_INVARIANT(k >= 0 && k <= groups)
            ZBM_LOOP_INVARIANT(groups >= 1 && groups <= 4)
            ZBM_LOOP_INVARIANT(k == 4 || (eq >> (k << 4)) == 0)
#ifdef ZBM_PROOF_BOUNDARY_VALUES
            ZBM_LOOP_INVARIANT((zbm_proof_boundary_index >> 6) != (unsigned)g ||
                ((zbm_proof_boundary_index & 63u) >> 4) >= (unsigned)k ||
                ((eq >> (zbm_proof_boundary_index & 63u)) & 1u) ==
                (nums[zbm_proof_boundary_index] == nums[zbm_proof_boundary_index + 1]))
#endif
            ZBM_LOOP_DECREASES(groups - k)
        {
#ifdef ZBM_PROOF
            __CPROVER_assert((g << 6) + (k << 4) + 17 <= cnt + 16,
                             "run comparison stays in active selectors plus initialized tail");
#endif
            const uint8_t *p = nums + (g << 6) + (k << 4);
            uint64_t m = zbm_eq16_mask(p, p + 1);
            eq |= m << (k << 4);
        }
        bnd[g] = ~eq;
    }
    /* The last block ends its run by definition, whatever followed it in
     * memory said. */
    bnd[(cnt - 1) >> 6] |= (uint64_t)1 << ((cnt - 1) & 63);
}

static void zbm_build_run_boundaries(struct zbm_compress_state *state)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_REQUIRES(state->bmp_cnt >= 0 && state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT)
ZBM_ASSIGNS(state->bmap_nums, state->run_bnd)
ZBM_ENSURES(state->bmp_cnt == 0 ||
    (state->run_bnd[(state->bmp_cnt - 1) >> 6] & ((uint64_t)1 << ((state->bmp_cnt - 1) & 63))) != 0)
#ifdef ZBM_PROOF_BOUNDARY_VALUES
ZBM_REQUIRES(state->bmp_cnt == 0 || zbm_proof_boundary_index < (unsigned)state->bmp_cnt)
ZBM_ENSURES(state->bmp_cnt == 0 ||
    ((state->run_bnd[zbm_proof_boundary_index >> 6] >> (zbm_proof_boundary_index & 63u)) & 1u) ==
    (zbm_proof_boundary_index == (unsigned)(state->bmp_cnt - 1) ||
     state->bmap_nums[zbm_proof_boundary_index] != state->bmap_nums[zbm_proof_boundary_index + 1]))
ZBM_ENSURES(state->bmp_cnt == 0 || state->bmap_nums[zbm_proof_boundary_index] ==
    ZBM_OLD(state->bmap_nums[state->bmp_cnt == 0 ? 0 : zbm_proof_boundary_index]))
#endif
{
    zbm_build_run_boundaries_arrays(&state->bmap_nums, &state->run_bnd, state->bmp_cnt);
}

static int zbm_nibble_cost_for_run(int r);

/* Exact byte count zbm_write_metadata_3() will occupy; only needed when the
 * one-nibble-per-block bound does not fit. */
static ptrdiff_t zbm_metadata_3_bytes(struct zbm_compress_state *state)
ZBM_REQUIRES(__CPROVER_r_ok(state, sizeof(*state)))
ZBM_REQUIRES(state->bmp_cnt >= 0 && state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT)
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value >= 0 && __CPROVER_return_value <= (state->bmp_cnt + 1) / 2)
{
    int nibbles = 0, repeat, num, i;

    if(state->bmp_cnt == 0)
        return 0;

    num = zbm_bmap_num_for_index(state, 0);
    for(i = 0; i < state->bmp_cnt; i += repeat)
        ZBM_LOOP_ASSIGNS(i, repeat, num, nibbles)
        ZBM_LOOP_INVARIANT(i >= 0 && i <= state->bmp_cnt)
        ZBM_LOOP_INVARIANT(nibbles >= 0 && nibbles <= i)
        ZBM_LOOP_DECREASES(state->bmp_cnt - i)
    {
        int next = num;

        repeat = zbm_run_length(state, i, num, &next);
        nibbles += zbm_nibble_cost_for_run(repeat);
        num = next;
    }
    return (nibbles + 1) / 2;
}

/* Four equal blocks require three consecutive equality edges. The next
 * word supplies the two edges that may cross a word boundary. */
static __attribute__((always_inline)) inline uint64_t zbm_long_run_starts(uint64_t nb, uint64_t nb1)
{
    return nb & (nb >> 1 | nb1 << 63) & (nb >> 2 | nb1 << 62);
}

/* Cover all four blocks of each marked window, including windows that
 * started in the preceding word. */
static __attribute__((always_inline)) inline uint64_t zbm_long_run_spread(uint64_t starts, uint64_t prev)
{
    return starts | starts << 1 | starts << 2 | starts << 3 | prev >> 61 | prev >> 62 | prev >> 63;
}

/* Sixteen bits beginning at shift; split the left shift so shift==0 never
 * requires a shift by 64. The writer only uses this low sixteen-bit window. */
static __attribute__((always_inline)) inline uint16_t zbm_long_run_window(uint64_t word, uint64_t next, unsigned shift)
ZBM_REQUIRES(shift < 64)
{
    return (uint16_t)(word >> shift | (next << 1) << (63 - shift));
}

#if defined(ZBM_PROOF) && defined(ZBM_PROOF_LONG_VALUES)
unsigned zbm_proof_long_index;
/* Side-effect-free expressions for contracts; the leaf harness independently
 * proves their four-block-window meaning using the actual helper bodies. */
#define ZBM_PROOF_LONG_STARTS(a, b) ((a) & ((a) >> 1 | (b) << 63) & ((a) >> 2 | (b) << 62))
#define ZBM_PROOF_LONG_SPREAD(a, b) ((a) | (a) << 1 | (a) << 2 | (a) << 3 | (b) >> 61 | (b) >> 62 | (b) >> 63)
#endif

static __attribute__((always_inline)) inline void zbm_build_long_runs_arrays(
    const uint64_t (*boundary_array)[ZBM_MAX_BITMAP_COUNT / 64 + 1],
    uint64_t (*long_array)[ZBM_MAX_BITMAP_COUNT / 64 + 1], int cnt)
ZBM_REQUIRES(cnt >= 0 && cnt <= ZBM_MAX_BITMAP_COUNT)
ZBM_REQUIRES(__CPROVER_r_ok(boundary_array, sizeof(*boundary_array)))
ZBM_REQUIRES(__CPROVER_rw_ok(long_array, sizeof(*long_array)))
ZBM_REQUIRES(!__CPROVER_same_object(boundary_array, long_array) ||
    (const uint8_t *)boundary_array + sizeof(*boundary_array) <= (const uint8_t *)long_array ||
    (const uint8_t *)long_array + sizeof(*long_array) <= (const uint8_t *)boundary_array)
ZBM_ASSIGNS(*long_array)
ZBM_ENSURES((*long_array)[(cnt + 63) >> 6] == 0)
#ifdef ZBM_PROOF_LONG_VALUES
ZBM_REQUIRES(cnt == 0 || zbm_proof_long_index < (unsigned)cnt)
ZBM_ENSURES(cnt == 0 || (*long_array)[zbm_proof_long_index >> 6] ==
    ZBM_PROOF_LONG_SPREAD(
        ZBM_PROOF_LONG_STARTS(~(*boundary_array)[zbm_proof_long_index >> 6],
            (zbm_proof_long_index >> 6) + 1 < (unsigned)((cnt + 63) >> 6) ? ~(*boundary_array)[(zbm_proof_long_index >> 6) + 1] : 0),
        (zbm_proof_long_index >> 6) == 0 ? 0 :
            ZBM_PROOF_LONG_STARTS(~(*boundary_array)[(zbm_proof_long_index >> 6) - 1], ~(*boundary_array)[zbm_proof_long_index >> 6])))
#endif
{
    const uint64_t *const bnd = *boundary_array;
    uint64_t *const lng = *long_array;
    const int words = (cnt + 63) >> 6;
    uint64_t prev = 0;
    int k;
#ifdef ZBM_PROOF_LONG_VALUES
    const unsigned qword = cnt == 0 ? 0 : zbm_proof_long_index >> 6;
    const uint64_t expected = cnt == 0 ? 0 : zbm_long_run_spread(
        zbm_long_run_starts(~bnd[qword], qword + 1 < (unsigned)words ? ~bnd[qword + 1] : 0),
        qword == 0 ? 0 : zbm_long_run_starts(~bnd[qword - 1], ~bnd[qword]));
#endif
    for(k = 0; k < words; ++k)
        ZBM_LOOP_ASSIGNS(k, prev, *long_array)
        ZBM_LOOP_INVARIANT(k >= 0 && k <= words)
#ifdef ZBM_PROOF_LONG_VALUES
        ZBM_LOOP_INVARIANT(prev == (k == 0 ? 0 : ZBM_PROOF_LONG_STARTS(~bnd[k - 1], k < words ? ~bnd[k] : 0)))
        ZBM_LOOP_INVARIANT(qword >= (unsigned)k || lng[qword] == expected)
#endif
        ZBM_LOOP_DECREASES(words - k)
    {
        uint64_t nb = ~bnd[k];
        uint64_t nb1 = k + 1 < words ? ~bnd[k + 1] : 0;
        uint64_t l = zbm_long_run_starts(nb, nb1);

        lng[k] = zbm_long_run_spread(l, prev);
        prev = l;
    }
    lng[words] = 0;
}

static __attribute__((always_inline)) inline int zbm_first_boundary_bit(uint64_t word)
ZBM_REQUIRES(word != 0)
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value >= 0 && __CPROVER_return_value < 64)
ZBM_ENSURES(((word >> __CPROVER_return_value) & 1u) == 1u)
ZBM_ENSURES((word & ((UINT64_C(1) << __CPROVER_return_value) - 1)) == 0)
{
    return __builtin_ctzll(word);
}

#if defined(ZBM_PROOF) && defined(ZBM_PROOF_RUN_END_VALUES)
unsigned zbm_proof_end_index;
#endif

/* The final active boundary bounds this search, even when earlier words
 * contain no boundaries. cnt is used by the proof's range contracts. */
static __attribute__((always_inline)) inline int zbm_find_run_end(
    const uint64_t (*boundary_array)[ZBM_MAX_BITMAP_COUNT / 64 + 1], int idx, int cnt)
ZBM_REQUIRES(cnt >= 1 && cnt <= ZBM_MAX_BITMAP_COUNT && idx >= 0 && idx < cnt)
ZBM_REQUIRES(__CPROVER_r_ok(boundary_array, sizeof(*boundary_array)))
ZBM_REQUIRES(((*boundary_array)[(cnt - 1) >> 6] & (UINT64_C(1) << ((cnt - 1) & 63))) != 0)
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value >= idx && __CPROVER_return_value < cnt)
ZBM_ENSURES(((*boundary_array)[__CPROVER_return_value >> 6] & (UINT64_C(1) << (__CPROVER_return_value & 63))) != 0)
#ifdef ZBM_PROOF_RUN_END_VALUES
ZBM_REQUIRES(zbm_proof_end_index < (unsigned)cnt)
ZBM_ENSURES(zbm_proof_end_index < (unsigned)idx || zbm_proof_end_index >= (unsigned)__CPROVER_return_value ||
    (((*boundary_array)[zbm_proof_end_index >> 6] >> (zbm_proof_end_index & 63u)) & 1u) == 0)
#endif
{
    const uint64_t *const bnd = *boundary_array;
    const int kk = idx >> 6, sft = idx & 63;
    uint64_t w = bnd[kk] >> sft;
    (void)cnt;

    if(w)
        return idx + zbm_first_boundary_bit(w);

    int b = kk + 1;
    while(bnd[b] == 0)
        ZBM_LOOP_ASSIGNS(b)
        ZBM_LOOP_INVARIANT(b >= kk + 1 && b <= ((cnt - 1) >> 6))
#ifdef ZBM_PROOF_RUN_END_VALUES
        ZBM_LOOP_INVARIANT((zbm_proof_end_index >> 6) < (unsigned)(kk + 1) ||
            (zbm_proof_end_index >> 6) >= (unsigned)b || bnd[zbm_proof_end_index >> 6] == 0)
#endif
        ZBM_LOOP_DECREASES(((cnt - 1) >> 6) - b)
        ++b;
    return (b << 6) + zbm_first_boundary_bit(bnd[b]);
}

/* Scalar selector calculations shared by the writer and its safety proofs. */
static __attribute__((always_inline)) inline uint64_t zbm_short_run_pattern(int repeat, unsigned number)
ZBM_REQUIRES(repeat >= 1 && repeat <= 3 && number <= 14)
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value == (uint64_t)zbm_nybl_rep_pat[repeat] * number)
ZBM_ENSURES((__CPROVER_return_value >> (4 * repeat)) == 0)
{
    return (uint64_t)zbm_nybl_rep_pat[repeat] * number;
}

static __attribute__((always_inline)) inline int zbm_selector_word_index(int index)
ZBM_REQUIRES(index >= 0 && index < ZBM_MAX_BITMAP_COUNT)
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value >= 0 && __CPROVER_return_value < ZBM_MAX_BITMAP_COUNT / 64)
ZBM_ENSURES(__CPROVER_return_value == index / 64)
ZBM_ENSURES((index & 63) == index % 64)
{
    return index >> 6;
}

static int zbm_write_metadata_3(struct zbm_compress_state *state)
{
    struct zbm_nybl_out out;
    uint8_t *end;

    if((state->bmp_cnt + 1) / 2 > state->dest_end - state->dest &&
       zbm_metadata_3_bytes(state) > state->dest_end - state->dest)
        return ZBM_CANT_COMPRESS;

    out.addr = state->dest;
    out.acc = 0;
    out.n = 0;

    /*
     * A run of fewer than four blocks is stored as one nibble per block, so
     * any sixteen blocks none of which is in a longer run are just their
     * numbers packed two to a byte: one vector step and one 8-byte store.
     * Everything else goes a run at a time, from the run boundaries.
     */
    {
        const uint8_t *nums = state->bmap_nums;
        uint64_t *lng = state->run_long;
        const int cnt = state->bmp_cnt;
        int i;

        zbm_build_run_boundaries(state);

        /* nb has bit t set when block t equals block t + 1, so l marks the
         * first block of four equal ones; smearing it over the next three
         * bits marks every block of a long run. Bits past the last block do
         * not matter: the last block always ends its run. */
        zbm_build_long_runs_arrays(&state->run_bnd, &state->run_long, cnt);

        i = 0;
        while(i < cnt) {
            const int kk = zbm_selector_word_index(i), sft = i & 63;
            int to_write, repeat, e;

            if(i + 16 <= cnt &&
               zbm_long_run_window(lng[kk], lng[kk + 1], (unsigned)sft) == 0) {
                uint64_t pk = zbm_pack_nibbles16(nums + i);

                zbm_write_16_nibbles(&out, pk);
                i += 16;
                continue;
            }

            /* The run (or, after a vector step, what is left of a short
             * one) from block i to the next boundary. */
            e = zbm_find_run_end(&state->run_bnd, i, cnt);
            to_write = nums[i];
            repeat = e - i + 1;
            i = e + 1;

            /* Fewer than 4 repetitions are done trivially */
            if(repeat <= 3) {
                zbm_write_nibbles(&out, zbm_short_run_pattern(repeat, (unsigned)to_write), repeat);
            } else {
                zbm_write_nibble(&out, (uint8_t)to_write);
                zbm_write_repetition_count(&out, repeat);
            }
        }
    }

    end = zbm_nybl_finish(&out);
    state->written += (uint32_t)(end - state->dest);
    state->dest = end;
    return 0;
}

/* This function does not perform boundary checks, the caller must do it */
static void zbm_write_single_bit(struct bit_ptr *bit, int val)
{
    *bit->addr |= val << bit->offset;

    ++bit->offset;
    if(bit->offset != 8)
        return;
    bit->offset = 0;
    ++bit->addr;
    return;
}

/* This function does not perform boundary checks, the caller must do it */
static void zbm_write_single_bitmap(struct bit_ptr *bit, struct zbm_bmap bmap)
{
    int i;

    /* The bitmap itself */
    for(i = 0; i < 8; ++i)
        zbm_write_single_bit(bit, bmap.bitmap >> i & 1);

    /* The trailing bits for the period bytecount */
    for(i = 0; i < 2; ++i)
        zbm_write_single_bit(bit, bmap.period_bytecnt >> i & 1);
}

static int zbm_write_trailing_bitmaps(struct zbm_compress_state *state)
{
    struct bit_ptr bmap = {0};
    int i;

    if(state->dest_end - state->dest < ZBM_BITMAP_BYTECNT)
        return ZBM_CANT_COMPRESS;
    memset(state->dest, 0, ZBM_BITMAP_BYTECNT);

    bmap.addr = state->dest;
    bmap.offset = 0;

    for(i = 0; i < ZBM_BITMAP_COUNT; ++i)
        zbm_write_single_bitmap(&bmap, state->top_bitmaps[i]);

    state->dest += ZBM_BITMAP_BYTECNT;
    state->written += ZBM_BITMAP_BYTECNT;
    return 0;
}

static struct uint24 zbm_u32_to_u24(uint32_t n)
{
    struct uint24 res;

    res.low = n;
    res.mid = n >> 8;
    res.hig = n >> 16;
    return res;
}

struct top_bmap {
    int          bmprot; /* -1 = empty slot */
    zbm_usecnt_t usecnt;
};

/* Finds the ZBM_BITMAP_COUNT most-used (bitmap, period_bytecnt) tuples from
 * usecnts[], which the decide loop already built. A tie at the boundary is
 * broken in bmprot order; any top-12 selection decodes correctly. */
#ifdef ZBM_PROOF
#define ZBM_TOP_KEY_AT(t, n, q) \
    (((q) >= (n)) | (((t)[q].bmprot >= -1) & ((t)[q].bmprot < ZBM_POSSIBLE_BMPROTS)))
#define ZBM_TOP_KEYS_OK(t, n) (ZBM_TOP_KEY_AT(t, n, 0) & \
    ZBM_TOP_KEY_AT(t, n, 1) & \
    ZBM_TOP_KEY_AT(t, n, 2) & \
    ZBM_TOP_KEY_AT(t, n, 3) & \
    ZBM_TOP_KEY_AT(t, n, 4) & \
    ZBM_TOP_KEY_AT(t, n, 5) & \
    ZBM_TOP_KEY_AT(t, n, 6) & \
    ZBM_TOP_KEY_AT(t, n, 7) & \
    ZBM_TOP_KEY_AT(t, n, 8) & \
    ZBM_TOP_KEY_AT(t, n, 9) & \
    ZBM_TOP_KEY_AT(t, n, 10) & \
    ZBM_TOP_KEY_AT(t, n, 11))
#endif

static void zbm_find_most_common_bitmaps(struct zbm_compress_state *state)
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_ASSIGNS(state->top_bitmaps, state->usecnts)
{
    struct top_bmap tops[ZBM_BITMAP_COUNT];
    int bmprot, i;

    for(i = 0; i < ZBM_BITMAP_COUNT; ++i)
        ZBM_LOOP_ASSIGNS(i, tops)
        ZBM_LOOP_INVARIANT(i >= 0 && i <= ZBM_BITMAP_COUNT)
        ZBM_LOOP_INVARIANT(ZBM_TOP_KEYS_OK(tops, i))
        ZBM_LOOP_DECREASES(ZBM_BITMAP_COUNT - i)
    {
        tops[i].bmprot = -1;
        tops[i].usecnt = 0;
    }

    for(bmprot = 0; bmprot < ZBM_POSSIBLE_BMPROTS; ++bmprot)
        ZBM_LOOP_ASSIGNS(bmprot, i, tops)
        ZBM_LOOP_INVARIANT(bmprot >= 0 && bmprot <= ZBM_POSSIBLE_BMPROTS)
        ZBM_LOOP_INVARIANT(ZBM_TOP_KEYS_OK(tops, ZBM_BITMAP_COUNT))
        ZBM_LOOP_DECREASES(ZBM_POSSIBLE_BMPROTS - bmprot)
    {
        zbm_usecnt_t usecnt = state->usecnts[bmprot];

        if(usecnt == 0)
            continue;

        /* tops[] is sorted descending, so its last entry is the bar to clear,
         * and nearly every key fails it. */
        if(tops[ZBM_BITMAP_COUNT - 1].usecnt >= usecnt)
            continue;

        for(i = 0; tops[i].usecnt >= usecnt; ++i)
            ZBM_LOOP_ASSIGNS(i)
            ZBM_LOOP_INVARIANT(i >= 0 && i < ZBM_BITMAP_COUNT)
            ZBM_LOOP_DECREASES(ZBM_BITMAP_COUNT - i)
            ;

        memmove(&tops[i + 1], &tops[i], (size_t)(ZBM_BITMAP_COUNT - i - 1) * sizeof(tops[i]));
        tops[i].bmprot = bmprot;
        tops[i].usecnt = usecnt;
    }

    for(i = 0; i < ZBM_BITMAP_COUNT; ++i)
        ZBM_LOOP_ASSIGNS(i, state->top_bitmaps, state->usecnts)
        ZBM_LOOP_INVARIANT(i >= 0 && i <= ZBM_BITMAP_COUNT)
        ZBM_LOOP_DECREASES(ZBM_BITMAP_COUNT - i)
    {
        if(tops[i].bmprot < 0) {
            /* Very few bitmaps, all are top */
            state->top_bitmaps[i].bitmap = 0;
            state->top_bitmaps[i].period_bytecnt = 0;
            continue;
        }
        state->top_bitmaps[i].bitmap = (uint8_t)(tops[i].bmprot >> 2);
        state->top_bitmaps[i].period_bytecnt = (uint8_t)(tops[i].bmprot & 3);
        /* Mark this as unused for the second metadata area */
        state->usecnts[tops[i].bmprot] = 0;
    }
}

/* Total bytes of the first metadata area: the sum of every block's
 * period_bytecnt (the odd byte lane of each pair). The u16 lanes cannot
 * overflow. */
static ptrdiff_t zbm_period_bytes_total(const struct zbm_bmap *bmaps, int cnt)
ZBM_REQUIRES(cnt >= 0 && cnt <= ZBM_MAX_BITMAP_COUNT)
ZBM_REQUIRES(__CPROVER_r_ok(bmaps, (size_t)cnt * sizeof(*bmaps)))
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value >= 0 && __CPROVER_return_value <= 255 * cnt)
{
    ptrdiff_t total = 0;
    int i = 0;

#ifdef ZBM_PROOF
    for(int v = 0; v + 16 <= cnt; v += 16)
        ZBM_LOOP_ASSIGNS(v)
        ZBM_LOOP_INVARIANT(v >= 0 && v <= cnt)
        ZBM_LOOP_DECREASES(cnt - v)
        __CPROVER_assert(__CPROVER_r_ok(bmaps + v, 16 * sizeof(*bmaps)),
                         "native period sum vector footprint is readable");
#endif

#if defined(__ARM_NEON) && !defined(CRUSH_SIMD_PORTABLE)
    if(cnt >= 16) {
        uint16x8_t acc = vdupq_n_u16(0);

        for(; i + 16 <= cnt; i += 16)
            acc = vpadalq_u8(acc, vld2q_u8((const uint8_t *)(const void *)&bmaps[i]).val[1]);
        total = (ptrdiff_t)vaddvq_u16(acc);
    }
#elif defined(__SSSE3__) && !defined(CRUSH_SIMD_PORTABLE)
    /*
     * Same PSHUFB deinterleave as zbm_literal_total(), keeping the odd
     * (period_bytecnt) lane instead of the even (bitmap) one. The values are
     * 0-2, so PSADBW sums them directly with no popcount step.
     */
    if(cnt >= 16) {
        const __m128i deint = ZBM_BMAP_DEINTERLEAVE;
        __m128i acc = _mm_setzero_si128();

        for(; i + 16 <= cnt; i += 16) {
            __m128i lo = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)&bmaps[i]), deint);
            __m128i hi = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)&bmaps[i + 8]), deint);
            __m128i pd = _mm_unpackhi_epi64(lo, hi); /* 16 period_bytecnt bytes */

            acc = _mm_add_epi64(acc, _mm_sad_epu8(pd, _mm_setzero_si128()));
        }
        total = (ptrdiff_t)(uint64_t)_mm_cvtsi128_si64(_mm_add_epi64(acc, _mm_unpackhi_epi64(acc, acc)));
    }
#endif
    for(; i < cnt; ++i)
        ZBM_LOOP_ASSIGNS(i, total)
        ZBM_LOOP_INVARIANT(i >= 0 && i <= cnt)
        ZBM_LOOP_INVARIANT(total >= 0 && total <= 255L * i)
        ZBM_LOOP_DECREASES(cnt - i)
        total += bmaps[i].period_bytecnt;
    return total;
}

/*
 * The first two metadata areas in one pass over the block list. Area 2 starts
 * where area 1 ends, so its length comes from zbm_period_bytes_total() up
 * front. Area 1's speculative store reaches one byte past its end, so area 2
 * is written two bytes clear and moved down afterwards. Returns 0 without
 * writing when the fused path does not apply (a tight destination); the
 * host); the output is byte-identical to the two writers in sequence.
 */
static int zbm_write_metadata_12(struct zbm_compress_state *state, struct zbm_cmp_chunk_hdr *hdr)
{
    const struct zbm_bmap *bmaps = state->bitmaps;
    const uint16_t *periods = state->periods;
    const uint8_t *tbl = state->bmap_num_tbl;
    uint8_t *nums = state->bmap_nums;
    ptrdiff_t room = state->dest_end - state->dest;
    int cnt = state->bmp_cnt;
    uint8_t *d0 = state->dest;
    uint8_t *d1, *d2, *area2;
    ptrdiff_t len1, len2;
    int i;

    len1 = zbm_period_bytes_total(bmaps, cnt);
    /* len1 + 2 covers area 1's overhang, cnt + 1 area 2's. */
    if(len1 + cnt + 3 > room)
        return 0;

    area2 = d0 + len1 + 2;
    d1 = d0;
    d2 = area2;
    for(i = 0; i < cnt; ++i) {
        unsigned key = zbm_bmkey(&bmaps[i]);
        unsigned num = tbl[key];
        uint16_t p = periods[i];

        memcpy(d1, &p, sizeof(p));
        d1 += key >> 8;             /* period_bytecnt, the key's high byte */
        nums[i] = (uint8_t)num;
        d2[0] = (uint8_t)key;       /* bitmap, the key's low byte */
        d2 += num < ZBM_BITMAP_BASE;
    }
    len2 = d2 - area2;
    memmove(d0 + len1, area2, (size_t)len2);

    hdr->meta_off_1 = zbm_u32_to_u24(state->written);
    hdr->meta_off_2 = zbm_u32_to_u24(state->written + (uint32_t)len1);
    state->written += (uint32_t)(len1 + len2);
    state->dest = d0 + len1 + len2;
    return 1;
}

static int zbm_build_metadata(struct zbm_compress_state *state, struct zbm_cmp_chunk_hdr *hdr)
{
    int err;

    zbm_find_most_common_bitmaps(state);
    zbm_build_bmap_num_table(state);

    if(!zbm_write_metadata_12(state, hdr)) {
        hdr->meta_off_1 = zbm_u32_to_u24(state->written);
        err = zbm_write_metadata_1(state);
        if(err)
            return err;

        hdr->meta_off_2 = zbm_u32_to_u24(state->written);
        err = zbm_write_metadata_2(state);
        if(err)
            return err;
    }

    hdr->meta_off_3 = zbm_u32_to_u24(state->written);
    err = zbm_write_metadata_3(state);
    if(err)
        return err;

    return zbm_write_trailing_bitmaps(state);
}

/*
 * Exact nibble count for a run of R blocks sharing one bitmap number, in
 * closed form. R in [1,3]: R nibbles. R >= 4: with d = R - 4, 2 (number plus
 * 0xf marker) + ceil(d/15) digit nibbles, plus a terminating 0 when d is an
 * exact multiple of 15, since the last digit written was itself 0xf.
 */
static int zbm_nibble_cost_for_run(int r)
ZBM_REQUIRES(r >= 0 && r <= ZBM_MAX_BITMAP_COUNT)
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value >= 0 && __CPROVER_return_value <= r)
ZBM_ENSURES(r < 4 ? __CPROVER_return_value == r : __CPROVER_return_value == 3 + (r - 4) / 15)
{
    int d, digits, terminator;

    if(r <= 0)
        return 0;
    if(r <= 3)
        return r;

    /* One division gives both the digit count and, via a zero remainder, the
     * terminator. */
    d = r - 4;
    digits = d / 15;
    terminator = (d - digits * 15) == 0;
    digits += !terminator;
    return 2 + digits + terminator;
}

/* zbm_nibble_cost_for_run(len + 1) - zbm_nibble_cost_for_run(len): 0 or 1.
 * zbm_cost_model_test checks it against the subtraction. */
static int zbm_nibble_extend_delta(int len)
ZBM_REQUIRES(len >= 1 && len < ZBM_MAX_BITMAP_COUNT)
ZBM_ASSIGNS()
ZBM_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == 1)
{
    if(len < 3)             /* 1 -> 2 and 2 -> 3 each add a plain nibble */
        return 1;
    if(len < 18)            /* 3 -> 4 through 17 -> 18 are free */
        return 0;
    return (len - 3) % 15 == 0;
}

/* zbm_bmprot() for a pair that has not been appended yet. */
static __attribute__((always_inline)) inline int zbm_bmprot_of(uint8_t bitmap, int period_bytecnt)
{
    return (int)bitmap << 2 | period_bytecnt;
}

static int zbm_period_bytecnt_for(uint16_t period, uint16_t current_period)
{
    /* Branchless: `ne` gates whether any period-change cost applies and
     * `wide` adds the second byte. */
    int ne = period != current_period;
    int wide = period > 0xff;

    return ne * (1 + wide);
}

/*
 * A candidate is a period and a bitmap, not a pointer. Every producer has the
 * xor against the needle in hand, so the bitmap is a few ALU ops there. The
 * period is the identity zbm_greedy_add_cand() de-duplicates on: state->src is
 * fixed for the block, so ptr == src - period is a bijection.
 */
struct zbm_candidate {
    uint16_t period;    /* this candidate is at state->src - period */
    uint8_t  bmp;       /* zbm_diff_bitmap() of it against the needle, whole
                         * blocks only — a short final block's needle is
                         * zero-padded, so the scorer recomputes there */
};

/* A chunk's final block only: the bounds-aware assembly. */
static uint64_t zbm_load_needle_short(const uint8_t *src, int bytecnt)
{
    uint64_t needle = 0;
    int i;

    for(i = 0; i < bytecnt; ++i)
        needle |= (uint64_t)src[i] << i * 8;
    return needle;
}

/* The needle and this block's length, returned by value. */
struct zbm_needle { uint64_t needle; int bytecnt; };

static struct zbm_needle zbm_read_needle(const struct zbm_compress_state *state)
{
    struct zbm_needle r;

    r.bytecnt = (int)MIN(8u, state->decmp_len - state->read);
    r.needle = r.bytecnt == 8 ? zbm_load_u64(state->src)
                              : zbm_load_needle_short(state->src, r.bytecnt);
    return r;
}

/*
 * Scores the gathered candidates by the exact bit-cost model and commits the
 * winner, updating *run_bmprot and *run_len for the next block's run pricing.
 * The model charges 8 bits per literal, the meta_1 bytes if the period
 * changes, 8 bits of meta_2 unless the tuple is estimated to be a top-12 one,
 * and the marginal meta_3 nibble cost of extending or breaking the run. It
 * does not touch the MRU ring, the index, or state->src/read; each caller
 * does those itself.
 */
/*
 * One-block lookahead: whichever period wins here is the one the next block
 * continues for free, so each candidate is also charged what its period
 * would cost block i+1, capped in bits. The cap matters: a period that serves
 * the next block badly is never paid at its full badness, because block i+1
 * changes period instead. The fewer-literals tie-break is not subsumed by
 * this: on a cycling-period signal the right period is the one that does not
 * serve the next block.
 */
#define ZBM_LOOKAHEAD_WEIGHT 1   /* bits charged per next-block literal */
#define ZBM_LOOKAHEAD_CAP    6   /* ceiling on the whole term, in bits */

/*
 * The row tier prices its own lookahead harder. It re-scores exactly two
 * candidates, both of them already cheap, so the next block's literals are
 * the only thing left that separates them; at weight 1 and cap 6 the term
 * saturates on almost every searched block and stops separating anything.
 * Weight 2 with a cap that only clips the hopeless half of the range keeps
 * it discriminating all the way up.
 */
#define ZBM_ROW_LOOKAHEAD_WEIGHT 2
#define ZBM_ROW_LOOKAHEAD_CAP    16

/*
 * The row tier's stand-in for the meta_2 term the chain scorer reads out of
 * is_top_estimate[]: one pass has no estimate to read, so a tuple already
 * used by at least 1/2^SHIFT of the blocks decided so far is assumed to
 * make the chunk's top-12 table and every other tuple is charged
 * ZBM_ROW_HOT_COST bits. usecnts[] is being built by the loop anyway; the
 * run in force is still pending, so its count is completed on the spot.
 */
#define ZBM_ROW_HOT_SHIFT 6
#define ZBM_ROW_HOT_COST  6

/*
 * The give-up gate. On high-entropy content the exact per-block model keeps
 * buying barely-better periods, and every change grows the period stream,
 * breaks the repetition run, and can push the chunk to raw. With k the lanes
 * the current period matches and L the lanes a candidate matches, a period
 * change is admissible only when L >= k + ZBM_GIVEUP_GATE and
 * L >= ZBM_GIVEUP_FLOOR; otherwise the block is emitted on the period in
 * force. Both bounds are in lanes. Setting both to 0 removes the gate exactly.
 */
#ifndef ZBM_GIVEUP_GATE
#define ZBM_GIVEUP_GATE 0   /* extra lanes a change must beat the incumbent by */
#endif
#ifndef ZBM_GIVEUP_FLOOR
#define ZBM_GIVEUP_FLOOR 2  /* lanes a change must match outright */
#endif
#define ZBM_GIVEUP_ON (ZBM_GIVEUP_GATE > 0 || ZBM_GIVEUP_FLOOR > 0)

/* A base cost no real candidate can reach (the maximum is 92 bits), so a
 * vetoed candidate loses every comparison without a branch of its own. */
#define ZBM_GIVEUP_VETO (1 << 20)

static uint8_t zbm_diff_count_only(uint64_t xor);

/*
 * Append the chosen (bitmap, period) and roll the run-length bookkeeping the
 * next block prices against; the one function every commit goes through.
 * @period_bytecnt is passed in because the scorer already priced it against
 * the same state->period.
 */
static void zbm_commit_block_pbc(struct zbm_compress_state *state, uint8_t bitmap, uint16_t period,
                                 int period_bytecnt, int *run_bmprot, int *run_len)
{
    struct zbm_bmap *new_bmp = &state->bitmaps[state->bmp_cnt];
    int bmprot = (int)bitmap << 2 | period_bytecnt;

    /* The encoder never selects copy periods below 8, and the decoder
     * rejects them. Check the period invariant before committing a block. */
    assert(period >= 8);

    new_bmp->bitmap = bitmap;
    new_bmp->period_bytecnt = (uint8_t)period_bytecnt;
    state->periods[state->bmp_cnt] = period;
    ++state->bmp_cnt;
    ++state->usecnts[bmprot];
    state->period = period;

    if(bmprot == *run_bmprot) {
        ++*run_len;
    } else {
        *run_bmprot = bmprot;
        *run_len = 1;
    }
}

static void zbm_commit_block(struct zbm_compress_state *state, uint8_t bitmap, uint16_t period,
                             int *run_bmprot, int *run_len)
{
    zbm_commit_block_pbc(state, bitmap, period,
                         zbm_period_bytecnt_for(period, state->period),
                         run_bmprot, run_len);
}

/* The candidate loop, with @whole (every block a full 8 bytes) and @look (the
 * next block is priceable) as constants. Returns the winning index and its
 * bitmap; commits nothing. */
static inline int zbm_score_loop(struct zbm_compress_state *state,
                                 const struct zbm_candidate cands[], int n,
                                 int bytecnt, int gate_on, int gate_max, uint64_t next,
                                 int run_bmprot, int run_len,
                                 uint8_t *out_bitmap, int *out_pbc, int whole, int look)
{
    const uint8_t *src = state->src;
    const uint8_t *is_top = state->is_top_estimate;
    uint16_t cur_period = state->period;
    int best_idx = 0, best_cost = 0, best_pbc = 0, i;
    uint8_t best_pops = 0, bitmap = 0;
    /* The run-extension term is 4 unless the candidate extends the current
     * run, and zbm_nibble_extend_delta(run_len) is loop-invariant: when it is
     * 1 the term is 4 for every candidate, so the key is set to a value no
     * bmprot can equal. */
    const int run_key = zbm_nibble_extend_delta(run_len) ? -1 : run_bmprot;

    for(i = 0; i < n; ++i) {
        uint16_t cand_period = cands[i].period;
        const uint8_t *cptr = src - cand_period;
        /* The gather's bitmap is the plain lane-difference map; the period
         * floor is applied to the winner after the loop. A short final block
         * is recomputed: its needle is zero-padded, so the gather's bitmap
         * describes lanes it does not have. */
        uint8_t cand_bitmap = whole
            ? cands[i].bmp
            : zbm_calculate_bitmap(cptr, src, (uint8_t)bytecnt, cand_period);
        uint8_t pop = zbm_popcount8(cand_bitmap);
        int period_bytecnt = zbm_period_bytecnt_for(cand_period, cur_period);
        int bmprot = zbm_bmprot_of(cand_bitmap, period_bytecnt);
        int cost;

        cost = 8 * (int)pop
             + period_bytecnt * 8
             + (is_top[bmprot] ? 0 : 8)
             + (bmprot == run_key ? 0 : 4);
        if(i == 0) {
            if(gate_on) {
                /* pop is the incumbent's literal count, 8 - k, so both gate
                 * tests are bounds on pop. */
                int rel = (int)pop - ZBM_GIVEUP_GATE;
                int flr = 8 - ZBM_GIVEUP_FLOOR;

                gate_max = rel < flr ? rel : flr;
            }
        } else if((int)pop > gate_max) {
            cost = ZBM_GIVEUP_VETO;
        }

        if(look) {
            /* cptr + 8 .. + 15 stays at or below src + 7: every candidate
             * period is at least 8, and the caller's look_ok makes the block
             * at src + 8 whole. */
            int l = ZBM_LOOKAHEAD_WEIGHT
                  * zbm_diff_count_only(zbm_load_u64(cptr + 8) ^ next);

            cost += l > ZBM_LOOKAHEAD_CAP ? ZBM_LOOKAHEAD_CAP : l;
        }

        if(i == 0 || cost < best_cost || (cost == best_cost && pop < best_pops)) {
            best_cost = cost;
            best_pops = pop;
            best_idx = i;
            best_pbc = period_bytecnt;
            bitmap = cand_bitmap;
        }
    }
    /*
     * The period floor is applied once to the winner. No candidate ever has a
     * period below 8 (the chain walk admits nothing below 8, the MRU replays
     * committed candidates, and the chunk opens on period 8), so applying it
     * per candidate could not change a decision; on the winner it still
     * guarantees no out-of-range period is emitted.
     */
    if(whole)
        bitmap = zbm_period_floor_bitmap(bitmap, cands[best_idx].period, 8);
    *out_bitmap = bitmap;
    *out_pbc = best_pbc;
    return best_idx;
}

static void zbm_score_and_commit_candidates(struct zbm_compress_state *state, struct zbm_candidate cands[], int n,
                                             int bytecnt, int *run_bmprot, int *run_len)
{
    /* Scoring is one pass with no arrays: a store through an escaped array
     * pointer may alias *state and forces reloads. The lookahead is computed
     * for every candidate rather than a pruned subset. */
    int best_idx = 0;
    int best_pbc = 0;
    uint8_t bitmap = 0;
    uint64_t next;
    /* The next block is priceable only when this block is whole and another
     * whole block follows it inside the chunk. */
    int look_ok = (bytecnt == 8) && (state->decmp_len >= state->read + 16);
    /* Most literals a period change may cost and still be admissible; 8
     * admits everything. Only slot 0 can be the continuing candidate, so the
     * gate is checked rather than assumed, and a short final block is left
     * ungated. */
    int gate_max = 8;
    int gate_on;

    /* One candidate: nothing to score, and the common case on high-entropy
     * content. */
    if(n == 1) {
        uint16_t cp = cands[0].period;

        zbm_commit_block(state, bytecnt == 8
                             ? zbm_period_floor_bitmap(cands[0].bmp, cp, 8)
                             : zbm_calculate_bitmap(state->src - cp, state->src, bytecnt, cp),
                         cp, run_bmprot, run_len);
        return;
    }

    gate_on = ZBM_GIVEUP_ON && (bytecnt == 8) &&
              (cands[0].period == state->period);

    /* The next block's needle, loaded once; only its literal count is
     * wanted. */
    next = look_ok ? zbm_load_u64(state->src + 8) : 0;

    /* Three expansions of one loop, with `whole` and `look` constant at each
     * call. The final block of a chunk is the only one not whole and needs
     * neither the lookahead nor the gate. */
    if(bytecnt == 8)
        best_idx = look_ok
            ? zbm_score_loop(state, cands, n, 8, gate_on, gate_max, next,
                             *run_bmprot, *run_len, &bitmap, &best_pbc, 1, 1)
            : zbm_score_loop(state, cands, n, 8, gate_on, gate_max, 0,
                             *run_bmprot, *run_len, &bitmap, &best_pbc, 1, 0);
    else
        best_idx = zbm_score_loop(state, cands, n, bytecnt, 0, gate_max, 0,
                                  *run_bmprot, *run_len, &bitmap, &best_pbc, 0, 0);

    zbm_commit_block_pbc(state, bitmap, cands[best_idx].period,
                         best_pbc, run_bmprot, run_len);
}

static void zbm_snapshot_save(struct zbm_compress_state *state, struct zbm_bitmap_snapshot *snap)
{
    memcpy(snap->bitmaps, state->bitmaps, sizeof(state->bitmaps));
    memcpy(snap->periods, state->periods, sizeof(state->periods));
    snap->bmp_cnt = state->bmp_cnt;
    memcpy(snap->usecnts, state->usecnts, sizeof(state->usecnts));
}

static void zbm_snapshot_restore(struct zbm_compress_state *state, struct zbm_bitmap_snapshot *snap)
{
    memcpy(state->bitmaps, snap->bitmaps, sizeof(state->bitmaps));
    memcpy(state->periods, snap->periods, sizeof(state->periods));
    state->bmp_cnt = snap->bmp_cnt;
    memcpy(state->usecnts, snap->usecnts, sizeof(state->usecnts));
}

/* Scores the chunk currently decided by running the real metadata writer
 * against a scratch destination, restores state->dest/dest_end/written, and
 * refreshes is_top_estimate from the top-12 table. Returns the total chunk
 * size, or 0 if the metadata does not fit ZBM_META_SCRATCH_SIZE. */
static size_t zbm_score_trial(struct zbm_compress_state *state, long data_bytes)
{
    uint8_t *saved_dest = state->dest;
    const uint8_t *saved_dest_end = state->dest_end;
    uint32_t saved_written = state->written;
    struct zbm_cmp_chunk_hdr trial_hdr;
    int err;
    size_t total = 0;
    int i;

    state->dest = state->meta_scratch;
    state->dest_end = state->meta_scratch + ZBM_META_SCRATCH_SIZE;
    state->written = 0;

    err = zbm_build_metadata(state, &trial_hdr);
    if(!err) {
        total = sizeof(struct zbm_cmp_chunk_hdr) + (size_t)data_bytes + state->written;

        /* Some slots may be the {0,0} placeholder for fewer than 12 distinct
         * tuples; marking it is harmless, since a placeholder only occurs when
         * every used tuple already has a slot. */
        memset(state->is_top_estimate, 0, ZBM_POSSIBLE_BMPROTS);
        for(i = 0; i < ZBM_BITMAP_COUNT; ++i)
            state->is_top_estimate[zbm_bmprot(&state->top_bitmaps[i])] = 1;
    }

    state->dest = saved_dest;
    state->dest_end = saved_dest_end;
    state->written = saved_written;
    return total;
}

/*
 * How many of the eight bytes differ, given their xor. On aarch64 a vector
 * compare collapses each byte to a flag lane and the popcount of the mask is
 * 8 per differing byte, the unit the probe cost charges;
 * elsewhere a SWAR step does the collapse.
 */
#if defined(__aarch64__)
typedef uint8_t zbm_v8b __attribute__((vector_size(8)));

/* 8 * (number of differing bytes), the unit the probe cost charges. */
static inline unsigned zbm_diff_bits8(uint64_t xorv)
{
    zbm_v8b v, m;
    uint64_t mask;

    memcpy(&v, &xorv, sizeof v);
    m = (zbm_v8b)(v != (zbm_v8b){ 0, 0, 0, 0, 0, 0, 0, 0 });
    memcpy(&mask, &m, sizeof mask);
    return (unsigned)__builtin_popcountll(mask);
}

static uint8_t zbm_diff_count_only(uint64_t xor)
{
    return (uint8_t)(zbm_diff_bits8(xor) >> 3);
}

#define ZBM_HAVE_V8 1

#else
/* Without -mpopcnt the eight flag bits are summed by a multiply into the top
 * byte (the sum is at most 8, so nothing carries). */
static inline unsigned zbm_diff_bits8(uint64_t xorv)
{
    uint64_t t = (xorv & 0x7f7f7f7f7f7f7f7fULL) + 0x7f7f7f7f7f7f7f7fULL;

    t = (t | xorv) & 0x8080808080808080ULL;
    return (unsigned)(((t >> 7) * 0x0101010101010101ULL) >> 56) * 8u;
}

static uint8_t zbm_diff_count_only(uint64_t xor)
{
    uint64_t t = (xor & 0x7f7f7f7f7f7f7f7fULL) + 0x7f7f7f7f7f7f7f7fULL;

    t = (t | xor) & 0x8080808080808080ULL;
    return (uint8_t)(((t >> 7) * 0x0101010101010101ULL) >> 56);
}

#endif

/* ------------------------------------------------------------------ */
/* CRUSHLZBITMAP_STRATEGY_ROW: bucket index, one read per byte window.          */
/* ------------------------------------------------------------------ */

/*
 * The block loop uses vector primitives provided by crush_simd.h across
 * ARM NEON and x86 SSE4.1/POPCNT.
 */

#ifdef ZBM_STATS
#include <stdio.h>
unsigned long long zbm_stat[16];
static void zbm_stat_dump(void)
{
    fprintf(stderr, "stats: run %llu gathered %llu found %llu take1 %llu fastsearch %llu\n",
            zbm_stat[0], zbm_stat[1], zbm_stat[2], zbm_stat[3], zbm_stat[4]);
}
__attribute__((constructor)) static void zbm_stat_init(void) { atexit(zbm_stat_dump); }
#define ZBM_STAT(i) (++zbm_stat[i])
#else
#define ZBM_STAT(i) ((void)0)
#endif

/*
 * The index is 2^hash_bits buckets of `ways` entries (ways = depth, 1, 2 or
 * 4), keyed by zbm_row_key(). A position takes the slot its block hashes to, so
 * a bucket holds the most recent position of each slot class with that
 * key, an insert is one store, and no bucket is ever read to be written.
 * An entry is a 24-bit position under an 8-bit epoch; a stale epoch or an
 * out-of-reach distance vetoes it, and the probe against real bytes catches
 * everything else.
 *
 * The recent-period ring is four 16-bit lanes in one word, lane 0 the period
 * in force, touched without a branch.
 */

static inline uint32_t zbm_load_u32(const uint8_t *p)
{
    uint32_t v;

    memcpy(&v, p, sizeof v);
    return v;
}

/*
 * The row tier's bucket key at @p: bytes 0, 1, 3 and 4, skipping byte 2.
 * Probed at the block's eight windows, the key covers lane sets
 * {j, j+1, j+3, j+4}, so a period still surfaces when its matching lanes are
 * broken up by single literals: machine code that differs only in a
 * register or immediate byte of each instruction, for one. Four contiguous
 * bytes would need a run of four matching lanes; any run of five still
 * holds one window's key.
 */
#define ZBM_ROW_KEY_BYTES 5

static inline uint32_t zbm_row_key(const uint8_t *p)
{
    uint32_t lo = zbm_load_u32(p), hi = zbm_load_u32(p + 1);

    return (lo & 0xffffu) | (hi & 0xffff0000u);
}

/*
 * The second index, which only the DP and beam seeding pass keeps: bytes 0,
 * 2, 4 and 6, so its eight windows cover the even and the odd lanes of the
 * block in turn. It finds periods whose literals alternate with matches,
 * which no window of zbm_row_key() can. Its finds compete in the seeding
 * pass's own decisions like the main index's, and are recorded as
 * candidates for the parse.
 */
#define ZBM_ROW_KEY2_BYTES  7
#define ZBM_ROW2_BITS       14
#define ZBM_ROW2_WAYS       4
#define ZBM_ROW2_BYTES      (sizeof(uint32_t) * ZBM_ROW2_WAYS << ZBM_ROW2_BITS)

static inline uint32_t zbm_row_key2(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[2] << 8 | (uint32_t)p[4] << 16 | (uint32_t)p[6] << 24;
}

static inline uint32_t zbm_row_bucket(uint32_t key, int sh)
{
    return (key * 0x9E3779B1u) >> sh;
}

/*
 * The table bits a call actually uses: the level's hash_bits, capped at
 * ZBM_TAB_SLACK_BITS more than the input's length needs (floor 8). Every
 * encode clears its table first (zbm_state_begin), so a small input would
 * otherwise pay to clear, and then scatter over, a table sized for 64 KiB.
 * The cap depends on the whole input's length alone, so encode_chunk still
 * matches encode_buffer, and inputs over 32 KiB are not affected.
 */
#define ZBM_TAB_SLACK_BITS 1

static inline int zbm_tab_bits(const struct zbm_compress_state *state, int hash_bits)
{
    int need = 8;

    while(need < hash_bits && ((size_t)1 << need) < state->buf_len)
        need++;
    need += ZBM_TAB_SLACK_BITS;
    return need < hash_bits ? need : hash_bits;
}

/*
 * The slot a position takes in its bucket is a hash of its block, not its
 * low bits: aligned data recurs at one residue, and would otherwise fight
 * over one slot of the bucket. The eight windows of a block share a slot;
 * they rarely share a bucket.
 */
static inline unsigned zbm_row_slot(uint32_t pos, unsigned ways)
{
    uint32_t h = (pos >> 3) * 0x9E3779B1u;

    /* Two hash bits for up to four ways, four beyond; the split keeps the
     * small tables' output what it was before the wide ones existed. */
    return (ways <= 4 ? h >> 30 : h >> 28) & (ways - 1u);
}

static inline uint32_t zbm_row_entry_index(uint32_t bucket, uint32_t pos, unsigned ways)
{
    return bucket * ways + zbm_row_slot(pos, ways);
}

static inline void zbm_row_insert(uint32_t *tab, uint32_t bucket, uint32_t pos, unsigned ways, uint32_t epoch_hi)
{
    tab[zbm_row_entry_index(bucket, pos, ways)] = (pos & ZBM_ROW_POS_MASK) | epoch_hi;
}

/*
 * Move-to-front of a 16-bit period in the four-lane ring @m, branch-free.
 * If @p is in lane i, lanes 0..i become [p, m0 .. m(i-1)] and lanes above i
 * are kept; otherwise every lane shifts up and lane 3 is evicted. Lanes are
 * distinct, so the zero-lane test's false positives (only ever above a true
 * match) cannot change the result.
 */
static inline uint64_t zbm_mru4_touch(uint64_t m, uint32_t p)
{
    const uint64_t ones = 0x0001000100010001ULL;
    const uint64_t high = 0x8000800080008000ULL;
    uint64_t x = m ^ (ones * p);
    uint64_t t = (x - ones) & ~x & high;    /* 0x8000 in a matching lane */
    uint64_t u = t << 16;                   /* lanes above the match... */
    uint64_t keep;

    u |= u << 16;
    u |= u << 32;
    keep = u | (u - (u >> 15));             /* ...as full-lane masks */
    return (m & keep) | (((m << 16) | p) & ~keep);
}

/* Whether @p is in a lane of @m. */
static inline int zbm_mru4_has(uint64_t m, uint32_t p)
{
    const uint64_t ones = 0x0001000100010001ULL;
    const uint64_t high = 0x8000800080008000ULL;
    uint64_t x = m ^ (ones * p);

    return ((x - ones) & ~x & high) != 0;
}

/* Move-to-front over eight lanes in two words: the low word's eviction
 * becomes the high word's front unless @p was already in the low word. */
static inline void zbm_mru8_touch(uint64_t *lo, uint64_t *hi, uint32_t p)
{
    uint64_t l = *lo, h = *hi;
    uint64_t nh = (zbm_mru4_touch(h, p) & ~0xffffULL) | (l >> 48);

    *lo = zbm_mru4_touch(l, p);
    *hi = zbm_mru4_has(l, p) ? h : nh;
}

/* Index every position in [from, to) that has a whole key. */
static void zbm_row_index_range(struct zbm_compress_state *state, uint32_t from, uint32_t to)
{
    const uint8_t *base = state->buf_base;
    uint32_t *tab = state->row_tab;
    const int sh = state->row_sh;
    const unsigned ways = state->row_ways;
    const uint32_t epoch_hi = state->row_epoch << 24;
    uint32_t p;

    if(state->buf_len < ZBM_ROW_KEY_BYTES)
        return;
    if(to > state->buf_len - (ZBM_ROW_KEY_BYTES - 1))
        to = (uint32_t)(state->buf_len - (ZBM_ROW_KEY_BYTES - 1));
    for(p = from; p < to; ++p)
        zbm_row_insert(tab, zbm_row_bucket(zbm_row_key(base + p), sh), p, ways, epoch_hi);
    if(state->row_tab2) {
        uint32_t *tab2 = state->row_tab2;
        const int sh2 = state->row_sh2;

        if(state->buf_len < ZBM_ROW_KEY2_BYTES)
            return;
        if(to > state->buf_len - (ZBM_ROW_KEY2_BYTES - 1))
            to = (uint32_t)(state->buf_len - (ZBM_ROW_KEY2_BYTES - 1));
        for(p = from; p < to; ++p)
            zbm_row_insert(tab2, zbm_row_bucket(zbm_row_key2(base + p), sh2), p, ZBM_ROW2_WAYS, epoch_hi);
    }
}

/*
 * Cover everything behind @chunk_start the format can reference. A new
 * epoch retires every entry of the previous call at once.
 */
static void zbm_row_prepare_index(struct zbm_compress_state *state, uint32_t chunk_start)
{
    uint32_t from;

    state->row_sh = (uint8_t)(32 - zbm_tab_bits(state, state->params.p.row.hash_bits));
    state->row_ways = (uint8_t)state->params.p.row.depth;
    state->row_sh2 = (uint8_t)(32 - zbm_tab_bits(state, ZBM_ROW2_BITS));
    if(state->index_live && state->index_pos == chunk_start)
        return;

    state->row_epoch = (state->row_epoch + 1) & ((1u << ZBM_ROW_EPOCH_BITS) - 1u);
    if(state->row_epoch == 0) {
        /* Epoch 0 is never live, so a cleared table matches nothing. */
        memset(state->row_tab, 0,
               sizeof(state->row_tab[0]) * state->row_ways * ((size_t)1 << (32 - state->row_sh)));
        if(state->row_tab2)
            memset(state->row_tab2, 0, sizeof(uint32_t) * ZBM_ROW2_WAYS << (32 - state->row_sh2));
        state->row_epoch = 1;
    }
    from = chunk_start > ZBM_GREEDY_REACH ? chunk_start - ZBM_GREEDY_REACH : 0;
    zbm_row_index_range(state, from, chunk_start);
    state->index_pos = chunk_start;
    state->index_live = 1;
}

/* The ring's probe count: lanes 1 .. min(dist_cache_size, 8) - 1. */
static inline int zbm_row_mru_lanes(const struct zbm_compress_state *state)
{
    int dc = state->params.p.row.dist_cache_size;

    return dc > 8 ? 8 : dc;
}

/*
 * One block, the general form: any length, any position. Scalar, and only
 * the blocks the vector loop below declines take it (a chunk's last block,
 * the last 16 bytes of the buffer). Same candidates as the vector loop:
 * the continuation, the ring, every entry of every window's bucket, except
 * that it does not probe the second index.
 */
static void zbm_decide_block_row_generic(struct zbm_compress_state *state, int *run_bmprot, int *run_len)
{
    struct zbm_candidate cands[2];
    const uint8_t *base = state->buf_base;
    uint32_t *tab = state->row_tab;
    const int sh = state->row_sh;
    const unsigned ways = state->row_ways;
    const uint32_t epoch_hi = state->row_epoch << 24;
    const uint32_t pos = (uint32_t)(state->preread + state->read);
    const uint16_t cur_period = state->period;
    const uint8_t *src = state->src;
    const int accept = state->params.p.row.accept_diff;
    uint64_t needle;
    int bytecnt, n = 1, best_cost, i, j, nwin, nl;
    uint32_t best_d = cur_period, band;

    { struct zbm_needle nd = zbm_read_needle(state); needle = nd.needle; bytecnt = nd.bytecnt; }

    /* The continuation, always first. A short block's needle is zero-padded
     * and its probe may run past the buffer, so it is probed only whole. */
    if(bytecnt == 8 && cur_period <= pos) {
        uint64_t xor = zbm_load_u64(src - cur_period) ^ needle;

        best_cost = (int)zbm_diff_bits8(xor);
        cands[0].bmp = zbm_diff_bitmap(xor);
    } else {
        best_cost = 1 << 12;
        cands[0].bmp = 0xff;
    }
    cands[0].period = cur_period;

    if(bytecnt == 8 && best_cost > accept * 8) {
        band = pos >= 8 ? (pos < ZBM_GREEDY_REACH ? pos : ZBM_GREEDY_REACH) - 8u : 0;

        nl = zbm_row_mru_lanes(state);
        for(i = 1; i < nl; ++i) {
            uint32_t cp = (uint32_t)((i < 4 ? state->row_mru : state->row_mru2) >> (16 * (i & 3))) & 0xffffu;
            int cost;

            if(cp < 8 || cp > pos)
                continue;
            cost = (int)zbm_diff_bits8(zbm_load_u64(src - cp) ^ needle)
                 + (cp > 0xff ? ZBM_PROBE_PEN_2B : ZBM_PROBE_PEN_1B);
            if(cost < best_cost) {
                best_cost = cost;
                best_d = cp;
            }
        }

        if(state->buf_len < ZBM_ROW_KEY_BYTES || (size_t)pos + ZBM_ROW_KEY_BYTES > state->buf_len)
            nwin = 0;
        else
            nwin = (int)MIN(8, state->buf_len - (ZBM_ROW_KEY_BYTES - 1) - pos);
        for(j = 0; j < nwin && pos >= 8; ++j) {
            uint32_t here = pos + (uint32_t)j;
            uint32_t *b = tab + (size_t)zbm_row_bucket(zbm_row_key(base + here), sh) * ways;
            unsigned k;

            for(k = 0; k < ways; ++k) {
                uint32_t e = b[k];
                uint32_t d = (here - e) & ZBM_ROW_POS_MASK;
                int cost;

                if((e & ~ZBM_ROW_POS_MASK) != epoch_hi || d - 8u > band)
                    continue;
                cost = (int)zbm_diff_bits8(zbm_load_u64(src - d) ^ needle)
                     + (d > 0xff ? ZBM_PROBE_PEN_2B : ZBM_PROBE_PEN_1B);
                if(cost < best_cost) {
                    best_cost = cost;
                    best_d = d;
                }
            }
        }
        if(best_d != cur_period) {
            cands[1].period = (uint16_t)best_d;
            cands[1].bmp = zbm_diff_bitmap(zbm_load_u64(src - best_d) ^ needle);
            n = 2;
        }
    }

    if(state->dp_recording && state->bmp_cnt < ZBM_MAX_BITMAP_COUNT) {
        int blk = state->bmp_cnt, q;
        int nrec = n < state->dp_cand_stride ? n : state->dp_cand_stride;

        for(q = 0; q < nrec; ++q)
            ZBM_DP_CAND(state, blk)[q] = cands[q].period;
        state->dp_ncand[blk] = (uint8_t)nrec;
    }
    zbm_score_and_commit_candidates(state, cands, n, bytecnt, run_bmprot, run_len);
    if(state->period != (uint16_t)state->row_mru)
        zbm_mru8_touch(&state->row_mru, &state->row_mru2, state->period);

    zbm_row_index_range(state, state->index_pos > pos ? state->index_pos : pos, pos + (uint32_t)bytecnt);
    if(state->index_pos < pos + (uint32_t)bytecnt)
        state->index_pos = pos + (uint32_t)bytecnt;
    state->src += bytecnt;
    state->read += bytecnt;
}

/* The loop-invariant vectors of the block loop. */
struct zbm_row_k {
    uint32x4_t mulv;    /* the bucket hash multiplier */
    int32x4_t  nsh;     /* -(32 - hash_bits), for vshlq */
    uint32x4_t lanesA;  /* 0 1 2 3 */
    uint32x4_t lanesB;  /* 4 5 6 7 */
    uint32x4_t bandv;   /* reach - 8 */
    uint32x4_t epochv;  /* epoch << 24 */
    uint8x16_t nv2;     /* the needle, twice */
    uint8x16_t nx16;    /* the needle, then the next block */
    uint8x16_t bitsn;   /* 1 2 4 ... 128, then eight 1s */
    uint8x16_t bits2;   /* 1 2 4 ... 128, twice */
    uint8x8_t  bits;    /* 1 2 4 ... 128 */
};

/* Bucket indices of a block's eight windows: keys from one 16-byte load,
 * hashed as two vectors. */
static __attribute__((always_inline)) inline
void zbm_row_hash8(const uint8_t *src, const struct zbm_row_k *k, uint32x4_t *hA, uint32x4_t *hB)
{
    /* zbm_row_key() of windows 0..3 and 4..7, gathered from one 16-byte
     * load; window 7's key ends at byte 11. */
    static const uint8_t sel[32] = {
        0, 1, 3, 4,  1, 2, 4, 5,  2, 3, 5, 6,  3, 4, 6, 7,
        4, 5, 7, 8,  5, 6, 8, 9,  6, 7, 9, 10, 7, 8, 10, 11,
    };
    uint8x16_t v = vld1q_u8(src);
    uint32x4_t kA = vreinterpretq_u32_u8(vqtbl1q_u8(v, vld1q_u8(sel)));
    uint32x4_t kB = vreinterpretq_u32_u8(vqtbl1q_u8(v, vld1q_u8(sel + 16)));

    *hA = vshlq_u32(vmulq_u32(kA, k->mulv), k->nsh);
    *hB = vshlq_u32(vmulq_u32(kB, k->mulv), k->nsh);
}

/* zbm_row_key2() of the eight windows, bucketed at @nsh2; window 7's key
 * ends at byte 13. */
static __attribute__((always_inline)) inline
void zbm_row_hash8_2(const uint8_t *src, const struct zbm_row_k *k, int32x4_t nsh2,
                     uint32x4_t *hA, uint32x4_t *hB)
{
    static const uint8_t sel[32] = {
        0, 2, 4, 6,  1, 3, 5, 7,  2, 4, 6, 8,  3, 5, 7, 9,
        4, 6, 8, 10, 5, 7, 9, 11, 6, 8, 10, 12, 7, 9, 11, 13,
    };
    uint8x16_t v = vld1q_u8(src);
    uint32x4_t kA = vreinterpretq_u32_u8(vqtbl1q_u8(v, vld1q_u8(sel)));
    uint32x4_t kB = vreinterpretq_u32_u8(vqtbl1q_u8(v, vld1q_u8(sel + 16)));

    *hA = vshlq_u32(vmulq_u32(kA, k->mulv), nsh2);
    *hB = vshlq_u32(vmulq_u32(kB, k->mulv), nsh2);
}

/* 0xff in every lane whose byte differs. */
static __attribute__((always_inline)) inline uint8x8_t zbm_diff_mask8(uint64_t xor)
{
    uint8x8_t x = vcreate_u8(xor);

    return vtst_u8(x, x);
}

static __attribute__((always_inline)) inline uint8_t zbm_mask_bitmap(uint8x8_t m, const struct zbm_row_k *k)
{
    return (uint8_t)vaddv_u8(vand_u8(m, k->bits));
}

/*
 * Four probes as one wave: the distances @d, of which @ok says which are
 * admissible, each loaded from src - d (a vetoed lane reads eight bytes
 * back, always readable) and compared with the needle. Returns per lane
 * cost << 24 | bitmap << 16 | distance, where the bitmap marks the
 * differing bytes; one min over lanes then yields the cheapest probe and,
 * among equals, the lowest bitmap and then the nearest, with its bitmap in
 * hand. The bitmap tie-break is deliberate: it makes the bitmap stream
 * repeat, which the top-12 table and the run nibbles both pay for.
 *
 * Without @la the cost is the literal count, one more past distance 255
 * (the second period byte), 128 more when vetoed. With @la each lane loads
 * sixteen bytes, the block after it at the same distance included, and the
 * cost is 4 per literal or far period byte plus one per next-block
 * literal: a period that also serves the next block is preferred, which is
 * what keeps a period in force. The veto is then bit 30.
 */
static __attribute__((always_inline)) inline
uint32x4_t zbm_row_probe4(const uint8_t *src, uint32x4_t d, uint32x4_t ok, const struct zbm_row_k *k,
                          const int la)
{
    uint32x4_t sel = vbslq_u32(ok, d, vdupq_n_u32(8));
    uint32x4_t hi;

#if defined(__AVX2__) && !defined(__ARM_NEON) && !defined(CRUSH_SIMD_PORTABLE)
    /*
     * AVX2 arm: the four probes are compared in one or two ymm registers and
     * VPMOVMSKB hands back each probe's differing-byte bitmap directly, where
     * the NEON arm folds per-byte bit values with pairwise adds (each one two
     * PMADDUBSWs and a PACKUSWB on x86). The bitmaps come out in the byte
     * order the folds leave them in, so the costs below are the NEON arm's.
     */
    if(la) {
        const __m256i nx = _mm256_broadcastsi128_si256(k->nx16);
        __m256i p01 = _mm256_inserti128_si256(_mm256_castsi128_si256(vld1q_u8(src - vgetq_lane_u32(sel, 0))),
                                              vld1q_u8(src - vgetq_lane_u32(sel, 1)), 1);
        __m256i p23 = _mm256_inserti128_si256(_mm256_castsi128_si256(vld1q_u8(src - vgetq_lane_u32(sel, 2))),
                                              vld1q_u8(src - vgetq_lane_u32(sel, 3)), 1);
        /* Per probe, two bytes: the bitmap, then the next block's differing bytes. */
        uint32_t m01 = ~(uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(p01, nx));
        uint32_t m23 = ~(uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(p23, nx));
        uint8x8_t bn = _mm_cvtsi64_si128((long long)((uint64_t)m23 << 32 | m01));
        uint32x4_t wide = vmovl_u16(vreinterpret_u16_u8(bn));
        uint32x4_t cnt = vmovl_u16(vreinterpret_u16_u8(vcnt_u8(bn)));
        uint32x4_t bm = vandq_u32(wide, vdupq_n_u32(0xff));
        uint32x4_t lit = vandq_u32(cnt, vdupq_n_u32(0xff));
        uint32x4_t nxt = vshrq_n_u32(cnt, 8);
        uint32x4_t cost = vaddq_u32(vshlq_n_u32(lit, 2), nxt);

        cost = vaddq_u32(cost, vandq_u32(vcgtq_u32(d, vdupq_n_u32(255)), vdupq_n_u32(4)));
        hi = vorrq_u32(vshlq_n_u32(cost, 24), vshlq_n_u32(bm, 16));
        hi = vaddq_u32(hi, vbicq_u32(vdupq_n_u32(1u << 30), ok));
    } else {
        /* Plain loads: VPGATHERDQ measured 9.5% slower here on Coffee Lake. */
        __m256i p = _mm256_inserti128_si256(
            _mm256_castsi128_si256(vcombine_u64(vcreate_u64(zbm_load_u64(src - vgetq_lane_u32(sel, 0))),
                                                vcreate_u64(zbm_load_u64(src - vgetq_lane_u32(sel, 1))))),
            vcombine_u64(vcreate_u64(zbm_load_u64(src - vgetq_lane_u32(sel, 2))),
                         vcreate_u64(zbm_load_u64(src - vgetq_lane_u32(sel, 3)))), 1);
        uint32_t m = ~(uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(p, _mm256_broadcastsi128_si256(k->nv2)));
        uint8x8_t bm8 = _mm_cvtsi32_si128((int)m);
        uint8x8_t cnt8 = vcnt_u8(bm8);

        hi = vshlq_n_u32(vmovl_u16(vreinterpret_u16_u8(vzip1_u8(bm8, cnt8))), 16);
        hi = vaddq_u32(hi, vandq_u32(vcgtq_u32(d, vdupq_n_u32(255)), vdupq_n_u32(1u << 24)));
        hi = vaddq_u32(hi, vbicq_u32(vdupq_n_u32(128u << 24), ok));
    }
    return vorrq_u32(hi, d);
#endif

    if(la) {
        uint8x16_t L0 = vbicq_u8(k->bitsn, vceqq_u8(vld1q_u8(src - vgetq_lane_u32(sel, 0)), k->nx16));
        uint8x16_t L1 = vbicq_u8(k->bitsn, vceqq_u8(vld1q_u8(src - vgetq_lane_u32(sel, 1)), k->nx16));
        uint8x16_t L2 = vbicq_u8(k->bitsn, vceqq_u8(vld1q_u8(src - vgetq_lane_u32(sel, 2)), k->nx16));
        uint8x16_t L3 = vbicq_u8(k->bitsn, vceqq_u8(vld1q_u8(src - vgetq_lane_u32(sel, 3)), k->nx16));
        uint8x16_t q = vpaddq_u8(vpaddq_u8(L0, L1), vpaddq_u8(L2, L3));
        /* Byte lanes: the bitmap, then the next block's literals, per probe. */
        uint8x8_t bn = vget_low_u8(vpaddq_u8(q, q));
        uint16x4_t bn16 = vreinterpret_u16_u8(bn);
        uint32x4_t wide = vmovl_u16(bn16);
        uint32x4_t bm = vandq_u32(wide, vdupq_n_u32(0xff));
        uint32x4_t nxt = vshrq_n_u32(wide, 8);
        uint32x4_t lit = vandq_u32(vmovl_u16(vreinterpret_u16_u8(vcnt_u8(bn))), vdupq_n_u32(0xff));
        uint32x4_t cost = vaddq_u32(vshlq_n_u32(lit, 2), nxt);

        cost = vaddq_u32(cost, vandq_u32(vcgtq_u32(d, vdupq_n_u32(255)), vdupq_n_u32(4)));
        hi = vorrq_u32(vshlq_n_u32(cost, 24), vshlq_n_u32(bm, 16));
        hi = vaddq_u32(hi, vbicq_u32(vdupq_n_u32(1u << 30), ok));
    } else {
        uint64x2_t p01 = vcombine_u64(vcreate_u64(zbm_load_u64(src - vgetq_lane_u32(sel, 0))),
                                      vcreate_u64(zbm_load_u64(src - vgetq_lane_u32(sel, 1))));
        uint64x2_t p23 = vcombine_u64(vcreate_u64(zbm_load_u64(src - vgetq_lane_u32(sel, 2))),
                                      vcreate_u64(zbm_load_u64(src - vgetq_lane_u32(sel, 3))));
        /* The differing bytes' bit values, folded to one bitmap byte per probe. */
        uint8x16_t x0 = vbicq_u8(k->bits2, vceqq_u8(vreinterpretq_u8_u64(p01), k->nv2));
        uint8x16_t x1 = vbicq_u8(k->bits2, vceqq_u8(vreinterpretq_u8_u64(p23), k->nv2));
        uint8x16_t bm = vpaddq_u8(x0, x1);
        uint8x8_t bm8, cnt8;

        bm = vpaddq_u8(bm, bm);
        bm = vpaddq_u8(bm, bm);
        bm8 = vget_low_u8(bm);
        cnt8 = vcnt_u8(bm8);
        /* Lanes of count << 8 | bitmap, widened, then shifted above the
         * distance; the surcharges land on the count byte. */
        hi = vshlq_n_u32(vmovl_u16(vreinterpret_u16_u8(vzip1_u8(bm8, cnt8))), 16);
        hi = vaddq_u32(hi, vandq_u32(vcgtq_u32(d, vdupq_n_u32(255)), vdupq_n_u32(1u << 24)));
        hi = vaddq_u32(hi, vbicq_u32(vdupq_n_u32(128u << 24), ok));
    }
    return vorrq_u32(hi, d);
}

/* One slot of the eight buckets, entries in @EA (windows 0-3) and @EB
 * (4-7): admissibility, distances, and the packed best folded into @acc. */
static __attribute__((always_inline)) inline
uint32x4_t zbm_row_slot_wave(const uint8_t *src, uint32x4_t E, uint32x4_t here,
                             const struct zbm_row_k *k, uint32x4_t acc, const int la,
                             uint32_t *lanes, int *nlanes)
{
    /* @here carries the epoch in its top byte as the entries do, so the
     * difference is the distance exactly when the epochs agree, and lands
     * far outside the reach otherwise: one compare covers both. */
    uint32x4_t dfull = vsubq_u32(here, E);
    uint32x4_t ok = vcleq_u32(vsubq_u32(dfull, vdupq_n_u32(8)), k->bandv);
    uint32x4_t d = vandq_u32(dfull, vdupq_n_u32(0xffffu));

    uint32x4_t pr = zbm_row_probe4(src, d, ok, k, la);

    /* Recording for the DP keeps every lane, not just the min. */
    if(lanes) {
        vst1q_u32(lanes + *nlanes, pr);
        *nlanes += 4;
    }
    return vminq_u32(acc, pr);
}

/* Four buckets' slots @off .. @off + 3, transposed so each slot is one
 * wave over the four windows. */
static __attribute__((always_inline)) inline
uint32x4_t zbm_row_group4(const uint8_t *src, const uint32_t *b0, const uint32_t *b1,
                          const uint32_t *b2, const uint32_t *b3, unsigned off, uint32x4_t here,
                          const struct zbm_row_k *k, uint32x4_t acc, const int la,
                          uint32_t *lanes, int *nlanes)
{
    uint32x4_t q0 = vld1q_u32(b0 + off), q1 = vld1q_u32(b1 + off);
    uint32x4_t q2 = vld1q_u32(b2 + off), q3 = vld1q_u32(b3 + off);
    uint32x4_t r0 = vzip1q_u32(q0, q1), r1 = vzip2q_u32(q0, q1);
    uint32x4_t r2 = vzip1q_u32(q2, q3), r3 = vzip2q_u32(q2, q3);
#define ZBM_Z1(a, b) vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(a), vreinterpretq_u64_u32(b)))
#define ZBM_Z2(a, b) vreinterpretq_u32_u64(vzip2q_u64(vreinterpretq_u64_u32(a), vreinterpretq_u64_u32(b)))
    acc = zbm_row_slot_wave(src, ZBM_Z1(r0, r2), here, k, acc, la, lanes, nlanes);
    acc = zbm_row_slot_wave(src, ZBM_Z2(r0, r2), here, k, acc, la, lanes, nlanes);
    acc = zbm_row_slot_wave(src, ZBM_Z1(r1, r3), here, k, acc, la, lanes, nlanes);
    acc = zbm_row_slot_wave(src, ZBM_Z2(r1, r3), here, k, acc, la, lanes, nlanes);
#undef ZBM_Z1
#undef ZBM_Z2
    return acc;
}

#if defined(__AVX2__) && !defined(__ARM_NEON) && !defined(CRUSH_SIMD_PORTABLE)
/* The near-period scan's per-byte match tally over 32 source bytes at once,
 * i.e. two adjacent 16-period segments: 8 minus the needle bytes that agree
 * at each lane's period, summed as a tree like the 16-byte arm. */
static __attribute__((always_inline)) inline __m256i zbm_scan32(const uint8_t *g, uint64_t needle)
{
#define ZBM_EQ(j) _mm256_cmpeq_epi8(_mm256_loadu_si256((const __m256i *)(const void *)(g + (j))), \
                                    _mm256_set1_epi8((char)(needle >> (8 * (j)))))
    __m256i c0 = _mm256_add_epi8(ZBM_EQ(0), ZBM_EQ(1));
    __m256i c1 = _mm256_add_epi8(ZBM_EQ(2), ZBM_EQ(3));
    __m256i c2 = _mm256_add_epi8(ZBM_EQ(4), ZBM_EQ(5));
    __m256i c3 = _mm256_add_epi8(ZBM_EQ(6), ZBM_EQ(7));
#undef ZBM_EQ
    return _mm256_add_epi8(_mm256_set1_epi8(8), _mm256_add_epi8(_mm256_add_epi8(c0, c1), _mm256_add_epi8(c2, c3)));
}
#define ZBM_SCAN_AVX2 1
#else
#define ZBM_SCAN_AVX2 0
#endif

/*
 * The block loop, expanded per way count. Every block reads or writes only
 * locals until the loop exits, and nothing but the run-or-search test
 * branches on data. The run path is a probe, a two-byte commit and eight
 * stores; the search is the ring and the buckets as vector waves, one exact
 * scoring of the continuation against the best find, and the commit.
 * Handles whole blocks with 16 readable bytes at pos >= 8; the rest go to
 * zbm_decide_block_row_generic().
 */
static __attribute__((always_inline)) inline
void zbm_row_loop_w(struct zbm_compress_state *state, int *run_bmprot_io, int *run_len_io,
                    const unsigned ways, const int la, const int rec)
{
    /* With @rec every block is searched and every lane kept, so the DP gets
     * each block's candidate list; the decisions made here are then only
     * a seed. */
    uint32_t lanebuf[8 * 16 + 8 * ZBM_ROW2_WAYS + 8 + 4];
    uint32_t *lanes = rec ? lanebuf : NULL;
    int nlanes = 0;
    const crushlzbitmap_row_params *rp = &state->params.p.row;
    const int accept = rp->accept_diff;
    /* The eight-lane ring comes with the lookahead flavour; the plain
     * flavour, which the speed levels use, keeps four. */
    const int nl = la ? zbm_row_mru_lanes(state) : (zbm_row_mru_lanes(state) > 4 ? 4 : zbm_row_mru_lanes(state));
    const uint32_t nseg = (uint32_t)rp->scan_window / 16u;
    uint32_t *restrict tab = state->row_tab;
    /* The second index is kept whenever it exists, as zbm_row_index_range
     * keeps it, and probed only while recording. */
    uint32_t *restrict tab2 = state->row_tab2;
    const int32x4_t nsh2 = vdupq_n_s32(-state->row_sh2);
    const uint32_t epoch_hi = state->row_epoch << 24;
    const uint32_t decmp_len = state->decmp_len;
    const size_t buf_len = state->buf_len;
    const uint8_t *src = state->src;
    uint32_t read = state->read;
    uint32_t pos = (uint32_t)(state->preread + read);
    uint32_t per = state->period;
    int run_bmprot = *run_bmprot_io, run_len = *run_len_io;
    int cnt = state->bmp_cnt;
    struct zbm_bmap *restrict nb = state->bitmaps;
    uint16_t *restrict pp = state->periods;
    zbm_usecnt_t *restrict uc = state->usecnts;
    uint64_t mru = state->row_mru, mru2 = state->row_mru2;
    /* The ring as it stood a block ago is what this block probes: the
     * decision that touched it is then a block behind, not on this block's
     * path. */
    uint64_t mru_use = mru, mru2_use = mru2;
    /* The next block's continuation, always handed over: by the lookahead
     * of a searched block, by a plain probe on a run block. */
    int next_c = state->row_next_diff;
    uint8_t next_b = 0xff;
    zbm_usecnt_t pending = 0;
    /* Lanes of the ring probed: lane 0 is the continuation, vetoed here. */
    const uint32x4_t mru_ok0 = ZBM_V4U32(0, nl > 1 ? ~0u : 0, nl > 2 ? ~0u : 0, nl > 3 ? ~0u : 0);
    const uint32x4_t mru_ok1 = ZBM_V4U32(nl > 4 ? ~0u : 0, nl > 5 ? ~0u : 0, nl > 6 ? ~0u : 0, nl > 7 ? ~0u : 0);
    struct zbm_row_k k;
    uint32_t nblocks;

    k.mulv = vdupq_n_u32(0x9E3779B1u);
    k.nsh = vdupq_n_s32(-state->row_sh);
    k.lanesA = ZBM_V4U32(0, 1, 2, 3);
    k.lanesB = ZBM_V4U32(4, 5, 6, 7);
    k.epochv = vdupq_n_u32(epoch_hi);
    k.bits = ZBM_V8U8(1, 2, 4, 8, 16, 32, 64, (char)128);
    k.bits2 = vcombine_u8(k.bits, k.bits);
    k.bitsn = vcombine_u8(k.bits, vdup_n_u8(1));

    /* Whole blocks in the chunk with 16 readable bytes, at pos >= 8. */
    {
        uint32_t nblk = decmp_len >= read + 8 ? (decmp_len - read) / 8 : 0;
        uint32_t nbuf = buf_len >= (size_t)pos + 16 ? (uint32_t)((buf_len - pos - 16) / 8) + 1 : 0;

        if(pos < 8)
            nblk = 0;
        if(nblk > nbuf)
            nblk = nbuf;
        nblocks = nblk;
    }
    if(next_c < 0 && nblocks > 0) {
        next_b = zbm_mask_bitmap(zbm_diff_mask8(zbm_load_u64(src - per) ^ zbm_load_u64(src)), &k);
        next_c = zbm_popcount8(next_b);
    }

    for(; nblocks > 0; --nblocks) {
        const uint64_t needle = zbm_load_u64(src);
        const uint8_t b0 = next_b;
        const int c = next_c;
        const uint32_t e = (pos & ZBM_ROW_POS_MASK) | epoch_hi;
        uint32x4_t hA, hB;
        uint32_t *bk0, *bk1, *bk2, *bk3, *bk4, *bk5, *bk6, *bk7;
        uint8_t bitmap;
        int bp, same;

        zbm_row_hash8(src, &k, &hA, &hB);
        bk0 = tab + (size_t)vgetq_lane_u32(hA, 0) * ways;
        bk1 = tab + (size_t)vgetq_lane_u32(hA, 1) * ways;
        bk2 = tab + (size_t)vgetq_lane_u32(hA, 2) * ways;
        bk3 = tab + (size_t)vgetq_lane_u32(hA, 3) * ways;
        bk4 = tab + (size_t)vgetq_lane_u32(hB, 0) * ways;
        bk5 = tab + (size_t)vgetq_lane_u32(hB, 1) * ways;
        bk6 = tab + (size_t)vgetq_lane_u32(hB, 2) * ways;
        bk7 = tab + (size_t)vgetq_lane_u32(hB, 3) * ways;
        uint32_t *bq0 = NULL, *bq1 = NULL, *bq2 = NULL, *bq3 = NULL, *bq4 = NULL, *bq5 = NULL, *bq6 = NULL, *bq7 = NULL;
        if(tab2) {
            uint32x4_t gA, gB;

            zbm_row_hash8_2(src, &k, nsh2, &gA, &gB);
            bq0 = tab2 + (size_t)vgetq_lane_u32(gA, 0) * ZBM_ROW2_WAYS;
            bq1 = tab2 + (size_t)vgetq_lane_u32(gA, 1) * ZBM_ROW2_WAYS;
            bq2 = tab2 + (size_t)vgetq_lane_u32(gA, 2) * ZBM_ROW2_WAYS;
            bq3 = tab2 + (size_t)vgetq_lane_u32(gA, 3) * ZBM_ROW2_WAYS;
            bq4 = tab2 + (size_t)vgetq_lane_u32(gB, 0) * ZBM_ROW2_WAYS;
            bq5 = tab2 + (size_t)vgetq_lane_u32(gB, 1) * ZBM_ROW2_WAYS;
            bq6 = tab2 + (size_t)vgetq_lane_u32(gB, 2) * ZBM_ROW2_WAYS;
            bq7 = tab2 + (size_t)vgetq_lane_u32(gB, 3) * ZBM_ROW2_WAYS;
        }

        if(!rec && c <= accept) {
            ZBM_STAT(0);
            bitmap = b0;
            bp = (int)bitmap << 2;
            nb[cnt].bitmap = bitmap;
            nb[cnt].period_bytecnt = 0;
            pp[cnt] = per;
            ++cnt;
            mru_use = mru;
            mru2_use = mru2;
            /* The next block's continuation, off this block's path: the
             * period is unchanged, so its address is already known. */
            {
                uint8x8_t mn = zbm_diff_mask8(zbm_load_u64(src - per + 8) ^ zbm_load_u64(src + 8));

                next_b = zbm_mask_bitmap(mn, &k);
                next_c = zbm_popcount8(next_b);
            }
        } else {
            const int look_ok = read + 16 <= decmp_len;
            const int pop0 = c;
            const uint32x4_t hereA = vaddq_u32(vdupq_n_u32(e), k.lanesA);
            const uint32x4_t hereB = vaddq_u32(hereA, vdupq_n_u32(4));
            uint32x4_t acc = vdupq_n_u32(0xffffffffu);
            uint32_t minv, wcost, wd, p1;
            const uint32_t per_in = per;

            nlanes = 0;
            uint8_t b1;
            int pop1, pbc1, bp0, bp1, cost0, cost1, gate_max, take1, run_key, found;
            int l0, l1;

            ZBM_STAT(1);
            k.bandv = vdupq_n_u32((pos < ZBM_GREEDY_REACH ? pos : ZBM_GREEDY_REACH) - 8u);
            k.nv2 = vreinterpretq_u8_u64(vdupq_n_u64(needle));
            if(la)
                k.nx16 = vld1q_u8(src);

            /* The ring: lanes 1-3, and 4-7 when the cache is that deep. */
            {
                uint32x4_t d = vmovl_u16(vcreate_u16(mru_use));
                uint32x4_t ok = vandq_u32(mru_ok0,
                                          vcleq_u32(vsubq_u32(d, vdupq_n_u32(8)), k.bandv));

                uint32x4_t pr = zbm_row_probe4(src, d, ok, &k, la);

                if(rec) { vst1q_u32(lanes + nlanes, pr); nlanes += 4; }
                acc = vminq_u32(acc, pr);
                if(la && nl > 4) {
                    uint32x4_t d2 = vmovl_u16(vcreate_u16(mru2_use));
                    uint32x4_t ok2 = vandq_u32(mru_ok1,
                                               vcleq_u32(vsubq_u32(d2, vdupq_n_u32(8)), k.bandv));
                    uint32x4_t pr2 = zbm_row_probe4(src, d2, ok2, &k, la);

                    if(rec) { vst1q_u32(lanes + nlanes, pr2); nlanes += 4; }
                    acc = vminq_u32(acc, pr2);
                }
            }

            /* The buckets: every slot of every window's bucket. */
            if(ways == 1) {
                uint32x4_t EA = vdupq_n_u32(0), EB = EA;

                EA = vld1q_lane_u32(bk0, EA, 0);
                EA = vld1q_lane_u32(bk1, EA, 1);
                EA = vld1q_lane_u32(bk2, EA, 2);
                EA = vld1q_lane_u32(bk3, EA, 3);
                EB = vld1q_lane_u32(bk4, EB, 0);
                EB = vld1q_lane_u32(bk5, EB, 1);
                EB = vld1q_lane_u32(bk6, EB, 2);
                EB = vld1q_lane_u32(bk7, EB, 3);
                acc = zbm_row_slot_wave(src, EA, hereA, &k, acc, la, lanes, &nlanes);
                acc = zbm_row_slot_wave(src, EB, hereB, &k, acc, la, lanes, &nlanes);
            } else if(ways == 2) {
                uint32x4_t q01 = vreinterpretq_u32_u64(vcombine_u64(vld1_u64((const uint64_t *)bk0), vld1_u64((const uint64_t *)bk1)));
                uint32x4_t q23 = vreinterpretq_u32_u64(vcombine_u64(vld1_u64((const uint64_t *)bk2), vld1_u64((const uint64_t *)bk3)));
                uint32x4_t q45 = vreinterpretq_u32_u64(vcombine_u64(vld1_u64((const uint64_t *)bk4), vld1_u64((const uint64_t *)bk5)));
                uint32x4_t q67 = vreinterpretq_u32_u64(vcombine_u64(vld1_u64((const uint64_t *)bk6), vld1_u64((const uint64_t *)bk7)));

                acc = zbm_row_slot_wave(src, vuzp1q_u32(q01, q23), hereA, &k, acc, la, lanes, &nlanes);
                acc = zbm_row_slot_wave(src, vuzp2q_u32(q01, q23), hereA, &k, acc, la, lanes, &nlanes);
                acc = zbm_row_slot_wave(src, vuzp1q_u32(q45, q67), hereB, &k, acc, la, lanes, &nlanes);
                acc = zbm_row_slot_wave(src, vuzp2q_u32(q45, q67), hereB, &k, acc, la, lanes, &nlanes);
            } else {
                unsigned g;

                for(g = 0; g < ways; g += 4) {
                    acc = zbm_row_group4(src, bk0, bk1, bk2, bk3, g, hereA, &k, acc, la, lanes, &nlanes);
                    acc = zbm_row_group4(src, bk4, bk5, bk6, bk7, g, hereB, &k, acc, la, lanes, &nlanes);
                }
            }
            if(tab2 && rec) {
                acc = zbm_row_group4(src, bq0, bq1, bq2, bq3, 0, hereA, &k, acc, la, lanes, &nlanes);
                acc = zbm_row_group4(src, bq4, bq5, bq6, bq7, 0, hereB, &k, acc, la, lanes, &nlanes);
            }

            /*
             * The nearest periods, scanned outright: the buckets only find
             * a period the bytes of a key agree on, and the small periods
             * of structured data often match sparser than that.
             * Segment s covers periods 8 + 16s to 23 + 16s: every needle
             * byte broadcast against the 16 source bytes that lie at those
             * periods from it, the match counts summed in byte lanes, then
             * literals << 5 | period id so one min finds the best and
             * nearest. Only segments entirely behind the buffer's start run.
             */
            if(nseg > 0) {
                uint32_t segs = (pos - 8u) / 16u;
                uint32_t sg, best, slit, soff, sok, sval;
                uint8_t sbm;

                if(segs > nseg)
                    segs = nseg;
                if(!la) {
                    /* The plain flavour scans at most 32 periods: byte lanes
                     * of literals << 5 | (period - 8), literals saturated at
                     * 7, so a lane with none matching cannot win. */
                    uint8x16_t smin = vdupq_n_u8(0xff);

                    sg = 0;
#if ZBM_SCAN_AVX2
                    /* Both segments in one pass: bytes 0-15 are segment 1,
                     * 16-31 segment 0, and lane i is id 31 - i across both. */
                    if(segs == 2) {
                        const __m256i iota = _mm256_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                                                              16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31);
                        __m256i a = _mm256_min_epu8(zbm_scan32(src - 39u, needle), _mm256_set1_epi8(7));
                        __m256i key = _mm256_or_si256(_mm256_and_si256(_mm256_slli_epi16(a, 5), _mm256_set1_epi8((char)0xe0)),
                                                      _mm256_sub_epi8(_mm256_set1_epi8(31), iota));

                        smin = _mm_min_epu8(_mm256_castsi256_si128(key), _mm256_extracti128_si256(key, 1));
                        sg = 2;
                    }
#endif
                    for(; sg < segs; ++sg) {
                        const uint8_t *g = src - (23u + 16u * sg);
                        /* lane i is period 23 + 16 sg - i, i.e. id 15 + 16 sg - i */
                        uint8x16_t ids = vsubq_u8(vdupq_n_u8((uint8_t)(15u + 16u * sg)),
                                                  ZBM_V16U8_IOTA);
                        /* Each compare is -1 per match; summed as a tree, so the
                         * eight do not serialise. a = 8 - matches = literals. */
                        uint8x16_t c0 = vaddq_u8(vceqq_u8(vld1q_u8(g + 0), vdupq_laneq_u8(k.nv2, 0)),
                                                 vceqq_u8(vld1q_u8(g + 1), vdupq_laneq_u8(k.nv2, 1)));
                        uint8x16_t c1 = vaddq_u8(vceqq_u8(vld1q_u8(g + 2), vdupq_laneq_u8(k.nv2, 2)),
                                                 vceqq_u8(vld1q_u8(g + 3), vdupq_laneq_u8(k.nv2, 3)));
                        uint8x16_t c2 = vaddq_u8(vceqq_u8(vld1q_u8(g + 4), vdupq_laneq_u8(k.nv2, 4)),
                                                 vceqq_u8(vld1q_u8(g + 5), vdupq_laneq_u8(k.nv2, 5)));
                        uint8x16_t c3 = vaddq_u8(vceqq_u8(vld1q_u8(g + 6), vdupq_laneq_u8(k.nv2, 6)),
                                                 vceqq_u8(vld1q_u8(g + 7), vdupq_laneq_u8(k.nv2, 7)));
                        uint8x16_t a = vaddq_u8(vdupq_n_u8(8), vaddq_u8(vaddq_u8(c0, c1), vaddq_u8(c2, c3)));

                        a = vminq_u8(a, vdupq_n_u8(7));
                        smin = vminq_u8(smin, vorrq_u8(vshlq_n_u8(a, 5), ids));
                    }
                    best = vminvq_u8(smin);
                    slit = best >> 5;
                    soff = (best & 31u) + 8u;
                    sok = best != 0xffu;    /* an empty scan or 7 literals at id 31 cannot win either way */
                } else {
                    /* The lookahead flavour scans any width: literals << 8 |
                     * id in 16-bit lanes. */
                    uint16x8_t smin = vdupq_n_u16(0xffff);
                    const uint16x8_t lane_lo = ZBM_V8U16(0, 1, 2, 3, 4, 5, 6, 7);
                    const uint16x8_t lane_hi = ZBM_V8U16(8, 9, 10, 11, 12, 13, 14, 15);

                    sg = 0;
#if ZBM_SCAN_AVX2
                    /* Two segments a pass: bytes 0-15 are segment sg + 1,
                     * 16-31 segment sg, each widened to its own ids. */
                    {
                        const __m256i iota16 = _mm256_setr_epi16(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
                        __m256i smin2 = _mm256_set1_epi16(-1);

                        for(; sg + 2 <= segs; sg += 2) {
                            __m256i a = zbm_scan32(src - (39u + 16u * sg), needle);
                            __m256i id1 = _mm256_sub_epi16(_mm256_set1_epi16((short)(31u + 16u * sg)), iota16);
                            __m256i id0 = _mm256_sub_epi16(_mm256_set1_epi16((short)(15u + 16u * sg)), iota16);
                            __m256i l1 = _mm256_cvtepu8_epi16(_mm256_castsi256_si128(a));
                            __m256i l0 = _mm256_cvtepu8_epi16(_mm256_extracti128_si256(a, 1));

                            smin2 = _mm256_min_epu16(smin2, _mm256_or_si256(_mm256_slli_epi16(l1, 8), id1));
                            smin2 = _mm256_min_epu16(smin2, _mm256_or_si256(_mm256_slli_epi16(l0, 8), id0));
                        }
                        smin = _mm_min_epu16(_mm256_castsi256_si128(smin2), _mm256_extracti128_si256(smin2, 1));
                    }
#endif
                    for(; sg < segs; ++sg) {
                        const uint8_t *g = src - (23u + 16u * sg);
                        uint16x8_t base = vdupq_n_u16((uint16_t)(15u + 16u * sg));
                        uint8x16_t c0 = vaddq_u8(vceqq_u8(vld1q_u8(g + 0), vdupq_laneq_u8(k.nv2, 0)),
                                                 vceqq_u8(vld1q_u8(g + 1), vdupq_laneq_u8(k.nv2, 1)));
                        uint8x16_t c1 = vaddq_u8(vceqq_u8(vld1q_u8(g + 2), vdupq_laneq_u8(k.nv2, 2)),
                                                 vceqq_u8(vld1q_u8(g + 3), vdupq_laneq_u8(k.nv2, 3)));
                        uint8x16_t c2 = vaddq_u8(vceqq_u8(vld1q_u8(g + 4), vdupq_laneq_u8(k.nv2, 4)),
                                                 vceqq_u8(vld1q_u8(g + 5), vdupq_laneq_u8(k.nv2, 5)));
                        uint8x16_t c3 = vaddq_u8(vceqq_u8(vld1q_u8(g + 6), vdupq_laneq_u8(k.nv2, 6)),
                                                 vceqq_u8(vld1q_u8(g + 7), vdupq_laneq_u8(k.nv2, 7)));
                        uint8x16_t a = vaddq_u8(vdupq_n_u8(8), vaddq_u8(vaddq_u8(c0, c1), vaddq_u8(c2, c3)));
                        uint16x8_t llo = vmovl_u8(vget_low_u8(a)), lhi = vmovl_u8(vget_high_u8(a));

                        smin = vminq_u16(smin, vorrq_u16(vshlq_n_u16(llo, 8), vsubq_u16(base, lane_lo)));
                        smin = vminq_u16(smin, vorrq_u16(vshlq_n_u16(lhi, 8), vsubq_u16(base, lane_hi)));
                    }
                    best = vminvq_u16(smin);
                    slit = best >> 8;
                    soff = (best & 0xffu) + 8u;
                    sok = slit < 8u;
                }
                sbm = zbm_mask_bitmap(zbm_diff_mask8(zbm_load_u64(src - (sok ? soff : 8u)) ^ needle), &k);
                if(la) {
                    uint32_t snx = zbm_popcount8(zbm_mask_bitmap(zbm_diff_mask8(
                        zbm_load_u64(src - (sok ? soff : 8u) + 8) ^ zbm_load_u64(src + 8)), &k));

                    sval = ((4u * slit + snx) << 24) | ((uint32_t)sbm << 16) | soff | (sok ? 0u : 1u << 30);
                } else {
                    sval = (slit << 24) | ((uint32_t)sbm << 16) | soff | (sok ? 0u : 128u << 24);
                }
                acc = vminq_u32(acc, vdupq_n_u32(sval));
                if(rec)
                    lanes[nlanes++] = sval;
            }
            minv = vminvq_u32(acc);
            wcost = minv >> 24;
            wd = minv & 0xffffu;
            /* The challenger: the best find when it can beat the
             * continuation, else the continuation itself, which then ties
             * and loses in the scorer. With the lookahead lanes the test is
             * permissive: the scorer prices the next block exactly. */
            found = la ? (int)wcost < 4 * c + 8 : (int)wcost < c;
            p1 = found ? wd : per;
            if(found) ZBM_STAT(2);
            b1 = found ? (uint8_t)(minv >> 16) : b0;
            pop1 = !found ? c : la ? (int)zbm_popcount8(b1) : (int)wcost - (wd > 0xff);

            /* The exact model: literals, period bytes, the run-extension
             * nibble, the give-up gate, one block of lookahead. */
            /* zbm_nibble_extend_delta(run_len) in arithmetic, so it costs
             * no branch: 1 below 3, 0 to 17, then every 15th. */
            {
                unsigned rl = (unsigned)run_len;
                int ext = (rl < 3u) | ((rl >= 18u) & ((rl - 3u) % 15u == 0u));

                run_key = ext ? -1 : run_bmprot;
            }
            pbc1 = (p1 != per) * (1 + (p1 > 0xff));
            bp0 = (int)b0 << 2;
            bp1 = (int)b1 << 2 | pbc1;
            cost0 = 8 * pop0 + (bp0 == run_key ? 0 : 4);
            cost1 = 8 * pop1 + 8 * pbc1 + (bp1 == run_key ? 0 : 4);
            {
                int u0 = (int)uc[bp0] + (bp0 == run_bmprot ? (int)pending : 0);
                int u1 = (int)uc[bp1] + (bp1 == run_bmprot ? (int)pending : 0);

                cost0 += (u0 << ZBM_ROW_HOT_SHIFT) >= cnt ? 0 : ZBM_ROW_HOT_COST;
                cost1 += (u1 << ZBM_ROW_HOT_SHIFT) >= cnt ? 0 : ZBM_ROW_HOT_COST;
            }
            gate_max = pop0 < 8 - ZBM_GIVEUP_FLOOR ? pop0 : 8 - ZBM_GIVEUP_FLOOR;
            cost1 += pop1 > gate_max ? ZBM_GIVEUP_VETO : 0;
            if(look_ok) {
                uint64_t next = zbm_load_u64(src + 8);
                uint8x8_t m0n = zbm_diff_mask8(zbm_load_u64(src - per + 8) ^ next);
                uint8x8_t m1n = zbm_diff_mask8(zbm_load_u64(src - p1 + 8) ^ next);
                uint8_t b0n = zbm_mask_bitmap(m0n, &k), b1n = zbm_mask_bitmap(m1n, &k);

                /* Counts by table: the compiler otherwise round-trips the
                 * bitmap through the vector unit for a population count. */
                l0 = zbm_popcount8(b0n);
                l1 = zbm_popcount8(b1n);
                {
                    int lw0 = ZBM_ROW_LOOKAHEAD_WEIGHT * l0, lw1 = ZBM_ROW_LOOKAHEAD_WEIGHT * l1;

                    cost0 += lw0 > ZBM_ROW_LOOKAHEAD_CAP ? ZBM_ROW_LOOKAHEAD_CAP : lw0;
                    cost1 += lw1 > ZBM_ROW_LOOKAHEAD_CAP ? ZBM_ROW_LOOKAHEAD_CAP : lw1;
                }
                /* With the lookahead priced this finely a tie is a real tie:
                 * the incumbent keeps it, along with the period stream and
                 * the tuple run it is on, which is also 4% of throughput. */
                take1 = cost1 < cost0;
                next_c = take1 ? l1 : l0;
                next_b = take1 ? b1n : b0n;
            } else {
                take1 = (cost1 < cost0) | ((cost1 == cost0) & (pop1 < pop0));
                next_c = -1;
            }
            if(take1) ZBM_STAT(3);
            bitmap = take1 ? b1 : b0;
            bp = take1 ? bp1 : bp0;
            nb[cnt].bitmap = bitmap;
            nb[cnt].period_bytecnt = (uint8_t)(take1 ? pbc1 : 0);
            per = take1 ? p1 : per;
            pp[cnt] = per;
            if(rec && cnt < ZBM_MAX_BITMAP_COUNT) {
                /*
                 * The block's candidate list for the DP: the period that was
                 * in force first (the DP's "stay" needs it present), then
                 * every distinct admissible lane by lane cost, counting-sorted
                 * on the cost byte since there are at most 64 costs.
                 */
                uint16_t *out = ZBM_DP_CAND(state, cnt);
                int stride = state->dp_cand_stride, n = 0, ci, li;
                uint8_t head[64], tail[64], next[8 * 16 + 8 * ZBM_ROW2_WAYS + 8 + 4];

                memset(head, 0xff, sizeof(head));
                for(li = 0; li < nlanes; ++li) {
                    uint32_t c = lanes[li] >> 24;
                    if(c < 64u) {
                        if(head[c] == 0xff)
                            head[c] = (uint8_t)li;
                        else
                            next[tail[c]] = (uint8_t)li;
                        tail[c] = (uint8_t)li;
                        next[li] = 0xff;
                    }
                }

                out[n++] = (uint16_t)per_in;
                if(stride <= 32) {
                    uint16_t tab[64] = {0};
                    uint32_t h0 = ((uint16_t)per_in ^ ((uint16_t)per_in >> 6)) & 63;
                    tab[h0] = (uint16_t)per_in;

                    int c_max = 64;
                    for(ci = 0; ci < c_max && n < stride; ++ci) {
                        for(li = head[ci]; li != 0xff && n < stride; li = next[li]) {
                            uint16_t d = (uint16_t)(lanes[li] & 0xffffu);
                            uint32_t h = (d ^ (d >> 6)) & 63;
                            while(tab[h] != 0) {
                                if(tab[h] == d) goto zbm_dup;
                                h = (h + 1) & 63;
                            }
                            tab[h] = d;
                            out[n++] = d;
                            if(c_max == 64) c_max = ci + 20;
                        zbm_dup: ;
                        }
                    }
                } else {
                    for(ci = 0; ci < 64 && n < stride; ++ci) {
                        for(li = head[ci]; li != 0xff && n < stride; li = next[li]) {
                            uint16_t d = (uint16_t)(lanes[li] & 0xffffu);
                            int dup = 0, q;

                            for(q = 0; q < n; ++q)
                                if(out[q] == d) { dup = 1; break; }
                            if(!dup)
                                out[n++] = d;
                        }
                    }
                }
                state->dp_ncand[cnt] = (uint8_t)n;
            }
            ++cnt;
            mru_use = mru;
            mru2_use = mru2;
            if(la && nl > 4) {
                uint64_t tl = mru, th = mru2;

                zbm_mru8_touch(&tl, &th, per);
                mru = take1 ? tl : mru;
                mru2 = take1 ? th : mru2;
            } else {
                uint64_t touched = zbm_mru4_touch(mru, per);

                mru = take1 ? touched : mru;
            }
        }

        /* The inserts, after every bucket has been read. */
        {
            const unsigned slot = zbm_row_slot(pos, ways);

            bk0[slot] = e;     bk1[slot] = e + 1; bk2[slot] = e + 2; bk3[slot] = e + 3;
            bk4[slot] = e + 4; bk5[slot] = e + 5; bk6[slot] = e + 6; bk7[slot] = e + 7;
            if(tab2) {
                const unsigned slot2 = zbm_row_slot(pos, ZBM_ROW2_WAYS);

                bq0[slot2] = e;     bq1[slot2] = e + 1; bq2[slot2] = e + 2; bq3[slot2] = e + 3;
                bq4[slot2] = e + 4; bq5[slot2] = e + 5; bq6[slot2] = e + 6; bq7[slot2] = e + 7;
            }
        }

        /* Run bookkeeping without a branch: the use count of a run is
         * settled when it ends, and a run that continues adds 0. */
        same = bp == run_bmprot;
        uc[run_bmprot & (ZBM_POSSIBLE_BMPROTS - 1)] += same ? 0 : pending;
        pending = same ? pending + 1 : 1;
        run_len = same ? run_len + 1 : 1;
        run_bmprot = bp;

        src += 8;
        read += 8;
        pos += 8;
    }

    uc[run_bmprot & (ZBM_POSSIBLE_BMPROTS - 1)] += pending;
    state->row_mru = mru;
    state->row_mru2 = mru2;
    state->bmp_cnt = cnt;
    state->period = (uint16_t)per;
    state->src = src;
    state->read = read;
    /* The generic path recomputes its continuation; the run path's handoff
     * reads eight bytes past a block that may be the buffer's last whole
     * one, so the value is dropped rather than trusted. */
    state->row_next_diff = -1;
    if(state->index_pos < pos)
        state->index_pos = pos;
    *run_bmprot_io = run_bmprot;
    *run_len_io = run_len;
}

#define ZBM_ROW_LOOP(w, la)                                                   \
    static __attribute__((noinline))                                          \
    void zbm_row_loop_w##w##_##la(struct zbm_compress_state *state,           \
                                  int *run_bmprot, int *run_len)              \
    {                                                                         \
        zbm_row_loop_w(state, run_bmprot, run_len, w, la, 0);                 \
    }
#define ZBM_ROW_LOOP_REC(w)                                                   \
    static __attribute__((noinline))                                          \
    void zbm_row_loop_rec_w##w(struct zbm_compress_state *state,              \
                               int *run_bmprot, int *run_len)                 \
    {                                                                         \
        zbm_row_loop_w(state, run_bmprot, run_len, w, 1, 1);                  \
    }
ZBM_ROW_LOOP(1, 0)
ZBM_ROW_LOOP(2, 0)
ZBM_ROW_LOOP(4, 0)
ZBM_ROW_LOOP(8, 0)
ZBM_ROW_LOOP(16, 0)
ZBM_ROW_LOOP(1, 1)
ZBM_ROW_LOOP(2, 1)
ZBM_ROW_LOOP(4, 1)
ZBM_ROW_LOOP(8, 1)
ZBM_ROW_LOOP(16, 1)
ZBM_ROW_LOOP_REC(1)
ZBM_ROW_LOOP_REC(2)
ZBM_ROW_LOOP_REC(4)
ZBM_ROW_LOOP_REC(8)
ZBM_ROW_LOOP_REC(16)
#undef ZBM_ROW_LOOP
#undef ZBM_ROW_LOOP_REC

static void zbm_row_loop(struct zbm_compress_state *state, int *run_bmprot, int *run_len)
{
    if(state->dp_recording) {
        switch(state->row_ways) {
        case 1:  zbm_row_loop_rec_w1(state, run_bmprot, run_len); break;
        case 2:  zbm_row_loop_rec_w2(state, run_bmprot, run_len); break;
        case 4:  zbm_row_loop_rec_w4(state, run_bmprot, run_len); break;
        case 8:  zbm_row_loop_rec_w8(state, run_bmprot, run_len); break;
        default: zbm_row_loop_rec_w16(state, run_bmprot, run_len); break;
        }
    } else if(state->params.p.row.lookahead) {
        switch(state->row_ways) {
        case 1:  zbm_row_loop_w1_1(state, run_bmprot, run_len); break;
        case 2:  zbm_row_loop_w2_1(state, run_bmprot, run_len); break;
        case 4:  zbm_row_loop_w4_1(state, run_bmprot, run_len); break;
        case 8:  zbm_row_loop_w8_1(state, run_bmprot, run_len); break;
        default: zbm_row_loop_w16_1(state, run_bmprot, run_len); break;
        }
    } else {
        switch(state->row_ways) {
        case 1:  zbm_row_loop_w1_0(state, run_bmprot, run_len); break;
        case 2:  zbm_row_loop_w2_0(state, run_bmprot, run_len); break;
        case 4:  zbm_row_loop_w4_0(state, run_bmprot, run_len); break;
        case 8:  zbm_row_loop_w8_0(state, run_bmprot, run_len); break;
        default: zbm_row_loop_w16_0(state, run_bmprot, run_len); break;
        }
    }
}

static long zbm_decide_chunk_row(struct zbm_compress_state *state, const uint8_t *chunk_src)
{
    int run_bmprot = -1, run_len = 0;
    uint32_t chunk_start = (uint32_t)state->preread;

    state->src = chunk_src;
    state->read = 0;
    state->period = 8;
    state->bmp_cnt = 0;
    state->row_mru = 8;     /* lane 0 is the period in force */
    state->row_mru2 = 0;
    state->row_next_diff = -1;
    memset(state->usecnts, 0, sizeof(state->usecnts));

    zbm_row_prepare_index(state, chunk_start);

    if(state->preread == 0) {
        struct zbm_bmap *init = &state->bitmaps[0];

        if(state->decmp_len < 8)
            return -1;
        init->bitmap = 0xff;
        init->period_bytecnt = 0;
        /* The third write to periods[], bypassing both commit paths. */
        assert(state->period >= 8);
        state->periods[0] = state->period;
        state->bmp_cnt = 1;
        state->usecnts[zbm_bmprot(init)] = 1;
        run_bmprot = zbm_bmprot(init);
        run_len = 1;
        state->src += 8;
        state->read += 8;
        zbm_row_index_range(state, 0, 8);
        state->index_pos = 8;
    }

    zbm_row_loop(state, &run_bmprot, &run_len);
    while(state->read < state->decmp_len)
        zbm_decide_block_row_generic(state, &run_bmprot, &run_len);

    return zbm_literal_total(state->bitmaps, state->bmp_cnt);
}

static int zbm_build_compressed_chunk_row(struct zbm_compress_state *state)
{
    struct zbm_cmp_chunk_hdr *hdr = NULL;
    const uint8_t *chunk_src;
    long data_bytes;
    int err;

    if(sizeof(*hdr) > (size_t)(state->dest_end - state->dest))
        return ZBM_CANT_COMPRESS;
    state->dest -= sizeof(hdr->hdr);
    state->written -= sizeof(hdr->hdr);
    hdr = (struct zbm_cmp_chunk_hdr *)state->dest;
    state->dest += sizeof(*hdr);
    state->written += sizeof(*hdr);

    chunk_src = state->src;
    memset(state->is_top_estimate, 0, sizeof(state->is_top_estimate));

    data_bytes = zbm_decide_chunk_row(state, chunk_src);
    if(data_bytes < 0)
        return ZBM_CANT_COMPRESS;

    err = zbm_emit_literals(state, chunk_src, data_bytes);
    if(err)
        return err;

    return zbm_build_metadata(state, hdr);
}


/* ------------------------------------------------------------------ */
/* CRUSHLZBITMAP_STRATEGY_FAST: search only where the period fails.   */
/* ------------------------------------------------------------------ */

/*
 * The fast tier keeps the row tier's table layout (one way, an entry a 24-bit
 * position under the chunk's epoch) but changes what is paid per block. A
 * block the period in force serves within accept_diff literals costs one
 * probe and a few stores: nothing is hashed and nothing is indexed, since its
 * bytes repeat bytes already behind it. Only a searched block looks anything
 * up, and only a searched block is indexed. The search itself is branch-free:
 * `windows` table entries spread over the block plus the recent periods, each
 * scored as literals plus one for the change (two past distance 255), and one
 * running minimum picks the winner; the continuation keeps its period on a
 * tie in literals. The literals are packed into the destination as the
 * blocks are decided, the period bytes into a side buffer, and the use
 * counts kept as they go, so what is left after the loop is the metadata.
 *
 * A search that keeps the period counts as fruitless; after n of them in a
 * row the next n >> skip_shift blocks are not searched at all, which is what
 * keeps incompressible stretches near the cost of the plain probe.
 */

/* The fast table is one way of at most 2^MAX_FAST_HASH_BITS entries; the rest
 * of row_tab stages a chunk's literals when the destination is too tight. */
#define ZBM_FAST_TAB_ENTRIES ((size_t)1 << CRUSHLZBITMAP_MAX_FAST_HASH_BITS)
typedef char zbm_fast_stage_fits[(ZBM_FAST_TAB_ENTRIES * sizeof(uint32_t) + CRUSHLZBITMAP_CHUNK_SIZE + 8 <=
                                  sizeof(((struct zbm_compress_state *)0)->row_tab)) ? 1 : -1];

/* A condition the branch predictor cannot learn, so the compiler should
 * select rather than branch; only clang takes the hint. */
#if defined(__has_builtin)
#if __has_builtin(__builtin_unpredictable)
#define ZBM_UNPREDICTABLE(x) __builtin_unpredictable(x)
#endif
#endif
#ifndef ZBM_UNPREDICTABLE
#define ZBM_UNPREDICTABLE(x) (x)
#endif

#if defined(__ARM_NEON) && !defined(CRUSH_SIMD_PORTABLE)
#define ZBM_FAST_NEON 1
#else
#define ZBM_FAST_NEON 0
#endif

/*
 * The plain probe of a block against the period in force: the bitmap of the
 * differing lanes, with the block itself left in a register the literal pack
 * can reuse. One vector compare and one mask extraction where there is a
 * vector unit; the SWAR form elsewhere.
 */
#if ZBM_FAST_NEON
typedef uint8x8_t zbm_fast_blk;

static __attribute__((always_inline)) inline
uint32_t zbm_fast_probe(const uint8_t *src, uint32_t per, zbm_fast_blk *blk)
{
    static const uint8_t bits[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };

    *blk = vld1_u8(src);
    return vaddv_u8(vbic_u8(vld1_u8(bits), vceq_u8(*blk, vld1_u8(src - per))));
}

static __attribute__((always_inline)) inline
void zbm_fast_pack(uint8_t *d, zbm_fast_blk blk, uint32_t bm)
{
    vst1_u8(d, vtbl1_u8(blk, vget_low_u8(vld1q_u8(zbm_pack_row[bm]))));
}
#elif defined(__SSE4_1__) && !defined(CRUSH_SIMD_PORTABLE)
typedef __m128i zbm_fast_blk;

static __attribute__((always_inline)) inline
uint32_t zbm_fast_probe(const uint8_t *src, uint32_t per, zbm_fast_blk *blk)
{
    *blk = _mm_loadl_epi64((const __m128i *)(const void *)src);
    return ~(uint32_t)_mm_movemask_epi8(
               _mm_cmpeq_epi8(*blk, _mm_loadl_epi64((const __m128i *)(const void *)(src - per)))) & 0xffu;
}

static __attribute__((always_inline)) inline
void zbm_fast_pack(uint8_t *d, zbm_fast_blk blk, uint32_t bm)
{
    _mm_storel_epi64((__m128i *)(void *)d,
                     _mm_shuffle_epi8(blk, _mm_loadl_epi64((const __m128i *)(const void *)zbm_pack_row[bm])));
}
#else
typedef const uint8_t *zbm_fast_blk;

static __attribute__((always_inline)) inline
uint32_t zbm_fast_probe(const uint8_t *src, uint32_t per, zbm_fast_blk *blk)
{
    *blk = src;
    return zbm_diff_bitmap(zbm_load_u64(src) ^ zbm_load_u64(src - per));
}

static __attribute__((always_inline)) inline
void zbm_fast_pack(uint8_t *d, zbm_fast_blk blk, uint32_t bm)
{
    zbm_pack8(d, blk, zbm_pack_row[bm]);
}
#endif

/*
 * Scores @K candidates (K even: 4, 6 or 10) at the distances @dd, every one
 * of them in reach, and returns the least of @best and their keys, cost << 20
 * | distance with cost the literals plus one, plus one more past distance 255.
 * dd[K] and dd[K + 1] must repeat dd[K - 2] and dd[K - 1] when K / 2 is odd:
 * the NEON reduction pairs the last load with itself.
 */
static __attribute__((always_inline)) inline
uint32_t zbm_fast_score(const uint8_t *src, uint64_t needle, const uint32_t *dd, const int K, uint32_t best)
{
#if ZBM_FAST_NEON
    /* Pairs of candidates per register, equal bytes as -1, summed by a
     * three-level pairwise-add tree so candidate j lands in byte j. */
    const uint8x16_t nn = vreinterpretq_u8_u64(vdupq_n_u64(needle));
    uint8x16_t e[5], t;
    int32x4_t g[3];
    uint32x4_t m;
    int p, q;

    for(p = 0; p < K / 2; ++p)
        e[p] = vceqq_u8(vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(zbm_load_u64(src - dd[2 * p])),
                                                          vcreate_u64(zbm_load_u64(src - dd[2 * p + 1])))),
                        nn);
    if(K == 4) {
        t = vpaddq_u8(e[0], e[1]);
        t = vpaddq_u8(t, t);
        t = vpaddq_u8(t, t);
    } else if(K == 6) {
        t = vpaddq_u8(vpaddq_u8(e[0], e[1]), vpaddq_u8(e[2], e[2]));
        t = vpaddq_u8(t, t);
    } else {
        t = vpaddq_u8(vpaddq_u8(vpaddq_u8(e[0], e[1]), vpaddq_u8(e[2], e[3])),
                      vpaddq_u8(vpaddq_u8(e[4], e[4]), vpaddq_u8(e[4], e[4])));
    }
    {
        int16x8_t w0 = vmovl_s8(vget_low_s8(vreinterpretq_s8_u8(t)));
        int16x8_t w1 = vmovl_s8(vget_high_s8(vreinterpretq_s8_u8(t)));

        g[0] = vmovl_s16(vget_low_s16(w0));
        g[1] = vmovl_s16(vget_high_s16(w0));
        g[2] = vmovl_s16(vget_low_s16(w1));
    }
    m = vdupq_n_u32(best);
    for(q = 0; q < (K + 3) / 4; ++q) {
        uint32x4_t d = vld1q_u32(dd + 4 * q);
        /* 9 - equal bytes = literals + 1; the far mask is -1 */
        uint32x4_t c = vsubq_u32(vreinterpretq_u32_s32(vaddq_s32(g[q], vdupq_n_s32(9))),
                                 vcgtq_u32(d, vdupq_n_u32(0xffu)));

        m = vminq_u32(m, vorrq_u32(vshlq_n_u32(c, 20), d));
    }
    return vminvq_u32(m);
#elif defined(__SSE4_1__) && !defined(CRUSH_SIMD_PORTABLE)
    /* Pairs of candidates per register; PSADBW sums each one's equal bytes
     * (masked to 1) into its 64-bit half. Two pairs fill a group of four
     * 32-bit lanes in the order 0, 2, 1, 3, so the distances are shuffled to
     * match before the keys are built. */
    const __m128i nn = _mm_set1_epi64x((long long)needle);
    const __m128i one = _mm_set1_epi8(1);
    __m128i c[6], m = _mm_set1_epi32((int)best);
    int p, q;

    for(p = 0; p < K / 2; ++p) {
        __m128i v = _mm_unpacklo_epi64(_mm_loadl_epi64((const __m128i *)(const void *)(src - dd[2 * p])),
                                       _mm_loadl_epi64((const __m128i *)(const void *)(src - dd[2 * p + 1])));

        c[p] = _mm_sad_epu8(_mm_and_si128(_mm_cmpeq_epi8(v, nn), one), _mm_setzero_si128());
    }
    if(K / 2 & 1)
        c[K / 2] = c[K / 2 - 1];
    for(q = 0; q < (K + 3) / 4; ++q) {
        __m128i eq = _mm_or_si128(c[2 * q], _mm_slli_epi64(c[2 * q + 1], 32));
        __m128i d = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)(const void *)(dd + 4 * q)),
                                      _MM_SHUFFLE(3, 1, 2, 0));
        /* 9 - equal bytes = literals + 1; the far mask is -1 */
        __m128i cost = _mm_sub_epi32(_mm_sub_epi32(_mm_set1_epi32(9), eq),
                                     _mm_cmpgt_epi32(d, _mm_set1_epi32(0xff)));

        m = _mm_min_epu32(m, _mm_or_si128(_mm_slli_epi32(cost, 20), d));
    }
    m = _mm_min_epu32(m, _mm_shuffle_epi32(m, _MM_SHUFFLE(1, 0, 3, 2)));
    m = _mm_min_epu32(m, _mm_shuffle_epi32(m, _MM_SHUFFLE(2, 3, 0, 1)));
    return (uint32_t)_mm_cvtsi128_si32(m);
#else
    int j;

    for(j = 0; j < K; ++j) {
        uint32_t c = zbm_diff_count_only(needle ^ zbm_load_u64(src - dd[j])) + 1u + (dd[j] > 0xffu);
        uint32_t k = c << 20 | dd[j];

        best = ZBM_UNPREDICTABLE(k < best) ? k : best;
    }
    return best;
#endif
}

/* The eight windows' buckets, as zbm_row_bucket() of each window's 4 bytes. */
static __attribute__((always_inline)) inline
void zbm_fast_hash8(const uint8_t *src, int sh, uint32_t h[8])
{
#if ZBM_FAST_NEON
    static const uint8_t idx[32] = { 0, 1, 2, 3, 1, 2, 3, 4, 2, 3, 4, 5, 3, 4, 5, 6,
                                     4, 5, 6, 7, 5, 6, 7, 8, 6, 7, 8, 9, 7, 8, 9, 10 };
    const uint8x16_t v = vld1q_u8(src);
    const uint32x4_t mul = vdupq_n_u32(0x9E3779B1u);
    const int32x4_t nsh = vdupq_n_s32(-sh);

    vst1q_u32(h, vshlq_u32(vmulq_u32(vreinterpretq_u32_u8(vqtbl1q_u8(v, vld1q_u8(idx))), mul), nsh));
    vst1q_u32(h + 4, vshlq_u32(vmulq_u32(vreinterpretq_u32_u8(vqtbl1q_u8(v, vld1q_u8(idx + 16))), mul), nsh));
#else
    const uint64_t lo = zbm_load_u64(src), hi4 = zbm_load_u64(src + 4);
    int j;

    for(j = 0; j < 8; ++j)
        h[j] = zbm_row_bucket(j < 5 ? (uint32_t)(lo >> (8 * j)) : (uint32_t)(hi4 >> (8 * (j - 4))), sh);
#endif
}

/* Bytes from a search to the next block that may search again. The loop keeps
 * the skip marker as this many bytes past the searching block's offset from
 * its first block, not as a pointer: src + skip could point beyond the input
 * allocation, which C leaves undefined even though it is only compared. The
 * offset stays far below SIZE_MAX, and comparing offsets makes the same
 * decision for every block as comparing the pointers did. */
static __attribute__((always_inline)) inline
size_t zbm_fast_skip_bytes(uint32_t failures, int shift)
ZBM_REQUIRES(failures <= ZBM_MAX_BITMAP_COUNT && shift >= 1 && shift <= 31)
ZBM_ENSURES(__CPROVER_return_value >= 8 && __CPROVER_return_value <= 8 + 4 * (size_t)ZBM_MAX_BITMAP_COUNT)
{
    return 8 + 8 * (size_t)(failures >> shift);
}

/*
 * The block loop over every whole block with 16 readable bytes at pos >= 8.
 * @W is the window count (offsets 0, 8/W, 2 * 8/W, ...). Each block leaves
 * its (bitmap, period_bytecnt) in state->bitmaps and its use count, and a
 * period change leaves its bytes at *m1p. The literals are packed at *litp
 * with 8-byte stores, which need the chunk's length plus 8 bytes of room.
 */
static __attribute__((always_inline)) inline
void zbm_fast_loop_w(struct zbm_compress_state *state, uint8_t **litp, uint8_t **m1p, const int W)
{
    const crushlzbitmap_fast_params *fp = &state->params.p.fast;
    uint32_t *restrict tab = state->row_tab;
    const uint32_t epoch_hi = state->row_epoch << 24;
    const int sh = state->row_sh;
    const uint32_t decmp_len = state->decmp_len;
    const size_t buf_len = state->buf_len;
    const uint32_t acc = (uint32_t)fp->accept_diff;
    const int nmru = fp->dist_cache_size;
    const int skipsh = fp->skip_shift ? fp->skip_shift : 31;
    const uint8_t *src = state->src;
    uint32_t read = state->read;
    uint32_t pos = (uint32_t)(state->preread + read);
    uint32_t per = state->period;
    struct zbm_bmap *restrict kp = state->bitmaps + state->bmp_cnt;
    zbm_usecnt_t *restrict uc = state->key_usecnts;
    uint8_t *restrict d = *litp;
    uint8_t *restrict m1 = *m1p;
    const uint32_t keep0 = nmru > 0 ? ~0u : 0u, keep1 = nmru > 1 ? ~0u : 0u;
    uint32_t mru0 = 0, mru1 = 0;
    const uint8_t *const src0 = src;
    const uint32_t pos0 = pos;
    const uint8_t *end;
    size_t skip_off = 0;    /* first offset from src0 that may search */
    uint32_t nblocks, fails = 0;

    {
        uint32_t nblk = decmp_len >= read + 8 ? (decmp_len - read) / 8 : 0;
        uint32_t nbuf = buf_len >= (size_t)pos + 16 ? (uint32_t)((buf_len - pos - 16) / 8) + 1 : 0;

        if(pos < 8)
            nblk = 0;
        if(nblk > nbuf)
            nblk = nbuf;
        nblocks = nblk;
    }
    end = src + 8 * (size_t)nblocks;

    for(; src < end; src += 8, ++kp) {
        zbm_fast_blk blk;
        uint32_t bm = zbm_fast_probe(src, per, &blk);
        uint32_t pbc = 0;

        if(zbm_popcount8_table[bm] > acc && (size_t)(src - src0) >= skip_off) {
            const uint64_t needle = zbm_load_u64(src);
            const uint32_t here = pos0 + (uint32_t)(src - src0);
            const uint32_t band = (here < ZBM_GREEDY_REACH ? here : ZBM_GREEDY_REACH) - 8u;
            const uint32_t e = (here & ZBM_ROW_POS_MASK) | epoch_hi;
            /* The period in force keys at distance 0, below any real one,
             * so it keeps every tie. */
            uint32_t best = (uint32_t)zbm_popcount8_table[bm] << 20;
            uint32_t h[8], dd[12];
            int j;

            ZBM_STAT(4);
            zbm_fast_hash8(src, sh, h);

            /* The candidates: the windows' entries, then the two recent
             * periods. One out of reach (or a recent-period lane past
             * dist_cache_size) is replaced by period 8, which pos >= 8 always
             * admits, so every candidate is real and none needs a veto. */
            for(j = 0; j < W; ++j) {
                const int o = j * (8 / W);
                uint32_t dist = (e + (uint32_t)o) - tab[h[o]];

                dd[j] = dist - 8u <= band ? dist : 8u;
            }
            dd[W] = mru0 - 8u <= band ? mru0 : 8u;
            dd[W + 1] = mru1 - 8u <= band ? mru1 : 8u;
            if(W == 1) {
                dd[3] = 8u;
                best = zbm_fast_score(src, needle, dd, 4, best);
            } else if(W == 2) {
                best = zbm_fast_score(src, needle, dd, 4, best);
            } else {
                dd[W + 2] = dd[W];
                dd[W + 3] = dd[W + 1];
                best = zbm_fast_score(src, needle, dd, W + 2, best);
            }

            /* Indexed after every lookup, so a block never finds itself. */
            for(j = 0; j < 8; ++j)
                tab[h[j]] = e + (uint32_t)j;

            {
                uint32_t nd = (best & 0xffffu) ? best & 0xffffu : per;
                uint32_t chg = nd != per;

                pbc = chg * (1 + (nd > 0xffu));
                bm = zbm_diff_bitmap(needle ^ zbm_load_u64(src - nd));
                /* Both bytes unconditionally, low first (the format's
                 * order on any host); pbc decides how many are kept. */
                m1[0] = (uint8_t)nd;
                m1[1] = (uint8_t)(nd >> 8);
                m1 += pbc;
                /* The ring holds 0 in a lane past dist_cache_size, and
                 * distance 0 is never in reach. */
                mru1 = chg ? mru0 & keep1 : mru1;
                mru0 = chg ? per & keep0 : mru0;
                per = nd;
                fails = chg ? 0 : fails + 1;
                skip_off = (size_t)(src - src0) + zbm_fast_skip_bytes(fails, skipsh);
            }
        }

        {
            /* the (bitmap, period_bytecnt) pair as one store, in the
             * struct's byte order, and its use count by the same key */
            const uint32_t key = bm | pbc << 8;
            const uint16_t pair = (uint16_t)key;

            memcpy(kp, &pair, sizeof(pair));
            ++uc[key];
        }
        zbm_fast_pack(d, blk, bm);
        d += zbm_popcount8_table[bm];
    }

    read += (uint32_t)(src - src0);
    pos += (uint32_t)(src - src0);
    state->bmp_cnt = (int)(kp - state->bitmaps);
    state->period = (uint16_t)per;
    state->src = src;
    state->read = read;
    *litp = d;
    *m1p = m1;
}

#define ZBM_FAST_LOOP(w)                                                        \
    static __attribute__((noinline))                                            \
    void zbm_fast_loop_w##w(struct zbm_compress_state *state, uint8_t **litp,   \
                            uint8_t **m1p)                                      \
    {                                                                           \
        zbm_fast_loop_w(state, litp, m1p, w);                                   \
    }
ZBM_FAST_LOOP(1)
ZBM_FAST_LOOP(2)
ZBM_FAST_LOOP(4)
ZBM_FAST_LOOP(8)
#undef ZBM_FAST_LOOP

static void zbm_fast_loop(struct zbm_compress_state *state, uint8_t **litp, uint8_t **m1p)
{
    switch(state->params.p.fast.windows) {
    case 1:  zbm_fast_loop_w1(state, litp, m1p); break;
    case 2:  zbm_fast_loop_w2(state, litp, m1p); break;
    case 4:  zbm_fast_loop_w4(state, litp, m1p); break;
    default: zbm_fast_loop_w8(state, litp, m1p); break;
    }
}

/*
 * A block the loop declines: the chunk's short last block, or one too near
 * the buffer's end for the loop's 16-byte reads. The period in force, no
 * search; a lane whose source would precede the buffer is a literal.
 */
static void zbm_fast_tail_block(struct zbm_compress_state *state, uint8_t **litp)
{
    const uint8_t *src = state->src;
    const uint32_t pos = (uint32_t)(state->preread + state->read);
    const uint32_t per = state->period;
    const int n = (int)MIN(8u, state->decmp_len - state->read);
    uint8_t bm = 0;
    int j;

    for(j = 0; j < n; ++j)
        if(per > pos || src[j] != src[j - (ptrdiff_t)per])
            bm |= (uint8_t)(1u << j);
    bm = zbm_period_floor_bitmap(bm, (uint16_t)per, (uint8_t)n);

    state->bitmaps[state->bmp_cnt].bitmap = bm;
    state->bitmaps[state->bmp_cnt].period_bytecnt = 0;
    ++state->key_usecnts[bm];
    ++state->bmp_cnt;
    for(j = 0; j < n; ++j)
        if(bm >> j & 1)
            *(*litp)++ = src[j];
    state->src += n;
    state->read += (uint32_t)n;
}

/*
 * Every block's bitmap number, and area 2: the bitmaps of the blocks whose
 * (bitmap, period_bytecnt) did not make the top table, packed in block order
 * from @d2. Returns the end of area 2. Eight blocks a step where there is a
 * vector unit: the number defaults to the period byte count and the twelve
 * top keys overwrite it, lowest slot last so it wins as
 * zbm_build_bmap_num_table() has it; the area-2 bytes are then packed with
 * the literal packer's shuffle rows. Stores run up to 8 bytes past the area.
 */
static uint8_t *zbm_fast_nums_meta2(struct zbm_compress_state *state, uint8_t *d2)
{
    const struct zbm_bmap *bmaps = state->bitmaps;
    const uint8_t *tbl = state->bmap_num_tbl;
    uint8_t *nums = state->bmap_nums;
    const int cnt = state->bmp_cnt;
    int i = 0, t;

    /* The vector steps read each (bitmap, period_bytecnt) pair as one
     * little-endian 16-bit lane. */
#if ZBM_FAST_NEON
    {
        uint16x8_t top[ZBM_BITMAP_COUNT];
        const uint8x8_t bits = ZBM_V8U8(1, 2, 4, 8, 16, 32, 64, (char)128);

        for(t = 0; t < ZBM_BITMAP_COUNT; ++t)
            top[t] = vdupq_n_u16((uint16_t)zbm_bmkey(&state->top_bitmaps[t]));
        for(; i + 8 <= cnt; i += 8) {
            uint16x8_t k = vld1q_u16((const uint16_t *)(const void *)(bmaps + i));
            uint16x8_t n = vshrq_n_u16(k, 8);
            uint8x8_t n8, m;
            uint32_t mask;

            for(t = ZBM_BITMAP_COUNT - 1; t >= 0; --t)
                n = vbslq_u16(vceqq_u16(k, top[t]), vdupq_n_u16((uint16_t)(t + ZBM_BITMAP_BASE)), n);
            n8 = vmovn_u16(n);
            vst1_u8(nums + i, n8);
            m = vclt_u8(n8, vdup_n_u8(ZBM_BITMAP_BASE));
            mask = vaddv_u8(vand_u8(m, bits));
            vst1_u8(d2, vtbl1_u8(vmovn_u16(k), vget_low_u8(vld1q_u8(zbm_pack_row[mask]))));
            d2 += zbm_popcount8_table[mask];
        }
    }
#elif defined(__SSE4_1__) && !defined(CRUSH_SIMD_PORTABLE)
    {
        __m128i top[ZBM_BITMAP_COUNT];
        const __m128i lo = _mm_set1_epi16(0x00ff);

        for(t = 0; t < ZBM_BITMAP_COUNT; ++t)
            top[t] = _mm_set1_epi16((short)zbm_bmkey(&state->top_bitmaps[t]));
        for(; i + 8 <= cnt; i += 8) {
            __m128i k = _mm_loadu_si128((const __m128i *)(const void *)(bmaps + i));
            __m128i n = _mm_srli_epi16(k, 8);
            __m128i n8, b8;
            uint32_t mask;

            for(t = ZBM_BITMAP_COUNT - 1; t >= 0; --t)
                n = _mm_blendv_epi8(n, _mm_set1_epi16((short)(t + ZBM_BITMAP_BASE)), _mm_cmpeq_epi16(k, top[t]));
            n8 = _mm_packus_epi16(n, n);
            _mm_storel_epi64((__m128i *)(void *)(nums + i), n8);
            mask = (uint32_t)_mm_movemask_epi8(_mm_cmplt_epi8(n8, _mm_set1_epi8(ZBM_BITMAP_BASE))) & 0xffu;
            b8 = _mm_packus_epi16(_mm_and_si128(k, lo), _mm_and_si128(k, lo));
            _mm_storel_epi64((__m128i *)(void *)d2,
                             _mm_shuffle_epi8(b8, _mm_loadl_epi64((const __m128i *)(const void *)zbm_pack_row[mask])));
            d2 += zbm_popcount8_table[mask];
        }
    }
#endif
    (void)t;
    for(; i < cnt; ++i) {
        unsigned num = tbl[zbm_bmkey(&bmaps[i])];

        nums[i] = (uint8_t)num;
        d2[0] = bmaps[i].bitmap;
        d2 += num < ZBM_BITMAP_BASE;
    }
    return d2;
}

/* Areas 1 and 2 and the trailing table, area 1 copied from the side buffer
 * the loop wrote; byte-identical to zbm_build_metadata() on the same blocks. */
static int zbm_build_metadata_fast(struct zbm_compress_state *state, struct zbm_cmp_chunk_hdr *hdr,
                                   const uint8_t *m1, size_t len1)
{
    ptrdiff_t len2 = 0;
    unsigned key;
    int err;
    uint8_t *d0, *d2;

    /* The use counts into the bmprot order the top-12 search reads. */
    memset(state->usecnts, 0, sizeof(state->usecnts));
    for(key = 0; key < (3u << 8); ++key)
        state->usecnts[(key & 0xffu) << 2 | key >> 8] = state->key_usecnts[key];
    zbm_find_most_common_bitmaps(state);
    zbm_build_bmap_num_table(state);

    /* The top table's counts are now zero, so the rest is area 2's length.
     * Area 2 stores speculatively, eight bytes past its end at most. */
    for(key = 0; key < ZBM_POSSIBLE_BMPROTS; ++key)
        len2 += state->usecnts[key];
    if((ptrdiff_t)len1 + len2 + 8 > state->dest_end - state->dest)
        return ZBM_CANT_COMPRESS;
    d0 = state->dest;
    hdr->meta_off_1 = zbm_u32_to_u24(state->written);
    memcpy(d0, m1, len1);
    hdr->meta_off_2 = zbm_u32_to_u24(state->written + (uint32_t)len1);
    d2 = zbm_fast_nums_meta2(state, d0 + len1);
    state->written += (uint32_t)(d2 - d0);
    state->dest = d2;

    hdr->meta_off_3 = zbm_u32_to_u24(state->written);
    err = zbm_write_metadata_3(state);
    if(err)
        return err;
    return zbm_write_trailing_bitmaps(state);
}

/*
 * Every chunk starts a new epoch, so nothing the previous chunk's decisions
 * left in the table survives into this one, and then indexes the reach
 * behind it at two positions in every eight, offsets 0 and 3. What the table
 * holds at a chunk's start is then a function of the source alone, so a
 * chunk encoded on its own (crushlzbitmap_encode_chunk) is byte-identical to
 * the same chunk of a whole-buffer encode. Offsets of both parities matter:
 * the windows sit at even offsets, so even-only entries would only ever
 * yield even distances.
 *
 * The loop tells an old epoch's entry by its distance alone, which a 24-bit
 * position wrap defeats, so a table whose entries could straddle one is
 * cleared instead.
 */
static void zbm_fast_prepare_index(struct zbm_compress_state *state, uint32_t chunk_start)
{
    const uint8_t *base = state->buf_base;
    uint32_t *tab = state->row_tab;
    const uint32_t span = CRUSHLZBITMAP_CHUNK_SIZE + ZBM_GREEDY_REACH;
    const uint32_t lo = chunk_start > span ? chunk_start - span : 0;
    uint32_t epoch_hi, p;
    int sh;

    state->row_sh = (uint8_t)(32 - zbm_tab_bits(state, state->params.p.fast.hash_bits));
    state->row_ways = 1;
    state->row_epoch = (state->row_epoch + 1) & ((1u << ZBM_ROW_EPOCH_BITS) - 1u);
    if(state->row_epoch == 0 || ((lo ^ (chunk_start + CRUSHLZBITMAP_CHUNK_SIZE)) & ~ZBM_ROW_POS_MASK)) {
        /* Epoch 0 is never live, so a cleared table matches nothing. */
        memset(state->row_tab, 0, sizeof(state->row_tab[0]) << (32 - state->row_sh));
        state->row_epoch = 1;
    }

    sh = state->row_sh;
    epoch_hi = state->row_epoch << 24;
    p = chunk_start > ZBM_GREEDY_REACH ? (chunk_start - ZBM_GREEDY_REACH + 7u) & ~7u : 0;
    /* Whole groups only: offset 3's key is bytes 3 to 6. */
    for(; p + 8 <= chunk_start; p += 8) {
        uint64_t v = zbm_load_u64(base + p);
        uint32_t e = (p & ZBM_ROW_POS_MASK) | epoch_hi;

        tab[zbm_row_bucket((uint32_t)v, sh)] = e;
        tab[zbm_row_bucket((uint32_t)(v >> 24), sh)] = e + 3;
    }
}

static int zbm_build_compressed_chunk_fast(struct zbm_compress_state *state)
{
    struct zbm_cmp_chunk_hdr *hdr = NULL;
    const uint8_t *chunk_src;
    uint8_t *lit, *lit0, *m1;
    size_t room;

    if(sizeof(*hdr) > (size_t)(state->dest_end - state->dest))
        return ZBM_CANT_COMPRESS;
    state->dest -= sizeof(hdr->hdr);
    state->written -= sizeof(hdr->hdr);
    hdr = (struct zbm_cmp_chunk_hdr *)state->dest;
    state->dest += sizeof(*hdr);
    state->written += sizeof(*hdr);

    chunk_src = state->src;
    state->read = 0;
    state->period = 8;
    state->bmp_cnt = 0;
    memset(state->key_usecnts, 0, sizeof(state->key_usecnts));
    zbm_fast_prepare_index(state, (uint32_t)state->preread);

    /* The literals go straight to the destination as the blocks are decided,
     * or, when it cannot take the loop's overhang, to the part of row_tab the
     * fast table leaves free, and are copied over below. */
    room = (size_t)(state->dest_end - state->dest);
    lit = lit0 = room >= state->decmp_len + 8 ? state->dest : (uint8_t *)(state->row_tab + ZBM_FAST_TAB_ENTRIES);
    /* The period bytes, at most two per block, go to the side buffer. */
    m1 = state->meta_scratch;

    if(state->preread == 0) {
        /* The stream's first block has nothing behind it: all literal. */
        if(state->decmp_len < 8)
            return ZBM_CANT_COMPRESS;
        state->bitmaps[0].bitmap = 0xff;
        state->bitmaps[0].period_bytecnt = 0;
        state->key_usecnts[0xff] = 1;
        state->bmp_cnt = 1;
        memcpy(lit, chunk_src, 8);
        lit += 8;
        state->src += 8;
        state->read += 8;
    }

    zbm_fast_loop(state, &lit, &m1);
    while(state->read < state->decmp_len)
        zbm_fast_tail_block(state, &lit);

    if((size_t)(lit - lit0) > room)
        return ZBM_CANT_COMPRESS;
    if(lit0 != state->dest)
        memcpy(state->dest, lit0, (size_t)(lit - lit0));
    state->written += (uint32_t)(lit - lit0);
    state->dest += lit - lit0;

    return zbm_build_metadata_fast(state, hdr, state->meta_scratch, (size_t)(m1 - state->meta_scratch));
}

/* ------------------------------------------------------------------ */
/* CRUSHLZBITMAP_STRATEGY_DP: exact shortest path over the period sequence.      */
/* ------------------------------------------------------------------ */

#define ZBM_DP_INF  (1L << 30)

/* Bytes the DP's per-block tables take at this max_candidates. The scratch
 * carve in zbm_state_begin must walk the same two regions in the same order,
 * and crushlzbitmap_scratch_size must add exactly this. */
static size_t zbm_dp_tables_bytes(int max_candidates)
{
    size_t n = (size_t)max_candidates;
    return sizeof(uint16_t) * ZBM_MAX_BITMAP_COUNT * n     /* dp_cand */
         + sizeof(uint8_t)  * ZBM_MAX_BITMAP_COUNT * n;    /* dp_parent */
}

#define ZBM_DP_FROM_MIN  0xff  /* dp_parent sentinel: jumped from the previous row's best */

/* Literal count for block @blk at period @p, or -1 if p cannot reach back. */
static int zbm_dp_literals(struct zbm_compress_state *state, const uint8_t *chunk_src,
                            int blk, uint16_t p, int *out_bytecnt, uint8_t *out_bitmap)
{
    uint32_t off = (uint32_t)blk * 8;
    size_t abs = state->preread + off;
    int bytecnt = (int)MIN(8u, state->decmp_len - off);
    uint8_t bitmap;

    *out_bytecnt = bytecnt;
    if(p < 8 || (size_t)p > abs)
        return -1;
    bitmap = zbm_calculate_bitmap(chunk_src + off - p, chunk_src + off, (uint8_t)bytecnt, p);
    *out_bitmap = bitmap;
    return zbm_popcount8(bitmap);
}

static long zbm_decide_chunk_dp(struct zbm_compress_state *state, const uint8_t *chunk_src)
{
    long prev_buf[ZBM_GREEDY_MAX_CANDS], cur_buf[ZBM_GREEDY_MAX_CANDS];
    long *prev = prev_buf, *cur = cur_buf;
    int nblocks, first, i, k, j, bytecnt;
    long data_bytes = 0;

    /* Pass 1: the row tier's decision with the lookahead lanes, recording
     * each block's candidate list. The period in force is in every list, so
     * the DP cannot do worse than staying. The lists do not depend on the
     * tuple estimate, so a later iteration reuses them. */
    if(!state->dp_cand)                 /* carved by zbm_state_begin */
        return -1;
    if(!state->dp_lists_ready) {
        memset(state->dp_ncand, 0, sizeof(state->dp_ncand));
        state->dp_recording = 1;
        if(zbm_decide_chunk_row(state, chunk_src) < 0) {
            state->dp_recording = 0;
            return -1;
        }
        state->dp_recording = 0;
        state->dp_lists_ready = 1;
        state->dp_nblocks = state->bmp_cnt;
    }

    nblocks = state->dp_nblocks;
    first = (state->preread == 0) ? 1 : 0;
    if(nblocks - first < 3)
        return zbm_decide_chunk_row(state, chunk_src);

    long gmin = ZBM_DP_INF;
    int gidx = 0;

    /* Pass 2: the recurrence, over each block's OWN candidates. Entering the
     * chunk the current period is 8, so row `first` pays a change unless it
     * picks 8 itself. */
    for(k = 0; k < state->dp_ncand[first]; ++k) {
        uint16_t p = ZBM_DP_CAND(state, first)[k];
        uint8_t bm = 0;
        int lit = zbm_dp_literals(state, chunk_src, first, p, &bytecnt, &bm);
        int pbc = (p == 8) ? 0 : (p <= 0xff ? 1 : 2);

        prev[k] = (lit < 0) ? ZBM_DP_INF
                : 8L * lit + 8L * pbc
                  + (state->is_top_estimate[zbm_bmprot_of(bm, pbc)] ? 0 : 8);
        ZBM_DP_PARENT(state, first)[k] = ZBM_DP_FROM_MIN;
        if(prev[k] < gmin) {
            gmin = prev[k];
            gidx = k;
        }
    }

    int stride = state->dp_cand_stride;

    for(i = first + 1; i < nblocks; ++i) {
        int np = state->dp_ncand[i], npp = state->dp_ncand[i - 1];
        long next_gmin = ZBM_DP_INF;
        int next_gidx = 0;
        uint32_t off = (uint32_t)i * 8;
        int blk_bytecnt = (int)MIN(8u, state->decmp_len - off);
        const uint8_t *curr = chunk_src + off;
        uint64_t needle = (blk_bytecnt == 8) ? zbm_load_u64(curr) : 0;
        const uint16_t *prev_cands = ZBM_DP_CAND(state, i - 1);
        const uint16x8_t idx_1_to_8 = ZBM_V8U16(1, 2, 3, 4, 5, 6, 7, 8);
        uint16x8_t npp_vec = vdupq_n_u16((uint16_t)npp);
        uint16x8_t pc0, pc1, pc2, pc3;
        uint16x8_t act0, act1, act2, act3;

        if(stride <= 8) {
            pc0 = vld1q_u16(prev_cands);
            act0 = vandq_u16(idx_1_to_8, vcltq_u16(ZBM_V8U16(0, 1, 2, 3, 4, 5, 6, 7), npp_vec));
        } else if(stride <= 16) {
            pc0 = vld1q_u16(prev_cands);
            pc1 = vld1q_u16(prev_cands + 8);
            act0 = vandq_u16(idx_1_to_8, vcltq_u16(ZBM_V8U16(0, 1, 2, 3, 4, 5, 6, 7), npp_vec));
            act1 = vandq_u16(ZBM_V8U16(9, 10, 11, 12, 13, 14, 15, 16),
                             vcltq_u16(ZBM_V8U16(8, 9, 10, 11, 12, 13, 14, 15), npp_vec));
        } else if(stride <= 32) {
            pc0 = vld1q_u16(prev_cands);
            pc1 = vld1q_u16(prev_cands + 8);
            pc2 = vld1q_u16(prev_cands + 16);
            pc3 = vld1q_u16(prev_cands + 24);
            act0 = vandq_u16(idx_1_to_8, vcltq_u16(ZBM_V8U16(0, 1, 2, 3, 4, 5, 6, 7), npp_vec));
            act1 = vandq_u16(ZBM_V8U16(9, 10, 11, 12, 13, 14, 15, 16),
                             vcltq_u16(ZBM_V8U16(8, 9, 10, 11, 12, 13, 14, 15), npp_vec));
            act2 = vandq_u16(ZBM_V8U16(17, 18, 19, 20, 21, 22, 23, 24),
                             vcltq_u16(ZBM_V8U16(16, 17, 18, 19, 20, 21, 22, 23), npp_vec));
            act3 = vandq_u16(ZBM_V8U16(25, 26, 27, 28, 29, 30, 31, 32),
                             vcltq_u16(ZBM_V8U16(24, 25, 26, 27, 28, 29, 30, 31), npp_vec));
        }

        const uint16_t *cands = ZBM_DP_CAND(state, i);
        const uint8_t *is_top = state->is_top_estimate;
        uint8_t *parents = ZBM_DP_PARENT(state, i);

        if(__builtin_expect(blk_bytecnt == 8, 1)) {
            for(k = 0; k + 1 < np; k += 2) {
                uint16_t p0 = cands[k];
                uint16_t p1 = cands[k + 1];
                int parent0 = ZBM_DP_FROM_MIN, parent1 = ZBM_DP_FROM_MIN;
                long stay_best0 = ZBM_DP_INF, stay_best1 = ZBM_DP_INF;

                uint64_t w0 = zbm_load_u64(curr - p0);
                uint64_t w1 = zbm_load_u64(curr - p1);

                uint8_t bm0 = zbm_diff_bitmap(needle ^ w0);
                uint8_t bm1 = zbm_diff_bitmap(needle ^ w1);

                int lit0 = zbm_popcount8(bm0);
                int lit1 = zbm_popcount8(bm1);

                int move_pbc0 = (p0 <= 0xff) ? 1 : 2;
                int move_pbc1 = (p1 <= 0xff) ? 1 : 2;

                int stay_extra0 = is_top[zbm_bmprot_of(bm0, 0)] ? 0 : 8;
                int stay_extra1 = is_top[zbm_bmprot_of(bm1, 0)] ? 0 : 8;

                int move_extra0 = is_top[zbm_bmprot_of(bm0, move_pbc0)] ? 0 : 8;
                int move_extra1 = is_top[zbm_bmprot_of(bm1, move_pbc1)] ? 0 : 8;

                long best0 = gmin + 8L * move_pbc0 + move_extra0;
                long best1 = gmin + 8L * move_pbc1 + move_extra1;

                if(stride <= 8) {
                    uint16x8_t eq0 = vceqq_u16(pc0, vdupq_n_u16(p0));
                    uint16x8_t eq1 = vceqq_u16(pc0, vdupq_n_u16(p1));
                    uint16_t m0 = vmaxvq_u16(vandq_u16(eq0, act0));
                    uint16_t m1 = vmaxvq_u16(vandq_u16(eq1, act0));
                    if(m0) { stay_best0 = prev[m0 - 1]; parent0 = m0 - 1; }
                    if(m1) { stay_best1 = prev[m1 - 1]; parent1 = m1 - 1; }
                } else if(stride <= 16) {
                    uint16x8_t pv0 = vdupq_n_u16(p0), pv1 = vdupq_n_u16(p1);
                    uint16x8_t m0_0 = vandq_u16(vceqq_u16(pc0, pv0), act0);
                    uint16x8_t m0_1 = vandq_u16(vceqq_u16(pc1, pv0), act1);
                    uint16x8_t m1_0 = vandq_u16(vceqq_u16(pc0, pv1), act0);
                    uint16x8_t m1_1 = vandq_u16(vceqq_u16(pc1, pv1), act1);
                    uint16_t m0 = vmaxvq_u16(vorrq_u16(m0_0, m0_1));
                    uint16_t m1 = vmaxvq_u16(vorrq_u16(m1_0, m1_1));
                    if(m0) { stay_best0 = prev[m0 - 1]; parent0 = m0 - 1; }
                    if(m1) { stay_best1 = prev[m1 - 1]; parent1 = m1 - 1; }
                } else if(stride <= 32) {
                    uint16x8_t pv0 = vdupq_n_u16(p0), pv1 = vdupq_n_u16(p1);
                    uint16x8_t a0_0 = vandq_u16(vceqq_u16(pc0, pv0), act0);
                    uint16x8_t a0_1 = vandq_u16(vceqq_u16(pc1, pv0), act1);
                    uint16x8_t a0_2 = vandq_u16(vceqq_u16(pc2, pv0), act2);
                    uint16x8_t a0_3 = vandq_u16(vceqq_u16(pc3, pv0), act3);
                    uint16x8_t a1_0 = vandq_u16(vceqq_u16(pc0, pv1), act0);
                    uint16x8_t a1_1 = vandq_u16(vceqq_u16(pc1, pv1), act1);
                    uint16x8_t a1_2 = vandq_u16(vceqq_u16(pc2, pv1), act2);
                    uint16x8_t a1_3 = vandq_u16(vceqq_u16(pc3, pv1), act3);
                    uint16_t m0 = vmaxvq_u16(vorrq_u16(vorrq_u16(a0_0, a0_1), vorrq_u16(a0_2, a0_3)));
                    uint16_t m1 = vmaxvq_u16(vorrq_u16(vorrq_u16(a1_0, a1_1), vorrq_u16(a1_2, a1_3)));
                    if(m0) { stay_best0 = prev[m0 - 1]; parent0 = m0 - 1; }
                    if(m1) { stay_best1 = prev[m1 - 1]; parent1 = m1 - 1; }
                } else {
                    for(j = 0; j < npp; ++j) {
                        if(prev_cands[j] == p0) {
                            if(prev[j] < stay_best0) { stay_best0 = prev[j]; parent0 = j; }
                            break;
                        }
                    }
                    for(j = 0; j < npp; ++j) {
                        if(prev_cands[j] == p1) {
                            if(prev[j] < stay_best1) { stay_best1 = prev[j]; parent1 = j; }
                            break;
                        }
                    }
                }

                if(stay_best0 < ZBM_DP_INF && stay_best0 + stay_extra0 < best0)
                    best0 = stay_best0 + stay_extra0;
                else
                    parent0 = ZBM_DP_FROM_MIN;

                if(stay_best1 < ZBM_DP_INF && stay_best1 + stay_extra1 < best1)
                    best1 = stay_best1 + stay_extra1;
                else
                    parent1 = ZBM_DP_FROM_MIN;

                long c0 = best0 + 8L * lit0;
                long c1 = best1 + 8L * lit1;
                cur[k] = c0;
                cur[k + 1] = c1;
                parents[k] = (uint8_t)parent0;
                parents[k + 1] = (uint8_t)parent1;

                if(c0 < next_gmin) { next_gmin = c0; next_gidx = k; }
                if(c1 < next_gmin) { next_gmin = c1; next_gidx = k + 1; }
            }

            if(k < np) {
                uint16_t p = cands[k];
                int parent = ZBM_DP_FROM_MIN;
                long stay_best = ZBM_DP_INF;
                uint64_t w = zbm_load_u64(curr - p);
                uint8_t bm = zbm_diff_bitmap(needle ^ w);
                int lit = zbm_popcount8(bm);
                int move_pbc = (p <= 0xff) ? 1 : 2;
                int stay_extra = is_top[zbm_bmprot_of(bm, 0)] ? 0 : 8;
                int move_extra = is_top[zbm_bmprot_of(bm, move_pbc)] ? 0 : 8;
                long best = gmin + 8L * move_pbc + move_extra;

                if(stride <= 8) {
                    uint16x8_t eq = vceqq_u16(pc0, vdupq_n_u16(p));
                    uint16_t m = vmaxvq_u16(vandq_u16(eq, act0));
                    if(m) { stay_best = prev[m - 1]; parent = m - 1; }
                } else if(stride <= 16) {
                    uint16x8_t pv = vdupq_n_u16(p);
                    uint16x8_t m0 = vandq_u16(vceqq_u16(pc0, pv), act0);
                    uint16x8_t m1 = vandq_u16(vceqq_u16(pc1, pv), act1);
                    uint16_t m = vmaxvq_u16(vorrq_u16(m0, m1));
                    if(m) { stay_best = prev[m - 1]; parent = m - 1; }
                } else if(stride <= 32) {
                    uint16x8_t pv = vdupq_n_u16(p);
                    uint16x8_t m0 = vandq_u16(vceqq_u16(pc0, pv), act0);
                    uint16x8_t m1 = vandq_u16(vceqq_u16(pc1, pv), act1);
                    uint16x8_t m2 = vandq_u16(vceqq_u16(pc2, pv), act2);
                    uint16x8_t m3 = vandq_u16(vceqq_u16(pc3, pv), act3);
                    uint16_t m = vmaxvq_u16(vorrq_u16(vorrq_u16(m0, m1), vorrq_u16(m2, m3)));
                    if(m) { stay_best = prev[m - 1]; parent = m - 1; }
                } else {
                    for(j = 0; j < npp; ++j) {
                        if(prev_cands[j] == p) {
                            if(prev[j] < stay_best) { stay_best = prev[j]; parent = j; }
                            break;
                        }
                    }
                }

                if(stay_best < ZBM_DP_INF && stay_best + stay_extra < best)
                    best = stay_best + stay_extra;
                else
                    parent = ZBM_DP_FROM_MIN;

                long c = best + 8L * lit;
                cur[k] = c;
                parents[k] = (uint8_t)parent;
                if(c < next_gmin) { next_gmin = c; next_gidx = k; }
            }
        } else {
            for(k = 0; k < np; ++k) {
                uint16_t p = cands[k];
                int parent = ZBM_DP_FROM_MIN;
                uint8_t bm = 0;
                int lit = zbm_dp_literals(state, chunk_src, i, p, &bytecnt, &bm);
                if(lit < 0) {
                    cur[k] = ZBM_DP_INF;
                    parents[k] = ZBM_DP_FROM_MIN;
                    continue;
                }
                int move_pbc = (p <= 0xff) ? 1 : 2;
                int stay_extra = is_top[zbm_bmprot_of(bm, 0)] ? 0 : 8;
                int move_extra = is_top[zbm_bmprot_of(bm, move_pbc)] ? 0 : 8;
                long best = gmin + 8L * move_pbc + move_extra;
                long stay_best = ZBM_DP_INF;

                if(stride <= 8) {
                    uint16x8_t eq = vceqq_u16(pc0, vdupq_n_u16(p));
                    uint16_t m = vmaxvq_u16(vandq_u16(eq, act0));
                    if(m) { stay_best = prev[m - 1]; parent = m - 1; }
                } else if(stride <= 16) {
                    uint16x8_t pv = vdupq_n_u16(p);
                    uint16x8_t m0 = vandq_u16(vceqq_u16(pc0, pv), act0);
                    uint16x8_t m1 = vandq_u16(vceqq_u16(pc1, pv), act1);
                    uint16_t m = vmaxvq_u16(vorrq_u16(m0, m1));
                    if(m) { stay_best = prev[m - 1]; parent = m - 1; }
                } else if(stride <= 32) {
                    uint16x8_t pv = vdupq_n_u16(p);
                    uint16x8_t m0 = vandq_u16(vceqq_u16(pc0, pv), act0);
                    uint16x8_t m1 = vandq_u16(vceqq_u16(pc1, pv), act1);
                    uint16x8_t m2 = vandq_u16(vceqq_u16(pc2, pv), act2);
                    uint16x8_t m3 = vandq_u16(vceqq_u16(pc3, pv), act3);
                    uint16_t m = vmaxvq_u16(vorrq_u16(vorrq_u16(m0, m1), vorrq_u16(m2, m3)));
                    if(m) { stay_best = prev[m - 1]; parent = m - 1; }
                } else {
                    for(j = 0; j < npp; ++j) {
                        if(prev_cands[j] == p) {
                            if(prev[j] < stay_best) { stay_best = prev[j]; parent = j; }
                            break;
                        }
                    }
                }

                if(stay_best < ZBM_DP_INF && stay_best + stay_extra < best)
                    best = stay_best + stay_extra;
                else
                    parent = ZBM_DP_FROM_MIN;

                long c = best + 8L * lit;
                cur[k] = c;
                parents[k] = (uint8_t)parent;
                if(c < next_gmin) { next_gmin = c; next_gidx = k; }
            }
        }

        state->dp_argmin_row[i] = (uint8_t)gidx;
        gmin = next_gmin;
        gidx = next_gidx;

        {
            long *tmp = prev;
            prev = cur;
            cur = tmp;
        }
    }

    /* Backtrack from the best cell of the final row. */
    {
        int bk = (gmin < ZBM_DP_INF) ? gidx : -1;
        if(bk < 0)
            return zbm_decide_chunk_row(state, chunk_src);

        for(i = nblocks - 1; i > first; --i) {
            int parent = ZBM_DP_PARENT(state, i)[bk];

            state->dp_chosen[i] = ZBM_DP_CAND(state, i)[bk];
            bk = (parent == ZBM_DP_FROM_MIN) ? state->dp_argmin_row[i] : parent;
        }
        state->dp_chosen[first] = ZBM_DP_CAND(state, first)[bk];
    }

    /* Pass 3: re-commit the chosen sequence through the ordinary emit path. */
    state->src = chunk_src;
    state->read = 0;
    state->period = 8;
    state->bmp_cnt = 0;
    memset(state->usecnts, 0, sizeof(state->usecnts));

    if(first == 1) {
        struct zbm_bmap *init = &state->bitmaps[0];

        init->bitmap = 0xff;
        init->period_bytecnt = 0;
        state->periods[0] = 8;
        state->bmp_cnt = 1;
        state->usecnts[zbm_bmprot(init)] = 1;
        data_bytes += 8;
        state->src += 8;
        state->read += 8;
    }

    for(i = first; i < nblocks; ++i) {
        uint16_t p = state->dp_chosen[i];
        uint8_t bitmap;

        bytecnt = (int)MIN(8u, state->decmp_len - state->read);
        bitmap = zbm_calculate_bitmap(state->src - p, state->src, (uint8_t)bytecnt, p);
        zbm_append_new_bitmap(state, bitmap, p);
        data_bytes += zbm_popcount8(bitmap);
        state->src += bytecnt;
        state->read += bytecnt;
    }

    return data_bytes;
}

struct zbm_beam_node {
    long cost;
    uint16_t period, key, run;
    uint8_t parent;
};
static int zbm_beam_cmp(const struct zbm_beam_node *x, const struct zbm_beam_node *y)
{
    if(x->cost != y->cost) return x->cost < y->cost ? -1 : 1;
    if(x->run != y->run) return x->run > y->run ? -1 : 1;
    return (int)x->period - y->period;
}

/* Adds @p to the block's candidate set; returns 0 if it was already there. */
static inline int zbm_beam_first_seen(struct zbm_beam_seen *tab, uint16_t p, uint16_t stamp)
{
    const unsigned mask = (1u << ZBM_BEAM_SEEN_BITS) - 1;
    unsigned h = (uint32_t)(p * 2654435761u) >> (32 - ZBM_BEAM_SEEN_BITS);

    while(tab[h].stamp == stamp) {
        if(tab[h].period == p)
            return 0;
        h = (h + 1) & mask;
    }
    tab[h].period = p;
    tab[h].stamp = stamp;
    return 1;
}

/* Hoare partition of @a[lo..hi] around its median of three: afterwards
 * a[lo..*jp] <= pivot <= a[*ip..hi]. */
static inline void zbm_partition_u64(uint64_t *a, int lo, int hi, int *ip, int *jp)
{
    const uint64_t x = a[lo], y = a[(lo + hi) >> 1], z = a[hi];
    const uint64_t piv = x < y ? (y < z ? y : (x < z ? z : x)) : (x < z ? x : (y < z ? z : y));
    int i = lo, j = hi;

    while(i <= j) {
        while(a[i] < piv) ++i;
        while(a[j] > piv) --j;
        if(i <= j) {
            const uint64_t t = a[i];
            a[i++] = a[j];
            a[j--] = t;
        }
    }
    *ip = i;
    *jp = j;
}

/* Moves the @k least keys of @a[0..n) to its front, in no particular order. */
static void zbm_select_u64(uint64_t *a, int n, int k)
{
    int lo = 0, hi = n - 1, i, j;

    while(lo < hi) {
        zbm_partition_u64(a, lo, hi, &i, &j);
        if(k - 1 <= j)
            hi = j;
        else if(k - 1 >= i)
            lo = i;
        else
            break;
    }
}

/* Sorts @a[0..n) ascending: quicksort down to runs of 16, then one
 * insertion pass over the whole. */
static void zbm_sort_u64(uint64_t *a, int n)
{
    int stack[64], sp = 0, lo = 0, hi = n - 1, i, j;

    for(;;) {
        while(hi - lo > 16) {
            zbm_partition_u64(a, lo, hi, &i, &j);
            /* The larger side waits on the stack; the smaller is next. */
            if(j - lo > hi - i) {
                stack[sp++] = lo;
                stack[sp++] = j;
                lo = i;
            } else {
                stack[sp++] = i;
                stack[sp++] = hi;
                hi = j;
            }
        }
        if(!sp)
            break;
        hi = stack[--sp];
        lo = stack[--sp];
    }
    for(i = 1; i < n; ++i) {
        const uint64_t v = a[i];

        for(j = i; j > 0 && a[j - 1] > v; --j)
            a[j] = a[j - 1];
        a[j] = v;
    }
}

/*
 * The @width best of @nt trials, best first, into @out; returns how many.
 * Best is the least cost, then the longer run, then the smaller period
 * (zbm_beam_cmp), then the earlier trial.
 *
 * A narrow beam turns most trials away with one compare against its worst
 * survivor, so it inserts in place. A wide one packs each trial into a key,
 * selects and sorts the keys: cost (under 2^24, at most ~100 per block), run
 * inverted (at most one per block, under 2^13), period, then the index.
 */
static int zbm_beam_select(const struct zbm_beam_node *trials, int nt, int width,
                           struct zbm_beam_node *out)
{
    uint64_t keys[2 * (255 + CRUSHLZBITMAP_MAX_BEAM_WIDTH)];
    int n, j, k;

    if(width <= ZBM_BEAM_INSERT_MAX_WIDTH) {
        n = 0;
        for(k = 0; k < nt; ++k) {
            j = n;
            if(j == width) {
                if(zbm_beam_cmp(&trials[k], &out[j - 1]) >= 0)
                    continue;
                --j;
            } else {
                ++n;
            }
            while(j > 0 && zbm_beam_cmp(&trials[k], &out[j - 1]) < 0) {
                out[j] = out[j - 1];
                --j;
            }
            out[j] = trials[k];
        }
        return n;
    }

    n = nt < width ? nt : width;
    for(k = 0; k < nt; ++k) {
        assert(trials[k].cost >= 0 && trials[k].cost < (1L << 24) && trials[k].run < 8192);
        keys[k] = (uint64_t)trials[k].cost << 39 | (uint64_t)(8191u - trials[k].run) << 26 |
                  (uint64_t)trials[k].period << 10 | (unsigned)k;
    }
    if(nt > width)
        zbm_select_u64(keys, nt, width);
    zbm_sort_u64(keys, n);
    for(j = 0; j < n; ++j)
        out[j] = trials[keys[j] & 1023];
    return n;
}

/* Carry competitive periods across blocks. The row parse remains the incumbent;
 * approximate bitmap pricing is checked against the actual metadata writer. */
static long zbm_decide_chunk_beam(struct zbm_compress_state *state, const uint8_t *chunk_src)
{
    const int width = state->params.p.beam.beam_width;
    struct zbm_beam_node prev[CRUSHLZBITMAP_MAX_BEAM_WIDTH], next[CRUSHLZBITMAP_MAX_BEAM_WIDTH];
    struct zbm_beam_node trials[2 * (255 + CRUSHLZBITMAP_MAX_BEAM_WIDTH)];
    struct zbm_beam_trace *trace = state->beam_trace;
    struct zbm_beam_seen *seen = state->beam_seen;
    memset(seen, 0, sizeof(*seen) << ZBM_BEAM_SEEN_BITS);
    const int first = state->preread == 0 ? 1 : 0;
    const int nb = state->dp_nblocks;
    int np = 1, i, j, k;
    long literals = 0;
    prev[0] = (struct zbm_beam_node){0, 8, first ? state->bmap_num_tbl[255] : 1023, first ? 1 : 0, 0};
    for(i = first; i < nb; ++i) {
        uint16_t candidates[255 + CRUSHLZBITMAP_MAX_BEAM_WIDTH];
        int nc = 0, nt = 0;
        const uint16_t stamp = (uint16_t)(i + 1);
        const size_t pos = state->preread + (size_t)i * 8;
        const int nbytes = (int)MIN(8u, state->decmp_len - (uint32_t)i * 8);
        const uint8_t *src = chunk_src + (size_t)i * 8;
        for(j = 0; j < state->dp_ncand[i]; ++j) {
            uint16_t p = ZBM_DP_CAND(state, i)[j];
            if(p >= 8 && p <= pos && zbm_beam_first_seen(seen, p, stamp))
                candidates[nc++] = p;
        }
        for(j = 0; j < np; ++j) {
            uint16_t p = prev[j].period;
            if(p >= 8 && p <= pos && zbm_beam_first_seen(seen, p, stamp))
                candidates[nc++] = p;
        }
        /* A change needs the global minimum, or a same-number run bonus.
         * Keep the cheapest two different periods in each group so the
         * current candidate can exclude its own period in constant time. */
        int base[2] = {0, -1};
        int bonus[16][2][2];
        uint16_t period_keys[CRUSHLZBITMAP_MAX_BEAM_WIDTH * 4];
        memset(period_keys, 0, (size_t)width * 4 * sizeof(*period_keys));
        int16_t period_heads[CRUSHLZBITMAP_MAX_BEAM_WIDTH * 4], links[CRUSHLZBITMAP_MAX_BEAM_WIDTH];
        const unsigned hash_mask = (unsigned)width * 4 - 1;
        memset(bonus, 0xff, sizeof(bonus));
        for(j = 0; j < np; ++j) {
            unsigned h = ((unsigned)prev[j].period * 40503u >> 8) & hash_mask;
            while(period_keys[h] && period_keys[h] != prev[j].period) h = (h + 1) & hash_mask;
            if(!period_keys[h]) { period_keys[h] = prev[j].period; period_heads[h] = -1; }
            links[j] = period_heads[h]; period_heads[h] = (int16_t)j;
            if(base[1] < 0 && prev[j].period != prev[0].period) base[1] = j;
            if(prev[j].key < 16) {
                const int delta = zbm_nibble_extend_delta(prev[j].run);
                int *g = bonus[prev[j].key][delta];
                if(g[0] < 0) g[0] = j;
                else if(g[1] < 0 && prev[j].period != prev[g[0]].period) g[1] = j;
            }
        }
        for(k = 0; k < nc; ++k) {
            const uint16_t p = candidates[k];
            const uint8_t bm = zbm_calculate_bitmap(src - p, src, (uint8_t)nbytes, p);
            const int lit = zbm_popcount8(bm);
            struct zbm_beam_node best[2] = {{.cost=ZBM_DP_INF, .run=0, .parent=255},
                                           {.cost=ZBM_DP_INF, .run=0, .parent=255}};
            /* Stay: at most two states per period were generated. */
            unsigned h = ((unsigned)p * 40503u >> 8) & hash_mask;
            while(period_keys[h] && period_keys[h] != p) h = (h + 1) & hash_mask;
            if(period_keys[h]) for(j = period_heads[h]; j >= 0; j = links[j]) {
                const uint16_t key = state->bmap_num_tbl[bm];
                const int same = key == prev[j].key;
                const uint16_t run = (uint16_t)(same ? prev[j].run + 1 : 1);
                const int nibs = same ? zbm_nibble_extend_delta(prev[j].run) : 1;
                const long cost = prev[j].cost + 8L * lit +
                    (state->is_top_estimate[zbm_bmprot_of(bm, 0)] ? 0 : 8) + 4L * nibs;
                if(cost < best[0].cost || (cost == best[0].cost &&
                   (run > best[0].run || (run == best[0].run && j < best[0].parent))))
                    best[0] = (struct zbm_beam_node){cost, p, key, run, (uint8_t)j};
            }
            /* Change: one global minimum and up to two run minima. */
            const int pbc = 1 + (p > 255);
            const uint16_t key = state->bmap_num_tbl[bm | pbc << 8];
            int options[3];
            options[0] = prev[base[0]].period != p ? base[0] : base[1];
            for(int delta = 0; delta < 2; ++delta) {
                const int *g = bonus[key][delta];
                options[delta + 1] = g[0] >= 0 && prev[g[0]].period != p ? g[0] : g[1];
            }
            for(int oi = 0; oi < 3; ++oi) {
                j = options[oi];
                if(j < 0) continue;
                const int same = key == prev[j].key;
                const uint16_t run = (uint16_t)(same ? prev[j].run + 1 : 1);
                const int nibs = same ? zbm_nibble_extend_delta(prev[j].run) : 1;
                const long cost = prev[j].cost + 8L * lit + 8L * pbc +
                    (state->is_top_estimate[zbm_bmprot_of(bm, pbc)] ? 0 : 8) + 4L * nibs;
                if(cost < best[1].cost || (cost == best[1].cost &&
                   (run > best[1].run || (run == best[1].run && j < best[1].parent))))
                    best[1] = (struct zbm_beam_node){cost, p, key, run, (uint8_t)j};
            }
            for(j = 0; j < 2; ++j) if(best[j].cost < ZBM_DP_INF) trials[nt++] = best[j];
        }
        if(!nt) return -1;
        np = zbm_beam_select(trials, nt, width, next);
        for(j = 0; j < np; ++j) {
            trace[(size_t)i * width + j] = (struct zbm_beam_trace){next[j].period, next[j].parent};
        }
        memcpy(prev, next, (size_t)np * sizeof(prev[0]));
    }
    j = 0;
    for(i = nb - 1; i >= first; --i) {
        const struct zbm_beam_trace tr = trace[(size_t)i * width + j];
        state->dp_chosen[i] = tr.period;
        j = tr.parent;
    }
    state->src = chunk_src; state->read = 0; state->period = 8; state->bmp_cnt = 0;
    memset(state->usecnts, 0, sizeof(state->usecnts));
    if(first) {
        zbm_append_new_bitmap(state, 255, 8);
        state->src += 8; state->read += 8; literals = 8;
    }
    for(i = first; i < nb; ++i) {
        uint16_t p = state->dp_chosen[i];
        int n = (int)MIN(8u, state->decmp_len - state->read);
        uint8_t bm = zbm_calculate_bitmap(state->src - p, state->src, (uint8_t)n, p);
        zbm_append_new_bitmap(state, bm, p);
        state->src += n; state->read += (uint32_t)n; literals += zbm_popcount8(bm);
    }
    return literals;
}

static int zbm_build_compressed_chunk_dp(struct zbm_compress_state *state)
{
    struct zbm_cmp_chunk_hdr *hdr = NULL;
    const uint8_t *chunk_src;
    int iter;

    if(sizeof(*hdr) > (size_t)(state->dest_end - state->dest))
        return ZBM_CANT_COMPRESS;
    state->dest -= sizeof(hdr->hdr);
    state->written -= sizeof(hdr->hdr);
    hdr = (struct zbm_cmp_chunk_hdr *)state->dest;
    state->dest += sizeof(*hdr);
    state->written += sizeof(*hdr);

    chunk_src = state->src;
    state->best_size = 0;
    state->dp_lists_ready = 0;
    memset(state->is_top_estimate, 0, sizeof(state->is_top_estimate));

    for(iter = 0; iter < state->params.p.dp.iterations; ++iter) {
        struct zbm_bitmap_snapshot candidate;
        long data_bytes;
        size_t total;

        data_bytes = zbm_decide_chunk_dp(state, chunk_src);
        if(data_bytes < 0) {
            if(state->best_size == 0) return ZBM_CANT_COMPRESS;
            break;
        }
        zbm_snapshot_save(state, &candidate);
        total = zbm_score_trial(state, data_bytes);
        if(total != 0 && (state->best_size == 0 || total < state->best_size)) {
            state->best_size = total;
            state->best = candidate;
        }
    }

    if(state->best_size == 0)
        return ZBM_CANT_COMPRESS;

    zbm_snapshot_restore(state, &state->best);
    {
        /* No total is tracked alongside the snapshots, so zbm_emit_literals()
         * recomputes it. */
        int err = zbm_emit_literals(state, chunk_src, -1);

        if(err)
            return err;
    }
    return zbm_build_metadata(state, hdr);
}

static int zbm_build_compressed_chunk_beam(struct zbm_compress_state *state)
{
    struct zbm_cmp_chunk_hdr *hdr;
    struct zbm_bitmap_snapshot candidate;
    const uint8_t *chunk_src = state->src;
    long data_bytes;
    size_t total;
    int err;

    if(sizeof(*hdr) > (size_t)(state->dest_end - state->dest))
        return ZBM_CANT_COMPRESS;
    state->dest -= sizeof(hdr->hdr);
    state->written -= sizeof(hdr->hdr);
    hdr = (struct zbm_cmp_chunk_hdr *)state->dest;
    state->dest += sizeof(*hdr);
    state->written += sizeof(*hdr);

    state->best_size = 0;
    memset(state->is_top_estimate, 0, sizeof(state->is_top_estimate));
    memset(state->dp_ncand, 0, sizeof(state->dp_ncand));
    state->dp_recording = 1;
    data_bytes = zbm_decide_chunk_row(state, chunk_src);
    state->dp_recording = 0;
    state->dp_nblocks = state->bmp_cnt;
    if(data_bytes < 0) return ZBM_CANT_COMPRESS;

    /* Scoring updates the top table and consumes use counts. Snapshot first. */
    zbm_snapshot_save(state, &state->best);
    state->best_size = zbm_score_trial(state, data_bytes);
    if(!state->best_size) return ZBM_CANT_COMPRESS;
    /* The beam all but never rescues a chunk the row parse cannot shrink
     * below its stored form, and would be most of such a chunk's cost. */
    if(state->dp_nblocks > 1 &&
       state->best_size < state->decmp_len + sizeof(struct zbm_chunk_hdr)) {
        data_bytes = zbm_decide_chunk_beam(state, chunk_src);
        if(data_bytes >= 0) {
            zbm_snapshot_save(state, &candidate);
            total = zbm_score_trial(state, data_bytes);
            if(total && total < state->best_size) {
                state->best_size = total;
                state->best = candidate;
            }
        }
    }
    zbm_snapshot_restore(state, &state->best);
    err = zbm_emit_literals(state, chunk_src, -1);
    if(err) return err;
    err = zbm_build_metadata(state, hdr);
    /* The trial scored this same restored state with the same writers. */
    if(!err && state->written != state->best_size)
        return ZBM_INVAL;
    return err;
}

static int zbm_compress_single_chunk(struct zbm_compress_state *state, int (*build_chunk)(struct zbm_compress_state *))
ZBM_REQUIRES(__CPROVER_rw_ok(state, sizeof(*state)))
ZBM_REQUIRES(state->src_left <= CRUSHLZBITMAP_MAX_SRC_SIZE)
ZBM_REQUIRES(state->dest_left <= ((size_t)1 << 48))
ZBM_REQUIRES(__CPROVER_r_ok(state->src, MIN(state->src_left, (size_t)CRUSHLZBITMAP_CHUNK_SIZE)))
ZBM_REQUIRES(__CPROVER_w_ok(state->dest, state->dest_left))
ZBM_REQUIRES(!__CPROVER_same_object(state, state->src) &&
             !__CPROVER_same_object(state, state->dest) &&
             !__CPROVER_same_object(state->src, state->dest))
ZBM_ASSIGNS(state->read, state->written, state->decmp_len,
            state->src_end, state->dest_end, state->dest, state->src;
            state->dest_left > 0: __CPROVER_object_upto(state->dest, state->dest_left))
ZBM_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == ZBM_RANGE || __CPROVER_return_value < 0)
ZBM_ENSURES(__CPROVER_return_value == 0 ==>
            (state->decmp_len == MIN(ZBM_OLD(state->src_left), (size_t)CRUSHLZBITMAP_CHUNK_SIZE) &&
             state->read == state->decmp_len &&
             state->written >= sizeof(struct zbm_chunk_hdr) &&
             state->written <= state->decmp_len + sizeof(struct zbm_chunk_hdr) &&
             state->written <= ZBM_OLD(state->dest_left) &&
             state->dest == ZBM_OLD(state->dest) + state->written &&
             state->src == ZBM_OLD(state->src) + state->read))
ZBM_ENSURES(__CPROVER_return_value == ZBM_RANGE ==>
            (MIN(ZBM_OLD(state->src_left), (size_t)CRUSHLZBITMAP_CHUNK_SIZE) + sizeof(struct zbm_chunk_hdr) > ZBM_OLD(state->dest_left)))
{
    struct zbm_chunk_hdr *decmp_hdr = NULL;
    unsigned int max_chunk_sz;
    int err;

    state->read = 0;
    state->written = 0;

    state->decmp_len = MIN(state->src_left, CRUSHLZBITMAP_CHUNK_SIZE);
    state->src_end = state->src + state->decmp_len;

    /* If a chunk gets bigger than this, we'll just store it uncompressed */
    max_chunk_sz = state->decmp_len + sizeof(*decmp_hdr);
    if(max_chunk_sz > state->dest_left)
        return ZBM_RANGE;
    state->dest_end = state->dest + max_chunk_sz;
    decmp_hdr = (struct zbm_chunk_hdr *)state->dest;

    state->dest += sizeof(*decmp_hdr);
    state->written += sizeof(*decmp_hdr);

    err = build_chunk(state);
    if(!err && state->written >= max_chunk_sz)
        /*
         * A compressed chunk that only ties the uncompressed size would
         * collide with zbm_chunk_is_uncompressed()'s test
         * (len == decmp_len + sizeof(header)) and be misread as raw bytes, so
         * a tie falls back to a real passthrough chunk.
         */
        err = ZBM_CANT_COMPRESS;
    if(err == ZBM_CANT_COMPRESS)
        err = zbm_build_uncompressed_chunk(state);
    if(err)
        return err;

    decmp_hdr->len = zbm_u32_to_u24(state->written);
    decmp_hdr->decmp_len = zbm_u32_to_u24(state->decmp_len);
    return 0;
}

/* An output size that fits any input of src_size bytes: the stream magic,
 * one worst-case body chunk per CHUNK_SIZE piece of input, and the
 * zero-length terminating chunk. A bare `src_size / CHUNK_SIZE + 1` would
 * count one phantom extra body chunk whenever src_size is an exact
 * multiple of CHUNK_SIZE (the terminator's own cost is already the
 * separate LAST_CHUNK_SIZE term below), so this is a real ceiling
 * division instead. See zbm_bound_exactness_test.c. */
size_t crushlzbitmap_encode_bound(size_t src_size)
{
    size_t chunks = (src_size + CRUSHLZBITMAP_CHUNK_SIZE - 1) / CRUSHLZBITMAP_CHUNK_SIZE;
    return 4 + chunks * CRUSHLZBITMAP_MAX_CHUNK_SIZE + CRUSHLZBITMAP_LAST_CHUNK_SIZE;
}

/* Validates every field of @params against the documented range; returns 0
 * or ZBM_INVAL. Out-of-range values are rejected rather than clamped. */
static int zbm_validate_params(const crushlzbitmap_params *params)
{
    if(!params)
        return ZBM_INVAL;

    switch(params->strategy) {
    case CRUSHLZBITMAP_STRATEGY_ROW: {
        const crushlzbitmap_row_params *rp = &params->p.row;

        if(rp->hash_bits < CRUSHLZBITMAP_MIN_ROW_HASH_BITS || rp->hash_bits > CRUSHLZBITMAP_MAX_ROW_HASH_BITS)
            return ZBM_INVAL;
        if(rp->depth != 1 && rp->depth != 2 && rp->depth != 4 && rp->depth != 8 && rp->depth != 16)
            return ZBM_INVAL;
        /* The table is 2^18 entries: buckets times ways must fit. */
        if(rp->hash_bits + (rp->depth == 16 ? 4 : rp->depth == 8 ? 3 : rp->depth == 4 ? 2 : rp->depth == 2 ? 1 : 0) > 18)
            return ZBM_INVAL;
        if(rp->dist_cache_size < 0 || rp->dist_cache_size > 8)
            return ZBM_INVAL;
        if(rp->accept_diff < 0 || rp->accept_diff > 8)
            return ZBM_INVAL;
        if(rp->scan_window < 0 || rp->scan_window > CRUSHLZBITMAP_MAX_ROW_SCAN || rp->scan_window % 16)
            return ZBM_INVAL;
        if(rp->lookahead & ~1)
            return ZBM_INVAL;
        /* The deep options belong to the lookahead flavour; keeping them out
         * of the plain one keeps the plain block loop small. */
        if(!rp->lookahead && (rp->scan_window > 32 || rp->dist_cache_size > 4))
            return ZBM_INVAL;
        return 0;
    }
    case CRUSHLZBITMAP_STRATEGY_BEAM: {
        crushlzbitmap_params sub;
        const crushlzbitmap_beam_params *bp = &params->p.beam;
        if(bp->max_candidates < 1 || bp->max_candidates > CRUSHLZBITMAP_MAX_DP_CANDS ||
           bp->beam_width < 1 || bp->beam_width > CRUSHLZBITMAP_MAX_BEAM_WIDTH ||
           (bp->beam_width & (bp->beam_width - 1)) || bp->row.lookahead != 1)
            return ZBM_INVAL;
        sub.strategy = CRUSHLZBITMAP_STRATEGY_ROW;
        sub.p.row = bp->row;
        return zbm_validate_params(&sub);
    }
    case CRUSHLZBITMAP_STRATEGY_FAST: {
        const crushlzbitmap_fast_params *fp = &params->p.fast;

        if(fp->hash_bits < CRUSHLZBITMAP_MIN_FAST_HASH_BITS || fp->hash_bits > CRUSHLZBITMAP_MAX_FAST_HASH_BITS)
            return ZBM_INVAL;
        if(fp->windows != 1 && fp->windows != 2 && fp->windows != 4 && fp->windows != 8)
            return ZBM_INVAL;
        if(fp->dist_cache_size < 0 || fp->dist_cache_size > CRUSHLZBITMAP_MAX_FAST_DIST_CACHE)
            return ZBM_INVAL;
        /* At 8 nothing would ever be searched. */
        if(fp->accept_diff < 0 || fp->accept_diff > CRUSHLZBITMAP_MAX_FAST_ACCEPT_DIFF)
            return ZBM_INVAL;
        if(fp->skip_shift < 0 || fp->skip_shift > CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT)
            return ZBM_INVAL;
        return 0;
    }
    case CRUSHLZBITMAP_STRATEGY_DP: {
        crushlzbitmap_params sub;

        if(params->p.dp.max_candidates < 1 || params->p.dp.max_candidates > CRUSHLZBITMAP_MAX_DP_CANDS)
            return ZBM_INVAL;
        if(params->p.dp.iterations < 1 || params->p.dp.iterations > CRUSHLZBITMAP_MAX_ITERATIONS)
            return ZBM_INVAL;
        /* The lists are ranked by the lookahead lanes' cost. */
        if(params->p.dp.row.lookahead != 1)
            return ZBM_INVAL;
        sub.strategy = CRUSHLZBITMAP_STRATEGY_ROW;
        sub.p.row = params->p.dp.row;
        return zbm_validate_params(&sub);
    }
    default:
        return ZBM_INVAL;
    }
}

int crushlzbitmap_default_params(int strategy, crushlzbitmap_params *params);

/*
 * Levels -5 to -3 are the fast tier, which searches only where the period
 * in force fails and trades windows and acceptance for speed.
 */
static const crushlzbitmap_fast_params zbm_fast_levels[] = {
    /*        hbits windows dcache  acc  skip */
    /* -5 */ {  16,     2,     2,    4,    3 },
    /* -4 */ {  16,     4,     2,    2,    4 },
    /* -3 */ {  16,     8,     2,    1,    4 },
};
#define ZBM_FAST_LEVELS ((int)(sizeof(zbm_fast_levels) / sizeof(zbm_fast_levels[0])))

struct zbm_level_row {
    int strategy;   /* CRUSHLZBITMAP_STRATEGY_* */
    int hash_bits, depth, lookahead, dist_cache_size;
    int scan_window, accept_diff;
    int max_candidates, iterations; /* DP passes, or BEAM width */
};

#define B CRUSHLZBITMAP_STRATEGY_BEAM
#define D CRUSHLZBITMAP_STRATEGY_DP
#define R CRUSHLZBITMAP_STRATEGY_ROW

/*
 * Levels -2 to 6 are the row tier, plain up to 0 and with the lookahead
 * lanes from 1; 7 chooses the period sequence by shortest path. Levels 8–12 use a
 * row-seeded beam with period carry and metadata run pricing. The lookahead levels search
 * every block the period in force does not fit exactly: with persistence in
 * the lane cost, a one-literal continuation left alone is the case that
 * costs most. Per-level figures live in the crate README.
 */
static const struct zbm_level_row zbm_levels[] = {
    /*        strat hbits depth  la  dcache   scan  acc  cands passes/width */
    /* -2 */ {  R,    14,    1,   0,     4,      0,   2,     0,   0 },
    /* -1 */ {  R,    16,    2,   0,     4,      0,   1,     0,   0 },
    /*  0 */ {  R,    16,    2,   0,     4,     16,   1,     0,   0 },
    /*  1 */ {  R,    16,    1,   1,     4,     48,   0,     0,   0 },
    /*  2 */ {  R,    15,    4,   1,     4,      0,   0,     0,   0 },
    /*  3 */ {  R,    16,    4,   1,     4,     64,   0,     0,   0 },
    /*  4 */ {  R,    16,    4,   1,     8,    256,   0,     0,   0 },
    /*  5 */ {  R,    15,    8,   1,     4,    256,   0,     0,   0 },
    /*  6 */ {  R,    14,   16,   1,     8,    256,   0,     0,   0 },
    /*  7 */ {  D,    15,    8,   1,     8,    256,   0,     8,   2 },
    /*  8 */ {  B,    15,    8,   1,     4,    256,   0,     4,   4 },
    /*  9 */ {  B,    15,    8,   1,     4,    256,   0,     4,   8 },
    /* 10 */ {  B,    14,   16,   1,     8,    256,   0,     8,  16 },
    /* 11 */ {  B,    14,   16,   1,     8,    256,   0,    16,  32 },
    /* 12 */ {  B,    14,   16,   1,     8,    256,   0,    32,  64 },
};

#undef B
#undef R
#undef D

/* The settings a level stands for. Returns the level actually used: levels
 * outside the range are clamped, not rejected. Returns
 * CRUSHLZBITMAP_LEVEL_INVALID, which is never a level, only for a NULL out. */
int crushlzbitmap_params_for_level(int level, crushlzbitmap_params *params)
{
    const struct zbm_level_row *row;
    crushlzbitmap_row_params *rp;

    if(!params)
        return CRUSHLZBITMAP_LEVEL_INVALID;

    /* Clamped, not rejected: a caller asking for "as fast as possible" with
     * INT_MIN should get the fastest level, not an error. The clamped level
     * is what comes back, so the caller can see what it actually got. */
    if(level < CRUSHLZBITMAP_LEVEL_MIN)
        level = CRUSHLZBITMAP_LEVEL_MIN;
    if(level > CRUSHLZBITMAP_LEVEL_MAX)
        level = CRUSHLZBITMAP_LEVEL_MAX;
    if(level - CRUSHLZBITMAP_LEVEL_MIN < ZBM_FAST_LEVELS) {
        crushlzbitmap_default_params(CRUSHLZBITMAP_STRATEGY_FAST, params);
        params->p.fast = zbm_fast_levels[level - CRUSHLZBITMAP_LEVEL_MIN];
        return level;
    }
    row = &zbm_levels[level - CRUSHLZBITMAP_LEVEL_MIN - ZBM_FAST_LEVELS];

    crushlzbitmap_default_params(row->strategy, params);
    rp = row->strategy == CRUSHLZBITMAP_STRATEGY_DP ? &params->p.dp.row :
         row->strategy == CRUSHLZBITMAP_STRATEGY_BEAM ? &params->p.beam.row : &params->p.row;
    rp->hash_bits = row->hash_bits;
    rp->depth = row->depth;
    rp->lookahead = row->lookahead;
    rp->dist_cache_size = row->dist_cache_size;
    rp->scan_window = row->scan_window;
    rp->accept_diff = row->accept_diff;
    if(row->strategy == CRUSHLZBITMAP_STRATEGY_DP) {
        params->p.dp.max_candidates = row->max_candidates;
        params->p.dp.iterations = row->iterations;
    } else if(row->strategy == CRUSHLZBITMAP_STRATEGY_BEAM) {
        params->p.beam.max_candidates = row->max_candidates;
        params->p.beam.beam_width = row->iterations;
    }
    return level;
}


/* The documented defaults of one strategy. Returns 0, or ZBM_INVAL for an
 * unknown strategy. */
int crushlzbitmap_default_params(int strategy, crushlzbitmap_params *params)
{
    if(!params)
        return ZBM_INVAL;

    /* Fully initialize, including the unused union arm, so the struct is safe
     * to memcmp() or hash. */
    memset(params, 0, sizeof(*params));

    switch(strategy) {
    case CRUSHLZBITMAP_STRATEGY_BEAM:
        params->strategy = strategy;
        params->p.beam.row = (crushlzbitmap_row_params){15, 8, 4, 0, 256, 1};
        params->p.beam.max_candidates = 4;
        params->p.beam.beam_width = 4;
        return 0;
    case CRUSHLZBITMAP_STRATEGY_DP:
        /* dp.row is the first member of crushlzbitmap_dp_params, so
         * it aliases p.row exactly; keep it first. */
        params->strategy = CRUSHLZBITMAP_STRATEGY_DP;
        params->p.dp.row.hash_bits = ZBM_DEFAULT_DP_HASH_BITS;
        params->p.dp.row.depth = ZBM_DEFAULT_DP_DEPTH;
        params->p.dp.row.dist_cache_size = ZBM_DEFAULT_DP_DIST_CACHE_SIZE;
        params->p.dp.row.accept_diff = 0;
        params->p.dp.row.scan_window = ZBM_DEFAULT_DP_SCAN_WINDOW;
        params->p.dp.row.lookahead = 1;
        params->p.dp.max_candidates = ZBM_DEFAULT_DP_MAX_CANDIDATES;
        params->p.dp.iterations = ZBM_DEFAULT_DP_ITERATIONS;
        return 0;
    case CRUSHLZBITMAP_STRATEGY_FAST:
        params->strategy = CRUSHLZBITMAP_STRATEGY_FAST;
        params->p.fast.hash_bits = ZBM_DEFAULT_FAST_HASH_BITS;
        params->p.fast.windows = ZBM_DEFAULT_FAST_WINDOWS;
        params->p.fast.dist_cache_size = ZBM_DEFAULT_FAST_DIST_CACHE_SIZE;
        params->p.fast.accept_diff = ZBM_DEFAULT_FAST_ACCEPT_DIFF;
        params->p.fast.skip_shift = ZBM_DEFAULT_FAST_SKIP_SHIFT;
        return 0;
    case CRUSHLZBITMAP_STRATEGY_ROW:
        params->strategy = CRUSHLZBITMAP_STRATEGY_ROW;
        params->p.row.hash_bits = ZBM_DEFAULT_ROW_HASH_BITS;
        params->p.row.depth = ZBM_DEFAULT_ROW_DEPTH;
        params->p.row.dist_cache_size = ZBM_DEFAULT_ROW_DIST_CACHE_SIZE;
        params->p.row.accept_diff = ZBM_DEFAULT_ROW_ACCEPT_DIFF;
        params->p.row.scan_window = ZBM_DEFAULT_ROW_SCAN_WINDOW;
        params->p.row.lookahead = ZBM_DEFAULT_ROW_LOOKAHEAD;
        return 0;
    default:
        return CRUSHLZBITMAP_INVALID;
    }
}


/*
 * Caller-owned encoder scratch: the state, then the DP candidate tables or beam candidate/trace/stamp
 * tables carved out behind it. A caller compressing many chunks supplies one
 * buffer sized by crushlzbitmap_scratch_size(params) and keeps it; NULL
 * allocates the same layout per call.
 *
 * dp_cand and dp_parent are written before they are read, bounded by
 * dp_ncand[], which is zeroed in zbm_decide_chunk_dp. The row epoch is reset
 * to force an active-table clear on the first index rebuild. Other fields
 * read before being written must also be initialized here, since caller
 * scratch can contain arbitrary bytes.
 */
size_t crushlzbitmap_scratch_size(const crushlzbitmap_params *params);
crushlzbitmap_capabilities crushlzbitmap_get_capabilities(void);

static struct zbm_compress_state *zbm_state_begin(void *scratch,
                                                  const crushlzbitmap_params *params)
{
    struct zbm_compress_state *state;

    if(scratch) {
        state = (struct zbm_compress_state *)scratch;
    } else {
        state = calloc(1, crushlzbitmap_scratch_size(params));
        if(!state)
            return NULL;
    }
    /* Force the first index rebuild to clear its active row table. Caller
     * scratch may contain arbitrary tags, including the next live epoch.
     * Later rebuilds within this encode can still retire entries by epoch. */
    state->row_epoch = (1u << ZBM_ROW_EPOCH_BITS) - 1u;
    state->index_live = 0;
    state->dp_recording = 0;
    state->dp_cand = NULL;
    state->dp_parent = NULL;
    state->dp_cand_stride = 0;
    state->beam_trace = NULL;
    state->beam_seen = NULL;
    state->row_tab2 = NULL;
    if(params->strategy == CRUSHLZBITMAP_STRATEGY_DP) {
        /* The second row index, then the two regions of
         * zbm_dp_tables_bytes in its order, so dp_parent ends the scratch
         * and an overrun past it leaves the buffer. sizeof the state and
         * ZBM_ROW2_BYTES are multiples of 16, so dp_cand stays aligned for
         * its uint16_t reads. */
        uint8_t *p = (uint8_t *)state + sizeof(*state);
        state->row_tab2 = (uint32_t *)p;
        p += ZBM_ROW2_BYTES;
        size_t n = (size_t)params->p.dp.max_candidates;
        state->dp_cand_stride = params->p.dp.max_candidates;
        state->dp_cand = (uint16_t *)p;
        p += sizeof(uint16_t) * ZBM_MAX_BITMAP_COUNT * n;
        state->dp_parent = p;
    }
    if(params->strategy == CRUSHLZBITMAP_STRATEGY_BEAM) {
        uint8_t *p = (uint8_t *)state + sizeof(*state);
        state->row_tab2 = (uint32_t *)p;
        p += ZBM_ROW2_BYTES;
        state->dp_cand_stride = params->p.beam.max_candidates;
        state->dp_cand = (uint16_t *)p;
        p += sizeof(uint16_t) * ZBM_MAX_BITMAP_COUNT * (size_t)state->dp_cand_stride;
        state->beam_trace = (struct zbm_beam_trace *)p;
        p += sizeof(*state->beam_trace) * ZBM_MAX_BITMAP_COUNT * (size_t)params->p.beam.beam_width;
        state->beam_seen = (struct zbm_beam_seen *)p;
    }
    return state;
}

/* The state is only ours to free when we allocated it; a caller-supplied
 * buffer outlives us by definition. The DP tables live inside whichever it
 * was, so there is nothing else to release. */
static void zbm_state_end(struct zbm_compress_state *state, void *scratch)
{
    if(!scratch)
        free(state);
}

/* The scratch buffer is cast straight to a struct zbm_compress_state, so the
 * alignment the header promises callers has to be the one the struct wants. */
typedef char zbm_scratch_align_matches[
    (CRUSHLZBITMAP_SCRATCH_ALIGN >= _Alignof(struct zbm_compress_state)) ? 1 : -1];

crushlzbitmap_capabilities crushlzbitmap_get_capabilities(void)
{
    crushlzbitmap_capabilities c;
    c.level_min                 = CRUSHLZBITMAP_LEVEL_MIN;
    c.level_max                 = CRUSHLZBITMAP_LEVEL_MAX;
    c.level_default             = CRUSHLZBITMAP_LEVEL_DEFAULT;
    c.row_hash_bits_min         = CRUSHLZBITMAP_MIN_ROW_HASH_BITS;
    c.row_hash_bits_max         = CRUSHLZBITMAP_MAX_ROW_HASH_BITS;
    c.row_depth_min             = 1;
    c.row_depth_max             = CRUSHLZBITMAP_MAX_ROW_DEPTH;
    c.row_lookahead_min         = 0;
    c.row_lookahead_max         = 1;
    c.row_dist_cache_size_min   = 0;
    c.row_dist_cache_size_max   = 8;
    c.row_scan_window_min       = 0;
    c.row_scan_window_max       = CRUSHLZBITMAP_MAX_ROW_SCAN;
    c.row_accept_diff_min       = 0;
    c.row_accept_diff_max       = 8;
    c.dp_max_candidates_min     = 1;
    c.dp_max_candidates_max     = CRUSHLZBITMAP_MAX_DP_CANDS;
    c.dp_iterations_min         = 1;
    c.dp_iterations_max         = CRUSHLZBITMAP_MAX_ITERATIONS;
    c.beam_width_min            = 1;
    c.beam_width_max            = CRUSHLZBITMAP_MAX_BEAM_WIDTH;
    c.fast_hash_bits_min        = CRUSHLZBITMAP_MIN_FAST_HASH_BITS;
    c.fast_hash_bits_max        = CRUSHLZBITMAP_MAX_FAST_HASH_BITS;
    c.fast_windows_min          = 1;
    c.fast_windows_max          = CRUSHLZBITMAP_MAX_FAST_WINDOWS;
    c.fast_dist_cache_size_min  = 0;
    c.fast_dist_cache_size_max  = CRUSHLZBITMAP_MAX_FAST_DIST_CACHE;
    c.fast_accept_diff_min      = 0;
    c.fast_accept_diff_max      = CRUSHLZBITMAP_MAX_FAST_ACCEPT_DIFF;
    c.fast_skip_shift_min       = 0;
    c.fast_skip_shift_max       = CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT;
    return c;
}

size_t crushlzbitmap_scratch_size(const crushlzbitmap_params *params)
{
    if(!params)
        return 0;
    if(params->strategy == CRUSHLZBITMAP_STRATEGY_BEAM) {
        if(zbm_validate_params(params)) return 0;
        return sizeof(struct zbm_compress_state) +
            sizeof(uint16_t) * ZBM_MAX_BITMAP_COUNT * (size_t)params->p.beam.max_candidates +
            sizeof(struct zbm_beam_trace) * ZBM_MAX_BITMAP_COUNT * (size_t)params->p.beam.beam_width +
            (sizeof(struct zbm_beam_seen) << ZBM_BEAM_SEEN_BITS) + ZBM_ROW2_BYTES;
    }
    if(params->strategy != CRUSHLZBITMAP_STRATEGY_DP)
        return sizeof(struct zbm_compress_state);
    return sizeof(struct zbm_compress_state) + zbm_dp_tables_bytes(params->p.dp.max_candidates) +
           ZBM_ROW2_BYTES;
}

static int zbm_compress_generic(void *scratch, size_t scratch_size, void *dest, size_t dest_size, const void *src, size_t src_size, size_t *out_len,
                                 int (*build_chunk)(struct zbm_compress_state *),
                                 const crushlzbitmap_params *params)
{
    struct zbm_compress_state *state = NULL;
    int err = 0;


    err = zbm_validate_params(params);
    if(err)
        return err;

    /* Source positions are tracked as uint32_t; see CRUSHLZBITMAP_MAX_SRC_SIZE. */
    if(src_size > CRUSHLZBITMAP_MAX_SRC_SIZE)
        return ZBM_OVERFLOW;

    /* The state and the DP tables are carved from the params, not from the
     * buffer, so a caller who sized for a row level and passed DP params
     * would have the carve run off the end. A NULL scratch is allocated by
     * zbm_state_begin and carries no extent to check. */
    if(scratch && scratch_size < crushlzbitmap_scratch_size(params))
        return ZBM_INVAL;

    state = zbm_state_begin(scratch, params);
    if(!state)
        return ZBM_NOMEM;

    state->params = *params;
    state->src = src;
    state->src_left = src_size;
    state->dest = dest;
    state->dest_left = dest_size;
    state->preread = 0;
    state->prewritten = 0;
    /* The index uses absolute offsets into the whole buffer. */
    state->buf_base = src;
    state->buf_len = src_size;

    err = zbm_write_magic(state);
    if(err)
        goto fail;

    do
        ZBM_LOOP_ASSIGNS(err, state->src, state->dest, state->src_left, state->dest_left,
                         state->preread, state->prewritten, state->read, state->written,
                         state->decmp_len, state->src_end, state->dest_end;
                         dest != NULL && dest_size > 0: __CPROVER_object_upto(dest, dest_size))
        ZBM_LOOP_INVARIANT(state->src_left <= src_size)
        ZBM_LOOP_INVARIANT(state->preread + state->src_left == src_size)
        ZBM_LOOP_INVARIANT(state->src == (const uint8_t *)src + state->preread)
        ZBM_LOOP_INVARIANT(state->prewritten <= dest_size)
        ZBM_LOOP_INVARIANT(state->dest_left == dest_size - state->prewritten)
        ZBM_LOOP_INVARIANT(dest == NULL ? state->dest == NULL :
                           state->dest == (uint8_t *)dest + state->prewritten)
        ZBM_LOOP_DECREASES(state->src_left)
    {
        err = zbm_compress_single_chunk(state, build_chunk);
        if(err)
            goto fail;
        state->src_left -= state->read;
        state->dest_left -= state->written;
        state->preread += state->decmp_len;
        state->prewritten += state->written;
    } while(state->read != 0);

    *out_len = state->prewritten;
fail:
    zbm_state_end(state, scratch);
    return err;
}

static int zbm_compress_chunk_generic(void *scratch, size_t scratch_size, void *dest, size_t dest_size, const void *src, size_t src_size, size_t index,
                                       size_t *out_len, int (*build_chunk)(struct zbm_compress_state *),
                                       const crushlzbitmap_params *params)
{
    struct zbm_compress_state *state = NULL;
    size_t offset;
    int err = 0;

    err = zbm_validate_params(params);
    if(err)
        return err;

    /* Same reason as zbm_compress_generic: source positions are uint32_t. */
    if(src_size > CRUSHLZBITMAP_MAX_SRC_SIZE)
        return ZBM_OVERFLOW;

    /* Same reason as zbm_compress_generic: the carve is sized by the params. */
    if(scratch && scratch_size < crushlzbitmap_scratch_size(params))
        return ZBM_INVAL;

    state = zbm_state_begin(scratch, params);
    if(!state)
        return ZBM_NOMEM;

    state->params = *params;
    state->src = src;
    state->src_left = src_size;
    state->dest = dest;
    state->dest_left = dest_size;
    state->preread = 0;
    state->prewritten = 0;
    state->buf_base = src;
    state->buf_len = src_size;

    if(index == 0) {
        err = zbm_write_magic(state);
        if(err)
            goto fail;
    }

    offset = index << CRUSHLZBITMAP_CHUNK_SIZE_BITS;
    if(offset >> CRUSHLZBITMAP_CHUNK_SIZE_BITS != index) {
        err = ZBM_OVERFLOW;
        goto fail;
    }
    if(state->src_left < offset) {
        state->preread = state->src_left;
        state->src += state->src_left;
        state->src_left = 0;
    } else {
        state->preread = offset;
        state->src += offset;
        state->src_left -= offset;
    }

    err = zbm_compress_single_chunk(state, build_chunk);
    if(err)
        goto fail;
    state->src_left -= state->read;
    state->dest_left -= state->written;
    state->preread += state->decmp_len;
    state->prewritten += state->written;

    *out_len = state->prewritten;
fail:
    zbm_state_end(state, scratch);
    return err;
}

static int (*zbm_builder_for(const crushlzbitmap_params *params))(struct zbm_compress_state *)
{
    if(!params)
        return zbm_build_compressed_chunk_row;
    switch(params->strategy) {
    case CRUSHLZBITMAP_STRATEGY_DP:   return zbm_build_compressed_chunk_dp;
    case CRUSHLZBITMAP_STRATEGY_BEAM: return zbm_build_compressed_chunk_beam;
    case CRUSHLZBITMAP_STRATEGY_FAST: return zbm_build_compressed_chunk_fast;
    default:                return zbm_build_compressed_chunk_row;
    }
}

/* Encodes src with explicit params. A NULL params means the default level,
 * the same as encode_chunk. Returns the compressed size, or 0 when dst is
 * NULL, params is out of range, or dst is too small. */
size_t crushlzbitmap_encode_buffer_advanced(void *dst, size_t dst_size, const void *src, size_t src_size,
                                            void *scratch, size_t scratch_size,
                                            const crushlzbitmap_params *params)
{
    crushlzbitmap_params dflt;
    size_t out = 0;
    if(!dst)
        return 0;
    if(!params) {
        crushlzbitmap_params_for_level(CRUSHLZBITMAP_LEVEL_DEFAULT, &dflt);
        params = &dflt;
    }
    if(zbm_compress_generic(scratch, scratch_size, dst, dst_size, src, src_size, &out, zbm_builder_for(params), params) != 0)
        return 0;
    return out;
}

/* Encodes src at a level (clamped to the supported range). Returns the
 * compressed size, or 0 on failure. */
size_t crushlzbitmap_encode_buffer(void *dst, size_t dst_size, const void *src, size_t src_size,
                                   void *scratch, size_t scratch_size, int level)
{
    crushlzbitmap_params params;
    crushlzbitmap_params_for_level(level, &params);
    return crushlzbitmap_encode_buffer_advanced(dst, dst_size, src, src_size, scratch, scratch_size, &params);
}

/* Emits chunk `index` of the stream for the whole input; a NULL params means
 * the default level. Returns the chunk's size, or 0 on failure. */
size_t crushlzbitmap_encode_chunk(void *dst, size_t dst_size, const void *src, size_t src_size, size_t index,
                                  void *scratch, size_t scratch_size,
                                  const crushlzbitmap_params *params)
{
    crushlzbitmap_params dflt;
    size_t out = 0;
    if(!dst)
        return 0;
    if(!params) {
        crushlzbitmap_params_for_level(CRUSHLZBITMAP_LEVEL_DEFAULT, &dflt);
        params = &dflt;
    }
    if(zbm_compress_chunk_generic(scratch, scratch_size, dst, dst_size, src, src_size, index, &out,
                                  zbm_builder_for(params), params) != 0)
        return 0;
    return out;
}
