// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * crushlz4 — Apple COMPRESSION_LZ4 encoder and decoder. See crushlz4.h for
 * the frame layout.
 *
 * The block encoder is upstream LZ4, vendored unmodified under vendor/lz4
 * (BSD 2-Clause; this file is MPL-2.0 and calls it as a library). What is
 * ours is the bv41 frame, the decoder below, the level ladder, and the
 * caller-owned reusable scratch interface.
 *
 * Blocks are encoded independently: no match reaches back past the start of
 * its own block. Apple's decoder would allow it (its match window is the
 * whole destination buffer, and Apple's own encoder emits such matches),
 * but callers here hand over one 64 KiB chunk at a time, so a cross-block
 * window would buy nothing and cost the property that makes these streams
 * decmpfs-chunkable: every block stands alone and can be cut out of the
 * frame and decoded by itself.
 *
 * The decoder below supports Apple's cross-block matches and blocks ending
 * on a match, which upstream's own decoder refuses. Nothing this encoder
 * emits uses either extension, so its block payloads can also be decoded by
 * upstream LZ4; the complete stream still requires Apple's bv4 framing.
 */

#include "crushlz4.h"

#include "vendor/lz4/lz4.h"
#include "vendor/lz4/lz4hc.h"

/* Internal status codes; the public entry points map them. */
#define CLZ4_NOMEM      (-1)
#define CLZ4_INVAL      (-2)
#define CLZ4_RANGE      (-3)

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define CLZ4_LITTLE_ENDIAN 1
#else
#define CLZ4_LITTLE_ENDIAN 0
#endif

/* Function and loop contracts for the CBMC proofs in harness/proofs.
 * Outside a proof build they expand to nothing. Clause order is fixed by
 * CBMC: requires, assigns, ensures on a function; assigns, invariant,
 * decreases on a loop. A loop invariant is all the proof knows about a
 * loop's effect, so an inner loop that only moves sp forward must say so
 * (sp >= CLZ4_LOOP_ENTRY(sp)) or the enclosing loop cannot be shown to
 * terminate. */
#ifdef CLZ4_PROOF
#define CLZ4_REQUIRES(x)        __CPROVER_requires(x)
#define CLZ4_ENSURES(x)         __CPROVER_ensures(x)
#define CLZ4_ASSIGNS(...)       __CPROVER_assigns(__VA_ARGS__)
#define CLZ4_LOOP_ASSIGNS(...)  __CPROVER_assigns(__VA_ARGS__)
#define CLZ4_LOOP_INVARIANT(x)  __CPROVER_loop_invariant(x)
#define CLZ4_LOOP_DECREASES(x)  __CPROVER_decreases(x)
#define CLZ4_LOOP_ENTRY(x)      __CPROVER_loop_entry(x)
#define CLZ4_OFFSET(p)          __CPROVER_POINTER_OFFSET(p)
#else
#define CLZ4_REQUIRES(x)
#define CLZ4_ENSURES(x)
#define CLZ4_ASSIGNS(...)
#define CLZ4_LOOP_ASSIGNS(...)
#define CLZ4_LOOP_INVARIANT(x)
#define CLZ4_LOOP_DECREASES(x)
#endif

/* ---- little helpers ----------------------------------------------------- */

static void put_le32(uint8_t *p, uint32_t v)
CLZ4_REQUIRES(__CPROVER_w_ok(p, 4))
CLZ4_ASSIGNS(__CPROVER_object_upto(p, 4))
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_le32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof v);
#if CLZ4_LITTLE_ENDIAN
    return v;
#else
    return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) |
           ((v >> 8) & 0xFF00u) | ((v >> 24) & 0xFFu);
#endif
}

static uint16_t get_le16(const uint8_t *p)
{
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

/* ---- level ladder -------------------------------------------------------
 *
 * Every rung is a measured point on the frontier of upstream's two encoders,
 * chosen on the 500 MiB corpus at 64 KiB blocks. The crate README carries the
 * table and the reasoning; the short version is that the negative levels are
 * the region no other codec here can reach (above LZBITMAP's 635 MB/s
 * ceiling) and the non-negative ones exist for the format rather than for
 * the ratio, since LZBITMAP beats every one of them outright when it is an
 * option at all.
 *
 * One upstream rung is deliberately absent. HC 8 sits 1.15x from HC 7 and
 * 1.19x from HC 9 for 0.04 points, and dropping it is what lets 7, 8 and 9
 * be HC 9, 10 and 11; without that the ladder jumps 3.4x from HC 9 to
 * HC 11. Below 0, acceleration roughly triples and then doubles per level,
 * each step about 1.4x faster.
 */
struct clz4_level_row {
    uint8_t mode;   /* CRUSHLZ4_MODE_* */
    int32_t param;  /* acceleration (up to CLZ4_ACCEL_MAX == 65537), or HC level */
};

static const struct clz4_level_row clz4_levels[] = {
    /* -5 */ { CRUSHLZ4_MODE_FAST, 128 },
    /* -4 */ { CRUSHLZ4_MODE_FAST, 64 },
    /* -3 */ { CRUSHLZ4_MODE_FAST, 32 },
    /* -2 */ { CRUSHLZ4_MODE_FAST, 16 },
    /* -1 */ { CRUSHLZ4_MODE_FAST,  5 },
    /*  0 */ { CRUSHLZ4_MODE_FAST,  1 },
    /*  1 */ { CRUSHLZ4_MODE_HC,    2 },
    /*  2 */ { CRUSHLZ4_MODE_HC,    3 },
    /*  3 */ { CRUSHLZ4_MODE_HC,    4 },
    /*  4 */ { CRUSHLZ4_MODE_HC,    5 },
    /*  5 */ { CRUSHLZ4_MODE_HC,    6 },
    /*  6 */ { CRUSHLZ4_MODE_HC,    7 },
    /*  7 */ { CRUSHLZ4_MODE_HC,    9 },
    /*  8 */ { CRUSHLZ4_MODE_HC,   10 },
    /*  9 */ { CRUSHLZ4_MODE_HC,   11 },
    /* 10 */ { CRUSHLZ4_MODE_HC,   12 },
};

#define CLZ4_LEVEL_COUNT ((int)(sizeof clz4_levels / sizeof clz4_levels[0]))

static const struct clz4_level_row *row_for_level(int level)
{
    if (level < CRUSHLZ4_LEVEL_MIN) level = CRUSHLZ4_LEVEL_MIN;
    if (level > CRUSHLZ4_LEVEL_MAX) level = CRUSHLZ4_LEVEL_MAX;
    return &clz4_levels[level - CRUSHLZ4_LEVEL_MIN];
}

/* ---- params and scratch -------------------------------------------------- */

/* Upstream clamps acceleration to this internally (LZ4_ACCELERATION_MAX in
 * lz4.c) but does not export it, so it is restated rather than reached for:
 * vendor/lz4 has to stay a verbatim copy. Anything at or above it is the
 * same encoder. */
#define CLZ4_ACCEL_MAX 65537

crushlz4_capabilities crushlz4_get_capabilities(void)
{
    crushlz4_capabilities c;
    c.level_min         = CRUSHLZ4_LEVEL_MIN;
    c.level_max         = CRUSHLZ4_LEVEL_MAX;
    c.level_default     = CRUSHLZ4_LEVEL_DEFAULT;
    c.mode_min          = CRUSHLZ4_MODE_FAST;
    c.mode_max          = CRUSHLZ4_MODE_HC;
    c.acceleration_min  = 1;
    c.acceleration_max  = CLZ4_ACCEL_MAX;
    c.hc_level_min      = 1;
    c.hc_level_max      = LZ4HC_CLEVEL_MAX;
    return c;
}

/* Dereferences `p` unchecked: callers must not pass a NULL params. */
static int clz4_validate_params(const crushlz4_encode_params *p)
{
    if (p->mode != CRUSHLZ4_MODE_FAST && p->mode != CRUSHLZ4_MODE_HC) return CLZ4_INVAL;
    if (p->mode == CRUSHLZ4_MODE_FAST) {
        if (p->acceleration < 1 || p->acceleration > CLZ4_ACCEL_MAX) return CLZ4_INVAL;
    } else {
        if (p->hc_level < 1 || p->hc_level > LZ4HC_CLEVEL_MAX) return CLZ4_INVAL;
    }
    return 0;
}

static struct clz4_level_row row_from_params(const crushlz4_encode_params *p)
{
    struct clz4_level_row row;
    row.mode  = (uint8_t)p->mode;
    /* CLZ4_ACCEL_MAX is 65537, past int16_t's range. */
    row.param = p->mode == CRUSHLZ4_MODE_FAST ? p->acceleration : p->hc_level;
    return row;
}

/* The encoder state upstream wants, plus slack to align it. LZ4's stream
 * types hold 64-bit fields and its initialisers refuse a misaligned buffer,
 * and the scratch a caller hands us carries no alignment promise, so the
 * size includes enough to step up to 16 from wherever it lands. */
#define CLZ4_SCRATCH_ALIGN 16

static size_t clz4_scratch_bytes(const struct clz4_level_row *row)
{
    size_t base = row->mode == CRUSHLZ4_MODE_HC ? sizeof(LZ4_streamHC_t)
                                                : sizeof(LZ4_stream_t);
    return base + (CLZ4_SCRATCH_ALIGN - 1);
}

static void *clz4_align(void *p)
CLZ4_REQUIRES(__CPROVER_rw_ok(p, CLZ4_SCRATCH_ALIGN))
CLZ4_ASSIGNS()
CLZ4_ENSURES(__CPROVER_same_object(__CPROVER_return_value, p))
CLZ4_ENSURES(CLZ4_OFFSET(__CPROVER_return_value) >= CLZ4_OFFSET(p))
CLZ4_ENSURES(CLZ4_OFFSET(__CPROVER_return_value) - CLZ4_OFFSET(p) < CLZ4_SCRATCH_ALIGN)
CLZ4_ENSURES(((uintptr_t)__CPROVER_return_value & (CLZ4_SCRATCH_ALIGN - 1)) == 0)
{
    uintptr_t v = (uintptr_t)p;
    v = (v + (CLZ4_SCRATCH_ALIGN - 1)) & ~(uintptr_t)(CLZ4_SCRATCH_ALIGN - 1);
    return (void *)v;
}

int crushlz4_params_for_level(int level, crushlz4_encode_params *out)
{
    const struct clz4_level_row *row;

    if (!out) return CRUSHLZ4_LEVEL_INVALID;
    if (level < CRUSHLZ4_LEVEL_MIN) level = CRUSHLZ4_LEVEL_MIN;
    if (level > CRUSHLZ4_LEVEL_MAX) level = CRUSHLZ4_LEVEL_MAX;
    row = &clz4_levels[level - CRUSHLZ4_LEVEL_MIN];

    out->mode = row->mode;
    /* Both fields are always written. The one the mode does not read is set
     * to that mode's own neutral value rather than left indeterminate, so a
     * caller that flips `mode` by hand gets a usable params either way. */
    out->acceleration = row->mode == CRUSHLZ4_MODE_FAST ? row->param : 1;
    out->hc_level     = row->mode == CRUSHLZ4_MODE_HC   ? row->param : LZ4HC_CLEVEL_DEFAULT;
    return level;
}

size_t crushlz4_scratch_size(const crushlz4_encode_params *params)
{
    struct clz4_level_row row;

    if (!params) return 0;
    if (clz4_validate_params(params) != 0)
        return 0;
    row = row_from_params(params);
    return clz4_scratch_bytes(&row);
}

#ifdef CLZ4_PROOF
/* Upstream LZ4 is outside this project's proof scope. These contracts are
 * the dependency boundary, not proofs of its implementation. extState
 * resets the supplied, suitably aligned state before reading it. */
int LZ4_compress_fast_extState(void *state, const char *src, char *dst,
                              int src_size, int dst_capacity, int acceleration)
CLZ4_REQUIRES(src_size > 0 && src_size <= CRUSHLZ4_BLOCK_SIZE)
CLZ4_REQUIRES(dst_capacity > 0)
CLZ4_REQUIRES(acceleration >= 1 && acceleration <= CLZ4_ACCEL_MAX)
CLZ4_REQUIRES(__CPROVER_rw_ok(state, sizeof(LZ4_stream_t)))
CLZ4_REQUIRES(((uintptr_t)state & (CLZ4_SCRATCH_ALIGN - 1)) == 0)
CLZ4_REQUIRES(__CPROVER_r_ok(src, (size_t)src_size))
CLZ4_REQUIRES(__CPROVER_w_ok(dst, (size_t)dst_capacity))
CLZ4_REQUIRES(!__CPROVER_same_object(src, dst))
CLZ4_REQUIRES(!__CPROVER_same_object(state, src))
CLZ4_REQUIRES(!__CPROVER_same_object(state, dst))
CLZ4_ASSIGNS(__CPROVER_object_upto(state, sizeof(LZ4_stream_t)),
             __CPROVER_object_upto(dst, (size_t)dst_capacity))
CLZ4_ENSURES(__CPROVER_return_value >= 0 && __CPROVER_return_value <= dst_capacity);

int LZ4_compress_HC_extStateHC(void *state, const char *src, char *dst,
                             int src_size, int dst_capacity, int level)
CLZ4_REQUIRES(src_size > 0 && src_size <= CRUSHLZ4_BLOCK_SIZE)
CLZ4_REQUIRES(dst_capacity > 0)
CLZ4_REQUIRES(level >= 1 && level <= LZ4HC_CLEVEL_MAX)
CLZ4_REQUIRES(__CPROVER_rw_ok(state, sizeof(LZ4_streamHC_t)))
CLZ4_REQUIRES(((uintptr_t)state & (CLZ4_SCRATCH_ALIGN - 1)) == 0)
CLZ4_REQUIRES(__CPROVER_r_ok(src, (size_t)src_size))
CLZ4_REQUIRES(__CPROVER_w_ok(dst, (size_t)dst_capacity))
CLZ4_REQUIRES(!__CPROVER_same_object(src, dst))
CLZ4_REQUIRES(!__CPROVER_same_object(state, src))
CLZ4_REQUIRES(!__CPROVER_same_object(state, dst))
CLZ4_ASSIGNS(__CPROVER_object_upto(state, sizeof(LZ4_streamHC_t)),
             __CPROVER_object_upto(dst, (size_t)dst_capacity))
CLZ4_ENSURES(__CPROVER_return_value >= 0 && __CPROVER_return_value <= dst_capacity);
#endif

#ifdef CLZ4_ALLOC_PROOF
/* The implementation of this boundary is the verbatim framing loop checked
 * by frama/lz4_frame.py. Used only to separate allocation from framing. */
int proof_lz4_frame(void *dest, size_t dest_size, const void *src, size_t src_size,
                    size_t *out_len, void *mem, size_t state_bytes,
                    const struct clz4_level_row *row)
CLZ4_REQUIRES(__CPROVER_w_ok(dest, dest_size))
CLZ4_REQUIRES(__CPROVER_r_ok(src, src_size))
CLZ4_REQUIRES(__CPROVER_w_ok(out_len, sizeof *out_len))
CLZ4_REQUIRES(__CPROVER_r_ok(row, sizeof *row))
CLZ4_REQUIRES(row->mode == CRUSHLZ4_MODE_FAST || row->mode == CRUSHLZ4_MODE_HC)
CLZ4_REQUIRES(row->mode == CRUSHLZ4_MODE_FAST ==> row->param >= 1 && row->param <= CLZ4_ACCEL_MAX)
CLZ4_REQUIRES(row->mode == CRUSHLZ4_MODE_HC ==> row->param >= 1 && row->param <= LZ4HC_CLEVEL_MAX)
CLZ4_REQUIRES(state_bytes == (row->mode == CRUSHLZ4_MODE_HC ? sizeof(LZ4_streamHC_t) : sizeof(LZ4_stream_t)))
CLZ4_REQUIRES(__CPROVER_rw_ok(mem, state_bytes))
CLZ4_REQUIRES(((uintptr_t)mem & (CLZ4_SCRATCH_ALIGN - 1)) == 0)
CLZ4_REQUIRES(!__CPROVER_same_object(dest, src))
CLZ4_REQUIRES(!__CPROVER_same_object(dest, out_len))
CLZ4_REQUIRES(!__CPROVER_same_object(dest, row))
CLZ4_REQUIRES(!__CPROVER_same_object(dest, mem))
CLZ4_REQUIRES(!__CPROVER_same_object(src, out_len))
CLZ4_REQUIRES(!__CPROVER_same_object(src, row))
CLZ4_REQUIRES(!__CPROVER_same_object(src, mem))
CLZ4_REQUIRES(!__CPROVER_same_object(out_len, row))
CLZ4_REQUIRES(!__CPROVER_same_object(out_len, mem))
CLZ4_REQUIRES(!__CPROVER_same_object(row, mem))
CLZ4_ASSIGNS(*out_len, __CPROVER_object_upto(dest, dest_size),
             __CPROVER_object_upto(mem, state_bytes))
CLZ4_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == CLZ4_RANGE)
CLZ4_ENSURES(__CPROVER_return_value == 0 ==> *out_len <= dest_size);
#endif

/* ---- encoder ------------------------------------------------------------- */

size_t crushlz4_encode_bound(size_t src_size)
{
    /* Worst case is every block stored: 8 bytes of header each, plus the
     * 4-byte terminator once. A compressed block can never cost more than
     * that (see encode()'s max_out), so this is the true tight bound, not
     * just a stored-only approximation. A bare `src_size / BLOCK_SIZE + 1`
     * would count one phantom extra block whenever src_size divides
     * BLOCK_SIZE evenly, so this is a real ceiling division instead. */
    size_t blocks = src_size == 0 ? 0 : (src_size - 1) / CRUSHLZ4_BLOCK_SIZE + 1;
    return src_size + blocks * 8 + 4;
}

/* One upstream call per block, straight into the frame.
 *
 * The attempt is given `block - 4` bytes of room to account for the larger
 * compressed header. Both outcomes fit the checked 8 + block bytes:
 * compressed writes a 12-byte header and at most block - 4 payload;
 * stored writes an 8-byte header followed by the original block. */
static int encode(void *dest, size_t dest_size, const void *src_v, size_t src_size,
                  size_t *out_len, void *scratch, size_t scratch_size,
                  const struct clz4_level_row *row)
CLZ4_REQUIRES(__CPROVER_w_ok(dest, dest_size))
CLZ4_REQUIRES(src_v == NULL || __CPROVER_r_ok(src_v, src_size))
CLZ4_REQUIRES(__CPROVER_w_ok(out_len, sizeof *out_len))
CLZ4_REQUIRES(__CPROVER_r_ok(row, sizeof *row))
CLZ4_REQUIRES(row->mode == CRUSHLZ4_MODE_FAST || row->mode == CRUSHLZ4_MODE_HC)
CLZ4_REQUIRES(row->mode == CRUSHLZ4_MODE_FAST ==>
              row->param >= 1 && row->param <= CLZ4_ACCEL_MAX)
CLZ4_REQUIRES(row->mode == CRUSHLZ4_MODE_HC ==>
              row->param >= 1 && row->param <= LZ4HC_CLEVEL_MAX)
CLZ4_REQUIRES(scratch == NULL || __CPROVER_rw_ok(scratch, scratch_size))
CLZ4_REQUIRES(src_v == NULL || !__CPROVER_same_object(src_v, dest))
CLZ4_REQUIRES(!__CPROVER_same_object(out_len, dest))
CLZ4_REQUIRES(!__CPROVER_same_object(row, dest))
CLZ4_REQUIRES(src_v == NULL || !__CPROVER_same_object(out_len, src_v))
CLZ4_REQUIRES(src_v == NULL || !__CPROVER_same_object(row, src_v))
CLZ4_REQUIRES(!__CPROVER_same_object(row, out_len))
CLZ4_REQUIRES(scratch == NULL || !__CPROVER_same_object(scratch, dest))
CLZ4_REQUIRES(scratch == NULL || src_v == NULL || !__CPROVER_same_object(scratch, src_v))
CLZ4_REQUIRES(scratch == NULL || !__CPROVER_same_object(scratch, out_len))
CLZ4_REQUIRES(scratch == NULL || !__CPROVER_same_object(scratch, row))
CLZ4_ASSIGNS(*out_len, __CPROVER_object_upto(dest, dest_size);
             scratch != NULL: __CPROVER_object_upto(scratch, scratch_size))
CLZ4_ENSURES(__CPROVER_return_value == 0 || __CPROVER_return_value == CLZ4_NOMEM ||
             __CPROVER_return_value == CLZ4_INVAL || __CPROVER_return_value == CLZ4_RANGE)
CLZ4_ENSURES(__CPROVER_return_value == 0 ==> *out_len <= dest_size)
{
    const uint8_t *src = src_v;
    uint8_t *out = dest;
    uint8_t *const out_end = out + dest_size;
    void *owned = NULL;
    void *mem;
    size_t pos = 0;
    int rc = 0;

    if (!row) return CLZ4_INVAL;
    if (src_size && !src) return CLZ4_INVAL;

    /* A NULL scratch is allocated internally; a scratch that is present but
     * too small is refused rather than quietly replaced. Silently allocating
     * over the caller's buffer would hide a sizing bug behind a malloc on
     * every block, which is exactly what the caller sized a scratch to
     * avoid. scratch_contract_test holds this for every codec here. */
    {   size_t need = clz4_scratch_bytes(row);
        if (!scratch) {
            owned = malloc(need);
            if (!owned) return CLZ4_NOMEM;
            scratch = owned;
        } else if (scratch_size < need) {
            return CLZ4_INVAL;
        }
    }
    /* Upstream's extState entry points reset the table themselves, so the
     * only thing owed here is alignment: they read it as 64-bit fields and
     * a caller's scratch carries no alignment promise. */
    mem = clz4_align(scratch);
#ifdef CLZ4_PROOF
    size_t mem_bytes = row->mode == CRUSHLZ4_MODE_HC
        ? sizeof(LZ4_streamHC_t) : sizeof(LZ4_stream_t);
#endif

#ifdef CLZ4_ALLOC_PROOF
    rc = proof_lz4_frame(dest, dest_size, src, src_size, out_len, mem, mem_bytes, row);
#else
    while (pos < src_size)
        CLZ4_LOOP_ASSIGNS(pos, out, rc,
                         __CPROVER_object_upto(dest, dest_size),
                         __CPROVER_object_upto(mem, mem_bytes))
        CLZ4_LOOP_INVARIANT(pos <= src_size)
        CLZ4_LOOP_INVARIANT(__CPROVER_same_object(out, dest))
        CLZ4_LOOP_INVARIANT(CLZ4_OFFSET(out) >= CLZ4_OFFSET(dest))
        CLZ4_LOOP_INVARIANT(CLZ4_OFFSET(out) <= CLZ4_OFFSET(out_end))
        CLZ4_LOOP_DECREASES(src_size - pos)
    {
        size_t block = src_size - pos;
        uint8_t *hdr = out;
        int k;

        if (block > CRUSHLZ4_BLOCK_SIZE) block = CRUSHLZ4_BLOCK_SIZE;
        /* 8 + block covers either outcome: a compressed result is capped
         * below at exactly what beats stored (see max_out), and stored
         * itself is 8 (its own header) + block. */
        if ((size_t)(out_end - hdr) < 8 + block) { rc = CLZ4_RANGE; goto done; }

        /* Capping upstream's maxOutputSize at block - 4, not block - 1,
         * means any k > 0 it returns already satisfies 12 + k <= 8 + block:
         * compressed can never come back worse than stored would have been,
         * so no separate size comparison is needed, and the true worst case
         * per block is a clean 8 + block instead of block + 11. block <= 4
         * skips the attempt outright, both because compression could not
         * help at that size and to avoid handing upstream a non-positive
         * maxOutputSize. */
        int max_out = block > 4 ? (int)block - 4 : 0;
        k = max_out <= 0 ? 0
          : row->mode == CRUSHLZ4_MODE_HC
              ? LZ4_compress_HC_extStateHC(mem, (const char *)(src + pos),
                                           (char *)(hdr + 12), (int)block,
                                           max_out, row->param)
              : LZ4_compress_fast_extState(mem, (const char *)(src + pos),
                                           (char *)(hdr + 12), (int)block,
                                           max_out, row->param);

        if (k > 0) {
            put_le32(hdr, CRUSHLZ4_MAGIC_COMPRESSED);
            put_le32(hdr + 4, (uint32_t)block);
            put_le32(hdr + 8, (uint32_t)k);
            out = hdr + 12 + (size_t)k;
        } else {
            put_le32(hdr, CRUSHLZ4_MAGIC_STORED);
            put_le32(hdr + 4, (uint32_t)block);
            memmove(hdr + 8, src + pos, block);
            out = hdr + 8 + block;
        }
        pos += block;
    }

    if ((size_t)(out_end - out) < 4) { rc = CLZ4_RANGE; goto done; }
    put_le32(out, CRUSHLZ4_MAGIC_END);
    out += 4;
    *out_len = (size_t)(out - (uint8_t *)dest);

#endif

done:
    free(owned);
    return rc;
}

size_t crushlz4_encode_buffer(void *dst, size_t dst_size, const void *src, size_t src_size,
                              void *scratch, size_t scratch_size, int level)
{
    size_t out = 0;
    if (!dst) return 0;
    if (encode(dst, dst_size, src, src_size, &out, scratch, scratch_size,
               row_for_level(level)) != 0)
        return 0;
    return out;
}

size_t crushlz4_encode_buffer_advanced(void *dst, size_t dst_size, const void *src, size_t src_size,
                                       void *scratch, size_t scratch_size,
                                       const crushlz4_encode_params *params)
{
    struct clz4_level_row row;
    size_t out = 0;

    if (!dst || !params) return 0;
    if (clz4_validate_params(params) != 0) return 0;
    row = row_from_params(params);
    if (encode(dst, dst_size, src, src_size, &out, scratch, scratch_size, &row) != 0)
        return 0;
    return out;
}

/* ---- decoder ------------------------------------------------------------- */

/* Successful complete decodes must agree with Apple's lengths and bytes;
 * acceptance of malformed streams may differ. When the caller's buffer is
 * too small, Apple truncates and reports the bytes written; this returns
 * CLZ4_RANGE. */
/* The wide match copy may write up to 15 bytes past the match, so it only
 * runs with this much room left in the destination. */
#define CLZ4_COPY_SLACK 16

/* The byte-wise overlapping copy must not be vectorized: it is only reached
 * with off < 8, so the wide version is dead code in the hot loop. */
#if defined(__clang__)
#define CLZ4_NOVEC _Pragma("clang loop vectorize(disable) unroll(disable)")
#else
#define CLZ4_NOVEC
#endif

#define CLZ4_LIKELY(x)    __builtin_expect(!!(x), 1)

/* Contract proved in harness/proofs/lz4_copy_match.c: given off bytes
 * before d and room bytes from d, it touches nothing outside d[-off, room),
 * never hands memcpy overlapping ranges, and terminates. decode_block's
 * proof checks every call site meets the requires clauses. */
static inline __attribute__((always_inline))
void copy_match(uint8_t *d, size_t off, size_t mlen, size_t room)
CLZ4_REQUIRES(off >= 1 && off <= CLZ4_OFFSET(d))
CLZ4_REQUIRES(__CPROVER_w_ok(d, room) && __CPROVER_r_ok(d - off, off))
CLZ4_REQUIRES(mlen <= room)
CLZ4_ASSIGNS(__CPROVER_object_upto(d, room))
{
    size_t k = 0;

    /* 16 bytes per iteration, overrunning by up to 15 into slack proved
     * here. Correct despite the overlap only because off >= 8. */
    if (off >= 8 && mlen + CLZ4_COPY_SLACK <= room) {
        do
            CLZ4_LOOP_ASSIGNS(k, __CPROVER_object_upto(d, room))
            CLZ4_LOOP_INVARIANT(k == 0 || k < mlen)
            CLZ4_LOOP_DECREASES(mlen - k)
        {
            memcpy(d + k, d + k - off, 8);
            memcpy(d + k + 8, d + k + 8 - off, 8);
            k += 16;
        } while (k < mlen);
        return;
    }

    /* off < 8 stays byte-wise: the match repeats a 1..7 byte pattern. The
     * source pointer is computed once because d[k - off] with k < off
     * underflows; d - off is valid because the decoder checked off <= dp. */
    const uint8_t *sp = d - off;
    CLZ4_NOVEC
    for (; k < mlen; k++)
        CLZ4_LOOP_ASSIGNS(k, __CPROVER_object_upto(d, room))
        CLZ4_LOOP_INVARIANT(k <= mlen)
        CLZ4_LOOP_DECREASES(mlen - k)
        d[k] = sp[k];
}

/* Safe-zone margins for the fast sequence path.
 * SRC: token 1 + literals at most 14 + offset 2 = 17, rounded to 32 so the
 *      16-byte literal overcopy can read past the run.
 * DST: literals at most 14, then a 32-byte match overcopy = 46, rounded to 64.
 * Inside the zone every safety bound is implied; only the validity checks
 * (off != 0 and off <= dp) remain, because they decide which streams are
 * accepted. */
#define CLZ4_FAST_SRC 32
#define CLZ4_FAST_DST 64

/* Contract proved in harness/proofs/lz4_decode_block.c: reads only
 * src[0, slen), writes only *dst_pos and dst[0, dst_cap), leaves
 * *dst_pos <= dst_cap, and terminates, for any bytes in src. */
static int decode_block(uint8_t *dst, size_t dst_cap, size_t *dst_pos,
                        const uint8_t *src, size_t slen)
CLZ4_REQUIRES(__CPROVER_r_ok(src, slen))
CLZ4_REQUIRES(dst == NULL || __CPROVER_w_ok(dst, dst_cap))
CLZ4_REQUIRES(dst == NULL || !__CPROVER_same_object(dst, src))
CLZ4_REQUIRES(__CPROVER_is_fresh(dst_pos, sizeof *dst_pos))
CLZ4_REQUIRES(*dst_pos <= dst_cap)
CLZ4_ASSIGNS(*dst_pos; dst != NULL: __CPROVER_object_upto(dst, dst_cap))
CLZ4_ENSURES(*dst_pos <= dst_cap)
CLZ4_ENSURES(__CPROVER_return_value == 0 ||
             __CPROVER_return_value == CLZ4_INVAL ||
             __CPROVER_return_value == CLZ4_RANGE)
{
    size_t sp = 0;
    size_t dp = *dst_pos;
    /* Whether there is a zone at all (never with dst == NULL) is decided once. */
    const int fast_ok = dst != NULL && slen >= CLZ4_FAST_SRC &&
                        dst_cap >= CLZ4_FAST_DST;
    const size_t sp_fast = fast_ok ? slen - CLZ4_FAST_SRC : 0;
    const size_t dp_fast = fast_ok ? dst_cap - CLZ4_FAST_DST : 0;

    while (sp < slen)
        CLZ4_LOOP_ASSIGNS(sp, dp; dst != NULL: __CPROVER_object_upto(dst, dst_cap))
        CLZ4_LOOP_INVARIANT(sp <= slen && dp <= dst_cap)
        CLZ4_LOOP_DECREASES(slen - sp)
    {
        uint8_t token;
        /* Fast path: a sequence with both nibbles below 15 runs with no
         * bounds test and fixed-size copies (literals <= 14, match <= 18).
         * Long matches are handled here; long literal runs go back to the
         * checked path. */
        while (fast_ok && sp <= sp_fast && dp <= dp_fast)
            CLZ4_LOOP_ASSIGNS(sp, dp; dst != NULL: __CPROVER_object_upto(dst, dst_cap))
            CLZ4_LOOP_INVARIANT(sp <= slen && dp <= dst_cap &&
                                sp >= CLZ4_LOOP_ENTRY(sp))
            CLZ4_LOOP_DECREASES(slen - sp)
        {
            uint8_t tk = src[sp];
            const uint8_t *s;
            uint8_t *d;
            size_t ll, ml, off;

            if (tk >= 0xf0) break;

            ll = tk >> 4;                                   /* <= 14 */
            s  = src + sp + 1;
            d  = dst + dp;

            memcpy(d, s, 16);

            off = get_le16(s + ll);
            dp += ll;

            ml  = (size_t)(tk & 0x0f) + CRUSHLZ4_MIN_MATCH;     /* <= 18 */
            sp += ll + 3;

            /* off - 1 >= dp is off == 0 || off > dp in one unsigned compare. */
            if (off - 1 >= dp) return CLZ4_INVAL;
            d = dst + dp;

            if (CLZ4_LIKELY((tk & 0x0f) != 0x0f)) {
                if (CLZ4_LIKELY(off >= 8)) {
                    const uint8_t *m = d - off;
                    memcpy(d, m, 8);
                    memcpy(d + 8, m + 8, 8);
                    memcpy(d + 16, m + 16, 8);
                } else {
                    /* d[k - off] with k < off would underflow; see copy_match. */
                    const uint8_t *mb = d - off;
                    CLZ4_NOVEC
                    for (size_t k = 0; k < ml; k++)
                        CLZ4_LOOP_ASSIGNS(k, __CPROVER_object_upto(d, ml))
                        CLZ4_LOOP_INVARIANT(k <= ml)
                        CLZ4_LOOP_DECREASES(ml - k)
                        d[k] = mb[k];
                }
                dp += ml;
                continue;
            }

            /* Long match: only the length is unbounded. The checks and their
             * order match the general path so a malformed stream gets the
             * same error. */
            for (;;)
                CLZ4_LOOP_ASSIGNS(sp, ml)
                CLZ4_LOOP_INVARIANT(sp <= slen && sp >= CLZ4_LOOP_ENTRY(sp))
                CLZ4_LOOP_DECREASES(slen - sp)
            {
                uint8_t b;
                if (sp >= slen) return CLZ4_INVAL;
                b = src[sp++];
                ml += b;
                if (b != 255) break;
            }
            if (ml > dst_cap - dp) return CLZ4_RANGE;
            copy_match(d, off, ml, dst_cap - dp);
            dp += ml;
        }
        /* The match-length extension can leave sp == slen; the token read
         * must not run then. */
        if (sp >= slen) break;
        token = src[sp++];
        size_t llen = token >> 4;
        size_t mlen = (size_t)(token & 0x0f) + CRUSHLZ4_MIN_MATCH;
        size_t off;

        if (llen == 15) {
            for (;;)
                CLZ4_LOOP_ASSIGNS(sp, llen)
                CLZ4_LOOP_INVARIANT(sp <= slen && sp >= CLZ4_LOOP_ENTRY(sp))
                CLZ4_LOOP_DECREASES(slen - sp)
            {
                if (sp >= slen) return CLZ4_INVAL;
                uint8_t b = src[sp++];
                llen += b;
                if (b != 255) break;
            }
        }
        if (llen > slen - sp) return CLZ4_INVAL;
        if (llen > dst_cap - dp) return CLZ4_RANGE;
        if (dst) memcpy(dst + dp, src + sp, llen);
        sp += llen;
        dp += llen;

        if (sp == slen) break;          /* literals-only final sequence */
        if (slen - sp < 2) return CLZ4_INVAL;
        off = get_le16(src + sp);
        sp += 2;
        /* off == 0 || off > dp, in one unsigned compare. */
        if (off - 1 >= dp) return CLZ4_INVAL;

        if ((token & 0x0f) == 15) {
            for (;;)
                CLZ4_LOOP_ASSIGNS(sp, mlen)
                CLZ4_LOOP_INVARIANT(sp <= slen && sp >= CLZ4_LOOP_ENTRY(sp))
                CLZ4_LOOP_DECREASES(slen - sp)
            {
                if (sp >= slen) return CLZ4_INVAL;
                uint8_t b = src[sp++];
                mlen += b;
                if (b != 255) break;
            }
        }
        if (mlen > dst_cap - dp) return CLZ4_RANGE;
        if (dst) copy_match(dst + dp, off, mlen, dst_cap - dp);
        dp += mlen;
    }

    *dst_pos = dp;
    return 0;
}

static int decode(void *dest, size_t dest_size, const void *src_v, size_t src_size, size_t *out_len)
{
    const uint8_t *src = src_v;
    uint8_t *dst = dest;
    size_t sp = 0, dp = 0;
    /* dest_size bounds the decoded total even with dest == NULL, so a probe
     * call can refuse a stream past a caller-chosen ceiling; pass SIZE_MAX
     * for no cap. */
    size_t cap = dest_size;

    if (!out_len) return CLZ4_INVAL;
    if (src_size && !src) { *out_len = dp; return CLZ4_INVAL; }

    for (;;)
        CLZ4_LOOP_ASSIGNS(sp, dp, *out_len;
                          dst != NULL: __CPROVER_object_upto(dst, dest_size))
        CLZ4_LOOP_INVARIANT(sp <= src_size && dp <= cap)
        CLZ4_LOOP_DECREASES(src_size - sp)
    {
        uint32_t magic;
        if (src_size - sp < 4) { *out_len = dp; return CLZ4_INVAL; }
        magic = get_le32(src + sp);

        if (magic == CRUSHLZ4_MAGIC_END) { sp += 4; break; }

        if (magic == CRUSHLZ4_MAGIC_STORED) {
            if (src_size - sp < 8) { *out_len = dp; return CLZ4_INVAL; }
            size_t n = get_le32(src + sp + 4);
            sp += 8;
            if (n > src_size - sp) { *out_len = dp; return CLZ4_INVAL; }
            if (n > cap - dp) { *out_len = dp; return CLZ4_RANGE; }
            if (dst) memcpy(dst + dp, src + sp, n);
            sp += n;
            dp += n;
            continue;
        }

        if (magic == CRUSHLZ4_MAGIC_COMPRESSED) {
            if (src_size - sp < 12) { *out_len = dp; return CLZ4_INVAL; }
            size_t decoded = get_le32(src + sp + 4);
            size_t encoded = get_le32(src + sp + 8);
            sp += 12;
            if (encoded > src_size - sp) { *out_len = dp; return CLZ4_INVAL; }
            if (decoded > cap - dp) { *out_len = dp; return CLZ4_RANGE; }

            size_t before = dp;
            int rc = decode_block(dst, dest_size, &dp, src + sp, encoded);
            /* decode_block only advances *dst_pos on its own success path;
             * on failure dp is still exactly `before`, i.e. every block
             * fully completed up to (not including) this one, at block
             * granularity, not byte-exact within a failing block, by
             * choice: reporting that precisely would mean touching
             * decode_block's own hot loop at every one of its early
             * returns, for a distinction that isn't worth that risk. */
            if (rc) { *out_len = dp; return rc; }
            /* Both size fields are contractual; a mismatch is a malformed
             * stream, but decode_block did complete, so dp is genuinely
             * valid through this block regardless of what its header claimed. */
            if (dp - before != decoded) { *out_len = dp; return CLZ4_INVAL; }
            sp += encoded;
            continue;
        }

        *out_len = dp;
        return CLZ4_INVAL;
    }

    *out_len = dp;
    return 0;
}

int crushlz4_decode_buffer(void *dst, size_t dst_size, const void *src, size_t src_size, size_t *out_len)
{
    int rc = decode(dst, dst_size, src, src_size, out_len);
    if (rc == 0) return 0;
    return rc == CLZ4_RANGE ? CRUSHLZ4_OUTPUT_TOO_SMALL : CRUSHLZ4_INVALID;
}
