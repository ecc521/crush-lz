// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

#include "crushlzmesh.h"
#include <string.h>
#include <stdlib.h>
#if defined(__AVX2__)
#include <immintrin.h>
#elif defined(__ARM_NEON) && defined(__aarch64__)
#include <arm_neon.h>
#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint16_t load16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}


static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void store16_le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}


size_t crushlzmesh_encode_bound(size_t src_size) {
    return src_size + 64;
}

size_t crushlzmesh_encode_scratch_buffer_size(const crushlzmesh_params *params) {
    if (!params) return 1 << 18;
    int hb = params->hash_bits ? params->hash_bits : 16;
    if (hb < 10) hb = 10;
    if (hb > 20) hb = 20;
    return (size_t)(1 << hb) * sizeof(uint32_t) + 65536;
}

size_t crushlzmesh_decode_scratch_buffer_size(void) {
    return 65536;
}

int crushlzmesh_params_for_level(int level, crushlzmesh_params *out) {
    if (!out) return CRUSHLZMESH_INVALID;
    if (level < CRUSHLZMESH_LEVEL_MIN) level = CRUSHLZMESH_LEVEL_MIN;
    if (level > CRUSHLZMESH_LEVEL_MAX) level = CRUSHLZMESH_LEVEL_MAX;

    memset(out, 0, sizeof(*out));
    out->min_match = 3;
    if (level <= 5) {
        // Lazy parse over a hash chain, or over hash rows from depth 16 on.
        // Negative levels are the same as 0.
        static const int8_t hb[6] = {16, 17, 17, 17, 18, 18};
        static const int8_t depth[6] = {1, 2, 4, 8, 24, 64};
        int i = level < 0 ? 0 : level;
        out->strategy = CRUSHLZMESH_STRAT_LAZY;
        out->hash_bits = hb[i];
        out->max_depth = depth[i];
    } else {
        // Optimal parse over a binary tree.
        static const int16_t hb[5] = {17, 17, 18, 18, 18};
        static const int16_t depth[5] = {8, 16, 16, 32, 128};
        static const int16_t nice[5] = {64, 96, 128, 128, 192};
        static const int16_t iters[5] = {1, 1, 2, 3, 3};
        int i = level - 6;
        out->strategy = CRUSHLZMESH_STRAT_OPTIMAL;
        out->hash_bits = hb[i];
        out->search_depth = depth[i];
        out->lookahead = nice[i];
        out->iterations = iters[i];
    }
    return CRUSHLZMESH_STATUS_OK;
}

// ---------------------------------------------------------------------------
// Decoder
//
// Payload: [raw/RLE streams][8 lanes][lane-size trailer][9-byte footer].
// Footer: modes u16 (3 bits each for lits, ops, extras, dists: 0 raw, 1 RLE,
// 2 Huffman in the lanes), then u16 ops, u16 extras, u16 lits, and the low
// byte of the dist count. The high byte is the byte after the payload.
// See docs/lzmesh-format-notes.md.
// ---------------------------------------------------------------------------

#define MESH_LANES 8
#define MESH_MAX_CODE 10
#define MESH_TABLE_SIZE (1u << MESH_MAX_CODE)
#define MESH_MAX_STREAM 65535u
#define MESH_SCRATCH_MAX 62944u
#define MESH_R32(x) (((x) + 31) & ~(size_t)31)

enum { MESH_RAW = 0, MESH_RLE = 1, MESH_HUFF = 2 };

typedef struct {
    const uint8_t *start;
    const uint8_t *p;
    const uint8_t *end;
    uint64_t bits;
    unsigned n;
} mesh_lane;

static inline uint64_t load64_le(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

static void lane_init(mesh_lane *l, const uint8_t *start, const uint8_t *end) {
    l->start = l->p = start;
    l->end = end;
    l->bits = 0;
    l->n = 0;
}

// Keeps at least 56 bits buffered; past the end of the lane it feeds zeros.
static inline void lane_refill(mesh_lane *l) {
    if (l->end - l->p >= 8) {
        l->bits |= load64_le(l->p) << l->n;
        l->p += (63 - l->n) >> 3;
        l->n |= 56;
        return;
    }
    while (l->n <= 56) {
        if (l->p < l->end) l->bits |= (uint64_t)*l->p++ << l->n;
        l->n += 8;
    }
}

static inline uint32_t lane_read(mesh_lane *l, unsigned k) {
    uint32_t v = (uint32_t)(l->bits & ((1ull << k) - 1));
    l->bits >>= k;
    l->n -= k;
    return v;
}

// Decode table entry: symbol | length << 8; length 0 marks an unused code.
typedef uint16_t mesh_dtable[MESH_TABLE_SIZE];

static inline unsigned bitrev(unsigned v, unsigned n) {
    unsigned r = 0;
    for (unsigned i = 0; i < n; i++) r |= ((v >> i) & 1u) << (n - 1 - i);
    return r;
}

// Canonical code (by length, then symbol), stored bit-reversed because codes
// are read first-bit-lowest.
static int build_dtable(uint16_t *table, unsigned table_bits, const uint8_t *lens, unsigned nsym) {
    unsigned count[MESH_MAX_CODE + 1] = {0};
    for (unsigned s = 0; s < nsym; s++) {
        if (lens[s] > table_bits) return CRUSHLZMESH_INVALID;
        count[lens[s]]++;
    }
    count[0] = 0;
    unsigned next[MESH_MAX_CODE + 2];
    unsigned code = 0;
    for (unsigned len = 1; len <= table_bits; len++) {
        code = (code + count[len - 1]) << 1;
        next[len] = code;
    }
    unsigned kraft = 0;
    for (unsigned len = 1; len <= table_bits; len++) kraft += count[len] << (table_bits - len);
    if (kraft > (1u << table_bits)) return CRUSHLZMESH_INVALID;
    memset(table, 0, sizeof(uint16_t) << table_bits);
    for (unsigned s = 0; s < nsym; s++) {
        unsigned len = lens[s];
        if (!len) continue;
        unsigned rc = bitrev(next[len]++, len);
        for (unsigned i = rc; i < (1u << table_bits); i += 1u << len) table[i] = (uint16_t)(s | (len << 8));
    }
    return CRUSHLZMESH_STATUS_OK;
}

static inline int lane_sym(mesh_lane *l, const uint16_t *table, unsigned table_bits) {
    uint16_t e = table[l->bits & ((1u << table_bits) - 1)];
    unsigned len = e >> 8;
    if (!len) return -1;
    l->bits >>= len;
    l->n -= len;
    return e & 0xFF;
}

// Reads a Huffman table from the lanes into `table`.
static int read_table(mesh_lane *lanes, uint16_t *table) {
    mesh_lane *h = &lanes[0];
    uint8_t cl[11];
    lane_refill(h);
    for (int v = 0; v < 11; v++) cl[v] = (uint8_t)lane_read(h, 3);
    lane_refill(h);
    uint32_t cls = lane_read(h, 32);

    uint16_t ctable[1u << 7];
    if (build_dtable(ctable, 7, cl, 11) != CRUSHLZMESH_STATUS_OK) return CRUSHLZMESH_INVALID;

    uint8_t lens[256];
    memset(lens, 0, sizeof(lens));
    unsigned j = 0;
    for (unsigned hi = 0; hi < 16; hi++) {
        unsigned c = (cls >> (2 * hi)) & 3;
        for (unsigned half = 0; half < 2; half++) {
            if (!(c & (half ? 2u : 1u))) continue;
            for (unsigned lo = 0; lo < 8; lo++) {
                mesh_lane *l = &lanes[j++ & 7];
                lane_refill(l);
                int v = lane_sym(l, ctable, 7);
                if (v < 0 || v > MESH_MAX_CODE) return CRUSHLZMESH_INVALID;
                lens[hi * 16 + half * 8 + lo] = (uint8_t)v;
            }
        }
    }
    return build_dtable(table, MESH_MAX_CODE, lens, 256);
}

// Out-of-line refill for lanes near the end of the payload.
static void lane_refill_slow(mesh_lane *l) {
    lane_refill(l);
}

// Lane state in locals: uint8_t stores could alias a mesh_lane in memory, which
// would force reloads after every output byte.
#define MESH_LANE_LOAD(x, L) uint64_t x##b = (L)->bits; unsigned x##n = (L)->n; const uint8_t *x##p = (L)->p
#define MESH_LANE_SAVE(x, L) ((L)->bits = x##b, (L)->n = x##n, (L)->p = x##p)
#define MESH_LANE_REFILL(x, L, end)                                                                                     \
    do {                                                                                                                \
        if ((end) - x##p >= 8) {                                                                                        \
            x##b |= load64_le(x##p) << x##n;                                                                            \
            x##p += (63 - x##n) >> 3;                                                                                   \
            x##n |= 56;                                                                                                 \
        } else {                                                                                                        \
            MESH_LANE_SAVE(x, L);                                                                                       \
            lane_refill_slow(L);                                                                                        \
            x##b = (L)->bits;                                                                                           \
            x##n = (L)->n;                                                                                              \
            x##p = (L)->p;                                                                                              \
        }                                                                                                               \
    } while (0)
#define MESH_LANE_SYM(x, dst)                                                                                           \
    do {                                                                                                                \
        unsigned e_ = table[x##b & (MESH_TABLE_SIZE - 1)], len_ = e_ >> 8;                                              \
        bad |= len_ == 0;                                                                                               \
        (dst) = (uint8_t)e_;                                                                                            \
        x##b >>= len_;                                                                                                  \
        x##n -= len_;                                                                                                   \
    } while (0)

// Symbols 8t + k for t < rounds, for the four lanes k0 .. k0 + 3. rounds is a
// multiple of 4: one refill covers four codes of up to 10 bits.
static unsigned decode_lanes4(mesh_lane *lanes, unsigned k0, const uint16_t *table, uint8_t *out, size_t rounds) {
    mesh_lane *L0 = &lanes[k0], *L1 = &lanes[k0 + 1], *L2 = &lanes[k0 + 2], *L3 = &lanes[k0 + 3];
    const uint8_t *end = L0->end;
    MESH_LANE_LOAD(a, L0);
    MESH_LANE_LOAD(b, L1);
    MESH_LANE_LOAD(c, L2);
    MESH_LANE_LOAD(d, L3);
    unsigned bad = 0;
    uint8_t *o = out + k0;
    for (size_t t = 0; t < rounds; t += 4, o += 32) {
        MESH_LANE_REFILL(a, L0, end);
        MESH_LANE_REFILL(b, L1, end);
        MESH_LANE_REFILL(c, L2, end);
        MESH_LANE_REFILL(d, L3, end);
        for (unsigned r = 0; r < 4; r++) {
            MESH_LANE_SYM(a, o[8 * r]);
            MESH_LANE_SYM(b, o[8 * r + 1]);
            MESH_LANE_SYM(c, o[8 * r + 2]);
            MESH_LANE_SYM(d, o[8 * r + 3]);
        }
    }
    MESH_LANE_SAVE(a, L0);
    MESH_LANE_SAVE(b, L1);
    MESH_LANE_SAVE(c, L2);
    MESH_LANE_SAVE(d, L3);
    return bad;
}

static int read_coded(mesh_lane *lanes, uint8_t *out, size_t n) {
    uint16_t table[MESH_TABLE_SIZE];
    if (read_table(lanes, table) != CRUSHLZMESH_STATUS_OK) return CRUSHLZMESH_INVALID;
    // Lanes are independent bitstreams, so each group of four decodes its
    // share of the first 8 * rounds symbols on its own.
    size_t rounds = (n / MESH_LANES) & ~(size_t)3;
    unsigned bad = 0;
    if (rounds) {
        bad |= decode_lanes4(lanes, 0, table, out, rounds);
        bad |= decode_lanes4(lanes, 4, table, out, rounds);
    }
    if (bad) return CRUSHLZMESH_INVALID;
    size_t i = rounds * MESH_LANES;
    for (unsigned k = 0; i < n; i++, k = (k + 1) & 7) {
        lane_refill(&lanes[k]);
        int sym = lane_sym(&lanes[k], table, MESH_MAX_CODE);
        if (sym < 0) return CRUSHLZMESH_INVALID;
        out[i] = (uint8_t)sym;
    }
    return CRUSHLZMESH_STATUS_OK;
}

// Per-call buffers for the decoded streams.
typedef struct {
    uint8_t lits[MESH_MAX_STREAM + 16];
    uint8_t ops[MESH_MAX_STREAM];
    uint8_t ex[MESH_MAX_STREAM];
    uint8_t dists[MESH_MAX_STREAM];
    uint32_t dvals[MESH_MAX_STREAM + 1]; // one spare slot for speculative reads
} mesh_dec_bufs;

static inline int read_extra(const uint8_t **p, const uint8_t *end, uint32_t *v) {
    if (*p >= end) return CRUSHLZMESH_INVALID;
    uint8_t b = *(*p)++;
    if (b != 0xFF) {
        *v = b;
        return CRUSHLZMESH_STATUS_OK;
    }
    if (end - *p < 4) return CRUSHLZMESH_INVALID;
    *v = load32_le(*p);
    *p += 4;
    return CRUSHLZMESH_STATUS_OK;
}

static int decode_compressed_block(
    uint8_t *dst,
    size_t dst_size,
    size_t dst_start,
    size_t usize,
    const uint8_t *pl,
    size_t s1,
    size_t s2,
    unsigned nd_hi,
    uint32_t reps[4],
    mesh_dec_bufs *B
) {
    if (s2 < 9 || s1 < 9) return CRUSHLZMESH_INVALID;
    size_t E = s2 - 9;
    size_t R = s1 - 9;
    if (R > E) return CRUSHLZMESH_INVALID;
    const uint8_t *f = pl + E;
    unsigned modes = (unsigned)f[0] | ((unsigned)f[1] << 8);
    size_t counts[4] = {load16_le(f + 6), load16_le(f + 2), load16_le(f + 4), 0};
    unsigned m[4];
    for (int i = 0; i < 4; i++) {
        m[i] = (modes >> (3 * i)) & 7;
        if (m[i] > MESH_HUFF) return CRUSHLZMESH_INVALID;
    }

    mesh_lane lanes[MESH_LANES];
    int have_lanes = R < E;
    if (have_lanes) {
        unsigned w = pl[E - 1] >> 3;
        size_t tlen = MAX((size_t)4, (7 * (size_t)w + 5 + 7) / 8);
        if (E < R + tlen) return CRUSHLZMESH_INVALID;
        size_t st = E - tlen;
        mesh_lane t;
        lane_init(&t, pl + st, pl + E);
        size_t pos = R;
        for (int k = 0; k < MESH_LANES; k++) {
            size_t sz;
            if (k < 7) {
                lane_refill(&t);
                sz = lane_read(&t, w);
            } else {
                sz = st - pos;
            }
            if (sz > st - pos) return CRUSHLZMESH_INVALID;
            // Sizes only place each lane's start: as Apple's decoder accepts, a
            // lane that reads past its end continues into the bytes after it.
            lane_init(&lanes[k], pl + pos, pl + E);
            pos += sz;
        }
    }

    uint8_t *bufs[4] = {B->lits, B->ops, B->ex, B->dists};
    const uint8_t *raw = pl;
    const uint8_t *raw_end = pl + R;
    for (int i = 0; i < 4; i++) {
        if (i == 3) {
            size_t nd = 0;
            for (size_t k = 0; k < counts[1]; k++) nd += (B->ops[k] & 63) >= 32;
            // The low byte of the count ends the payload; the high byte follows it.
            if (nd != (f[8] | (size_t)nd_hi << 8)) return CRUSHLZMESH_INVALID;
            counts[3] = nd;
        }
        size_t n = counts[i];
        if (m[i] == MESH_RAW) {
            if ((size_t)(raw_end - raw) < n) return CRUSHLZMESH_INVALID;
            memcpy(bufs[i], raw, n);
            raw += n;
        } else if (m[i] == MESH_RLE) {
            if (raw >= raw_end) return CRUSHLZMESH_INVALID;
            memset(bufs[i], *raw++, n);
        } else {
            if (!have_lanes) return CRUSHLZMESH_INVALID;
            if (read_coded(lanes, bufs[i], n) != CRUSHLZMESH_STATUS_OK) return CRUSHLZMESH_INVALID;
        }
    }
    if (raw != raw_end) return CRUSHLZMESH_INVALID;

    // Far-distance bits follow the coded streams; distance j uses lane j % 8.
    size_t nd = counts[3];
    for (size_t j = 0; j < nd; j++) {
        unsigned b = B->dists[j];
        unsigned k = b >> 3;
        uint64_t d = (b & 7) + 1;
        if (k) {
            if (!have_lanes) return CRUSHLZMESH_INVALID;
            mesh_lane *l = &lanes[j & 7];
            lane_refill(l);
            uint64_t a = ((uint64_t)1 << k) | lane_read(l, k);
            d = (((a - 1) << 3) | (b & 7)) + 1;
            // Apple keeps the low 32 bits; the match checks the result.
            d &= 0xFFFFFFFFu;
        }
        B->dvals[j] = (uint32_t)d;
    }
    // Execute the ops. The usize cap truncates the final match.
    // Fast paths copy in 16-byte chunks and may write up to 16 bytes past
    // the current position, but never past dst + dst_size.
    uint8_t *o = dst + dst_start;
    uint8_t *const oend = o + usize;
    uint8_t *const wend = dst_size >= 32 ? dst + dst_size - 32 : dst;
    const uint8_t *lit = B->lits;
    const uint8_t *lit_end = B->lits + counts[0];
    const uint8_t *ex = B->ex;
    const uint8_t *ex_end = B->ex + counts[2];
    const uint32_t *dv = B->dvals;
    const uint32_t *dv_end = B->dvals + nd;
    const uint8_t *opp = B->ops;
    const uint8_t *ope = B->ops + counts[1];
    size_t first_bonus = dst_start == 0;
    uint32_t r0 = reps[0], r1 = reps[1], r2 = reps[2], r3 = reps[3];
    // Rep and new-distance matches go through the same arithmetic: a new
    // distance is read speculatively (dvals has a spare slot) and kept only for
    // mcode >= 32, which moves the reps like using slot 3.
    while (opp < ope && o < oend) {
        unsigned op = *opp++;
        unsigned lc = op >> 6;
        unsigned mc = op & 63;
        uint32_t v;
        size_t nl = lc;
        if (lc == 3) {
            if (read_extra(&ex, ex_end, &v)) return CRUSHLZMESH_INVALID;
            nl = 3 + (size_t)v;
        }
        nl += first_bonus;
        first_bonus = 0;
        // Only the literals actually written must exist; the block's size can
        // cut the final run short, but not past r32(lits) + the current op
        // index, which Apple's decoder rejects.
        if ((size_t)(lit - B->lits) + nl > MESH_R32(counts[0]) + (size_t)(opp - 1 - B->ops)) return CRUSHLZMESH_INVALID;
        size_t take = MIN(nl, (size_t)(oend - o));
        if ((size_t)(lit_end - lit) < take) return CRUSHLZMESH_INVALID;
        if (take <= 16 && o <= wend) {
            memcpy(o, lit, 16);
        } else if (o + take <= wend) {
            for (size_t i = 0; i < take; i += 16) memcpy(o + i, lit + i, 16);
        } else {
            memcpy(o, lit, take);
        }
        lit += take;
        o += take;

        unsigned isnew = mc >= 32;
        uint32_t rv = mc & 16 ? (mc & 8 ? r3 : r2) : (mc & 8 ? r1 : r0);
        uint32_t d = isnew ? *dv : rv;
        unsigned r = isnew ? 3 : mc >> 3;
        size_t ml = isnew ? mc - 30 : (mc & 7) + 2;
        if (isnew ? mc == 63 : (mc & 7) == 7) {
            if (read_extra(&ex, ex_end, &v)) return CRUSHLZMESH_INVALID;
            ml = (isnew ? 33 : 9) + (size_t)v;
        }
        if (isnew) {
            if (dv >= dv_end) return CRUSHLZMESH_INVALID;
            dv++;
        }
        // Move to front.
        r3 = r >= 3 ? r2 : r3;
        r2 = r >= 2 ? r1 : r2;
        r1 = r >= 1 ? r0 : r1;
        r0 = d;
        if (o >= oend) break;
        // A distance that wrapped to 0 is rejected, but only when a match byte
        // is written, as Apple does.
        if (d == 0 || d > (size_t)(o - dst)) return CRUSHLZMESH_INVALID;
        const uint8_t *m = o - d;
        if (o + ml <= wend) {
            if (d >= 16) {
                // Two sequential 16-byte copies stay correct for d >= 16.
                memcpy(o, m, 16);
                memcpy(o + 16, m + 16, 16);
                for (size_t i = 32; i < ml; i += 16) memcpy(o + i, m + i, 16);
            } else if (d >= 8) {
                for (size_t i = 0; i < ml; i += 8) memcpy(o + i, m + i, 8);
            } else {
                // Spread the period to at least 8 bytes, then copy 8 at a time.
                static const unsigned inc[8] = {0, 1, 2, 1, 0, 4, 4, 4};
                static const int dec[8] = {0, 0, 0, -1, -4, 1, 2, 3};
                o[0] = m[0];
                o[1] = m[1];
                o[2] = m[2];
                o[3] = m[3];
                m += inc[d];
                memcpy(o + 4, m, 4);
                m -= dec[d];
                for (size_t i = 8; i < ml; i += 8) memcpy(o + i, m + i - 8, 8);
            }
            o += ml;
            if (o > oend) o = oend;
        } else {
            ml = MIN(ml, (size_t)(oend - o));
            for (size_t i = 0; i < ml; i++) o[i] = m[i];
            o += ml;
        }
    }
    reps[0] = r0;
    reps[1] = r1;
    reps[2] = r2;
    reps[3] = r3;
    // Apple's decoder also rejects blocks with unused stream elements.
    if (o != oend || opp != ope || lit != lit_end || ex != ex_end || dv != dv_end) return CRUSHLZMESH_INVALID;
    return CRUSHLZMESH_STATUS_OK;
}

int crushlzmesh_decode_buffer(
    uint8_t *dst,
    size_t dst_size,
    const uint8_t *src,
    size_t src_size,
    size_t *decoded_size
) {
    if (!src || !decoded_size) return CRUSHLZMESH_INVALID;
    *decoded_size = 0;

    size_t src_pos = 0;
    size_t dst_pos = 0;
    uint32_t reps[4] = {1, 1, 1, 1};
    mesh_dec_bufs *bufs = NULL;
    int rc = CRUSHLZMESH_INVALID;

    while (src_pos < src_size) {
        uint8_t btype = src[src_pos++];
        if (btype == CRUSHLZMESH_EOS) {
            rc = CRUSHLZMESH_STATUS_OK;
            break;
        } else if (btype == CRUSHLZMESH_BLOCK_RAW) {
            if (src_size - src_pos < 4) goto done;
            uint32_t usize = load32_le(src + src_pos);
            src_pos += 4;
            if (src_size - src_pos < usize) goto done;
            if (dst_size - dst_pos < usize) {
                rc = CRUSHLZMESH_OUTPUT_TOO_SMALL;
                goto done;
            }
            if (usize) memcpy(dst + dst_pos, src + src_pos, usize);
            dst_pos += usize;
            src_pos += usize;
        } else if (btype == CRUSHLZMESH_BLOCK_COMP) {
            if (src_size - src_pos < 8) goto done;
            uint32_t usize = load32_le(src + src_pos);
            uint16_t s1 = load16_le(src + src_pos + 4);
            uint16_t s2 = load16_le(src + src_pos + 6);
            src_pos += 8;
            if (src_size - src_pos < (size_t)s2 + 1) goto done;
            if (s2 >= usize) goto done;
            if (dst_size - dst_pos < usize) {
                rc = CRUSHLZMESH_OUTPUT_TOO_SMALL;
                goto done;
            }
            if (!bufs) {
                bufs = (mesh_dec_bufs *)malloc(sizeof(*bufs));
                if (!bufs) goto done;
            }
            if (decode_compressed_block(dst, dst_size, dst_pos, usize, src + src_pos, s1, s2, src[src_pos + s2], reps, bufs) !=
                CRUSHLZMESH_STATUS_OK)
                goto done;
            dst_pos += usize;
            src_pos += (size_t)s2 + 1;
        } else {
            goto done;
        }
    }
done:
    free(bufs);
    *decoded_size = dst_pos;
    return rc;
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

#define MESH_PAYLOAD_MAX 65535u
#define MESH_PRICE_SHIFT 4 // prices are in 1/16 bit
#define MESH_INF 0xFFFFFFFFu
#define MESH_NO_POS 0xFFFFFFFFu

typedef struct {
    uint32_t lits; // literals before the match
    uint32_t len;  // match length; 0 for a trailing literal-only run
    uint32_t dist;
    uint32_t est;  // estimated cost in 1/16 bit, for block sizing
} mesh_seq;

// Length-limited Huffman code lengths by package-merge. Unused symbols get 0.
static void huff_lengths(const uint32_t *freq, unsigned nsym, unsigned limit, uint8_t *lens) {
    unsigned idx[256];
    unsigned n = 0;
    memset(lens, 0, nsym);
    for (unsigned s = 0; s < nsym; s++)
        if (freq[s]) idx[n++] = s;
    if (n == 0) return;
    if (n == 1) {
        lens[idx[0]] = 1;
        return;
    }
    // Stable sort by frequency (ties stay in symbol order): LSD radix sort
    // over the bytes the largest frequency needs.
    uint32_t maxf = 0;
    for (unsigned i = 0; i < n; i++) maxf = MAX(maxf, freq[idx[i]]);
    unsigned tmp[256];
    for (unsigned sh = 0; sh < 32 && (maxf >> sh); sh += 8) {
        unsigned cnt[257] = {0};
        for (unsigned i = 0; i < n; i++) cnt[((freq[idx[i]] >> sh) & 0xFF) + 1]++;
        for (unsigned b = 0; b < 256; b++) cnt[b + 1] += cnt[b];
        for (unsigned i = 0; i < n; i++) tmp[cnt[(freq[idx[i]] >> sh) & 0xFF]++] = idx[i];
        memcpy(idx, tmp, n * sizeof(unsigned));
    }
    static const unsigned QMAX = 512;
    uint64_t wq[2][512];
    uint8_t leaf[MESH_MAX_CODE][512];
    unsigned qn[MESH_MAX_CODE];
    // Level limit-1 is the deepest and holds only leaves.
    int cur = 0;
    for (unsigned i = 0; i < n; i++) {
        wq[cur][i] = freq[idx[i]];
        leaf[limit - 1][i] = 1;
    }
    qn[limit - 1] = n;
    for (int lev = (int)limit - 2; lev >= 0; lev--) {
        unsigned np = qn[lev + 1] / 2;
        int nxt = cur ^ 1;
        unsigned a = 0, b = 0, k = 0;
        while ((a < n || b < np) && k < QMAX) {
            uint64_t pw = b < np ? wq[cur][2 * b] + wq[cur][2 * b + 1] : 0;
            if (b >= np || (a < n && freq[idx[a]] <= pw)) {
                wq[nxt][k] = freq[idx[a++]];
                leaf[lev][k++] = 1;
            } else {
                wq[nxt][k] = pw;
                b++;
                leaf[lev][k++] = 0;
            }
        }
        qn[lev] = k;
        cur = nxt;
    }
    unsigned t = 2 * n - 2;
    for (unsigned lev = 0; lev < limit && t; lev++) {
        unsigned x = 0;
        for (unsigned i = 0; i < t && i < qn[lev]; i++) x += leaf[lev][i];
        for (unsigned i = 0; i < x; i++) lens[idx[i]]++;
        t = 2 * (t - x);
    }
}

// Bit-reversed canonical codes, ready for LSB-first writing.
static void huff_codes(const uint8_t *lens, unsigned nsym, uint16_t *rcodes) {
    unsigned count[MESH_MAX_CODE + 1] = {0};
    for (unsigned s = 0; s < nsym; s++) count[lens[s]]++;
    count[0] = 0;
    unsigned next[MESH_MAX_CODE + 2];
    unsigned code = 0;
    for (unsigned len = 1; len <= MESH_MAX_CODE; len++) {
        code = (code + count[len - 1]) << 1;
        next[len] = code;
    }
    for (unsigned s = 0; s < nsym; s++)
        rcodes[s] = lens[s] ? (uint16_t)bitrev(next[lens[s]]++, lens[s]) : 0;
}

static inline void store64_le(uint8_t *p, uint64_t v) {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    memcpy(p, &v, 8);
}

// LSB-first bit writer. Every put stores 8 bytes at p, so the buffer needs 8
// bytes of slack past `end`; whole bytes are committed and n stays below 8.
typedef struct {
    uint8_t *start;
    uint8_t *p;
    uint8_t *end;
    uint64_t acc;
    unsigned n;
} mesh_bw;

static void bw_init(mesh_bw *w, uint8_t *buf, size_t cap) {
    w->start = w->p = buf;
    w->end = buf + cap;
    w->acc = 0;
    w->n = 0;
}

// Writes k <= 32 bits.
static inline void bw_put(mesh_bw *w, uint64_t v, unsigned k) {
    uint64_t acc = w->acc | v << w->n;
    unsigned n = w->n + k;
    store64_le(w->p, acc);
    w->p += n >> 3;
    w->acc = acc >> (n & ~7u);
    w->n = n & 7;
}

// Pads to a byte boundary. Returns 0 if the writer ran past its end.
static int bw_flush(mesh_bw *w) {
    if (w->n) {
        store64_le(w->p, w->acc);
        w->p++;
        w->acc = 0;
        w->n = 0;
    }
    return w->p <= w->end;
}

// Table layout: 11 3-bit code-length-code lengths, 16 2-bit half masks,
// then each participating symbol's length spread over the lanes.
typedef struct {
    uint8_t cllen[11];
    uint16_t clcode[11];
    unsigned halves;
    size_t bits;
} mesh_table_plan;

static void plan_table(const uint8_t *lens, mesh_table_plan *t) {
    uint32_t clfreq[11] = {0};
    t->halves = 0;
    for (unsigned h = 0; h < 32; h++) {
        int any = 0;
        for (unsigned i = 0; i < 8; i++) any |= lens[h * 8 + i] != 0;
        if (!any) continue;
        t->halves |= 1u << h;
        for (unsigned i = 0; i < 8; i++) clfreq[lens[h * 8 + i]]++;
    }
    unsigned used = 0, last = 0;
    for (unsigned v = 0; v < 11; v++)
        if (clfreq[v]) {
            used++;
            last = v;
        }
    if (used < 2) clfreq[last == 0 ? 1 : 0] = 1;
    huff_lengths(clfreq, 11, 7, t->cllen);
    huff_codes(t->cllen, 11, t->clcode);
    t->bits = 33 + 32;
    for (unsigned h = 0; h < 32; h++)
        if (t->halves >> h & 1)
            for (unsigned i = 0; i < 8; i++) t->bits += t->cllen[lens[h * 8 + i]];
}

static void write_table(mesh_bw *lanes, const uint8_t *lens, const mesh_table_plan *t) {
    for (unsigned v = 0; v < 11; v++) bw_put(&lanes[0], t->cllen[v], 3);
    for (unsigned hi = 0; hi < 16; hi++) bw_put(&lanes[0], (t->halves >> (2 * hi)) & 3, 2);
    unsigned j = 0;
    for (unsigned h = 0; h < 32; h++) {
        if (!(t->halves >> h & 1)) continue;
        for (unsigned i = 0; i < 8; i++, j++) {
            unsigned v = lens[h * 8 + i];
            bw_put(&lanes[j & 7], t->clcode[v], t->cllen[v]);
        }
    }
}

typedef struct {
    unsigned mode;
    uint8_t lens[256];
    uint16_t codes[256];
    mesh_table_plan plan;
} mesh_stream_plan;

static void plan_stream(const uint8_t *data, size_t n, mesh_stream_plan *sp) {
    uint32_t freq[256], f4[3][256];
    memset(freq, 0, sizeof(freq));
    memset(f4, 0, sizeof(f4));
    size_t i = 0;
    // Four counters per symbol so runs of one byte do not serialize on a store.
    for (; i + 4 <= n; i += 4) {
        freq[data[i]]++;
        f4[0][data[i + 1]]++;
        f4[1][data[i + 2]]++;
        f4[2][data[i + 3]]++;
    }
    for (; i < n; i++) freq[data[i]]++;
    for (unsigned k = 0; k < 256; k++) freq[k] += f4[0][k] + f4[1][k] + f4[2][k];
    unsigned distinct = 0;
    for (unsigned s = 0; s < 256; s++) distinct += freq[s] != 0;
    if (n == 0) {
        sp->mode = MESH_RAW;
        return;
    }
    if (distinct == 1) {
        sp->mode = MESH_RLE;
        return;
    }
    huff_lengths(freq, 256, MESH_MAX_CODE, sp->lens);
    huff_codes(sp->lens, 256, sp->codes);
    plan_table(sp->lens, &sp->plan);
    size_t bits = sp->plan.bits;
    for (unsigned s = 0; s < 256; s++) bits += (size_t)freq[s] * sp->lens[s];
    sp->mode = (bits + 7) / 8 + 8 < n ? MESH_HUFF : MESH_RAW;
}

typedef struct {
    uint8_t lits[MESH_MAX_STREAM + 32];
    uint8_t ops[MESH_MAX_STREAM];
    uint8_t ex[MESH_MAX_STREAM];
    uint8_t dists[MESH_MAX_STREAM];
    uint32_t far[MESH_MAX_STREAM];
    uint8_t lanebuf[MESH_LANES][MESH_PAYLOAD_MAX + 16];
} mesh_enc_bufs;

static inline unsigned bitlen32(uint32_t v) {
    return v ? 32 - (unsigned)__builtin_clz(v) : 0;
}

// Distance byte k<<3|low plus k raw bits holding a - 2^k.
static inline unsigned dist_code(uint32_t d, uint32_t *v, unsigned *k) {
    uint32_t x = d - 1;
    uint32_t a = (x >> 3) + 1;
    unsigned kk = bitlen32(a) - 1;
    *k = kk;
    *v = a - (1u << kk);
    return (kk << 3) | (x & 7);
}

enum { MESH_WB_OK = 0, MESH_WB_TOO_BIG = 1, MESH_WB_RAW = 2 };

// One block's streams, as built by build_streams.
typedef struct {
    size_t take;  // seqs in the block
    size_t usize; // their decoded length
    size_t nl, no, ne, nd;
    int far;      // some distance has raw bits
    uint32_t reps[4];
} mesh_block;

// Builds the streams for the longest prefix of seqs[0, nq) that fits the
// decoder's budget: Apple's decoder rejects blocks whose stream sizes
// exceed it (see the format notes). src points at the block's first byte; src_end bounds over-reads.
static void build_streams(const uint8_t *src, const uint8_t *src_end, const mesh_seq *q, size_t nq, int stream_start,
                          const uint32_t reps[4], mesh_enc_bufs *B, mesh_block *k) {
    size_t nl = 0, no = 0, ne = 0, nd = 0, us = 0, i;
    unsigned farbits = 0;
    uint32_t r0 = reps[0], r1 = reps[1], r2 = reps[2], r3 = reps[3];
    const uint8_t *p = src;
    for (i = 0; i < nq; i++) {
        const mesh_seq *t = &q[i];
        uint32_t lits = t->lits, L = t->len, d = t->dist;
        uint32_t enc = lits - (stream_start && i == 0);
        size_t e2 = ne + (enc < 3 ? 0 : enc - 3 < 255 ? 1 : 5), d2 = nd;
        int slot = 4;
        if (L) {
            slot = r0 == d ? 0 : r1 == d ? 1 : r2 == d ? 2 : r3 == d ? 3 : -1;
            if (slot >= 0) {
                if (L > 8) e2 += L - 9 < 255 ? 1 : 5;
            } else {
                if (L > 32) e2 += L - 33 < 255 ? 1 : 5;
                d2++;
            }
        }
        size_t cost = MESH_R32(nl + lits) + MESH_R32(no + 1) + MESH_R32(e2) + MESH_R32(d2) + MESH_R32(4 * d2);
        if (cost > MESH_SCRATCH_MAX || nl + lits > MESH_MAX_STREAM) break;

        if (lits <= 16 && src_end - p >= 16) {
            memcpy(B->lits + nl, p, 16);
        } else {
            memcpy(B->lits + nl, p, lits);
        }
        nl += lits;
        p += lits;
        unsigned lc = enc < 3 ? enc : 3;
        uint8_t *ex = B->ex;
        if (lc == 3) {
            if (enc - 3 < 255) ex[ne++] = (uint8_t)(enc - 3);
            else {
                ex[ne] = 0xFF;
                store32_le(ex + ne + 1, enc - 3);
                ne += 5;
            }
        }
        unsigned mc = 0;
        if (slot == 4) {
            // literal-only seq
        } else if (slot >= 0) {
            if (L <= 8) {
                mc = (unsigned)slot << 3 | (L - 2);
            } else {
                mc = (unsigned)slot << 3 | 7;
                if (L - 9 < 255) ex[ne++] = (uint8_t)(L - 9);
                else {
                    ex[ne] = 0xFF;
                    store32_le(ex + ne + 1, L - 9);
                    ne += 5;
                }
            }
            if (slot >= 3) r3 = r2;
            if (slot >= 2) r2 = r1;
            if (slot >= 1) r1 = r0;
            r0 = d;
        } else {
            if (L <= 32) {
                mc = L + 30;
            } else {
                mc = 63;
                if (L - 33 < 255) ex[ne++] = (uint8_t)(L - 33);
                else {
                    ex[ne] = 0xFF;
                    store32_le(ex + ne + 1, L - 33);
                    ne += 5;
                }
            }
            unsigned kb;
            uint32_t v;
            unsigned b = dist_code(d, &v, &kb);
            B->dists[nd] = (uint8_t)b;
            B->far[nd++] = v;
            farbits |= kb;
            r3 = r2;
            r2 = r1;
            r1 = r0;
            r0 = d;
        }
        B->ops[no++] = (uint8_t)(lc << 6 | mc);
        p += L;
        us += lits + L;
    }
    k->take = i;
    k->usize = us;
    k->nl = nl;
    k->no = no;
    k->ne = ne;
    k->nd = nd;
    k->far = farbits != 0;
    k->reps[0] = r0;
    k->reps[1] = r1;
    k->reps[2] = r2;
    k->reps[3] = r3;
}

// Writes one compressed block from streams built by build_streams. Returns
// its size, or 0 with *why set to MESH_WB_TOO_BIG (format limits) or
// MESH_WB_RAW (not worth compressing).
static size_t write_block(uint8_t *out, size_t cap, const mesh_block *k, mesh_enc_bufs *B, int *why) {
    *why = MESH_WB_TOO_BIG;
    size_t nl = k->nl, no = k->no, ne = k->ne, nd = k->nd, usize = k->usize;
    const uint8_t *data[4] = {B->lits, B->ops, B->ex, B->dists};
    size_t counts[4] = {nl, no, ne, nd};
    mesh_stream_plan sp[4];
    int need_lanes = 0;
    size_t raw_len = 0;
    for (int i = 0; i < 4; i++) {
        plan_stream(data[i], counts[i], &sp[i]);
        need_lanes |= sp[i].mode == MESH_HUFF;
        raw_len += sp[i].mode == MESH_RAW ? counts[i] : sp[i].mode == MESH_RLE ? 1 : 0;
    }
    need_lanes |= k->far;
    if (raw_len + 9 + 15 > usize) {
        *why = MESH_WB_RAW;
        return 0;
    }

    uint8_t *pl = out + 9;
    size_t room = cap > 10 ? cap - 10 : 0;
    if (room > MESH_PAYLOAD_MAX) room = MESH_PAYLOAD_MAX;
    if (raw_len + 9 > room) return 0;
    size_t pos = 0;
    for (int i = 0; i < 4; i++) {
        if (sp[i].mode == MESH_RAW) {
            memcpy(pl + pos, data[i], counts[i]);
            pos += counts[i];
        } else if (sp[i].mode == MESH_RLE) {
            pl[pos++] = data[i][0];
        }
    }
    size_t R = pos;
    if (need_lanes) {
        mesh_bw lanes[MESH_LANES];
        for (int k = 0; k < MESH_LANES; k++) bw_init(&lanes[k], B->lanebuf[k], MESH_PAYLOAD_MAX);
        for (int i = 0; i < 4; i++) {
            if (sp[i].mode != MESH_HUFF) continue;
            write_table(lanes, sp[i].lens, &sp[i].plan);
            uint32_t ce[256];
            for (unsigned c = 0; c < 256; c++) ce[c] = sp[i].codes[c] | (uint32_t)sp[i].lens[c] << 16;
            const uint8_t *d = data[i];
            size_t n = counts[i], j = 0;
            for (; j + 8 <= n; j += 8)
                for (unsigned l = 0; l < MESH_LANES; l++) {
                    uint32_t e = ce[d[j + l]];
                    bw_put(&lanes[l], e & 0xFFFF, e >> 16);
                }
            for (; j < n; j++) {
                uint32_t e = ce[d[j]];
                bw_put(&lanes[j & 7], e & 0xFFFF, e >> 16);
            }
        }
        if (k->far)
            for (size_t j = 0; j < nd; j++) bw_put(&lanes[j & 7], B->far[j], B->dists[j] >> 3);
        size_t sizes[MESH_LANES], total = 0, maxsz = 0;
        for (int l = 0; l < MESH_LANES; l++) {
            // A non-empty lane ends with a 1 bit before the zero padding.
            if (lanes[l].p != lanes[l].start || lanes[l].n) bw_put(&lanes[l], 1, 1);
            if (!bw_flush(&lanes[l])) return 0;
            sizes[l] = (size_t)(lanes[l].p - lanes[l].start);
            total += sizes[l];
            if (l < 7 && sizes[l] > maxsz) maxsz = sizes[l];
        }
        unsigned w = bitlen32((uint32_t)maxsz);
        if (w == 0) w = 1;
        size_t tlen = MAX((size_t)4, (7 * (size_t)w + 5 + 7) / 8);
        if (R + total + tlen + 9 > room) return 0;
        for (int l = 0; l < MESH_LANES; l++) {
            memcpy(pl + pos, B->lanebuf[l], sizes[l]);
            pos += sizes[l];
        }
        uint8_t *tr = pl + pos;
        uint8_t tb[32] = {0};
        mesh_bw tw;
        bw_init(&tw, tb, 24);
        for (int l = 0; l < 7; l++) bw_put(&tw, sizes[l], w);
        bw_flush(&tw);
        memcpy(tr, tb, tlen);
        tr[tlen - 1] |= (uint8_t)(w << 3);
        pos += tlen;
    }
    unsigned modes = sp[0].mode | sp[1].mode << 3 | sp[2].mode << 6 | sp[3].mode << 9;
    uint8_t *f = pl + pos;
    f[0] = (uint8_t)modes;
    f[1] = (uint8_t)(modes >> 8);
    store16_le(f + 2, (uint16_t)no);
    store16_le(f + 4, (uint16_t)ne);
    store16_le(f + 6, (uint16_t)nl);
    f[8] = (uint8_t)nd;
    pos += 9;
    // Keep compressed blocks at least 5 bytes under raw so the bound holds.
    if (pos + 10 + 5 > usize) {
        *why = MESH_WB_RAW;
        return 0;
    }

    out[0] = CRUSHLZMESH_BLOCK_COMP;
    store32_le(out + 1, (uint32_t)usize);
    store16_le(out + 5, (uint16_t)(R + 9));
    store16_le(out + 7, (uint16_t)pos);
    pl[pos] = (uint8_t)(nd >> 8);
    return pos + 10;
}

// ---------------------------------------------------------------------------
// Match finding and parsing
// ---------------------------------------------------------------------------

typedef struct {
    uint32_t len;
    uint32_t dist;
} mesh_match;

// Binary tree match finder (as in LZMA's BT4) with a small 3-byte hash for
// close short matches.
typedef struct {
    uint32_t *head;
    uint32_t *head3;
    uint32_t *son; // two children per window position
    uint32_t wmask;
    size_t n; // input size; the tree compares up to here, not the caller's end
    unsigned hbits;
    unsigned depth;
    uint32_t nice;
} mesh_mf;

#define MESH_HASH3_BITS 14

static inline uint32_t hash4(const uint8_t *p, unsigned bits) {
    return (load32_le(p) * 2654435761u) >> (32 - bits);
}

static inline uint32_t hash3(const uint8_t *p) {
    return ((load32_le(p) & 0xFFFFFF) * 2654435761u) >> (32 - MESH_HASH3_BITS);
}

static inline size_t match_len(const uint8_t *a, const uint8_t *b, const uint8_t *end) {
    const uint8_t *s = b;
    while (end - b >= 8) {
        uint64_t x, y;
        memcpy(&x, a, 8);
        memcpy(&y, b, 8);
        if (x != y) return (size_t)(b - s) + ((unsigned)__builtin_ctzll(x ^ y) >> 3);
        a += 8;
        b += 8;
    }
    while (b < end && *a == *b) {
        a++;
        b++;
    }
    return (size_t)(b - s);
}

static unsigned bt_find(mesh_mf *mf, const uint8_t *src, size_t pos, size_t end, mesh_match *out, unsigned max_out,
                        unsigned n, size_t best);

// Collects matches at `pos` with strictly increasing length, then inserts pos.
static unsigned mf_find(mesh_mf *mf, const uint8_t *src, size_t pos, size_t end, mesh_match *out, unsigned max_out) {
    unsigned n = 0;
    if (end - pos < 4) return 0;
    const uint8_t *ip = src + pos;
    const uint8_t *iend = src + end;
    size_t best = 2;
    uint32_t h3 = hash3(ip);
    uint32_t c3 = mf->head3[h3];
    mf->head3[h3] = (uint32_t)pos;
    if (c3 != MESH_NO_POS && pos - c3 < 4096) {
        size_t l = match_len(src + c3, ip, iend);
        if (l > best) {
            best = l;
            out[n].len = (uint32_t)l;
            out[n++].dist = (uint32_t)(pos - c3);
        }
    }
    return bt_find(mf, src, pos, end, out, max_out, n, best);
}

// Binary tree match finder over a window of wmask + 1 positions, keyed by a
// 4-byte hash (as in LZMA's BT4). Every call also inserts pos. With out ==
// NULL it only updates the tree.
static unsigned bt_find(mesh_mf *mf, const uint8_t *src, size_t pos, size_t end, mesh_match *out, unsigned max_out,
                        unsigned n, size_t best) {
    const uint8_t *ip = src + pos;
    uint32_t h = hash4(ip, mf->hbits);
    uint32_t cur = mf->head[h];
    mf->head[h] = (uint32_t)pos;
    uint32_t *son = mf->son, wm = mf->wmask;
    uint32_t *ptr0 = &son[2 * (pos & wm) + 1];
    uint32_t *ptr1 = &son[2 * (pos & wm)];
    size_t limit = MIN((size_t)mf->nice, mf->n - pos);
    size_t len0 = 0, len1 = 0;
    for (unsigned d = mf->depth;; d--) {
        if (cur == MESH_NO_POS || d == 0 || pos - cur > wm) {
            *ptr0 = *ptr1 = MESH_NO_POS;
            break;
        }
        uint32_t *pair = &son[2 * (cur & wm)];
        const uint8_t *pb = src + cur;
        size_t len = MIN(len0, len1);
        if (pb[len] == ip[len]) {
            len += match_len(pb + len, ip + len, ip + limit);
            size_t full = MIN(len, end - pos);
            if (full > best && out) {
                best = full;
                if (len == limit && full == len) full += match_len(pb + len, ip + len, src + end);
                if (n < max_out) n++;
                out[n - 1].len = (uint32_t)full;
                out[n - 1].dist = (uint32_t)(pos - cur);
            }
            if (len == limit) {
                *ptr1 = pair[0];
                *ptr0 = pair[1];
                break;
            }
        }
        if (pb[len] < ip[len]) {
            *ptr1 = cur;
            ptr1 = &pair[1];
            cur = *ptr1;
            len1 = len;
        } else {
            *ptr0 = cur;
            ptr0 = &pair[0];
            cur = *ptr0;
            len0 = len;
        }
    }
    return n;
}

// The tree walk is a chain of cache misses; this starts the first one for
// position pos ahead of time.
static inline void mf_prefetch(const mesh_mf *mf, const uint8_t *src, size_t pos, size_t end) {
    if (end - pos < 4) return;
    uint32_t c = mf->head[hash4(src + pos, mf->hbits)];
    if (c != MESH_NO_POS) {
        __builtin_prefetch(&mf->son[2 * (c & mf->wmask)]);
        __builtin_prefetch(src + c);
    }
}

static void mf_insert(mesh_mf *mf, const uint8_t *src, size_t pos, size_t end) {
    if (end - pos < 4) return;
    mf->head3[hash3(src + pos)] = (uint32_t)pos;
    bt_find(mf, src, pos, end, NULL, 0, 0, 0);
}

typedef struct {
    uint16_t lit[256];
    uint16_t op[256];
    uint16_t ex[256];
    uint16_t dist[256];
} mesh_prices;

static void prices_from_freq(uint16_t *out, const uint32_t *freq, unsigned unseen_bits) {
    uint8_t lens[256];
    uint32_t f[256];
    unsigned used = 0;
    for (unsigned s = 0; s < 256; s++) {
        f[s] = freq[s];
        used += f[s] != 0;
    }
    if (used < 2) {
        for (unsigned s = 0; s < 256; s++) out[s] = (uint16_t)((f[s] ? 1 : unseen_bits) << MESH_PRICE_SHIFT);
        return;
    }
    huff_lengths(f, 256, MESH_MAX_CODE, lens);
    for (unsigned s = 0; s < 256; s++)
        out[s] = (uint16_t)((lens[s] ? lens[s] : unseen_bits) << MESH_PRICE_SHIFT);
}

static inline uint32_t price_extra(const mesh_prices *pr, uint32_t v) {
    return v < 255 ? pr->ex[v] : pr->ex[255] + (32u << MESH_PRICE_SHIFT);
}

// How a node's reps follow from its predecessor's.
enum { MESH_RC_NEW = 4, MESH_RC_LIT = 5 }; // 0..3: that rep slot moved to the front

// A parse node; its price lives in a separate array (mesh_parser.price).
typedef struct {
    uint32_t litlen;
    uint32_t prev;
    uint32_t len;
    uint32_t dist;
    uint32_t rc;
    uint32_t reps[4]; // set when the node is visited
} mesh_node;

typedef struct {
    mesh_seq *v;
    size_t n;
    size_t cap;
} mesh_seqs;

static int seqs_push(mesh_seqs *s, mesh_seq q) {
    if (s->n == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 4096;
        mesh_seq *nv = (mesh_seq *)realloc(s->v, nc * sizeof(*nv));
        if (!nv) return 0;
        s->v = nv;
        s->cap = nc;
    }
    s->v[s->n++] = q;
    return 1;
}

#define MESH_MAX_CAND 12

typedef struct {
    const uint8_t *src;
    size_t n;
    mesh_mf mf;
    mesh_prices pr;
    unsigned iterations;
    uint32_t nice;
    // per-chunk state
    mesh_node *nodes;
    uint32_t *price; // per node, kept apart so runs of lengths compare as vectors
    mesh_seq *best; // the cheapest iteration's seqs for the current chunk
    mesh_match *cand;
    uint8_t *ncand;
    size_t chunk;
} mesh_parser;


static inline void relax(mesh_node *nd, uint32_t *price, size_t t, uint32_t p, uint32_t from, uint32_t len,
                         uint32_t dist, uint32_t rc) {
    if (p < price[t]) {
        price[t] = p;
        mesh_node *to = &nd[t];
        to->litlen = 0;
        to->prev = from;
        to->len = len;
        to->dist = dist;
        to->rc = rc;
    }
}

// Bit k set where base + lp[k] < price[k], for k < 8.
static inline unsigned less8(uint32_t base, const uint32_t *lp, const uint32_t *price) {
#if defined(__AVX2__)
    const __m256i bias = _mm256_set1_epi32((int)0x80000000u);
    __m256i p = _mm256_add_epi32(_mm256_set1_epi32((int)base), _mm256_loadu_si256((const __m256i *)lp));
    __m256i q = _mm256_loadu_si256((const __m256i *)price);
    __m256i lt = _mm256_cmpgt_epi32(_mm256_xor_si256(q, bias), _mm256_xor_si256(p, bias));
    return (unsigned)_mm256_movemask_ps(_mm256_castsi256_ps(lt));
#elif defined(__ARM_NEON) && defined(__aarch64__)
    static const uint32_t bits[8] = {1, 2, 4, 8, 16, 32, 64, 128};
    uint32x4_t b = vdupq_n_u32(base);
    uint32x4_t m0 = vcltq_u32(vaddq_u32(b, vld1q_u32(lp)), vld1q_u32(price));
    uint32x4_t m1 = vcltq_u32(vaddq_u32(b, vld1q_u32(lp + 4)), vld1q_u32(price + 4));
    return vaddvq_u32(vandq_u32(m0, vld1q_u32(bits))) | vaddvq_u32(vandq_u32(m1, vld1q_u32(bits + 4)));
#else
    unsigned m = 0;
    for (unsigned k = 0; k < 8; k++) m |= (unsigned)(base + lp[k] < price[k]) << k;
    return m;
#endif
}

// Relaxes nodes i + l for l in [a, b] with prices base + lp[l]. Few of these
// win, so eight lengths are compared at once and only winners are written.
static inline void relax_run(mesh_node *nd, uint32_t *price, size_t i, size_t a, size_t b, uint32_t base,
                             const uint32_t *lp, uint32_t dist, uint32_t rc) {
    size_t l = a;
    const uint32_t *pi = price + i;
    for (; l + 8 <= b + 1; l += 8) {
        unsigned m = less8(base, lp + l, pi + l);
        while (m) {
            unsigned k = (unsigned)__builtin_ctz(m);
            m &= m - 1;
            relax(nd, price, i + l + k, base + lp[l + k], (uint32_t)i, (uint32_t)(l + k), dist, rc);
        }
    }
    for (; l <= b; l++) relax(nd, price, i + l, base + lp[l], (uint32_t)i, (uint32_t)l, dist, rc);
}

// Derives node t's reps from its predecessor, which has been visited.
static inline void node_reps(mesh_node *nd, size_t t) {
    mesh_node *to = &nd[t];
    const uint32_t *pr = nd[to->prev].reps;
    uint32_t rc = to->rc;
    if (rc == MESH_RC_LIT) {
        memcpy(to->reps, pr, 16);
        return;
    }
    // A new distance (even one equal to a rep) shifts the reps like slot 3.
    unsigned r = rc == MESH_RC_NEW ? 3 : rc;
    uint32_t nr[4];
    nr[0] = to->dist;
    for (unsigned q = 1, k = 0; q < 4; k++) {
        if (k == r) continue;
        nr[q++] = pr[k];
    }
    memcpy(to->reps, nr, 16);
}

// Optimal parse of [s, e) starting with `ll` pending literals and `reps`.
// Appends sequences for every match; returns the pending literal count.
static size_t dp_chunk(mesh_parser *P, size_t s, size_t e, uint32_t ll, uint32_t reps[4], mesh_seqs *out) {
    const uint8_t *src = P->src;
    const mesh_prices *pr = &P->pr;
    size_t N = e - s;
    mesh_node *nd = P->nodes;
    uint32_t *price = P->price;
    // Op plus length-extra price of each match length up to 64, by literal
    // code: for each rep slot, and for new distances.
    uint32_t rep_lp[4][4][65], new_lp[4][65];
    for (unsigned lc = 0; lc < 4; lc++) {
        const uint16_t *opp = &pr->op[lc << 6];
        for (unsigned l = 2; l <= 64; l++) {
            for (unsigned r = 0; r < 4; r++)
                rep_lp[lc][r][l] = l <= 8 ? opp[r << 3 | (l - 2)] : opp[r << 3 | 7] + price_extra(pr, l - 9);
            new_lp[lc][l] = l <= 32 ? opp[l + 30] : opp[63] + price_extra(pr, l - 33);
        }
    }
    price[0] = 0;
    nd[0].litlen = ll;
    nd[0].len = 0;
    memcpy(nd[0].reps, reps, 16);
    for (size_t i = 1; i <= N; i++) price[i] = MESH_INF;
    size_t reach = 0; // nodes past this have not been relaxed

    for (size_t i = 0; i < N; i++) {
        mesh_node *cur = &nd[i];
        if (i) node_reps(nd, i);
        size_t pos = s + i;
        // literal
        uint32_t lp = price[i] + pr->lit[src[pos]];
        if (lp < price[i + 1]) {
            price[i + 1] = lp;
            nd[i + 1].litlen = cur->litlen + 1;
            nd[i + 1].prev = (uint32_t)i;
            nd[i + 1].len = 0;
            nd[i + 1].rc = MESH_RC_LIT;
        }
        size_t avail = N - i;
        reach = MAX(reach, i + 1);
        if (avail < 2) continue;
        uint32_t ll_i = cur->litlen;
        unsigned lc = ll_i < 3 ? ll_i : 3;
        // Op symbols for this literal count, and the base price of any match here.
        const uint16_t *opp = &pr->op[lc << 6];
        uint32_t base_price = price[i] + (ll_i < 3 ? 0 : price_extra(pr, ll_i - 3));
        uint16_t here2 = load16_le(src + pos);
        uint32_t best_len = 0, best_dist = 0;
        // repeat distances
        const uint32_t *cr = cur->reps;
        // Slots holding the same distance as an earlier slot are skipped.
        unsigned dup = (cr[1] == cr[0]) << 1 | (cr[2] == cr[0] || cr[2] == cr[1]) << 2 |
                       (cr[3] == cr[0] || cr[3] == cr[1] || cr[3] == cr[2]) << 3;
        for (unsigned r = 0; r < 4; r++) {
            uint32_t d = cr[r];
            if (d > pos || (dup >> r & 1) || load16_le(src + pos - d) != here2) continue;
            size_t L = match_len(src + pos - d, src + pos, src + e);
            if (L < 2) continue;
            reach = MAX(reach, i + L);
            if (L >= P->nice) {
                best_len = (uint32_t)L;
                best_dist = d;
            }
            size_t lmax = MIN(L, (size_t)64);
            relax_run(nd, price, i, 2, lmax, base_price, rep_lp[lc][r], d, r);
            if (L > lmax)
                relax(nd, price, i + L, base_price + opp[r << 3 | 7] + price_extra(pr, (uint32_t)L - 9), (uint32_t)i, (uint32_t)L, d, r);
        }
        // new distances
        unsigned nc = P->ncand[i];
        const mesh_match *cm = &P->cand[i * MESH_MAX_CAND];
        size_t prevl = 2;
        const uint32_t *lpt = new_lp[lc];
        for (unsigned c = 0; c < nc; c++) {
            size_t L = MIN((size_t)cm[c].len, avail);
            uint32_t d = cm[c].dist;
            if (L <= prevl) continue;
            uint32_t v;
            unsigned k;
            unsigned b = dist_code(d, &v, &k);
            uint32_t bp = base_price + pr->dist[b] + (k << MESH_PRICE_SHIFT);
            if (L >= P->nice && L > best_len) {
                best_len = (uint32_t)L;
                best_dist = d;
            }
            size_t lmax = MIN(L, (size_t)64);
            relax_run(nd, price, i, prevl + 1, lmax, bp, lpt, d, MESH_RC_NEW);
            // A length past 64 is only tried when the previous candidate was at
            // most 64 bytes long (this keeps the established parse).
            if (L > lmax && prevl <= lmax)
                relax(nd, price, i + L, bp + opp[63] + price_extra(pr, (uint32_t)L - 33), (uint32_t)i, (uint32_t)L, d, MESH_RC_NEW);
            reach = MAX(reach, i + L);
            prevl = L;
        }
        if (best_len) {
            // Long match: commit to it and restart the parse after it.
            mesh_node *to = &nd[i + best_len];
            int slot = -1;
            for (int q = 0; q < 4; q++)
                if (cur->reps[q] == best_dist) {
                    slot = q;
                    break;
                }
            price[i + best_len] = price[i];
            to->litlen = 0;
            to->prev = (uint32_t)i;
            to->len = best_len;
            to->dist = best_dist;
            to->rc = slot < 0 ? MESH_RC_NEW : (uint32_t)slot;
            // Invalidate everything between so the backtrack goes through it.
            size_t j = i + best_len;
            for (size_t t = j + 1; t <= reach; t++) price[t] = MESH_INF;
            reach = j;
            for (size_t t = i + 1; t < j; t++) price[t] = MESH_INF;
            price[j] = 0;
            i = j - 1;
        }
    }
    if (N) node_reps(nd, N);

    // Backtrack from N.
    size_t cnt = 0;
    for (size_t i = N; i > 0;) {
        size_t pv = nd[i].prev;
        if (nd[i].len) cnt++;
        i = pv;
    }
    size_t first = out->n;
    for (size_t k = 0; k < cnt; k++) {
        mesh_seq z = {0, 0, 0, 0};
        if (!seqs_push(out, z)) return (size_t)-1;
    }
    size_t k = out->n;
    uint32_t pending = 0;
    size_t i = N;
    // Walk back: literals between matches accumulate into the following seq.
    uint32_t lits_after = 0;
    while (i > 0) {
        size_t pv = nd[i].prev;
        if (nd[i].len) {
            k--;
            out->v[k].len = nd[i].len;
            out->v[k].dist = nd[i].dist;
            if (k + 1 < out->n) out->v[k + 1].lits = lits_after;
            else pending = lits_after;
            lits_after = 0;
        } else {
            lits_after++;
        }
        i = pv;
    }
    if (cnt) out->v[first].lits = lits_after + ll;
    else pending = lits_after + ll;
    memcpy(reps, nd[N].reps, 16);
    return pending;
}

// Symbol statistics of seqs[a, b) as the block writer would emit them. Sets
// prices from them and returns the estimated coded size in 1/16 bit.
static uint64_t seq_stats(const uint8_t *src, size_t pos, const mesh_seq *q, size_t a, size_t b, const uint32_t reps_in[4],
                      mesh_prices *pr) {
    uint32_t fl[256] = {0}, fo[256] = {0}, fe[256] = {0}, fd[256] = {0};
    uint64_t far = 0;
    uint32_t r[4] = {reps_in[0], reps_in[1], reps_in[2], reps_in[3]};
    for (size_t i = a; i < b; i++) {
        for (uint32_t k = 0; k < q[i].lits; k++) fl[src[pos + k]]++;
        pos += q[i].lits;
        uint32_t ll = q[i].lits;
        unsigned lc = ll < 3 ? ll : 3;
        if (lc == 3) fe[ll - 3 < 255 ? ll - 3 : 255]++;
        unsigned mc = 0;
        if (q[i].len) {
            uint32_t d = q[i].dist, L = q[i].len;
            int slot = -1;
            for (int k = 0; k < 4; k++)
                if (r[k] == d) {
                    slot = k;
                    break;
                }
            if (slot >= 0) {
                mc = (unsigned)slot << 3 | (L <= 8 ? L - 2 : 7);
                if (L > 8) fe[L - 9 < 255 ? L - 9 : 255]++;
                for (int k = slot; k > 0; k--) r[k] = r[k - 1];
            } else {
                mc = L <= 32 ? L + 30 : 63;
                if (L > 32) fe[L - 33 < 255 ? L - 33 : 255]++;
                uint32_t v;
                unsigned k;
                fd[dist_code(d, &v, &k)]++;
                far += k;
                r[3] = r[2];
                r[2] = r[1];
                r[1] = r[0];
            }
            r[0] = d;
            pos += L;
        }
        fo[lc << 6 | mc]++;
    }
    prices_from_freq(pr->lit, fl, 11);
    prices_from_freq(pr->op, fo, 11);
    prices_from_freq(pr->ex, fe, 10);
    prices_from_freq(pr->dist, fd, 10);
    uint64_t cost = far << MESH_PRICE_SHIFT;
    for (unsigned k = 0; k < 256; k++)
        cost += (uint64_t)fl[k] * pr->lit[k] + (uint64_t)fo[k] * pr->op[k] + (uint64_t)fe[k] * pr->ex[k] +
                (uint64_t)fd[k] * pr->dist[k];
    return cost;
}

// Prices for the first chunk, from a greedy parse over its candidates: the
// longest new match or a rep0 match at each position, whichever is longer.
static void seed_prices(mesh_parser *P, size_t s, size_t e, const uint32_t reps[4]) {
    const uint8_t *src = P->src;
    mesh_seq *q = P->best;
    size_t nq = 0, anchor = s;
    uint32_t r0 = reps[0];
    for (size_t i = s; i + 4 <= e;) {
        size_t L = 0;
        uint32_t d = 0;
        if (r0 <= i) {
            L = match_len(src + i - r0, src + i, src + e);
            d = r0;
        }
        unsigned nc = P->ncand[i - s];
        if (nc) {
            const mesh_match *cm = &P->cand[(i - s) * MESH_MAX_CAND + nc - 1];
            size_t l = MIN((size_t)cm->len, e - i);
            if (l > L) {
                L = l;
                d = cm->dist;
            }
        }
        if (L < 2) {
            i++;
            continue;
        }
        q[nq++] = (mesh_seq){(uint32_t)(i - anchor), (uint32_t)L, d, 0};
        r0 = d;
        i = anchor = i + L;
    }
    q[nq++] = (mesh_seq){(uint32_t)(e - anchor), 0, 0, 0};
    seq_stats(src, s, q, 0, nq, reps, &P->pr);
}

static int parse_optimal(mesh_parser *P, mesh_seqs *out) {
    const uint8_t *src = P->src;
    size_t n = P->n;
    uint32_t reps[4] = {1, 1, 1, 1};
    uint32_t ll = 0;
    int have_prices = 0;
    // Re-pricing a chunk against its own statistics only pays when the chunk
    // is coded as a block of its own, so larger inputs take one pass per
    // chunk, priced from the chunk before.
    unsigned iters = n <= P->chunk ? P->iterations : 1;
    for (size_t s = 0; s < n;) {
        size_t e = MIN(n, s + P->chunk);
        for (size_t i = s; i < e; i++) {
            mesh_match *cm = &P->cand[(i - s) * MESH_MAX_CAND];
            mf_prefetch(&P->mf, src, i + 1, e);
            unsigned c = mf_find(&P->mf, src, i, e, cm, MESH_MAX_CAND);
            P->ncand[i - s] = (uint8_t)c;
            // The parse commits to matches of nice length, so skip searching inside them.
            if (c && cm[c - 1].len >= P->nice) {
                size_t j = MIN(e, i + cm[c - 1].len);
                while (++i < j) {
                    mf_insert(&P->mf, src, i, e);
                    P->ncand[i - s] = 0;
                }
                i--;
            }
        }
        if (!have_prices) {
            seed_prices(P, s, e, reps);
            have_prices = 1;
        }
        uint32_t r0[4];
        memcpy(r0, reps, 16);
        size_t mark = out->n;
        size_t pending = 0;
        // Re-pricing does not always converge, so keep the cheapest pass.
        uint64_t best_cost = UINT64_MAX;
        size_t best_n = 0, best_pending = 0;
        uint32_t best_reps[4] = {0, 0, 0, 0};
        for (unsigned it = 0; it < iters; it++) {
            out->n = mark;
            memcpy(reps, r0, 16);
            pending = dp_chunk(P, s, e, ll, reps, out);
            if (pending == (size_t)-1) return 0;
            // The first seq's literals start ll bytes before s.
            uint64_t cost = seq_stats(src, s - ll, out->v, mark, out->n, r0, &P->pr);
            if (cost < best_cost) {
                best_cost = cost;
                best_n = out->n - mark;
                best_pending = pending;
                memcpy(best_reps, reps, 16);
                if (iters > 1 && best_n) memcpy(P->best, out->v + mark, best_n * sizeof(mesh_seq));
            }
        }
        if (iters > 1) {
            out->n = mark;
            for (size_t k = 0; k < best_n; k++)
                if (!seqs_push(out, P->best[k])) return 0;
            pending = best_pending;
            memcpy(reps, best_reps, 16);
        }
        ll = (uint32_t)pending;
        s = e;
    }
    if (ll || out->n == 0) {
        mesh_seq z = {ll, 0, 0, 0};
        if (!seqs_push(out, z)) return 0;
    }
    return 1;
}

// Fast parser cost estimates, in 1/16 bit.
typedef struct {
    int32_t lit, rep_op, new_op, dsym, ext;
} mesh_fast_cost;

typedef struct {
    uint32_t len, dist;
    int32_t gain;
} mesh_cand;

static inline int32_t fast_gain(const mesh_fast_cost *c, uint32_t len, uint32_t d, int rep) {
    int32_t g = (int32_t)len * c->lit;
    if (rep) return g - c->rep_op - (len > 8 ? c->ext : 0);
    uint32_t a = ((d - 1) >> 3) + 1;
    return g - c->new_op - c->dsym - (int32_t)((bitlen32(a) - 1) << MESH_PRICE_SHIFT) - (len > 32 ? c->ext : 0);
}

// The fast levels split match finding in two. An indexing pass hashes every
// position into the tables (hash8, hash4 or hash4 rows, and a small hash3 for
// near matches) and records what it found there in a ring of slots; it runs
// straight through without data-dependent branches. The parse then reads
// slots instead of probing tables, so lazy look-ahead is cheap and the
// positions inside a match need no further work.
//
// Deeper levels replace the single hash4 entry with rows: each bucket keeps
// its last R positions and an 8-bit tag of each one's hash. Candidates are the
// row entries whose tag matches, so the search verifies independent loads
// instead of walking a chain of dependent ones.
#define MESH_FAST_H3_BITS 14
#define MESH_FAST_H3_DIST 4096
#define MESH_RING 1024

// The previous occupants of position i's hash8, hash4 and hash3 entries.
typedef struct {
    uint32_t c8, c4, c3;
} mesh_slot;

typedef struct {
    const uint8_t *src;
    size_t n;
    size_t lim;    // positions with 8 readable bytes
    size_t filled; // positions below this are indexed
    uint32_t *h4;
    uint32_t *h3;
    uint32_t *h8;
    uint32_t *prev;  // hash4 chain, for depths 2 to 8
    uint32_t *rpos;  // hash4 rows of R positions, for deeper searches
    uint8_t *rtag;   // the tags of those positions
    uint8_t *rhead;  // per row, the slot of its newest position
    unsigned rlog;   // log2 R
    unsigned rbits;  // log2 of the number of rows
    unsigned depth;
    unsigned hb;
    mesh_fast_cost c;
    mesh_slot ring[MESH_RING];
} mesh_fast;

// Length of the match between a and b given x = load64(a) ^ load64(b), with
// at least 8 bytes readable at b.
static inline uint32_t xor_len(const uint8_t *a, const uint8_t *b, const uint8_t *end, uint64_t x) {
    if (x) return (unsigned)__builtin_ctzll(x) >> 3;
    return 8 + (uint32_t)match_len(a + 8, b + 8, end);
}

// Indexes positions [a, b), all below lim. Tables start zeroed, so an empty
// entry names position 0, which is still a real position to compare with.
static void fast_index(mesh_fast *F, size_t a, size_t b) {
    const uint8_t *src = F->src;
    uint32_t *h8 = F->h8, *h4 = F->h4, *h3 = F->h3;
    unsigned sh8 = 64 - F->hb, sh4 = 32 - F->hb;
    mesh_slot *ring = F->ring;
    uint32_t *prev = F->prev;
    int rows = F->rpos != NULL;
    if (prev) {
        for (size_t i = a; i < b; i++) {
            uint32_t v = load32_le(src + i);
            uint32_t *s4 = &h4[(v * 2654435761u) >> sh4];
            prev[i] = *s4;
            *s4 = (uint32_t)i;
        }
    } else if (rows) {
        unsigned rlog = F->rlog, rmask = (1u << rlog) - 1, rsh = 32 - F->rbits;
        for (size_t i = a; i < b; i++) {
            uint32_t h = load32_le(src + i) * 2654435761u;
            uint32_t row = h >> rsh;
            unsigned slot = (F->rhead[row] + 1) & rmask;
            F->rhead[row] = (uint8_t)slot;
            F->rpos[(row << rlog) + slot] = (uint32_t)i;
            F->rtag[(row << rlog) + slot] = (uint8_t)(h >> (rsh - 8));
        }
    }
    for (size_t i = a; i < b; i++) {
        uint64_t x = load64_le(src + i);
        uint32_t v = (uint32_t)x;
        uint32_t *s8 = &h8[(uint32_t)((x * 0x9E3779B185EBCA87ull) >> sh8)];
        uint32_t *s3 = &h3[((v & 0xFFFFFF) * 2654435761u) >> (32 - MESH_FAST_H3_BITS)];
        mesh_slot *e = &ring[i & (MESH_RING - 1)];
        e->c8 = *s8;
        e->c3 = *s3;
        *s8 = *s3 = (uint32_t)i;
        if (prev) {
            e->c4 = prev[i];
        } else if (!rows) {
            uint32_t *s4 = &h4[(v * 2654435761u) >> sh4];
            e->c4 = *s4;
            *s4 = (uint32_t)i;
        } else {
            e->c4 = 0;
        }
    }
}

// Makes sure position i (below lim) is indexed. Indexing runs ahead in half
// rings, so the slots of the last MESH_RING / 2 positions stay valid. With
// rows it runs ahead less, as later positions push older ones out of a row.
static inline const mesh_slot *fast_slot(mesh_fast *F, size_t i) {
    while (F->filled <= i) {
        size_t b = MIN(F->filled + (F->rpos ? 64 : MESH_RING / 2), F->lim);
        fast_index(F, F->filled, b);
        F->filled = b;
    }
    return &F->ring[i & (MESH_RING - 1)];
}

// Best match at i among the reps and the indexed candidates. Needs 8
// readable bytes at i.
static inline mesh_cand fast_best(mesh_fast *F, size_t i, const uint32_t r[4]) {
    const uint8_t *src = F->src, *ip = src + i, *iend = src + F->n;
    const mesh_slot *e = fast_slot(F, i);
    mesh_cand b = {0, 0, 0};
    uint64_t x8 = load64_le(ip);
    const size_t rem = F->n - i;
    // A hash candidate is only extended if it could be longer than the best.
#define MESH_MAY_BEAT(c) (b.len < rem && src[(c) + b.len] == ip[b.len])
    for (unsigned k = 0; k < 4; k++) {
        uint32_t d = r[k];
        if (d > i) continue;
        uint64_t x = load64_le(ip - d) ^ x8;
        if (x & 0xFFFF) continue;
        uint32_t l = xor_len(ip - d, ip, iend, x);
        int32_t g = fast_gain(&F->c, l, d, 1);
        if (g > b.gain) b = (mesh_cand){l, d, g};
    }
    uint32_t c8 = e->c8, c4 = F->rpos ? 0xFFFFFFFFu : e->c4, c3 = e->c3;
    if (c8 < i && load64_le(src + c8) == x8 && MESH_MAY_BEAT(c8)) {
        uint32_t l = 8 + (uint32_t)match_len(src + c8 + 8, ip + 8, iend);
        int32_t g = fast_gain(&F->c, l, (uint32_t)(i - c8), 0);
        if (g > b.gain) b = (mesh_cand){l, (uint32_t)(i - c8), g};
    }
    if (F->prev) {
        uint32_t c = c4;
        for (unsigned d = 0; d < F->depth && c < i; d++, c = F->prev[c]) {
            uint64_t x = load64_le(src + c) ^ x8;
            if ((uint32_t)x || !MESH_MAY_BEAT(c)) continue;
            uint32_t l = xor_len(src + c, ip, iend, x);
            int32_t g = fast_gain(&F->c, l, (uint32_t)(i - c), 0);
            if (g > b.gain) b = (mesh_cand){l, (uint32_t)(i - c), g};
        }
    } else if (F->rpos) {
        unsigned rlog = F->rlog, R = 1u << rlog, rsh = 32 - F->rbits;
        uint32_t h = (uint32_t)x8 * 2654435761u;
        uint32_t row = h >> rsh;
        const uint32_t *rp = F->rpos + (row << rlog);
        const uint8_t *rt = F->rtag + (row << rlog);
        uint64_t want = 0x0101010101010101ull * (uint8_t)(h >> (rsh - 8));
        uint64_t m = 0;
        for (unsigned k = 0; k < R; k += 8) {
            // Exact zero-byte test, then gather the high bits into a byte.
            uint64_t z = load64_le(rt + k) ^ want;
            uint64_t t = ~(((z & 0x7F7F7F7F7F7F7F7Full) + 0x7F7F7F7F7F7F7F7Full) | z | 0x7F7F7F7F7F7F7F7Full);
            m |= (((t >> 7) * 0x0102040810204080ull) >> 56) << k;
        }
        // Newest first: rotate the row's head to the top bit (entry j moves
        // to bit (j + R - 1 - hd) mod R).
        unsigned hd = F->rhead[row];
        uint64_t rmask = R == 64 ? ~0ull : (1ull << R) - 1;
        m = ((m << (R - 1 - hd)) | (hd + 1 < R ? m >> (hd + 1) : 0)) & rmask;
        for (unsigned d = 0; m && d < F->depth;) {
            unsigned top = 63 - (unsigned)__builtin_clzll(m);
            m &= ~(1ull << top);
            uint32_t c = rp[(top + hd + 1) & (R - 1)];
            if (c >= i) continue; // indexed ahead of the parse
            d++;
            uint64_t x = load64_le(src + c) ^ x8;
            if ((uint32_t)x || !MESH_MAY_BEAT(c)) continue;
            uint32_t l = xor_len(src + c, ip, iend, x);
            int32_t g = fast_gain(&F->c, l, (uint32_t)(i - c), 0);
            if (g > b.gain) b = (mesh_cand){l, (uint32_t)(i - c), g};
        }
    } else if (c4 < i && c4 != i - b.dist) {
        uint64_t x = load64_le(src + c4) ^ x8;
        if (!(uint32_t)x && MESH_MAY_BEAT(c4)) {
            uint32_t l = xor_len(src + c4, ip, iend, x);
            int32_t g = fast_gain(&F->c, l, (uint32_t)(i - c4), 0);
            if (g > b.gain) b = (mesh_cand){l, (uint32_t)(i - c4), g};
        }
    }
    if (b.len < 4 && c3 < i && c3 != c4 && i - c3 < MESH_FAST_H3_DIST) {
        uint64_t x = load64_le(src + c3) ^ x8;
        if (!(x & 0xFFFFFF)) {
            uint32_t l = xor_len(src + c3, ip, iend, x);
            int32_t g = fast_gain(&F->c, l, (uint32_t)(i - c3), 0);
            if (g > b.gain) b = (mesh_cand){l, (uint32_t)(i - c3), g};
        }
    }
#undef MESH_MAY_BEAT
    return b;
}

// The parse is a chain of evaluations whose next position depends on the
// last result, so the candidates' bytes are fetched early: those of the next
// position, and of the predicted end of a match while its lazy step runs.
static inline void fast_prefetch(mesh_fast *F, size_t i) {
    if (i >= F->filled) return;
    const mesh_slot *e = &F->ring[i & (MESH_RING - 1)];
    __builtin_prefetch(F->src + e->c8);
    __builtin_prefetch(F->src + e->c4);
    __builtin_prefetch(F->src + e->c3);
}

// Greedy or lazy parse driven by estimated bit savings, for the fast levels.
static int parse_fast(mesh_parser *P, mesh_seqs *out, int lazy, unsigned depth) {
    const uint8_t *src = P->src;
    size_t n = P->n;
    mesh_fast *F = (mesh_fast *)malloc(sizeof(mesh_fast));
    if (!F) return 0;
    F->src = src;
    F->n = n;
    F->lim = n - 7; // n >= 16
    F->filled = 0;
    F->hb = P->mf.hbits;
    F->h4 = (uint32_t *)calloc((size_t)1 << F->hb, sizeof(uint32_t));
    F->h3 = (uint32_t *)calloc((size_t)1 << MESH_FAST_H3_BITS, sizeof(uint32_t));
    F->h8 = (uint32_t *)calloc((size_t)1 << F->hb, sizeof(uint32_t));
    F->depth = depth;
    F->rpos = NULL;
    F->rtag = F->rhead = NULL;
    F->prev = NULL;
    if (depth > 1 && depth <= 8) {
        F->prev = (uint32_t *)malloc(sizeof(uint32_t) * n);
    } else if (depth > 8) {
        // Rows of R >= depth positions, with twice as many entries in all as
        // the hash4 table would have.
        unsigned rlog = 4;
        while ((1u << rlog) < depth && rlog < 6) rlog++;
        F->rlog = rlog;
        F->rbits = F->hb + 1 - rlog;
        size_t ne = (size_t)1 << (F->rbits + rlog);
        F->rpos = (uint32_t *)calloc(ne, sizeof(uint32_t));
        F->rtag = (uint8_t *)calloc(ne + 8, 1);
        F->rhead = (uint8_t *)calloc((size_t)1 << F->rbits, 1);
    }
    int ok = F->h4 && F->h3 && F->h8 && (depth <= 1 || F->prev || (F->rpos && F->rtag && F->rhead));
    F->c.lit = 6 << MESH_PRICE_SHIFT;
    F->c.rep_op = 6 << MESH_PRICE_SHIFT;
    F->c.new_op = 7 << MESH_PRICE_SHIFT;
    F->c.dsym = 5 << MESH_PRICE_SHIFT;
    F->c.ext = 6 << MESH_PRICE_SHIFT;

    uint32_t r[4] = {1, 1, 1, 1};
    size_t i = 1, anchor = 0, miss = 0;
    while (ok && i + 8 <= n) {
        mesh_cand m = fast_best(F, i, r);
        fast_prefetch(F, i + 1 + (m.gain > 0 ? m.len : 0));
        if (m.gain <= 0) {
            miss++;
            i += 1 + (miss >> 6);
            continue;
        }
        miss = 0;
        size_t mi = i;
        if (lazy) {
            while (mi + 9 <= n && m.len < 64) {
                mesh_cand m2 = fast_best(F, mi + 1, r);
                if (m2.gain <= m.gain + F->c.lit) break;
                m = m2;
                mi++;
                fast_prefetch(F, mi + m.len);
            }
        }
        size_t end = mi + m.len;
        if (end > n) end = n;
        mesh_seq q = {(uint32_t)(mi - anchor), (uint32_t)(end - mi), m.dist, 0};
        if (!seqs_push(out, q)) {
            ok = 0;
            break;
        }
        int slot = 3;
        for (int k = 0; k < 4; k++)
            if (r[k] == m.dist) {
                slot = k;
                break;
            }
        for (int k = slot; k > 0; k--) r[k] = r[k - 1];
        r[0] = m.dist;
        i = anchor = end;
    }
    if (ok && (anchor < n || out->n == 0)) {
        mesh_seq z = {(uint32_t)(n - anchor), 0, 0, 0};
        ok = seqs_push(out, z);
    }
    free(F->h4);
    free(F->h3);
    free(F->h8);
    free(F->prev);
    free(F->rpos);
    free(F->rtag);
    free(F->rhead);
    free(F);
    return ok;
}

typedef struct {
    uint8_t *dst;
    size_t cap;
    size_t pos;
    size_t raw_start;
    size_t raw_end;
} mesh_out;

static int flush_raw(mesh_out *o, const uint8_t *src) {
    size_t len = o->raw_end - o->raw_start;
    if (!len) return 1;
    if (len > 0xFFFFFFFFu || o->cap - o->pos < len + 5) return 0;
    o->dst[o->pos] = CRUSHLZMESH_BLOCK_RAW;
    store32_le(o->dst + o->pos + 1, (uint32_t)len);
    memcpy(o->dst + o->pos + 5, src + o->raw_start, len);
    o->pos += len + 5;
    o->raw_start = o->raw_end;
    return 1;
}

// Packs seqs into blocks of at most 64 KiB payload, each as many seqs as fit
// the decoder's scratch budget.
static int pack_blocks(mesh_out *o, const uint8_t *src, size_t n, mesh_seq *q, size_t nq, mesh_enc_bufs *B) {
    uint32_t reps[4] = {1, 1, 1, 1};
    size_t in = 0;
    size_t si = 0;
    const uint8_t *src_end = src + n;
    while (si < nq) {
        mesh_block k;
        build_streams(src + in, src_end, q + si, nq - si, in == 0, reps, B, &k);
        if (k.take == 0) {
            // One huge literal run: emit a literal-only piece of it.
            mesh_seq piece = {32768, 0, 0, 0};
            mesh_seq *t = &q[si];
            int why;
            size_t w = 0;
            if (flush_raw(o, src) && o->cap - o->pos > 16) {
                build_streams(src + in, src_end, &piece, 1, in == 0, reps, B, &k);
                w = write_block(o->dst + o->pos, o->cap - o->pos, &k, B, &why);
            }
            if (w) {
                o->pos += w;
                o->raw_start = o->raw_end = in + 32768;
            } else {
                o->raw_end += 32768;
            }
            in += 32768;
            t->lits -= 32768;
            continue;
        }
        for (;;) {
            int why;
            if (!flush_raw(o, src)) return 0;
            size_t w = write_block(o->dst + o->pos, o->cap - o->pos, &k, B, &why);
            if (w) {
                memcpy(reps, k.reps, 16);
                o->pos += w;
                o->raw_start = o->raw_end = in + k.usize;
                break;
            }
            if (why == MESH_WB_RAW) {
                // The matches in a raw block no longer update the reps;
                // later blocks re-derive rep slots by distance.
                o->raw_end += k.usize;
                break;
            }
            if (k.take == 1) return 0;
            build_streams(src + in, src_end, q + si, k.take / 2, in == 0, reps, B, &k);
        }
        in += k.usize;
        si += k.take;
    }
    return flush_raw(o, src);
}

size_t crushlzmesh_encode_buffer(
    uint8_t *dst,
    size_t dst_size,
    const uint8_t *src,
    size_t src_size,
    void *scratch,
    const crushlzmesh_params *params
) {
    (void)scratch;
    if (!dst || (!src && src_size)) return 0;
    crushlzmesh_params dp;
    if (!params) {
        crushlzmesh_params_for_level(CRUSHLZMESH_LEVEL_DEFAULT, &dp);
        params = &dp;
    }
    mesh_out o = {dst, dst_size, 0, 0, 0};
    if (src_size < 16 || src_size > 0xFFFFFFF0u) {
        o.raw_end = src_size;
        if (!flush_raw(&o, src) || o.pos >= dst_size) return 0;
        dst[o.pos++] = CRUSHLZMESH_EOS;
        return o.pos;
    }

    mesh_parser P;
    memset(&P, 0, sizeof(P));
    P.src = src;
    P.n = src_size;
    unsigned hb = (unsigned)(params->hash_bits ? params->hash_bits : 16);
    if (hb < 10) hb = 10;
    if (hb > 22) hb = 22;
    P.mf.hbits = hb;
    int depth = params->strategy == CRUSHLZMESH_STRAT_OPTIMAL ? params->search_depth : params->max_depth;
    P.mf.depth = (unsigned)MIN(MAX(1, depth), 1024);
    P.mf.nice = (uint32_t)(params->lookahead > 8 ? MIN(params->lookahead, 4096) : 128);
    P.nice = P.mf.nice;
    P.iterations = (unsigned)MIN(MAX(1, params->iterations), 8);
    P.chunk = 1u << 16;
    mesh_enc_bufs *B = (mesh_enc_bufs *)malloc(sizeof(*B));
    mesh_seqs seqs = {NULL, 0, 0};
    size_t result = 0;
    int optimal = params->strategy == CRUSHLZMESH_STRAT_OPTIMAL;
    if (!B) goto done;
    if (optimal) {
        P.mf.head3 = (uint32_t *)malloc(sizeof(uint32_t) << MESH_HASH3_BITS);
        uint32_t w = 1u << 16;
        while (w < src_size && w < (1u << 24)) w <<= 1;
        P.mf.wmask = w - 1;
        P.mf.n = src_size;
        P.mf.son = (uint32_t *)malloc(sizeof(uint32_t) * 2 * (size_t)w);
        P.mf.head = (uint32_t *)malloc(sizeof(uint32_t) << hb);
        if (!P.mf.son || !P.mf.head) goto done;
        memset(P.mf.head, 0xFF, sizeof(uint32_t) << hb);
        P.nodes = (mesh_node *)malloc(sizeof(mesh_node) * (P.chunk + 1));
        P.price = (uint32_t *)malloc(sizeof(uint32_t) * (P.chunk + 1));
        P.cand = (mesh_match *)malloc(sizeof(mesh_match) * MESH_MAX_CAND * P.chunk);
        P.ncand = (uint8_t *)malloc(P.chunk);
        P.best = (mesh_seq *)malloc(sizeof(mesh_seq) * (P.chunk + 1));
        if (!P.mf.head3 || !P.nodes || !P.price || !P.cand || !P.ncand || !P.best) goto done;
        memset(P.mf.head3, 0xFF, sizeof(uint32_t) << MESH_HASH3_BITS);
    }

    if (optimal ? !parse_optimal(&P, &seqs) : !parse_fast(&P, &seqs, params->strategy == CRUSHLZMESH_STRAT_LAZY, P.mf.depth)) goto done;
    if (!pack_blocks(&o, src, src_size, seqs.v, seqs.n, B)) goto done;
    if (o.pos < dst_size) {
        dst[o.pos++] = CRUSHLZMESH_EOS;
        result = o.pos;
    }
done:
    free(P.mf.head);
    free(P.mf.head3);
    free(P.mf.son);
    free(P.nodes);
    free(P.price);
    free(P.cand);
    free(P.ncand);
    free(P.best);
    free(B);
    free(seqs.v);
    return result;
}
