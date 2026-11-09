// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Platform-agnostic SIMD abstraction for CrushLZ / LZBITMAP.
// Provides 128-bit vector primitives across ARM NEON and x86 SSE4.1+POPCNT.

#ifndef CRUSH_SIMD_H
#define CRUSH_SIMD_H

#include <stdint.h>
#include <string.h>

/*
 * CRUSH_SIMD_PORTABLE forces the scalar, array-backed branch below even on
 * hardware that could take a vector path (an explicit opt-in for maximum-
 * portability builds); it is also turned on automatically whenever neither
 * ARM NEON nor x86 SSE4.1+POPCNT is available, so an unsupported target gets
 * the scalar branch instead of the old #error. Once this header has been
 * included, CRUSH_SIMD_PORTABLE reliably reflects which branch was taken
 * (opt-in or automatic), so later code in the same translation unit can
 * test it instead of re-deriving the same condition.
 */
#if !defined(CRUSH_SIMD_PORTABLE) && !defined(__ARM_NEON) && \
    !(defined(__SSE4_1__) && defined(__POPCNT__))
#  define CRUSH_SIMD_PORTABLE 1
#endif

/*
 * CBMC contracts of the decoder's blend and copy wrappers, shared by all three
 * branches so a proof can replace any branch's wrapper by the same contract
 * (harness/proofs/simd). Each reads exactly its stated widths, writes exactly
 * dst[0, 8) or d[0, N), and nothing else; dst may equal base. The copies ask
 * what memcpy asks: no partial overlap. ZBM_REQUIRES and friends come from
 * the includer and expand to nothing outside a proof build.
 */
#define ZBM_BLEND8_CONTRACT                                                  \
    ZBM_REQUIRES(__CPROVER_r_ok(base, 8) && __CPROVER_r_ok(lits, 8))         \
    ZBM_REQUIRES(__CPROVER_w_ok(dst, 8))                                     \
    ZBM_ASSIGNS(__CPROVER_object_upto(dst, 8))
#define ZBM_BLEND8_ROW_CONTRACT                                              \
    ZBM_REQUIRES(__CPROVER_r_ok(base, 8) && __CPROVER_r_ok(lits, 8))         \
    ZBM_REQUIRES(__CPROVER_r_ok(row, 8) && __CPROVER_w_ok(dst, 8))           \
    ZBM_ASSIGNS(__CPROVER_object_upto(dst, 8))
#define ZBM_SEL_LOAD_CONTRACT                                                \
    ZBM_REQUIRES(__CPROVER_r_ok(row, 8))                                     \
    ZBM_ASSIGNS()
#define ZBM_CPY_CONTRACT(n)                                                  \
    ZBM_REQUIRES(__CPROVER_w_ok(d, n) && __CPROVER_r_ok(s, n))               \
    ZBM_REQUIRES(!__CPROVER_same_object(d, s) || d + (n) <= s || s + (n) <= d) \
    ZBM_ASSIGNS(__CPROVER_object_upto(d, n))

#if defined(CRUSH_SIMD_PORTABLE)
// Scalar reference implementation: every vector type is a plain struct
// wrapping a fixed-size array, and every primitive is a small loop or
// closed-form expression over that array. Lane widths and reductions match
// the NEON and SSE4.1+POPCNT branches below bit-for-bit (LZBITMAP_DIFF_TEST
// checks encode and decode output byte-for-byte against them); this branch
// trades throughput for having no ISA requirement at all.

typedef struct { uint8_t  v[16]; } uint8x16_t;
typedef struct { uint16_t v[8];  } uint16x8_t;
typedef struct { uint32_t v[4];  } uint32x4_t;
typedef struct { uint64_t v[2];  } uint64x2_t;
typedef struct { int32_t  v[4];  } int32x4_t;
typedef struct { uint8_t  v[8];  } uint8x8_t;
typedef struct { uint16_t v[4];  } uint16x4_t;

#  define ZBM_V4U32(a, b, c, d) \
       ((uint32x4_t){{(uint32_t)(a), (uint32_t)(b), (uint32_t)(c), (uint32_t)(d)}})
#  define ZBM_V8U16(a, b, c, d, e, f, g, h) \
       ((uint16x8_t){{(uint16_t)(a), (uint16_t)(b), (uint16_t)(c), (uint16_t)(d), \
                       (uint16_t)(e), (uint16_t)(f), (uint16_t)(g), (uint16_t)(h)}})
#  define ZBM_V8U8(a, b, c, d, e, f, g, h) \
       ((uint8x8_t){{(uint8_t)(a), (uint8_t)(b), (uint8_t)(c), (uint8_t)(d), \
                      (uint8_t)(e), (uint8_t)(f), (uint8_t)(g), (uint8_t)(h)}})
#  define ZBM_V16U8_IOTA \
       ((uint8x16_t){{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}})

static inline uint8x16_t vld1q_u8(const uint8_t *p) { uint8x16_t r; memcpy(r.v, p, 16); return r; }
static inline uint32x4_t vld1q_u32(const uint32_t *p) { uint32x4_t r; memcpy(r.v, p, 16); return r; }
static inline void vst1q_u32(uint32_t *p, uint32x4_t v) { memcpy(p, v.v, 16); }
static inline uint64x2_t vld1_u64(const uint64_t *p) { uint64x2_t r; r.v[0] = *p; r.v[1] = 0; return r; }
static inline uint16x8_t vld1q_u16(const uint16_t *p) { uint16x8_t r; memcpy(r.v, p, 16); return r; }

static inline uint32x4_t vdupq_n_u32(uint32_t x) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = x; return r; }
static inline int32x4_t vdupq_n_s32(int32_t x) { int32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = x; return r; }
static inline uint16x8_t vdupq_n_u16(uint16_t x) { uint16x8_t r; for (int i = 0; i < 8; i++) r.v[i] = x; return r; }
static inline uint8x16_t vdupq_n_u8(uint8_t x) { uint8x16_t r; for (int i = 0; i < 16; i++) r.v[i] = x; return r; }
static inline uint64x2_t vdupq_n_u64(uint64_t x) { uint64x2_t r; r.v[0] = x; r.v[1] = x; return r; }
static inline uint8x8_t vdup_n_u8(uint8_t x) { uint8x8_t r; for (int i = 0; i < 8; i++) r.v[i] = x; return r; }

static inline uint64x2_t vcreate_u64(uint64_t x) { uint64x2_t r; r.v[0] = x; r.v[1] = 0; return r; }
static inline uint16x4_t vcreate_u16(uint64_t x)
{
    uint16x4_t r;
    for (int i = 0; i < 4; i++) r.v[i] = (uint16_t)(x >> (16 * i));
    return r;
}
static inline uint8x8_t vcreate_u8(uint64_t x)
{
    uint8x8_t r;
    for (int i = 0; i < 8; i++) r.v[i] = (uint8_t)(x >> (8 * i));
    return r;
}

static inline uint64x2_t vcombine_u64(uint64x2_t lo, uint64x2_t hi) { uint64x2_t r; r.v[0] = lo.v[0]; r.v[1] = hi.v[0]; return r; }
static inline uint8x16_t vcombine_u8(uint8x8_t lo, uint8x8_t hi)
{
    uint8x16_t r;
    memcpy(&r.v[0], lo.v, 8);
    memcpy(&r.v[8], hi.v, 8);
    return r;
}
static inline uint8x8_t vget_low_u8(uint8x16_t v) { uint8x8_t r; memcpy(r.v, &v.v[0], 8); return r; }
static inline uint8x8_t vget_high_u8(uint8x16_t v) { uint8x8_t r; memcpy(r.v, &v.v[8], 8); return r; }

static inline uint32x4_t vzip1q_u32(uint32x4_t a, uint32x4_t b) { return ZBM_V4U32(a.v[0], b.v[0], a.v[1], b.v[1]); }
static inline uint32x4_t vzip2q_u32(uint32x4_t a, uint32x4_t b) { return ZBM_V4U32(a.v[2], b.v[2], a.v[3], b.v[3]); }
static inline uint64x2_t vzip1q_u64(uint64x2_t a, uint64x2_t b) { uint64x2_t r; r.v[0] = a.v[0]; r.v[1] = b.v[0]; return r; }
static inline uint64x2_t vzip2q_u64(uint64x2_t a, uint64x2_t b) { uint64x2_t r; r.v[0] = a.v[1]; r.v[1] = b.v[1]; return r; }
static inline uint8x8_t vzip1_u8(uint8x8_t a, uint8x8_t b)
{
    uint8x8_t r;
    r.v[0] = a.v[0]; r.v[1] = b.v[0]; r.v[2] = a.v[1]; r.v[3] = b.v[1];
    r.v[4] = a.v[2]; r.v[5] = b.v[2]; r.v[6] = a.v[3]; r.v[7] = b.v[3];
    return r;
}
static inline uint32x4_t vuzp1q_u32(uint32x4_t a, uint32x4_t b) { return ZBM_V4U32(a.v[0], a.v[2], b.v[0], b.v[2]); }
static inline uint32x4_t vuzp2q_u32(uint32x4_t a, uint32x4_t b) { return ZBM_V4U32(a.v[1], a.v[3], b.v[1], b.v[3]); }

static inline uint32x4_t vmulq_u32(uint32x4_t a, uint32x4_t b)
{
    uint32x4_t r;
    for (int i = 0; i < 4; i++) r.v[i] = (uint32_t)(a.v[i] * b.v[i]);
    return r;
}
// Per-lane signed shift, matching NEON VSHL.U32: positive shifts left,
// negative shifts right. libzbitmap.c always passes a broadcast shift
// vector, but this stays correct for a genuinely per-lane one too.
static inline uint32x4_t vshlq_u32(uint32x4_t a, int32x4_t b)
{
    uint32x4_t r;
    for (int i = 0; i < 4; i++) {
        int32_t s = b.v[i];
        if (s >= 0) r.v[i] = (s >= 32) ? 0u : (a.v[i] << s);
        else        r.v[i] = ((-s) >= 32) ? 0u : (a.v[i] >> (-s));
    }
    return r;
}
static inline uint32x4_t vandq_u32(uint32x4_t a, uint32x4_t b) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] & b.v[i]; return r; }
static inline uint16x8_t vandq_u16(uint16x8_t a, uint16x8_t b) { uint16x8_t r; for (int i = 0; i < 8; i++) r.v[i] = (uint16_t)(a.v[i] & b.v[i]); return r; }
static inline uint8x8_t vand_u8(uint8x8_t a, uint8x8_t b) { uint8x8_t r; for (int i = 0; i < 8; i++) r.v[i] = (uint8_t)(a.v[i] & b.v[i]); return r; }
static inline uint32x4_t vorrq_u32(uint32x4_t a, uint32x4_t b) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] | b.v[i]; return r; }
static inline uint16x8_t vorrq_u16(uint16x8_t a, uint16x8_t b) { uint16x8_t r; for (int i = 0; i < 8; i++) r.v[i] = (uint16_t)(a.v[i] | b.v[i]); return r; }
static inline uint8x16_t vorrq_u8(uint8x16_t a, uint8x16_t b) { uint8x16_t r; for (int i = 0; i < 16; i++) r.v[i] = (uint8_t)(a.v[i] | b.v[i]); return r; }
static inline uint32x4_t vbicq_u32(uint32x4_t a, uint32x4_t b) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] & ~b.v[i]; return r; }
static inline uint8x16_t vbicq_u8(uint8x16_t a, uint8x16_t b) { uint8x16_t r; for (int i = 0; i < 16; i++) r.v[i] = (uint8_t)(a.v[i] & (uint8_t)~b.v[i]); return r; }
static inline uint32x4_t vaddq_u32(uint32x4_t a, uint32x4_t b) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] + b.v[i]; return r; }
static inline uint8x16_t vaddq_u8(uint8x16_t a, uint8x16_t b) { uint8x16_t r; for (int i = 0; i < 16; i++) r.v[i] = (uint8_t)(a.v[i] + b.v[i]); return r; }
static inline uint32x4_t vsubq_u32(uint32x4_t a, uint32x4_t b) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] - b.v[i]; return r; }
static inline uint16x8_t vsubq_u16(uint16x8_t a, uint16x8_t b) { uint16x8_t r; for (int i = 0; i < 8; i++) r.v[i] = (uint16_t)(a.v[i] - b.v[i]); return r; }
static inline uint8x16_t vsubq_u8(uint8x16_t a, uint8x16_t b) { uint8x16_t r; for (int i = 0; i < 16; i++) r.v[i] = (uint8_t)(a.v[i] - b.v[i]); return r; }
static inline uint32x4_t vminq_u32(uint32x4_t a, uint32x4_t b) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] < b.v[i] ? a.v[i] : b.v[i]; return r; }
static inline uint16x8_t vminq_u16(uint16x8_t a, uint16x8_t b) { uint16x8_t r; for (int i = 0; i < 8; i++) r.v[i] = a.v[i] < b.v[i] ? a.v[i] : b.v[i]; return r; }
static inline uint8x16_t vminq_u8(uint8x16_t a, uint8x16_t b) { uint8x16_t r; for (int i = 0; i < 16; i++) r.v[i] = a.v[i] < b.v[i] ? a.v[i] : b.v[i]; return r; }

static inline uint32x4_t vshlq_n_u32(uint32x4_t a, int n) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] << n; return r; }
static inline uint32x4_t vshrq_n_u32(uint32x4_t a, int n) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] >> n; return r; }
static inline uint16x8_t vshlq_n_u16(uint16x8_t a, int n) { uint16x8_t r; for (int i = 0; i < 8; i++) r.v[i] = (uint16_t)(a.v[i] << n); return r; }
static inline uint8x16_t vshlq_n_u8(uint8x16_t a, int n) { uint8x16_t r; for (int i = 0; i < 16; i++) r.v[i] = (uint8_t)(a.v[i] << n); return r; }
static inline uint8x16_t vdupq_laneq_u8(uint8x16_t v, int l) { uint8x16_t r; for (int i = 0; i < 16; i++) r.v[i] = v.v[l]; return r; }

static inline uint8x16_t vextq_u8(uint8x16_t a, uint8x16_t b, int n)
{
    uint8x16_t r;
    for (int i = 0; i < 16; i++) r.v[i] = (i + n < 16) ? a.v[i + n] : b.v[i + n - 16];
    return r;
}
static inline uint8x16_t vqtbl1q_u8(uint8x16_t t, uint8x16_t idx)
{
    uint8x16_t r;
    for (int i = 0; i < 16; i++) r.v[i] = idx.v[i] < 16 ? t.v[idx.v[i]] : 0;
    return r;
}
static inline uint32_t vgetq_lane_u32(uint32x4_t v, int l) { return v.v[l]; }
static inline uint32x4_t vld1q_lane_u32(const uint32_t *p, uint32x4_t v, int l) { v.v[l] = *p; return v; }

static inline uint16x8_t vceqq_u16(uint16x8_t a, uint16x8_t b) { uint16x8_t r; for (int i = 0; i < 8; i++) r.v[i] = (uint16_t)(a.v[i] == b.v[i] ? 0xffffu : 0); return r; }
static inline uint16x8_t vcltq_u16(uint16x8_t a, uint16x8_t b) { uint16x8_t r; for (int i = 0; i < 8; i++) r.v[i] = (uint16_t)(a.v[i] < b.v[i] ? 0xffffu : 0); return r; }
static inline uint8x16_t vceqq_u8(uint8x16_t a, uint8x16_t b) { uint8x16_t r; for (int i = 0; i < 16; i++) r.v[i] = (uint8_t)(a.v[i] == b.v[i] ? 0xffu : 0); return r; }
static inline uint32x4_t vcgtq_u32(uint32x4_t a, uint32x4_t b) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] > b.v[i] ? 0xffffffffu : 0; return r; }
static inline uint32x4_t vcleq_u32(uint32x4_t a, uint32x4_t b) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = a.v[i] <= b.v[i] ? 0xffffffffu : 0; return r; }
// Bit-select, not lane-select, so it stays exact even if a caller ever
// passes a mask that isn't all-ones/all-zeros per lane.
static inline uint32x4_t vbslq_u32(uint32x4_t m, uint32x4_t a, uint32x4_t b) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = (m.v[i] & a.v[i]) | (~m.v[i] & b.v[i]); return r; }
static inline uint8x8_t vtst_u8(uint8x8_t a, uint8x8_t b) { uint8x8_t r; for (int i = 0; i < 8; i++) r.v[i] = (uint8_t)((a.v[i] & b.v[i]) != 0 ? 0xffu : 0); return r; }

static inline uint8_t vaddv_u8(uint8x8_t v)
{
    unsigned sum = 0;
    for (int i = 0; i < 8; i++) sum += v.v[i];
    return (uint8_t)sum;
}
static inline uint8x8_t vcnt_u8(uint8x8_t v)
{
    uint8x8_t r;
    for (int i = 0; i < 8; i++) r.v[i] = (uint8_t)__builtin_popcount(v.v[i]);
    return r;
}
static inline uint8x16_t vpaddq_u8(uint8x16_t a, uint8x16_t b)
{
    uint8x16_t r;
    for (int i = 0; i < 8; i++) {
        r.v[i]     = (uint8_t)(a.v[2 * i] + a.v[2 * i + 1]);
        r.v[8 + i] = (uint8_t)(b.v[2 * i] + b.v[2 * i + 1]);
    }
    return r;
}
static inline uint16x8_t vmovl_u8(uint8x8_t v) { uint16x8_t r; for (int i = 0; i < 8; i++) r.v[i] = v.v[i]; return r; }
static inline uint32x4_t vmovl_u16(uint16x4_t v) { uint32x4_t r; for (int i = 0; i < 4; i++) r.v[i] = v.v[i]; return r; }
static inline uint16_t vmaxvq_u16(uint16x8_t v)
{
    uint16_t m = v.v[0];
    for (int i = 1; i < 8; i++) if (v.v[i] > m) m = v.v[i];
    return m;
}
static inline uint32_t vminvq_u32(uint32x4_t v)
{
    uint32_t m = v.v[0];
    for (int i = 1; i < 4; i++) if (v.v[i] < m) m = v.v[i];
    return m;
}
static inline uint16_t vminvq_u16(uint16x8_t v)
{
    uint16_t m = v.v[0];
    for (int i = 1; i < 8; i++) if (v.v[i] < m) m = v.v[i];
    return m;
}
static inline uint8_t vminvq_u8(uint8x16_t v)
{
    uint8_t m = v.v[0];
    for (int i = 1; i < 16; i++) if (v.v[i] < m) m = v.v[i];
    return m;
}

// Bit-cast reinterprets, little-endian: matches the byte order real NEON and
// SSE hardware produce, which downstream arithmetic on the reinterpreted
// values depends on for its numeric result, not just its own consistency.
static inline uint64x2_t vreinterpretq_u64_u32(uint32x4_t x)
{
    uint64x2_t r;
    r.v[0] = (uint64_t)x.v[0] | ((uint64_t)x.v[1] << 32);
    r.v[1] = (uint64_t)x.v[2] | ((uint64_t)x.v[3] << 32);
    return r;
}
static inline uint32x4_t vreinterpretq_u32_u64(uint64x2_t x)
{
    return ZBM_V4U32((uint32_t)x.v[0], (uint32_t)(x.v[0] >> 32), (uint32_t)x.v[1], (uint32_t)(x.v[1] >> 32));
}
static inline uint32x4_t vreinterpretq_u32_u8(uint8x16_t x)
{
    uint32x4_t r;
    for (int i = 0; i < 4; i++)
        r.v[i] = (uint32_t)x.v[4 * i] | ((uint32_t)x.v[4 * i + 1] << 8) |
                 ((uint32_t)x.v[4 * i + 2] << 16) | ((uint32_t)x.v[4 * i + 3] << 24);
    return r;
}
static inline uint8x16_t vreinterpretq_u8_u64(uint64x2_t x)
{
    uint8x16_t r;
    for (int i = 0; i < 2; i++)
        for (int b = 0; b < 8; b++)
            r.v[8 * i + b] = (uint8_t)(x.v[i] >> (8 * b));
    return r;
}
static inline uint16x4_t vreinterpret_u16_u8(uint8x8_t x)
{
    uint16x4_t r;
    for (int i = 0; i < 4; i++) r.v[i] = (uint16_t)((uint16_t)x.v[2 * i] | ((uint16_t)x.v[2 * i + 1] << 8));
    return r;
}

typedef struct { uint8_t v[8]; } zbm_sel_t;
static inline zbm_sel_t zbm_sel_load(const uint8_t *row)
ZBM_SEL_LOAD_CONTRACT
{ zbm_sel_t r; memcpy(r.v, row, 8); return r; }

static inline void zbm_blend8_sel(uint8_t *dst, const uint8_t *base,
                                  const uint8_t *lits, zbm_sel_t sel)
ZBM_BLEND8_CONTRACT
{
    uint8_t combined[16];
    memcpy(&combined[0], lits, 8);
    memcpy(&combined[8], base, 8);
    for (int i = 0; i < 8; i++)
        ZBM_LOOP_ASSIGNS(i, __CPROVER_object_upto(dst, 8))
        ZBM_LOOP_INVARIANT(0 <= i && i <= 8)
        ZBM_LOOP_DECREASES(8 - i)
        dst[i] = combined[sel.v[i] & 0x0f];
}

static inline void zbm_blend8_row(uint8_t *dst, const uint8_t *base,
                                  const uint8_t *lits, const uint8_t *row)
ZBM_BLEND8_ROW_CONTRACT
{
    zbm_blend8_sel(dst, base, lits, zbm_sel_load(row));
}

static inline void zbm_pack8(uint8_t *d, const uint8_t *s, const uint8_t *row)
{
    for (int i = 0; i < 8; i++)
        d[i] = (row[i] < 8) ? s[row[i]] : 0;
}

static inline void zbm_cpy8(uint8_t *d, const uint8_t *s) ZBM_CPY_CONTRACT(8) { memcpy(d, s, 8); }
static inline void zbm_cpy16(uint8_t *d, const uint8_t *s) ZBM_CPY_CONTRACT(16) { memcpy(d, s, 16); }
static inline void zbm_cpy32(uint8_t *d, const uint8_t *s) ZBM_CPY_CONTRACT(32) { memcpy(d, s, 32); }

#if defined(ZBM_PROOF) && defined(ZBM_PROOF_BOUNDARY_VALUES)
extern unsigned zbm_proof_boundary_index;
#endif

static inline uint16_t zbm_eq16_mask(const uint8_t *a, const uint8_t *b)
#ifdef ZBM_PROOF
__CPROVER_requires(__CPROVER_r_ok(a, 16) && __CPROVER_r_ok(b, 16))
__CPROVER_assigns()
#ifdef ZBM_PROOF_BOUNDARY_VALUES
__CPROVER_ensures(((__CPROVER_return_value >> (zbm_proof_boundary_index & 15u)) & 1u) ==
    (a[zbm_proof_boundary_index & 15u] == b[zbm_proof_boundary_index & 15u]))
#endif
#ifdef ZBM_PROOF_SIMD_VALUES
__CPROVER_ensures(
    (((__CPROVER_return_value >> 0) & 1u) == (a[0] == b[0])) &
    (((__CPROVER_return_value >> 1) & 1u) == (a[1] == b[1])) &
    (((__CPROVER_return_value >> 2) & 1u) == (a[2] == b[2])) &
    (((__CPROVER_return_value >> 3) & 1u) == (a[3] == b[3])) &
    (((__CPROVER_return_value >> 4) & 1u) == (a[4] == b[4])) &
    (((__CPROVER_return_value >> 5) & 1u) == (a[5] == b[5])) &
    (((__CPROVER_return_value >> 6) & 1u) == (a[6] == b[6])) &
    (((__CPROVER_return_value >> 7) & 1u) == (a[7] == b[7])) &
    (((__CPROVER_return_value >> 8) & 1u) == (a[8] == b[8])) &
    (((__CPROVER_return_value >> 9) & 1u) == (a[9] == b[9])) &
    (((__CPROVER_return_value >> 10) & 1u) == (a[10] == b[10])) &
    (((__CPROVER_return_value >> 11) & 1u) == (a[11] == b[11])) &
    (((__CPROVER_return_value >> 12) & 1u) == (a[12] == b[12])) &
    (((__CPROVER_return_value >> 13) & 1u) == (a[13] == b[13])) &
    (((__CPROVER_return_value >> 14) & 1u) == (a[14] == b[14])) &
    (((__CPROVER_return_value >> 15) & 1u) == (a[15] == b[15])))
#endif
#endif
{
    uint16_t mask = 0;
    for (int i = 0; i < 16; i++)
        if (a[i] == b[i])
            mask |= (uint16_t)(1u << i);
    return mask;
}

// Sixteen values below 16, two to a byte, the first in the low nibble.
static inline uint64_t zbm_pack_nibbles16(const uint8_t *p)
#ifdef ZBM_PROOF
__CPROVER_requires(__CPROVER_r_ok(p, 16))
__CPROVER_assigns()
#ifdef ZBM_PROOF_SIMD_VALUES
/* Native packing has the same byte semantics for nibble-valued lanes.
 * The footprint contract still allows arbitrary bytes. */
__CPROVER_ensures(!(
    (p[0] <= 15) & (p[1] <= 15) & (p[2] <= 15) & (p[3] <= 15) & (p[4] <= 15) & (p[5] <= 15) & (p[6] <= 15) & (p[7] <= 15) & (p[8] <= 15) & (p[9] <= 15) & (p[10] <= 15) & (p[11] <= 15) & (p[12] <= 15) & (p[13] <= 15) & (p[14] <= 15) & (p[15] <= 15)) || (
    (((__CPROVER_return_value >> 0) & 15u) == (p[0] & 15u)) &
    (((__CPROVER_return_value >> 4) & 15u) == (p[1] & 15u)) &
    (((__CPROVER_return_value >> 8) & 15u) == (p[2] & 15u)) &
    (((__CPROVER_return_value >> 12) & 15u) == (p[3] & 15u)) &
    (((__CPROVER_return_value >> 16) & 15u) == (p[4] & 15u)) &
    (((__CPROVER_return_value >> 20) & 15u) == (p[5] & 15u)) &
    (((__CPROVER_return_value >> 24) & 15u) == (p[6] & 15u)) &
    (((__CPROVER_return_value >> 28) & 15u) == (p[7] & 15u)) &
    (((__CPROVER_return_value >> 32) & 15u) == (p[8] & 15u)) &
    (((__CPROVER_return_value >> 36) & 15u) == (p[9] & 15u)) &
    (((__CPROVER_return_value >> 40) & 15u) == (p[10] & 15u)) &
    (((__CPROVER_return_value >> 44) & 15u) == (p[11] & 15u)) &
    (((__CPROVER_return_value >> 48) & 15u) == (p[12] & 15u)) &
    (((__CPROVER_return_value >> 52) & 15u) == (p[13] & 15u)) &
    (((__CPROVER_return_value >> 56) & 15u) == (p[14] & 15u)) &
    (((__CPROVER_return_value >> 60) & 15u) == (p[15] & 15u))))
#endif
#endif
{
    uint64_t r = 0;
    for (int i = 0; i < 16; i++)
        r |= (uint64_t)(p[i] & 0xf) << (4 * i);
    return r;
}

#elif defined(__ARM_NEON)
#  include <arm_neon.h>

#  define ZBM_V4U32(a, b, c, d)              ((uint32x4_t){(a), (b), (c), (d)})
#  define ZBM_V8U16(a, b, c, d, e, f, g, h)  ((uint16x8_t){(a), (b), (c), (d), (e), (f), (g), (h)})
#  define ZBM_V8U8(a, b, c, d, e, f, g, h)   ((uint8x8_t){(a), (b), (c), (d), (e), (f), (g), (h)})
#  define ZBM_V16U8_IOTA                     ((uint8x16_t){0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

typedef uint8x8_t zbm_sel_t;
static inline zbm_sel_t zbm_sel_load(const uint8_t *row)
ZBM_SEL_LOAD_CONTRACT
{
    return vld1_u8(row);
}

static inline void zbm_blend8_sel(uint8_t *dst, const uint8_t *base,
                                  const uint8_t *lits, zbm_sel_t sel)
ZBM_BLEND8_CONTRACT
{
    vst1_u8(dst, vqtbl1_u8(vcombine_u8(vld1_u8(lits), vld1_u8(base)), sel));
}

static inline void zbm_blend8_row(uint8_t *dst, const uint8_t *base,
                                  const uint8_t *lits, const uint8_t *row)
ZBM_BLEND8_ROW_CONTRACT
{
    vst1_u8(dst, vqtbl1_u8(vcombine_u8(vld1_u8(lits), vld1_u8(base)),
                            vld1_u8(row)));
}

static inline void zbm_pack8(uint8_t *d, const uint8_t *s, const uint8_t *row)
{
    vst1_u8(d, vtbl1_u8(vld1_u8(s), vld1_u8(row)));
}

static inline void zbm_cpy8(uint8_t *d, const uint8_t *s)
ZBM_CPY_CONTRACT(8)
{
    vst1_u8(d, vld1_u8(s));
}

static inline void zbm_cpy16(uint8_t *d, const uint8_t *s)
ZBM_CPY_CONTRACT(16)
{
    vst1q_u8(d, vld1q_u8(s));
}

static inline void zbm_cpy32(uint8_t *d, const uint8_t *s)
ZBM_CPY_CONTRACT(32)
{
    vst1q_u8(d, vld1q_u8(s));
    vst1q_u8(d + 16, vld1q_u8(s + 16));
}

static inline uint16_t zbm_eq16_mask(const uint8_t *a, const uint8_t *b)
{
    static const uint8_t wt[16] = {1,2,4,8,16,32,64,128,1,2,4,8,16,32,64,128};
    uint8x16_t x = vandq_u8(vceqq_u8(vld1q_u8(a), vld1q_u8(b)), vld1q_u8(wt));
    return (uint16_t)vaddv_u8(vget_low_u8(x)) |
           ((uint32_t)vaddv_u8(vget_high_u8(x)) << 8);
}

static inline uint64_t zbm_pack_nibbles16(const uint8_t *p)
{
    uint16x8_t v = vreinterpretq_u16_u8(vld1q_u8(p));
    return vget_lane_u64(vreinterpret_u64_u8(vmovn_u16(vorrq_u16(v, vshrq_n_u16(v, 4)))), 0);
}

#elif defined(__SSE4_1__) && defined(__POPCNT__)
#  include <smmintrin.h>
#  include <nmmintrin.h>
#  include <tmmintrin.h>
#  include <emmintrin.h>
#  if defined(__AVX2__)
#    include <immintrin.h>
#  endif

typedef __m128i uint8x16_t;
typedef __m128i uint16x8_t;
typedef __m128i uint32x4_t;
typedef __m128i uint64x2_t;
typedef __m128i int32x4_t;
typedef __m128i uint8x8_t;
typedef __m128i uint16x4_t;

#  define ZBM_V4U32(a, b, c, d)              _mm_setr_epi32((int)(a), (int)(b), (int)(c), (int)(d))
#  define ZBM_V8U16(a, b, c, d, e, f, g, h)  _mm_setr_epi16(a, b, c, d, e, f, g, h)
#  define ZBM_V8U8(a, b, c, d, e, f, g, h)   _mm_setr_epi8(a, b, c, d, e, f, g, h, 0, 0, 0, 0, 0, 0, 0, 0)
#  define ZBM_V16U8_IOTA                     _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)

#  define vreinterpretq_u64_u32(x) (x)
#  define vreinterpretq_u32_u64(x) (x)
#  define vreinterpretq_u32_u8(x)  (x)
#  define vreinterpretq_u8_u64(x)  (x)
#  define vreinterpret_u16_u8(x)   (x)
#  define vgetq_lane_u32(v, l)     ((uint32_t)_mm_extract_epi32(v, l))
#  define vld1q_lane_u32(p, v, l)  _mm_insert_epi32(v, *(const int32_t *)(p), l)
#  define vextq_u8(a, b, n)        _mm_alignr_epi8(b, a, n)
#  define vshlq_n_u32(a, n)        _mm_slli_epi32(a, n)
#  define vshrq_n_u32(a, n)        _mm_srli_epi32(a, n)
#  define vshlq_n_u16(a, n)        _mm_slli_epi16(a, n)
#  define vshlq_n_u8(a, n)         _mm_and_si128(_mm_slli_epi16(a, n), _mm_set1_epi8((char)(0xffu << (n))))
#  define vdupq_laneq_u8(v, l)     _mm_shuffle_epi8(v, _mm_set1_epi8(l))
/* Indices are always below 16 here, where PSHUFB and TBL agree. */
#  define vqtbl1q_u8(t, idx)       _mm_shuffle_epi8(t, idx)

static inline uint8x16_t vld1q_u8(const uint8_t *p) { return _mm_loadu_si128((const __m128i *)(const void *)p); }
static inline uint32x4_t vld1q_u32(const uint32_t *p) { return _mm_loadu_si128((const __m128i *)(const void *)p); }
static inline void vst1q_u32(uint32_t *p, uint32x4_t v) { _mm_storeu_si128((__m128i *)(void *)p, v); }
static inline uint64x2_t vld1_u64(const uint64_t *p) { return _mm_loadl_epi64((const __m128i *)(const void *)p); }
static inline uint32x4_t vdupq_n_u32(uint32_t x) { return _mm_set1_epi32((int)x); }
static inline int32x4_t vdupq_n_s32(int32_t x) { return _mm_set1_epi32(x); }
static inline uint16x8_t vdupq_n_u16(uint16_t x) { return _mm_set1_epi16((short)x); }
static inline uint8x16_t vdupq_n_u8(uint8_t x) { return _mm_set1_epi8((char)x); }
static inline uint64x2_t vdupq_n_u64(uint64_t x) { return _mm_set1_epi64x((long long)x); }
static inline uint8x8_t vdup_n_u8(uint8_t x) { return _mm_set1_epi8((char)x); }
static inline uint64x2_t vcreate_u64(uint64_t x) { return _mm_cvtsi64_si128((long long)x); }
static inline uint16x4_t vcreate_u16(uint64_t x) { return _mm_cvtsi64_si128((long long)x); }
static inline uint8x8_t vcreate_u8(uint64_t x) { return _mm_cvtsi64_si128((long long)x); }
static inline uint64x2_t vcombine_u64(uint64x2_t lo, uint64x2_t hi) { return _mm_unpacklo_epi64(lo, hi); }
static inline uint8x16_t vcombine_u8(uint8x8_t lo, uint8x8_t hi) { return _mm_unpacklo_epi64(lo, hi); }
static inline uint8x8_t vget_low_u8(uint8x16_t v) { return v; }
static inline uint8x8_t vget_high_u8(uint8x16_t v) { return _mm_srli_si128(v, 8); }
static inline uint32x4_t vzip1q_u32(uint32x4_t a, uint32x4_t b) { return _mm_unpacklo_epi32(a, b); }
static inline uint32x4_t vzip2q_u32(uint32x4_t a, uint32x4_t b) { return _mm_unpackhi_epi32(a, b); }
static inline uint64x2_t vzip1q_u64(uint64x2_t a, uint64x2_t b) { return _mm_unpacklo_epi64(a, b); }
static inline uint64x2_t vzip2q_u64(uint64x2_t a, uint64x2_t b) { return _mm_unpackhi_epi64(a, b); }
static inline uint8x8_t vzip1_u8(uint8x8_t a, uint8x8_t b) { return _mm_unpacklo_epi8(a, b); }
static inline uint32x4_t vuzp1q_u32(uint32x4_t a, uint32x4_t b)
{ return _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(b), _MM_SHUFFLE(2, 0, 2, 0))); }
static inline uint32x4_t vuzp2q_u32(uint32x4_t a, uint32x4_t b)
{ return _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(b), _MM_SHUFFLE(3, 1, 3, 1))); }
static inline uint32x4_t vmulq_u32(uint32x4_t a, uint32x4_t b) { return _mm_mullo_epi32(a, b); }
static inline uint32x4_t vshlq_u32(uint32x4_t a, int32x4_t b) { return _mm_srl_epi32(a, _mm_cvtsi32_si128(-_mm_cvtsi128_si32(b))); }
static inline uint32x4_t vandq_u32(uint32x4_t a, uint32x4_t b) { return _mm_and_si128(a, b); }
static inline uint8x8_t vand_u8(uint8x8_t a, uint8x8_t b) { return _mm_and_si128(a, b); }
static inline uint32x4_t vorrq_u32(uint32x4_t a, uint32x4_t b) { return _mm_or_si128(a, b); }
static inline uint16x8_t vorrq_u16(uint16x8_t a, uint16x8_t b) { return _mm_or_si128(a, b); }
static inline uint8x16_t vorrq_u8(uint8x16_t a, uint8x16_t b) { return _mm_or_si128(a, b); }
static inline uint32x4_t vbicq_u32(uint32x4_t a, uint32x4_t b) { return _mm_andnot_si128(b, a); }
static inline uint8x16_t vbicq_u8(uint8x16_t a, uint8x16_t b) { return _mm_andnot_si128(b, a); }
static inline uint32x4_t vaddq_u32(uint32x4_t a, uint32x4_t b) { return _mm_add_epi32(a, b); }
static inline uint8x16_t vaddq_u8(uint8x16_t a, uint8x16_t b) { return _mm_add_epi8(a, b); }
static inline uint32x4_t vsubq_u32(uint32x4_t a, uint32x4_t b) { return _mm_sub_epi32(a, b); }
static inline uint16x8_t vsubq_u16(uint16x8_t a, uint16x8_t b) { return _mm_sub_epi16(a, b); }
static inline uint8x16_t vsubq_u8(uint8x16_t a, uint8x16_t b) { return _mm_sub_epi8(a, b); }
static inline uint32x4_t vminq_u32(uint32x4_t a, uint32x4_t b) { return _mm_min_epu32(a, b); }
static inline uint16x8_t vminq_u16(uint16x8_t a, uint16x8_t b) { return _mm_min_epu16(a, b); }
static inline uint8x16_t vminq_u8(uint8x16_t a, uint8x16_t b) { return _mm_min_epu8(a, b); }
static inline uint16x8_t vld1q_u16(const uint16_t *p) { return _mm_loadu_si128((const __m128i *)(const void *)p); }
static inline uint16x8_t vandq_u16(uint16x8_t a, uint16x8_t b) { return _mm_and_si128(a, b); }
static inline uint16x8_t vceqq_u16(uint16x8_t a, uint16x8_t b) { return _mm_cmpeq_epi16(a, b); }
static inline uint16x8_t vcltq_u16(uint16x8_t a, uint16x8_t b) {
    const __m128i sign = _mm_set1_epi16((short)0x8000u);
    return _mm_cmplt_epi16(_mm_xor_si128(a, sign), _mm_xor_si128(b, sign));
}
static inline uint16_t vmaxvq_u16(uint16x8_t v) {
    v = _mm_max_epu16(v, _mm_srli_si128(v, 8));
    v = _mm_max_epu16(v, _mm_srli_si128(v, 4));
    v = _mm_max_epu16(v, _mm_srli_si128(v, 2));
    return (uint16_t)_mm_cvtsi128_si32(v);
}
static inline uint8x16_t vceqq_u8(uint8x16_t a, uint8x16_t b) { return _mm_cmpeq_epi8(a, b); }
static inline uint32x4_t vcgtq_u32(uint32x4_t a, uint32x4_t b)
{ const __m128i sign = _mm_set1_epi32((int)0x80000000u); return _mm_cmpgt_epi32(_mm_xor_si128(a, sign), _mm_xor_si128(b, sign)); }
static inline uint32x4_t vcleq_u32(uint32x4_t a, uint32x4_t b) { return _mm_cmpeq_epi32(_mm_min_epu32(a, b), a); }
static inline uint32x4_t vbslq_u32(uint32x4_t m, uint32x4_t a, uint32x4_t b) { return _mm_blendv_epi8(b, a, m); }
static inline uint8x8_t vtst_u8(uint8x8_t a, uint8x8_t b)
{ return _mm_xor_si128(_mm_cmpeq_epi8(_mm_and_si128(a, b), _mm_setzero_si128()), _mm_set1_epi8(-1)); }
static inline uint8_t vaddv_u8(uint8x8_t v) { return (uint8_t)_mm_cvtsi128_si32(_mm_sad_epu8(_mm_move_epi64(v), _mm_setzero_si128())); }
static inline uint8x8_t vcnt_u8(uint8x8_t v)
{
    const __m128i lut = _mm_setr_epi8(0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4);
    const __m128i nib = _mm_set1_epi8(0x0f);
    return _mm_add_epi8(_mm_shuffle_epi8(lut, _mm_and_si128(v, nib)),
                        _mm_shuffle_epi8(lut, _mm_and_si128(_mm_srli_epi16(v, 4), nib)));
}
static inline uint8x16_t vpaddq_u8(uint8x16_t a, uint8x16_t b)
{ const __m128i ones = _mm_set1_epi8(1); return _mm_packus_epi16(_mm_maddubs_epi16(a, ones), _mm_maddubs_epi16(b, ones)); }
static inline uint16x8_t vmovl_u8(uint8x8_t v) { return _mm_cvtepu8_epi16(v); }
static inline uint32x4_t vmovl_u16(uint16x4_t v) { return _mm_cvtepu16_epi32(v); }
static inline uint32_t vminvq_u32(uint32x4_t v)
{ __m128i m = _mm_min_epu32(v, _mm_srli_si128(v, 8)); m = _mm_min_epu32(m, _mm_srli_si128(m, 4)); return (uint32_t)_mm_cvtsi128_si32(m); }
static inline uint16_t vminvq_u16(uint16x8_t v) { return (uint16_t)_mm_cvtsi128_si32(_mm_minpos_epu16(v)); }
static inline uint8_t vminvq_u8(uint8x16_t v)
{ __m128i m = _mm_min_epu16(_mm_cvtepu8_epi16(v), _mm_cvtepu8_epi16(_mm_srli_si128(v, 8))); return (uint8_t)_mm_cvtsi128_si32(_mm_minpos_epu16(m)); }

typedef __m128i zbm_sel_t;
static inline zbm_sel_t zbm_sel_load(const uint8_t *row)
ZBM_SEL_LOAD_CONTRACT
{
    return _mm_loadl_epi64((const __m128i *)(const void *)row);
}

static inline void zbm_blend8_sel(uint8_t *dst, const uint8_t *base,
                                  const uint8_t *lits, zbm_sel_t sel)
ZBM_BLEND8_CONTRACT
{
    __m128i l = _mm_loadl_epi64((const __m128i *)(const void *)lits);
    __m128i b = _mm_loadl_epi64((const __m128i *)(const void *)base);
    __m128i v = _mm_unpacklo_epi64(l, b);
    _mm_storel_epi64((__m128i *)(void *)dst, _mm_shuffle_epi8(v, sel));
}

static inline void zbm_blend8_row(uint8_t *dst, const uint8_t *base,
                                  const uint8_t *lits, const uint8_t *row)
ZBM_BLEND8_ROW_CONTRACT
{
    zbm_blend8_sel(dst, base, lits, zbm_sel_load(row));
}

static inline void zbm_pack8(uint8_t *d, const uint8_t *s, const uint8_t *row)
{
    _mm_storel_epi64((__m128i *)(void *)d,
                      _mm_shuffle_epi8(_mm_loadl_epi64((const __m128i *)(const void *)s),
                                       _mm_loadl_epi64((const __m128i *)(const void *)row)));
}

static inline void zbm_cpy8(uint8_t *d, const uint8_t *s)
ZBM_CPY_CONTRACT(8)
{
    _mm_storel_epi64((__m128i *)(void *)d,
                      _mm_loadl_epi64((const __m128i *)(const void *)s));
}

static inline void zbm_cpy16(uint8_t *d, const uint8_t *s)
ZBM_CPY_CONTRACT(16)
{
    _mm_storeu_si128((__m128i *)(void *)d,
                      _mm_loadu_si128((const __m128i *)(const void *)s));
}

static inline void zbm_cpy32(uint8_t *d, const uint8_t *s)
ZBM_CPY_CONTRACT(32)
{
    __m128i a = _mm_loadu_si128((const __m128i *)(const void *)s);
    __m128i b = _mm_loadu_si128((const __m128i *)(const void *)(s + 16));

    _mm_storeu_si128((__m128i *)(void *)d, a);
    _mm_storeu_si128((__m128i *)(void *)(d + 16), b);
}

static inline uint16_t zbm_eq16_mask(const uint8_t *a, const uint8_t *b)
{
    return (uint16_t)(unsigned)_mm_movemask_epi8(
        _mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)(const void *)a),
                       _mm_loadu_si128((const __m128i *)(const void *)b)));
}

static inline uint64_t zbm_pack_nibbles16(const uint8_t *p)
{
    __m128i v = _mm_loadu_si128((const __m128i *)(const void *)p);
    __m128i t = _mm_and_si128(_mm_or_si128(v, _mm_srli_epi16(v, 4)), _mm_set1_epi16(0x00ff));
    return (uint64_t)_mm_cvtsi128_si64(_mm_packus_epi16(t, t));
}

#endif // defined(CRUSH_SIMD_PORTABLE) / __ARM_NEON / __SSE4_1__ && __POPCNT__

#endif // CRUSH_SIMD_H
