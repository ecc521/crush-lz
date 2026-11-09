/*
 * C semantic models of the ARM NEON intrinsics the decoders use. See
 * README.md. Each model touches memory one byte at a time, so CBMC checks
 * the exact footprint, and is straight-line so loop contracts never see it.
 * harness/simd_validate checks every model against the hardware.
 *
 * Usable on its own (prefixed names, no clash with <arm_neon.h>) or through
 * the shadow include/arm_neon.h, which maps the real names onto these.
 */
#ifndef CRUSH_NEON_MODEL_H
#define CRUSH_NEON_MODEL_H

#include <stdint.h>

typedef struct { uint8_t b[8]; } M_uint8x8_t;
typedef struct { uint8_t b[16]; } M_uint8x16_t;

#define M_REP8(X) X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7)
#define M_REP16(X) M_REP8(X) X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15)

/* LD1 {Vt.8B}: reads p[0, 8), no alignment requirement. */
#define M_NEON_LD(i) r.b[i] = p[i];
static inline M_uint8x8_t M_vld1_u8(const uint8_t *p)
{
    M_uint8x8_t r;
    M_REP8(M_NEON_LD)
    return r;
}

/* LD1 {Vt.16B}: reads p[0, 16). */
static inline M_uint8x16_t M_vld1q_u8(const uint8_t *p)
{
    M_uint8x16_t r;
    M_REP16(M_NEON_LD)
    return r;
}

/* ST1 {Vt.8B}: writes p[0, 8). */
#define M_NEON_ST(i) p[i] = v.b[i];
static inline void M_vst1_u8(uint8_t *p, M_uint8x8_t v)
{
    M_REP8(M_NEON_ST)
}

/* ST1 {Vt.16B}: writes p[0, 16). */
static inline void M_vst1q_u8(uint8_t *p, M_uint8x16_t v)
{
    M_REP16(M_NEON_ST)
}

/* Lanes 0..7 from lo, 8..15 from hi. */
#define M_NEON_COMBINE(i) r.b[i] = lo.b[i]; r.b[8 + i] = hi.b[i];
static inline M_uint8x16_t M_vcombine_u8(M_uint8x8_t lo, M_uint8x8_t hi)
{
    M_uint8x16_t r;
    M_REP8(M_NEON_COMBINE)
    return r;
}

/* TBL Vd.8B, {Vn.16B}, Vm.8B: an index of 16 or more selects 0. */
#define M_NEON_TBL1(i) r.b[i] = idx.b[i] < 16 ? t.b[idx.b[i]] : 0;
static inline M_uint8x8_t M_vqtbl1_u8(M_uint8x16_t t, M_uint8x8_t idx)
{
    M_uint8x8_t r;
    M_REP8(M_NEON_TBL1)
    return r;
}

#endif
