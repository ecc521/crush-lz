/*
 * C semantic models of the x86 SSE2/SSSE3 intrinsics the decoders use. See
 * README.md. Each model touches memory one byte at a time, so CBMC checks
 * the exact footprint, and is straight-line so loop contracts never see it.
 * Lane i of the 128-bit value is byte i in memory (little-endian).
 * harness/simd_validate checks every model against the hardware.
 */
#ifndef CRUSH_SSE_MODEL_H
#define CRUSH_SSE_MODEL_H

#include <stdint.h>

typedef struct { uint8_t b[16]; } M_m128i;

#define M_REP8(X) X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7)
#define M_REP16(X) M_REP8(X) X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15)

/* MOVQ xmm, m64: reads p[0, 8); lanes 8..15 are zero. No alignment. */
#define M_SSE_LD(i) r.b[i] = p[i];
#define M_SSE_ZERO_HI(i) r.b[8 + i] = 0;
static inline M_m128i M_mm_loadl_epi64(const uint8_t *p)
{
    M_m128i r;
    M_REP8(M_SSE_LD)
    M_REP8(M_SSE_ZERO_HI)
    return r;
}

/* MOVDQU xmm, m128: reads p[0, 16). */
static inline M_m128i M_mm_loadu_si128(const uint8_t *p)
{
    M_m128i r;
    M_REP16(M_SSE_LD)
    return r;
}

/* MOVQ m64, xmm: writes p[0, 8). */
#define M_SSE_ST(i) p[i] = v.b[i];
static inline void M_mm_storel_epi64(uint8_t *p, M_m128i v)
{
    M_REP8(M_SSE_ST)
}

/* MOVDQU m128, xmm: writes p[0, 16). */
static inline void M_mm_storeu_si128(uint8_t *p, M_m128i v)
{
    M_REP16(M_SSE_ST)
}

/* PUNPCKLQDQ: low quadword of a, then low quadword of b. */
#define M_SSE_UNPACKLO64(i) r.b[i] = a.b[i]; r.b[8 + i] = b.b[i];
static inline M_m128i M_mm_unpacklo_epi64(M_m128i a, M_m128i b)
{
    M_m128i r;
    M_REP8(M_SSE_UNPACKLO64)
    return r;
}

/* PSHUFB: a control byte with bit 7 set selects 0, otherwise a[c & 15]. */
#define M_SSE_PSHUFB(i) r.b[i] = (b.b[i] & 0x80) ? 0 : a.b[b.b[i] & 15];
static inline M_m128i M_mm_shuffle_epi8(M_m128i a, M_m128i b)
{
    M_m128i r;
    M_REP16(M_SSE_PSHUFB)
    return r;
}

#endif
