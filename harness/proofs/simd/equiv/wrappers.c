/*
 * The decoder's SIMD wrappers from crates/lzbitmap/csrc/crush_simd.h,
 * exported under a prefix. run_equiv.sh compiles this file three times:
 * portable branch (P_), NEON branch (N_) and SSE branch (S_), the latter
 * two through the shadow intrinsic headers and models.
 */
#include <stdint.h>

#define ZBM_REQUIRES(x)
#define ZBM_ENSURES(x)
#define ZBM_ASSIGNS(...)
#define ZBM_LOOP_ASSIGNS(...)
#define ZBM_LOOP_INVARIANT(x)
#define ZBM_LOOP_DECREASES(x)
#include "crush_simd.h"

#if defined(EXPECT_PORTABLE) != defined(CRUSH_SIMD_PORTABLE)
#error "wrong crush_simd.h branch"
#endif
#if defined(EXPECT_NEON) && !defined(CRUSH_SIMD_SHADOW_NEON)
#error "NEON branch without the shadow arm_neon.h"
#endif
#if defined(EXPECT_SSE) && !defined(CRUSH_SIMD_SHADOW_X86)
#error "SSE branch without the shadow x86 headers"
#endif

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)

void CAT(PFX, blend8_row)(uint8_t *dst, const uint8_t *base,
                          const uint8_t *lits, const uint8_t *row)
{
    zbm_blend8_row(dst, base, lits, row);
}

/* zbm_patch_literals' form: the selector loaded once, then blended. */
void CAT(PFX, blend8_sel)(uint8_t *dst, const uint8_t *base,
                          const uint8_t *lits, const uint8_t *row)
{
    zbm_sel_t sel = zbm_sel_load(row);
    zbm_blend8_sel(dst, base, lits, sel);
}

/* zbm_patch_literals' in-place call: dst is base. */
void CAT(PFX, blend8_sel_inplace)(uint8_t *d, const uint8_t *lits,
                                  const uint8_t *row)
{
    zbm_sel_t sel = zbm_sel_load(row);
    zbm_blend8_sel(d, d, lits, sel);
}

void CAT(PFX, cpy8)(uint8_t *d, const uint8_t *s) { zbm_cpy8(d, s); }
void CAT(PFX, cpy16)(uint8_t *d, const uint8_t *s) { zbm_cpy16(d, s); }
void CAT(PFX, cpy32)(uint8_t *d, const uint8_t *s) { zbm_cpy32(d, s); }
