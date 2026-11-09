/*
 * The decoder's SIMD wrappers and zbm_copy_fwd from libzbitmap.c, exported
 * under the prefix PFX. run.sh compiles this three times: native branch on
 * the real intrinsics (R_), native branch on the models through the shadow
 * headers (D_), and the portable branch (P_). libzbitmap.c's own public
 * symbols are renamed by run.sh so the three copies link together.
 */
#include "libzbitmap.c"

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)

const char *CAT(PFX, branch)(void)
{
#if defined(CRUSH_SIMD_PORTABLE)
    return "portable";
#elif defined(CRUSH_SIMD_SHADOW_NEON) || defined(CRUSH_SIMD_SHADOW_X86)
    return "native-model";
#elif defined(__ARM_NEON)
    return "native-neon";
#else
    return "native-sse";
#endif
}

void CAT(PFX, blend8_row)(uint8_t *dst, const uint8_t *base,
                          const uint8_t *lits, const uint8_t *row)
{
    zbm_blend8_row(dst, base, lits, row);
}

void CAT(PFX, blend8_tab)(uint8_t *dst, const uint8_t *base,
                          const uint8_t *lits, uint8_t bmp)
{
    zbm_blend8(dst, base, lits, bmp);
}

void CAT(PFX, blend8_sel_inplace)(uint8_t *d, const uint8_t *lits,
                                  const uint8_t *row)
{
    zbm_sel_t sel = zbm_sel_load(row);
    zbm_blend8_sel(d, d, lits, sel);
}

void CAT(PFX, cpy8)(uint8_t *d, const uint8_t *s) { zbm_cpy8(d, s); }
void CAT(PFX, cpy16)(uint8_t *d, const uint8_t *s) { zbm_cpy16(d, s); }
void CAT(PFX, cpy32)(uint8_t *d, const uint8_t *s) { zbm_cpy32(d, s); }

void CAT(PFX, copy_fwd)(uint8_t *d, const uint8_t *s, uint32_t n)
{
    zbm_copy_fwd(d, s, n);
}

const uint8_t *CAT(PFX, blend_table)(void) { return &zbm_blend_row[0][0]; }
