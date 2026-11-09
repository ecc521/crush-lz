/* Exact bytes, including in-place blending, for every bitmap and input byte.
 * Unlike the safety harnesses, this uses memcpy's actual data semantics.
 *
 * Covers the three decoder call shapes: zbm_blend8 (row zbm_blend_row[bmp]),
 * the pair/block loops (row rowbase + (bmp << 4) with rowbase ==
 * zbm_blend_row[0]) and zbm_patch_literals (selector loaded once, then an
 * in-place zbm_blend8_sel). Built natively (_neon, _sse), where TBL and
 * PSHUFB differ from the portable `sel & 15` for selectors of 16 and up, it
 * carries the selector < 16 lemma into the decoder's values. CBMC 6.11 reads
 * through `rowbase + (bmp << 4)` as an unconstrained value (simd/README.md),
 * so that shape is first proved to be the same pointer as zbm_blend_row[bmp]
 * and the bytes are then read through the direct index. */
#include "proof.h"
#undef memcpy
#include "libzbitmap.c"

uint8_t nondet_u8(void);

void harness(void)
{
    uint8_t base[8], lits[8], saved[8], dst[8], row_dst[8], sel_base[8];
    uint8_t bitmap = nondet_u8();
    for (unsigned i = 0; i < 8; ++i) {
        base[i] = saved[i] = sel_base[i] = nondet_u8();
        lits[i] = nondet_u8();
    }
    const uint8_t *rowbase = zbm_blend_row[0];
    const uint8_t *row = rowbase + ((size_t)bitmap << 4);
    __CPROVER_assert(row == zbm_blend_row[bitmap], "pair-loop row is zbm_blend_row[bmp]");
    zbm_blend8(dst, base, lits, bitmap);
    zbm_blend8(base, base, lits, bitmap);
    zbm_blend8_row(row_dst, saved, lits, zbm_blend_row[bitmap]);
    zbm_sel_t sel = zbm_sel_load(zbm_blend_row[bitmap]);
    zbm_blend8_sel(sel_base, sel_base, lits, sel);
    unsigned literal = 0;
    for (unsigned i = 0; i < 8; ++i) {
        uint8_t want = bitmap & (1u << i) ? lits[literal++] : saved[i];
        __CPROVER_assert(dst[i] == want, "blend matches literal/copy semantics");
        __CPROVER_assert(base[i] == want, "in-place blend matches semantics");
        __CPROVER_assert(row_dst[i] == want, "row blend matches semantics");
        __CPROVER_assert(sel_base[i] == want, "in-place selector blend matches semantics");
    }
    __CPROVER_assert(literal == zbm_blend_row[bitmap][ZBM_BLEND_ROW_CNT],
                     "blend table literal consumption");
    PROOF_REACHABLE(bitmap == 0, "all copies");
    PROOF_REACHABLE(bitmap == 255, "all literals");
    PROOF_REACHABLE(bitmap == 0x55, "mixed bitmap");
}
