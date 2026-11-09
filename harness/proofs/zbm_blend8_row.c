/*
 * Proof: the portable zbm_blend8_row in crates/lzbitmap/csrc/crush_simd.h
 * meets its contract: it reads 8 bytes each of base, lits and row, and
 * writes only dst[0, 8). zbm_blend8_sel is replaced by its contract, proved
 * in zbm_blend8_sel.c.
 */
#include "proof.h"
#include "libzbitmap.c"

size_t nondet_size(void);

static uint8_t *any_buffer(void)
{
    size_t n = nondet_size(), o = nondet_size();
    __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT && o <= n);
    uint8_t *b = malloc(n);
    __CPROVER_assume(b != NULL);
    return b + o;
}

void harness(void)
{
    uint8_t *dst = any_buffer();
    zbm_blend8_row(dst, any_buffer(), any_buffer(), any_buffer());
    PROOF_REACHABLE(1, "blend returns");
}
