/*
 * Proof: the portable zbm_blend8_sel in crates/lzbitmap/csrc/crush_simd.h
 * meets its contract: it reads 8 bytes each of base and lits, and writes
 * only dst[0, 8), for any selector. dst may be base itself, as in the
 * decoder's run path.
 */
#include "proof.h"
#include "libzbitmap.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

/* A pointer into a fresh buffer of unconstrained size. */
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
    const uint8_t *base = nondet_bool() ? dst : any_buffer();
    const uint8_t *lits = any_buffer();
    zbm_sel_t sel;      /* uninitialized: any selector bytes */
    zbm_blend8_sel(dst, base, lits, sel);

    PROOF_REACHABLE(base == dst, "blend in place");
    PROOF_REACHABLE(base != dst, "blend from another buffer");
}
