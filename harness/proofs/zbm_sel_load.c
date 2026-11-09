/*
 * Proof: zbm_sel_load in crates/lzbitmap/csrc/crush_simd.h meets
 * ZBM_SEL_LOAD_CONTRACT on every branch: it reads only row[0, 8) and
 * writes nothing.
 */
#include "proof.h"
#include "libzbitmap.c"

size_t nondet_size(void);

void harness(void)
{
    size_t n = nondet_size(), o = nondet_size();
    __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT && o <= n);
    uint8_t *b = malloc(n);
    __CPROVER_assume(b != NULL);
    zbm_sel_t sel = zbm_sel_load(b + o);
    (void)sel;
    PROOF_REACHABLE(o + 8 == n, "row flush against the end");
}
