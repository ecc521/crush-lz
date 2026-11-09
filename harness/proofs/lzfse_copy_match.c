/*
 * Proof: lzfse_copy_match in crates/crushlzfse/csrc/lzfse_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);
ptrdiff_t nondet_diff(void);

void harness(void)
{
    ptrdiff_t D = nondet_diff();
    __CPROVER_assume(D >= 1 && D <= PROOF_MAX_OBJECT / 4);

    ptrdiff_t M = nondet_diff();
    __CPROVER_assume(M >= 0 && M <= PROOF_MAX_OBJECT / 4);

    size_t cap = (size_t)M + LZFSE_DECODE_COPY_MARGIN + (size_t)D + 32;
    __CPROVER_assume(cap <= PROOF_MAX_OBJECT);

    uint8_t *buf = malloc(cap);
    __CPROVER_assume(buf != NULL);

    uint8_t *dst = buf + D;

    lzfse_copy_match(dst, D, M);

    PROOF_REACHABLE(M > 0 && D >= 16, "wide branch");
    PROOF_REACHABLE(M >= 32 && D < 16, "periodic branch");
    PROOF_REACHABLE(M < 32 && D >= 8 && D < 16, "copy branch");
    PROOF_REACHABLE(M > 0 && D < 8, "bytes branch");
}
