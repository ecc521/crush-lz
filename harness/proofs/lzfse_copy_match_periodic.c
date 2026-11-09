/*
 * Proof: copy_match_periodic in crates/crushlzfse/csrc/lzfse_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);
ptrdiff_t nondet_diff(void);

void harness(void)
{
    ptrdiff_t D = nondet_diff();
    __CPROVER_assume(D >= 1 && D < 16);

    ptrdiff_t M = nondet_diff();
    __CPROVER_assume(M >= 32 && M <= PROOF_MAX_OBJECT / 4);

    size_t cap = (size_t)M + LZFSE_DECODE_COPY_MARGIN + (size_t)D + 32;
    __CPROVER_assume(cap <= PROOF_MAX_OBJECT);

    uint8_t *buf = malloc(cap);
    __CPROVER_assume(buf != NULL);

    uint8_t *dst = buf + D;

    copy_match_periodic(dst, D, M);

    PROOF_REACHABLE(D == 1, "D = 1 handled");
    PROOF_REACHABLE(D == 15, "D = 15 handled");
    PROOF_REACHABLE(M == 32, "minimum match length");
    PROOF_REACHABLE(M > 64, "match length exceeding target");
}
