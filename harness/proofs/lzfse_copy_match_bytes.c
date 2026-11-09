/*
 * Proof: lzfse_copy_match_bytes in crates/crushlzfse/csrc/lzfse_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);
ptrdiff_t nondet_diff(void);

void harness(void)
{
    size_t count = nondet_size();
    __CPROVER_assume(count <= PROOF_MAX_OBJECT / 4);

    ptrdiff_t D = nondet_diff();
    __CPROVER_assume(D > 0 && D <= PROOF_MAX_OBJECT / 4);

    size_t cap = count + (size_t)D + 32;
    __CPROVER_assume(cap <= PROOF_MAX_OBJECT);

    uint8_t *buf = malloc(cap);
    __CPROVER_assume(buf != NULL);

    uint8_t *dst = buf + D;

    lzfse_copy_match_bytes(dst, D, count);

    PROOF_REACHABLE(count == 0, "zero-length match");
    PROOF_REACHABLE(count > 0 && count <= (size_t)D, "match without self-overlap");
    PROOF_REACHABLE(count > (size_t)D, "match with self-overlap");
}
