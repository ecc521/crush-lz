/*
 * Proof: lzfse_copy_literal_bytes in crates/crushlzfse/csrc/lzfse_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);

void harness(void)
{
    size_t count = nondet_size();
    __CPROVER_assume(count <= PROOF_MAX_OBJECT / 4);

    size_t cap = count + 32;
    __CPROVER_assume(cap <= PROOF_MAX_OBJECT);

    uint8_t *dbuf = malloc(cap);
    __CPROVER_assume(dbuf != NULL);

    uint8_t *sbuf = malloc(cap);
    __CPROVER_assume(sbuf != NULL);

    lzfse_copy_literal_bytes(dbuf, sbuf, count);

    PROOF_REACHABLE(count == 0, "zero-length literal");
    PROOF_REACHABLE(count > 0, "non-zero literal copy");
}
