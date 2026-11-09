/*
 * Proof: copy in crates/crushlzfse/csrc/lzfse_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);

void harness(void)
{
    size_t length = nondet_size();
    __CPROVER_assume(length > 0 && length <= PROOF_MAX_OBJECT / 4);

    size_t cap = length + 8 + 32;
    __CPROVER_assume(cap <= PROOF_MAX_OBJECT);

    uint8_t *dbuf = malloc(cap);
    __CPROVER_assume(dbuf != NULL);

    uint8_t *sbuf = malloc(cap);
    __CPROVER_assume(sbuf != NULL);

    copy(dbuf, sbuf, length);

    PROOF_REACHABLE(length <= 8, "short copy");
    PROOF_REACHABLE(length > 8, "multi-step copy");
}
