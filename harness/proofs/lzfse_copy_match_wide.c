/*
 * Proof: copy_match_wide in crates/crushlzfse/csrc/lzfse_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t length = nondet_size();
    __CPROVER_assume(length <= PROOF_MAX_OBJECT / 4);

    size_t distance = nondet_size();
    __CPROVER_assume(distance <= PROOF_MAX_OBJECT / 4);
    size_t cap = length + LZFSE_DECODE_COPY_MARGIN + 32 + distance;
    __CPROVER_assume(cap <= PROOF_MAX_OBJECT);

    uint8_t *dbuf = malloc(cap);
    __CPROVER_assume(dbuf != NULL);

    uint8_t *sbuf = malloc(cap);
    __CPROVER_assume(sbuf != NULL);

    _Bool alias = nondet_bool();
    copy_match_wide(dbuf + distance, alias ? dbuf : sbuf, length);

    PROOF_REACHABLE(length == 0, "zero-length match");
    PROOF_REACHABLE(length <= LZFSE_DECODE_COPY_MARGIN, "short match inside margin");
    PROOF_REACHABLE(length > LZFSE_DECODE_COPY_MARGIN, "long match exceeding margin");
    PROOF_REACHABLE(alias && distance < 16 && length <= distance,
                    "short-distance production wide copy");
    PROOF_REACHABLE(alias && distance >= 16 && length > distance,
                    "overlapping wide match");
}
