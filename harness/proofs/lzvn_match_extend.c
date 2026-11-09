/*
 * Proof: match_extend in crates/crushlzfse/csrc/lzfse_internal.h meets its contract.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

size_t nondet_size(void);
uint32_t nondet_uint32(void);

void harness(void)
{
    uint32_t max_length = nondet_uint32();
    uint32_t length = nondet_uint32();
    __CPROVER_assume(length <= max_length && max_length <= 0xFFFFFFF0u);

    size_t an = nondet_size(), bn = nondet_size();
    __CPROVER_assume(an >= (size_t)max_length + 7 && an <= PROOF_MAX_OBJECT);
    __CPROVER_assume(bn >= (size_t)max_length + 7 && bn <= PROOF_MAX_OBJECT);
    uint8_t *a = malloc(an);
    uint8_t *b = malloc(bn);
    __CPROVER_assume(a != NULL && b != NULL);

    uint32_t r = match_extend(a, b, length, max_length);

    PROOF_REACHABLE(length == max_length && r == max_length, "already at the limit");
    PROOF_REACHABLE(length < max_length && r == length, "no further match");
    PROOF_REACHABLE(r > length && r < max_length, "partial extension");
    PROOF_REACHABLE(r == max_length && length < max_length, "clamped to the limit");
}
