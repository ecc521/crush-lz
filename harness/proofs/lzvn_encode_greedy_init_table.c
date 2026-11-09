/*
 * Proof: lzvn_encode_greedy_init_table in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

int32_t nondet_int(void);

void harness(void)
{
    int32_t hash_bits = nondet_int();
    __CPROVER_assume(hash_bits >= 10 && hash_bits <= 16);

    size_t table_bytes = ((size_t)1 << hash_bits) * sizeof(uint16_t);
    uint16_t *hist_cursor = malloc(table_bytes);
    __CPROVER_assume(hist_cursor != NULL);

    lzvn_encode_greedy_init_table(hash_bits, hist_cursor);

    PROOF_REACHABLE(hash_bits == 10, "min hash bits 10");
    PROOF_REACHABLE(hash_bits == 14, "mid hash bits 14");
    PROOF_REACHABLE(hash_bits == 16, "max hash bits 16");
}
