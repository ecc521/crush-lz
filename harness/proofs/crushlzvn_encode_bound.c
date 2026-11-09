/*
 * Proof: crushlzvn_encode_bound in crates/crushlzfse/csrc/crushlzvn.c.
 */
#include "proof.h"
#include "crushlzvn.c"

size_t nondet_size(void);

void harness(void)
{
    size_t n = nondet_size();
    __CPROVER_assume(n <= (size_t)LZVN_ZOPT_BLOCK_SIZE);

    crushlzvn_encode_params params;
    memset(&params, 0, sizeof(params));

    size_t bound = crushlzvn_encode_bound(n, &params);

    __CPROVER_assert(bound >= n + 64, "bound covers input size with slack");
    __CPROVER_assert(bound <= n + 2 * (n / 271) + 68, "bound within analytical envelope");

    PROOF_REACHABLE(n == 0, "empty input");
    PROOF_REACHABLE(n == 1, "1 byte input");
    PROOF_REACHABLE(n == 271, "chunk threshold 271");
    PROOF_REACHABLE(n == (size_t)LZVN_ZOPT_BLOCK_SIZE, "block size maximum");
}
