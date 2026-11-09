/*
 * Proof: crushlzfse_encode_bound in crates/crushlzfse/csrc/crushlzfse.c.
 */
#include "proof.h"
#include <string.h>
#include "crushlzvn.h"

/* The shipping LZVN dispatch layer, included as is. It and crushlzfse.c
 * both define these file-static names, so rename the LZVN ones while
 * crushlzvn.c is included. */
#define cand_capacity_for lzvn_cand_capacity_for
#define encode_block lzvn_encode_block
#define fast_params_valid lzvn_fast_params_valid
#define optimal_params_valid lzvn_optimal_params_valid
#define LEVEL_TABLE lzvn_LEVEL_TABLE
#include "crushlzvn.c"
#undef cand_capacity_for
#undef encode_block
#undef fast_params_valid
#undef optimal_params_valid
#undef LEVEL_TABLE

#include "crushlzfse.c"

size_t nondet_size(void);

void harness(void)
{
    size_t n = nondet_size();
    __CPROVER_assume(n <= (size_t)LZFSE_ZOPT_BLOCK_SIZE);

    crushlzfse_encode_params params;
    memset(&params, 0, sizeof(params));

    size_t bound = crushlzfse_encode_bound(n, &params);

    /* 1. Bound covers raw uncompressed fallback: write_uncompressed_block needs n + 12 */
    __CPROVER_assert(bound >= n + 12, "bound covers raw block expansion");
    __CPROVER_assert(bound == n + 16, "bound exact for single block");

    /* Also verify for n_large (multi-block hypothetical query) */
    size_t n_large = nondet_size();
    __CPROVER_assume(n_large <= (size_t)10 * LZFSE_ZOPT_BLOCK_SIZE);
    size_t bound_large = crushlzfse_encode_bound(n_large, &params);
    __CPROVER_assert(bound_large >= n_large + 16, "large bound covers expansion");

    PROOF_REACHABLE(n == 0, "empty input");
    PROOF_REACHABLE(n == 1, "1 byte input");
    PROOF_REACHABLE(n == (size_t)LZFSE_ZOPT_BLOCK_SIZE, "block size maximum");
}
