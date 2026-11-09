/*
 * Proof: crushlzfse_scratch_size in crates/crushlzfse/csrc/crushlzfse.c.
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

crushlzfse_encode_params nondet_params(void);

void harness(void)
{
    /* 1. NULL handling */
    __CPROVER_assert(crushlzfse_scratch_size(NULL) == 0, "null params scratch size is 0");

    /* 2. Valid parameter configurations */
    crushlzfse_encode_params p = nondet_params();
    int valid = 0;
    if (p.strategy == CRUSHLZFSE_STRATEGY_FAST) {
        valid = fast_params_valid(&p);
    } else if (p.strategy == CRUSHLZFSE_STRATEGY_LAZY) {
        valid = lazy_params_valid(&p);
    } else if (p.strategy == CRUSHLZFSE_STRATEGY_OPTIMAL) {
        valid = optimal_params_valid(&p);
    }
    __CPROVER_assume(valid == 1);

    size_t sz = crushlzfse_scratch_size(&p);
    __CPROVER_assert(sz >= sizeof(lzfse_encoder_state), "scratch size covers state header");

    /* Verify strategy-specific carved memory requirements */
    if (p.strategy == CRUSHLZFSE_STRATEGY_FAST) {
        size_t entries = (size_t)1 << fast_hash_bits_for(&p);
        size_t fast_bytes = (p.p.fast.long_table ? 2 : 1) * entries * sizeof(uint16_t);
        __CPROVER_assert(sizeof(lzfse_encoder_state) + fast_bytes <= sz,
                         "scratch size covers fast match tables");
        PROOF_REACHABLE(p.strategy == CRUSHLZFSE_STRATEGY_FAST, "carve fast");
    } else if (p.strategy == CRUSHLZFSE_STRATEGY_LAZY) {
        int hb, hw;
        lazy_dims_for(&p, &hb, &hw);
        size_t lazy_bytes = lazy_history_scratch_size(hb, hw);
        __CPROVER_assert(sizeof(lzfse_encoder_state) + lazy_bytes <= sz,
                         "scratch size covers lazy history tables");
        PROOF_REACHABLE(p.strategy == CRUSHLZFSE_STRATEGY_LAZY, "carve lazy");
    } else if (p.strategy == CRUSHLZFSE_STRATEGY_OPTIMAL) {
        size_t opt_bytes = lzfse_zopt_scratch_size(cand_capacity_for(&p),
                                                  p.p.optimal.split_max_blocks,
                                                  p.p.optimal.hash_bits,
                                                  nslots_for(&p),
                                                  p.p.optimal.table_search);
        __CPROVER_assert(sizeof(lzfse_encoder_state) + opt_bytes <= sz,
                         "scratch size covers optimal DP state");
        PROOF_REACHABLE(p.strategy == CRUSHLZFSE_STRATEGY_OPTIMAL, "carve optimal");
    }

    /* The LZVN fallback is only attempted when its params are valid; an
     * invalid one is rejected and its region goes unused. */
    crushlzvn_encode_params fp;
    lzvn_fallback_params(&p, &fp);
    __CPROVER_assert(crushlzvn_params_valid(&fp) == 1, "LZVN fallback params are valid");

    /* Verify fallback region is also covered */
    size_t fb_bytes = lzvn_fallback_region_size(&p) + (size_t)CRUSHLZFSE_LZVN_TMP_SIZE;
    __CPROVER_assert(sizeof(lzfse_encoder_state) + fb_bytes <= sz,
                     "scratch size covers fallback region");
}
