/*
 * Proof: load_seed in crates/crushlzfse/csrc/crushlzfse.c
 */
#include "proof.h"
#include <string.h>
#include "crushlzvn.h"

/* Both dispatch sources define these file-static names. */
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

uint32_t nondet_uint32(void);
_Bool nondet_bool(void);

void harness(void)
{
    crushlzfse_stats stats;
    _Bool valid_magic = nondet_bool();
    if (valid_magic) {
        stats.opaque[0] = CRUSHLZFSE_STATS_MAGIC;
    } else {
        _Bool zero = nondet_bool();
        if (zero) {
            stats.opaque[0] = 0;
        } else {
            stats.opaque[0] = nondet_uint32();
            __CPROVER_assume(stats.opaque[0] != CRUSHLZFSE_STATS_MAGIC);
        }
    }

    uint32_t seed[LZFSE_LMD_STATS_WORDS];

    int res = load_seed(&stats, seed);
    __CPROVER_assert(res == 0 || res == 1, "return 0 or 1");
    if (!valid_magic) {
        __CPROVER_assert(res == 0, "non-magic returns 0");
    }

    PROOF_REACHABLE(!valid_magic, "non-magic rejected");
    PROOF_REACHABLE(valid_magic && res == 0, "magic with zero total rejected");
    PROOF_REACHABLE(valid_magic && res == 1, "magic valid accepted");
}
