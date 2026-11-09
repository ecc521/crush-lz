#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    int run = nondet_int();
    __CPROVER_assume(run >= 0 && run <= ZBM_MAX_BITMAP_COUNT);
    int cost = zbm_nibble_cost_for_run(run);
#ifdef PROOF_RUN_DELTA
    if(run > 0 && run < ZBM_MAX_BITMAP_COUNT) {
        int extended = zbm_nibble_cost_for_run(run + 1);
        __CPROVER_assert(zbm_nibble_extend_delta(run) == extended - cost,
                         "incremental cost agrees with full cost difference");
    }
#endif
    PROOF_REACHABLE(run == 0 && cost == 0, "empty run");
    PROOF_REACHABLE(run == 3 && cost == 3, "last literal run");
    PROOF_REACHABLE(run == 4 && cost == 3, "minimum repeated run");
    PROOF_REACHABLE(run == ZBM_MAX_BITMAP_COUNT, "maximum run");
}
