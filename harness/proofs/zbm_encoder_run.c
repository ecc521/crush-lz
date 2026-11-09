#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_compress_state *st = malloc(sizeof(*st));
    __CPROVER_assume(st != NULL);
    st->bmp_cnt = nondet_int();
    int idx = nondet_int(), number = nondet_int(), next = nondet_int();
#ifdef ZBM_PROOF_RUN_VALUES
    zbm_proof_run_index = nondet_u32();
#endif
    int n = zbm_run_length(st, idx, number, &next);
    PROOF_REACHABLE(st->bmp_cnt == ZBM_MAX_BITMAP_COUNT && idx == 0 && n == ZBM_MAX_BITMAP_COUNT,
                    "full chunk run reaches boundary");
    PROOF_REACHABLE(st->bmp_cnt == 2 && idx == 0 && n == 1, "run ends at next block");
    PROOF_REACHABLE(idx == st->bmp_cnt - 1 && n == 1, "last block run");
}
