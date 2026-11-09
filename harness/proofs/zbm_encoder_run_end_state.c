#include "proof.h"
#include "libzbitmap.c"
int nondet_int(void);
unsigned nondet_u32(void);
void harness(void)
{
    struct zbm_compress_state state;
    int cnt = nondet_int(), idx = nondet_int();
    __CPROVER_assume(cnt >= 1 && cnt <= ZBM_MAX_BITMAP_COUNT && idx >= 0 && idx < cnt);
    state.bmp_cnt = cnt;
    zbm_proof_end_index = nondet_u32();
    __CPROVER_assume(zbm_proof_end_index < (unsigned)cnt);
    zbm_build_run_boundaries(&state);
    int end = zbm_find_run_end(&state.run_bnd, idx, cnt);
    __CPROVER_assert(end >= idx && end < cnt, "producer bounds actual-state search");
    __CPROVER_assert((state.run_bnd[end >> 6] & (UINT64_C(1) << (end & 63))) != 0,
        "actual-state search returns a boundary");
    __CPROVER_assert(zbm_proof_end_index < (unsigned)idx || zbm_proof_end_index >= (unsigned)end ||
        ((state.run_bnd[zbm_proof_end_index >> 6] >> (zbm_proof_end_index & 63u)) & 1u) == 0,
        "actual-state search skips no earlier boundary");
    PROOF_REACHABLE(cnt == ZBM_MAX_BITMAP_COUNT && idx == 0 && end == cnt - 1, "full-state final boundary");
    PROOF_REACHABLE(idx == cnt - 1 && end == idx, "full-state last block");
    PROOF_REACHABLE(cnt == 65 && idx == 63 && end == 64, "full-state next word");
    PROOF_REACHABLE(cnt == 4 && idx == 1 && end == 3, "full-state later boundary");
    PROOF_REACHABLE(cnt == 4 && idx == 1 && end == 1, "full-state immediate boundary");
}
