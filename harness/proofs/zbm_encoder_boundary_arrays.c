#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    uint8_t nums[ZBM_MAX_BITMAP_COUNT + 16];
    uint64_t bnd[ZBM_MAX_BITMAP_COUNT / 64 + 1];
    int cnt = nondet_int();
#ifdef ZBM_PROOF_BOUNDARY_VALUES
    zbm_proof_boundary_index = nondet_u32();
#endif
    zbm_build_run_boundaries_arrays(&nums, &bnd, cnt);
    PROOF_REACHABLE(cnt == 0, "empty boundary arrays");
    PROOF_REACHABLE(cnt == 1, "single boundary bit");
    PROOF_REACHABLE(cnt == 17, "partial second comparison group");
    PROOF_REACHABLE(cnt == 65, "partial second boundary word");
    PROOF_REACHABLE(cnt == ZBM_MAX_BITMAP_COUNT, "full boundary arrays");
}
