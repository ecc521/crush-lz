#include "proof.h"

#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_compress_state storage;
    struct zbm_compress_state *st = &storage;
    st->bmp_cnt = nondet_int();
#ifdef ZBM_PROOF_BOUNDARY_VALUES
    zbm_proof_boundary_index = nondet_u32();
#endif
    zbm_build_run_boundaries(st);
    PROOF_REACHABLE(st->bmp_cnt == 0, "empty boundary map");
    PROOF_REACHABLE(st->bmp_cnt == 1, "single block and full lookahead tail");
    PROOF_REACHABLE(st->bmp_cnt == 17, "partial second comparison group");
    PROOF_REACHABLE(st->bmp_cnt == 65, "partial second boundary word");
    PROOF_REACHABLE(st->bmp_cnt == ZBM_MAX_BITMAP_COUNT, "maximum boundary map");
}
