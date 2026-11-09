#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_compress_state storage;
    struct zbm_compress_state *st = &storage;
    st->bmp_cnt = nondet_int();
#ifdef ZBM_PROOF_SELECTOR_VALUES
    zbm_proof_block_index = nondet_u32();
#endif
    zbm_build_bmap_nums(st);
#ifdef ZBM_PROOF_SELECTOR_VALUES
    PROOF_REACHABLE(st->bmp_cnt > 0 && zbm_proof_block_index == 0,
                    "first queried selector block");
    PROOF_REACHABLE(st->bmp_cnt == ZBM_MAX_BITMAP_COUNT &&
                    zbm_proof_block_index == ZBM_MAX_BITMAP_COUNT - 1,
                    "last queried selector block");
#else
    PROOF_REACHABLE(st->bmp_cnt == 1 && st->bitmaps[0].bitmap == 0 &&
                    st->bitmaps[0].period_bytecnt == 0 && st->bmap_num_tbl[0] == 255 &&
                    st->bmap_nums[0] == 255, "arbitrary byte selector still memory safe");
#endif
    PROOF_REACHABLE(st->bmp_cnt == 0, "empty block list");
    PROOF_REACHABLE(st->bmp_cnt == ZBM_MAX_BITMAP_COUNT, "maximum block list");
    PROOF_REACHABLE(st->bmp_cnt == 1 && st->bitmaps[0].period_bytecnt == 2 && st->bitmaps[0].bitmap == 255,
                    "maximum live bitmap key");
}
