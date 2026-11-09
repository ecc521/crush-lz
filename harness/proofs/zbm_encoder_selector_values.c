#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

/* The real preparation order, at an arbitrary block. Preconditions belong
 * to upstream block generation/top selection, which remain separate gaps. */
void harness(void)
{
    struct zbm_compress_state storage;
    struct zbm_compress_state *st = &storage;
    st->bmp_cnt = nondet_int();
    __CPROVER_assume(st->bmp_cnt >= 0 && st->bmp_cnt <= ZBM_MAX_BITMAP_COUNT);
    __CPROVER_assume(ZBM_ENCODER_PBC_OK(st));
    for(int i = 0; i < ZBM_BITMAP_COUNT; ++i)
        __CPROVER_assume(st->top_bitmaps[i].period_bytecnt <= 2);

    zbm_proof_block_index = nondet_u32();
    __CPROVER_assume(st->bmp_cnt == 0 || zbm_proof_block_index < (unsigned)st->bmp_cnt);
    zbm_proof_selector_index = st->bmp_cnt == 0 ? 0 :
        ((unsigned)st->bitmaps[zbm_proof_block_index].bitmap |
         (unsigned)st->bitmaps[zbm_proof_block_index].period_bytecnt << 8);
    zbm_build_bmap_num_table(st);
    zbm_build_bmap_nums(st);
    __CPROVER_assert(st->bmp_cnt == 0 || st->bmap_nums[zbm_proof_block_index] <= 14,
                     "prepared selectors fit their format nibble at every active block");
    PROOF_REACHABLE(st->bmp_cnt == 0, "empty selector preparation");
    PROOF_REACHABLE(st->bmp_cnt > 0 && zbm_proof_block_index == 0,
                    "first prepared selector");
    PROOF_REACHABLE(st->bmp_cnt == ZBM_MAX_BITMAP_COUNT &&
                    zbm_proof_block_index == ZBM_MAX_BITMAP_COUNT - 1,
                    "last prepared selector");
}
