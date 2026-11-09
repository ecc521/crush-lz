#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_compress_state storage;
    struct zbm_compress_state *st = &storage;
    zbm_proof_selector_index = nondet_u32();
    zbm_build_bmap_num_table(st);
    PROOF_REACHABLE(zbm_proof_selector_index == 0, "first queried selector key");
    PROOF_REACHABLE(zbm_proof_selector_index == ZBM_POSSIBLE_BMPROTS - 1,
                    "last queried selector key");
    PROOF_REACHABLE(st->top_bitmaps[0].bitmap == 255 && st->top_bitmaps[0].period_bytecnt == 2 &&
                    st->usecnts[1022] == 0 && st->bmap_num_tbl[767] == 3, "maximum supported key selects top entry");
    PROOF_REACHABLE(st->bmap_num_tbl[767] == 2, "explicit two-byte period selector");
}
