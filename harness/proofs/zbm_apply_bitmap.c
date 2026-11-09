/*
 * Proof: zbm_apply_bitmap in crates/lzbitmap/csrc/libzbitmap.c meets its
 * contract, for any state ZBM_STATE_OK allows and any bitmap: it reads only
 * the chunk and the output so far, writes only the rest of the chunk's
 * output, keeps every cursor in the chunk, and makes progress.
 */
#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_state *st = zbm_any_state();
    struct zbm_bmap own;
    struct zbm_bmap *bm = &own;
    if (nondet_bool()) {
        size_t i = nondet_size();
        __CPROVER_assume(i < ZBM_BITMAP_COUNT);
        bm = &st->bitmaps[i];
    }
    uint32_t before = st->written;
    uint32_t total = st->decmp_len;
    uint8_t bmp = bm->bitmap;
    uint8_t pbc = bm->period_bytecnt;

    int rc = zbm_apply_bitmap(st, bm);

    PROOF_REACHABLE(rc == 0 && st->written == before + 8 && bmp == 0xff,
                    "all-literal block");
    PROOF_REACHABLE(rc == 0 && st->written == before + 8 && bmp == 0x0f &&
                    st->data + 8 <= st->src_end, "blended block");
    PROOF_REACHABLE(rc == 0 && st->written == before + 8 && bmp == 0x0f &&
                    st->data + 8 > st->src_end, "block at the end of the literals");
    PROOF_REACHABLE(rc == 0 && total - before < 8 && st->written == total,
                    "trailing partial block");
    PROOF_REACHABLE(rc == 0 && pbc == 2 && st->period > 255, "two-byte period");
    PROOF_REACHABLE(rc == ZBM_INVAL, "invalid block");
    PROOF_REACHABLE(rc == 0 && st->prewritten > 0 && st->written == 8,
                    "copy from the previous chunk");
    PROOF_REACHABLE(rc == 0 && before == 0 && st->prewritten == 8 &&
                    pbc == 0 && st->period == 9 && bmp == 1 && st->written == 8,
                    "period nine copy made valid by one literal");
}
