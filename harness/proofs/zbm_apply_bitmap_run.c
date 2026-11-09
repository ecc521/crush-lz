#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_state *st = zbm_any_state();
    struct zbm_bmap own;
    struct zbm_bmap *bm = &own;
    if(nondet_bool()) {
        size_t i = nondet_size();
        __CPROVER_assume(i < ZBM_BITMAP_COUNT);
        bm = &st->bitmaps[i];
    }
    uint16_t repeat = nondet_u16();
    uint8_t bmp = bm->bitmap;
    uint32_t before = st->written;
    uint16_t period = st->period;
    int rc = zbm_apply_bitmap_run(st, bm, repeat);
    PROOF_REACHABLE(rc == 0 && bmp == 255 && st->written >= before + 16, "literal bulk run");
    PROOF_REACHABLE(rc == 0 && bmp == 0 && st->written >= before + 16, "copy bulk run");
    PROOF_REACHABLE(rc == 0 && bmp == 15 && period == 8 && st->written >= before + 16, "mixed fused run");
    PROOF_REACHABLE(rc == 0 && bmp == 15 && period == 9 && st->written >= before + 32, "mixed scalar run");
    PROOF_REACHABLE(rc == 0 && st->written == st->decmp_len && st->decmp_len % 8, "partial tail");
    PROOF_REACHABLE(rc == ZBM_INVAL, "invalid run");
}
