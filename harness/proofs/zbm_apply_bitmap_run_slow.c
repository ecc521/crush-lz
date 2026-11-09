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
    int rc = zbm_apply_bitmap_run_slow(st, bm, repeat);
    PROOF_REACHABLE(rc == 0 && bmp == 255 && st->written >= before + 16, "literal fallback run");
    PROOF_REACHABLE(rc == 0 && bmp == 0 && st->written >= before + 16, "copy fallback run");
    PROOF_REACHABLE(rc == 0 && bmp == 15 && period == 8 && st->written >= before + 16, "mixed period-8 fallback run");
    PROOF_REACHABLE(rc == 0 && bmp == 15 && period == 9 && st->written >= before + 32, "mixed period-9 fallback run");
    PROOF_REACHABLE(rc == 0 && st->written == st->decmp_len && st->decmp_len % 8, "partial tail");
    PROOF_REACHABLE(rc == 0 && repeat == 0 && st->written == before, "zero remaining run");
    PROOF_REACHABLE(rc == ZBM_INVAL, "invalid run");
}
