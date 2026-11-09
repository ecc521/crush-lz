/* Exact shipping pair-to-key arithmetic used by append/count producers. */
#include "proof.h"
#include "libzbitmap.c"
uint8_t nondet_u8(void);
void harness(void)
{
    struct zbm_bmap bmap;
    bmap.bitmap = nondet_u8();
    bmap.period_bytecnt = nondet_u8();
    int key = zbm_bmprot(&bmap);
    __CPROVER_assert(0 <= key && key < ZBM_POSSIBLE_BMPROTS, "arbitrary byte pair key in table");
    PROOF_REACHABLE(bmap.bitmap == 255 && bmap.period_bytecnt == 255 && key == 1023,
                    "arbitrary maximum byte pair");
    __CPROVER_assume(bmap.period_bytecnt <= ZBM_MAX_PERIOD_BYTECNT);
    __CPROVER_assert(0 <= key && key < ZBM_POSSIBLE_BMPROTS, "pair key in table");
    __CPROVER_assert(key == 4 * (int)bmap.bitmap + bmap.period_bytecnt, "pair key arithmetic");
    __CPROVER_assert(key % 4 == bmap.period_bytecnt, "pair key has valid period count");
    int period_bytecnt = bmap.period_bytecnt;
    int direct = (int)bmap.bitmap << 2 | period_bytecnt;
    __CPROVER_assert(direct == key, "direct commit expression equals pair function");
    __CPROVER_assert(((int)bmap.bitmap << 2) == 4 * (int)bmap.bitmap, "bitmap shift equals multiplication");
    __CPROVER_assert(0 <= ((int)bmap.bitmap << 2) && ((int)bmap.bitmap << 2) <= 1020, "bitmap shift fits signed int");
    PROOF_REACHABLE(bmap.bitmap == 0 && bmap.period_bytecnt == 0 && key == 0, "first pair key");
    PROOF_REACHABLE(bmap.bitmap == 255 && bmap.period_bytecnt == 1 && key == 1021, "one byte maximum bitmap");
    PROOF_REACHABLE(bmap.bitmap == 255 && bmap.period_bytecnt == 2 && key == 1022, "last valid pair key");
}
