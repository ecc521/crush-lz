#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_compress_state storage;
    storage.bmp_cnt = nondet_int();
    int idx = nondet_int();
    int number = zbm_bmap_num_for_index(&storage, idx);
    PROOF_REACHABLE(idx == 0 && number == 0, "first explicit selector");
    PROOF_REACHABLE(idx == ZBM_MAX_BITMAP_COUNT - 1 && number == 255, "last slot with arbitrary byte value");
}
