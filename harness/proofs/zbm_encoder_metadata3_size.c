#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_compress_state storage;
    storage.bmp_cnt = nondet_int();
    ptrdiff_t bytes = zbm_metadata_3_bytes(&storage);
    PROOF_REACHABLE(storage.bmp_cnt == 0 && bytes == 0, "empty selector area");
    PROOF_REACHABLE(storage.bmp_cnt == 1 && bytes == 1, "single half-byte selector");
    PROOF_REACHABLE(storage.bmp_cnt == ZBM_MAX_BITMAP_COUNT && bytes == ZBM_MAX_BITMAP_COUNT / 2,
                    "one selector per maximum block list");
}
