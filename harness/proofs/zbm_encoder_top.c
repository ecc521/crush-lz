#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_compress_state storage;
    zbm_find_most_common_bitmaps(&storage);
    PROOF_REACHABLE(storage.top_bitmaps[0].bitmap == 0 && storage.top_bitmaps[0].period_bytecnt == 0, "empty or zero top bitmap");
    PROOF_REACHABLE(storage.top_bitmaps[0].bitmap == 255 && storage.top_bitmaps[0].period_bytecnt == 3, "maximum key top bitmap");
    PROOF_REACHABLE(storage.top_bitmaps[11].bitmap == 255, "last top slot populated");
}
