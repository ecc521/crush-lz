#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_state *st = zbm_any_state();
    int rc = zbm_read_bitmaps(st);
    PROOF_REACHABLE(rc == 0 && st->len == 17, "minimum table buffer");
    PROOF_REACHABLE(rc == 0 && st->len > 17, "table at chunk end");
    PROOF_REACHABLE(rc == ZBM_INVAL && st->len < 17, "truncated table");
    PROOF_REACHABLE(rc == ZBM_INVAL && st->len >= 17, "unsupported period byte count");
}
