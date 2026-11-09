#include "proof.h"
#undef memcpy
#include "libzbitmap.c"

void harness(void)
{
    struct zbm_bmap bmap;
    unsigned key = zbm_bmkey(&bmap);
    __CPROVER_assert(key == (unsigned)bmap.bitmap + 256u * bmap.period_bytecnt,
                     "bitmap key also has the arithmetic form used by WP");
    __CPROVER_assert(bmap.period_bytecnt > 2 || key <= 767,
                     "supported bitmap key stays in the selector table");
    __CPROVER_assert((key >> 8) == bmap.period_bytecnt,
                     "bitmap key high byte is the period count");
    __CPROVER_assert((key & 255u) == bmap.bitmap,
                     "bitmap key low byte is the bitmap");
    PROOF_REACHABLE(key == 0, "zero key");
    PROOF_REACHABLE(key == 65535, "all key bits set");
    PROOF_REACHABLE(key == 767, "maximum supported period-byte-count key");
}
