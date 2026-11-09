#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    size_t sn;
    uint8_t *src = zbm_any_buffer(&sn);
    const struct zbm_bmap *bmaps = (const struct zbm_bmap *)zbm_any_ptr(src, sn);
    int cnt = nondet_int();
#ifdef PROOF_PERIOD_TOTAL
    ptrdiff_t total = zbm_period_bytes_total(bmaps, cnt);
    PROOF_REACHABLE(cnt == ZBM_MAX_BITMAP_COUNT && total == 255 * cnt, "maximum byte-valued period counts");
    PROOF_REACHABLE(cnt == 1 && total == 2, "two-byte period");
#else
    long total = zbm_literal_total(bmaps, cnt);
    PROOF_REACHABLE(cnt == ZBM_MAX_BITMAP_COUNT && total == 8 * cnt, "all literal maximum chunk");
    PROOF_REACHABLE(cnt == 1 && total == 0, "no literal block");
#endif
    PROOF_REACHABLE(cnt == 0 && total == 0, "empty sum");
}
