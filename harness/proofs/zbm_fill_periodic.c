#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    size_t n;
    uint8_t *buf = zbm_any_buffer(&n);
    uint8_t *dest = zbm_any_ptr(buf, n);
    uint16_t period = nondet_u16();
    uint32_t total = nondet_u32();
    zbm_fill_periodic(dest, period, total);
    PROOF_REACHABLE(period == 8 && total == 32768, "doubling to a full chunk");
    PROOF_REACHABLE(period > total && total == 8, "only initial source copy");
    PROOF_REACHABLE(period == 9 && total == 128, "unaligned pattern length");
}
