#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    size_t n;
    uint8_t *buf = zbm_any_buffer(&n);
    const uint8_t *start = zbm_any_ptr(buf, n);
    struct nybl_ptr scan = {zbm_any_ptr(buf, n), nondet_int()};
    uint8_t result = zbm_last_nonrepeat_nibble(scan, start);
    PROOF_REACHABLE(result == 0, "default or explicit selector zero");
    PROOF_REACHABLE(result == 14, "last table selector");
    PROOF_REACHABLE(scan.addr > start + 32768 && result < 15, "long history scan");
}
