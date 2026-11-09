#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    size_t n;
    uint8_t *src = zbm_any_buffer(&n);
    uint8_t *data = zbm_any_ptr(src, n), *m1 = zbm_any_ptr(src, n);
    uint8_t *m2 = zbm_any_ptr(src, n), *m3 = zbm_any_ptr(src, n);
    uint8_t *end = zbm_any_ptr(src, n);
    size_t avail = nondet_size(), avail_end = nondet_size();
    uint32_t k = zbm_pair_budget(avail, avail_end, data, m1, m2, m3, end);
    PROOF_REACHABLE(k == 0, "no safe pairs");
    PROOF_REACHABLE(k == 1, "one safe pair");
    PROOF_REACHABLE(k == 2047, "maximum chunk pair budget");
}
