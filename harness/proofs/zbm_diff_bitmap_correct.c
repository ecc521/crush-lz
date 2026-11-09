#include "proof.h"
#include "libzbitmap.c"

uint64_t nondet_u64(void);

void harness(void)
{
    uint64_t diff = nondet_u64();
    uint8_t want = 0;
    for (unsigned i = 0; i < 8; ++i)
        if ((diff >> (8 * i)) & 0xff)
            want |= (uint8_t)(1u << i);
    uint8_t got = zbm_diff_bitmap(diff);
    __CPROVER_assert(got == want, "bitmap marks exactly the differing byte lanes");
    PROOF_REACHABLE(got == 0, "all copy lanes");
    PROOF_REACHABLE(got == 255, "all literal lanes");
    PROOF_REACHABLE(got == 128, "only highest lane differs");
}
