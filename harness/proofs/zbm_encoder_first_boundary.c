#include "proof.h"
#include "libzbitmap.c"
uint64_t nondet_u64(void);
void harness(void)
{
    uint64_t word = nondet_u64();
    int bit = zbm_first_boundary_bit(word);
    PROOF_REACHABLE(word == 1 && bit == 0, "first bit boundary");
    PROOF_REACHABLE(word == (UINT64_C(1) << 63) && bit == 63, "last bit boundary");
    PROOF_REACHABLE(word == ((UINT64_C(1) << 17) | (UINT64_C(1) << 42)) && bit == 17,
        "earliest of sparse boundaries");
}
