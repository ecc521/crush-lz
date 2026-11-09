/* producer-sha256: 04d1600f0dc94d786ab3be625dd2cc187304a46232652f9965b12c58e68dec1d */

#include "proof.h"
#include <stdint.h>
#include <stddef.h>
int32_t nondet_i32(void);
ptrdiff_t nondet_ptrdiff(void);
void harness(void)
{
    int32_t D = nondet_i32();
    ptrdiff_t span = nondet_ptrdiff(), L = nondet_ptrdiff();
    __CPROVER_assume(span >= 0 && L >= 0 && span <= PTRDIFF_MAX - L);
    int shipping = (uint64_t)((int64_t)D - 1) >= (uint64_t)span + (uint64_t)L;
    int proved = D <= 0 || (uint32_t)D > (size_t)span + (size_t)L;
    __CPROVER_assert(shipping == proved, "shipping distance check equals the proved form");
    PROOF_REACHABLE(D == -1 && shipping, "initial D rejected");
    PROOF_REACHABLE(D == 0, "zero distance");
    PROOF_REACHABLE(!shipping && D == span + L, "farthest distance accepted");
    PROOF_REACHABLE(span > ((ptrdiff_t)1 << 40) && !shipping, "span beyond 32 bits");
}
