/* Exact count permutation used by the shipping fast metadata initializer. */
#include "proof.h"
#include "libzbitmap.c"
unsigned nondet_u32(void);
void harness(void)
{
    unsigned key = nondet_u32();
    __CPROVER_assume(key < (3u << 8));
    unsigned index = (key & 0xffu) << 2 | key >> 8;
    __CPROVER_assert(index < ZBM_POSSIBLE_BMPROTS, "fold index in table");
    __CPROVER_assert(index == 4 * (key % 256) + key / 256, "fold index arithmetic");
    __CPROVER_assert(index % 4 <= 2, "fold index excludes reserved keys");
    __CPROVER_assert((key & 0xffu) <= 255, "low key byte bounded");
    __CPROVER_assert(((key & 0xffu) << 2) <= 1020, "fold shifted byte bounded");
    __CPROVER_assert((key >> 8) == key / 256, "fold high group equals quotient");
    PROOF_REACHABLE(key == 0 && index == 0, "first folded count");
    PROOF_REACHABLE(key == 256 && index == 1, "second period-count group");
    PROOF_REACHABLE(key == 767 && index == 1022, "last folded count");
}
