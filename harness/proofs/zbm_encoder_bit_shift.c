/* Signed shift used by the shipping one-bit table writer. */
#include "proof.h"
int nondet_int(void);
void harness(void)
{
    int val = nondet_int();
    int offset = nondet_int();
    __CPROVER_assume(0 <= val && val <= 1);
    __CPROVER_assume(0 <= offset && offset < 8);
    int shifted = val << offset;
    __CPROVER_assert(0 <= shifted && shifted <= 128, "single-bit shift fits signed int and byte");
    PROOF_REACHABLE(val == 1 && offset == 0 && shifted == 1, "first output bit");
    PROOF_REACHABLE(val == 1 && offset == 7 && shifted == 128, "last output bit");
    PROOF_REACHABLE(val == 0 && offset == 7 && shifted == 0, "zero last output bit");
}
