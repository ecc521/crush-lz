/* Full-domain stride bound for the shipping LZVN fast encoder. */
#include "proof.h"
#include "lzvn_encode_base.c"

lzvn_offset nondet_offset(void);
int nondet_int(void);

void harness(void)
{
    lzvn_offset ip = nondet_offset();
    lzvn_offset anchor = nondet_offset();
    int shift = nondet_int();
    int probed = nondet_int();
    lzvn_offset max_stride = nondet_offset();
    __CPROVER_assume(0 <= anchor && anchor <= ip && ip <= LZVN_ZOPT_BLOCK_SIZE + 64);
    __CPROVER_assume(1 <= shift && shift <= 31);
    __CPROVER_assume(1 <= probed && probed <= 2);
    __CPROVER_assume(probed <= max_stride && max_stride <= 64);

    lzvn_offset step = lzvn_fast_skip_step(ip, anchor, shift, probed, max_stride);
    __CPROVER_assert(1 <= step && step <= 64, "fast stride is positive and bounded");
    __CPROVER_assert(step <= max_stride, "fast stride obeys max_stride");

    PROOF_REACHABLE(step == 1, "unit stride");
    PROOF_REACHABLE(step == 2, "two-byte stride");
    PROOF_REACHABLE(step == 64, "maximal stride");
}
