/* Regression witness: insufficient input must be rejected before pointer
 * formation or reads. Full framing coverage is a separate inductive target. */
#include "proof.h"
#include "lzfse_decode_base.c"
size_t nondet_size(void);
void harness(void)
{
    uint8_t src[1];
    size_t n=nondet_size(),out;
    __CPROVER_assume(n<=1);
    int status=lzfse_declared_len(src,src+n,&out);
    __CPROVER_assert(status==-1,"insufficient magic rejected");
    PROOF_REACHABLE(n==0 && status==-1,"empty source");
    PROOF_REACHABLE(n==1 && status==-1,"one-byte source");
}
