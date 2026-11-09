/* Full-span native framing parser, including empty and malformed input. */
#include "proof.h"
#include "lzfse_decode_base.c"
size_t nondet_size(void);
void harness(void)
{
    size_t n=nondet_size();
    __CPROVER_assume(n<=PROOF_MAX_OBJECT);
    uint8_t *src=malloc(n!=0?n:1);
    __CPROVER_assume(src!=NULL);
    size_t output;
    int status=lzfse_declared_len(src,src+n,&output);
    PROOF_REACHABLE(n==0 && status==-1,"empty source rejected");
    PROOF_REACHABLE(status==0 && output==0,"empty stream accepted");
    PROOF_REACHABLE(status==0 && output>0,"nonempty stream accepted");
    PROOF_REACHABLE(status==-1 && n>32,"malformed stream rejected");
}
