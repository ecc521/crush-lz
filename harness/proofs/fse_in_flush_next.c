/* Actual ARM64 lookahead refill, including the previous-word register. */
#include "proof.h"
#include "lzfse_fse.h"
_Static_assert(FSE_LOOKAHEAD_REFILL==1,"this target must execute ARM64 lookahead");
size_t nondet_size(void);
uint64_t nondet_u64(void);
int32_t nondet_i32(void);
void harness(void)
{
    size_t size=nondet_size(),begin=nondet_size(),pos=nondet_size();
    __CPROVER_assume(size>=8 && size<=PROOF_MAX_OBJECT);
    __CPROVER_assume(8<=begin && begin<=pos && pos<=size);
    uint8_t *buffer=malloc(size);
    __CPROVER_assume(buffer!=NULL);
    const uint8_t *cursor=buffer+pos;
    fse_in_stream stream;
    stream.accum=nondet_u64();
    stream.accum_nbits=nondet_i32();
    uint64_t next=nondet_u64();
    int32_t before=stream.accum_nbits;
    int status=fse_in_flush_next(&stream,&cursor,buffer+begin,&next);
    PROOF_REACHABLE(status==0 && before>=56 && pos==size,"full accumulator at source end");
    PROOF_REACHABLE(status==0 && before==0,"maximum lookahead refill");
    PROOF_REACHABLE(status==0 && cursor==buffer+begin && begin==8 && before<56,"exact minimum lookbehind");
    PROOF_REACHABLE(status==-1 && before==0 && pos==begin,"truncated source");
}
