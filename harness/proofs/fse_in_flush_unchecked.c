/* Production bulk-decoder refill; the caller supplies its lookbehind span. */
#include "proof.h"
#include "lzfse_fse.h"
size_t nondet_size(void);
uint64_t nondet_u64(void);
int32_t nondet_i32(void);
void harness(void) {
  size_t size=nondet_size(),pos=nondet_size();
  __CPROVER_assume(size>=8 && size<=PROOF_MAX_OBJECT);
  __CPROVER_assume(pos>=8 && pos<=size);
  uint8_t *buffer=malloc(size);
  __CPROVER_assume(buffer!=NULL);
  const uint8_t *cursor=buffer+pos;
  fse_in_stream64 stream;
  stream.accum=nondet_u64();
  stream.accum_nbits=nondet_i32();
  int32_t before=stream.accum_nbits;
  fse_in_flush64_unchecked(&stream,&cursor);
  PROOF_REACHABLE(before==0,"maximum unchecked refill");
  PROOF_REACHABLE(before>=56 && pos==size,"full accumulator at source end");
}
