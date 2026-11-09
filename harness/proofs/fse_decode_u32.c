/* Shipping 1024-state literal step, under its explicit table-row invariant.
 * Establishing that invariant from table builders remains a separate target. */
#include "proof.h"
#include "lzfse_fse.h"
uint32_t nondet_u32(void);
uint64_t nondet_u64(void);
int32_t nondet_i32(void);
void harness(void)
{
    int32_t *table=malloc(LZFSE_ENCODE_LITERAL_STATES*sizeof *table);
    __CPROVER_assume(table!=NULL);
    uint32_t state=nondet_u32();
    fse_in_stream input;
    input.accum=nondet_u64();
    input.accum_nbits=nondet_i32();
    uint32_t before=state;
    uint8_t symbol=fse_decode_u32(&state,table,&input);
    PROOF_REACHABLE(before==1023,"shipping upper literal state");
    PROOF_REACHABLE((table[before]&0xff)==0,"zero-bit transition");
    PROOF_REACHABLE((table[before]&0xff)==10,"ten-bit transition");
    PROOF_REACHABLE(symbol==255,"upper literal symbol");
}
