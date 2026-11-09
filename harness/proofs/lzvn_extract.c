/* Native bit extraction for all ranges used by the LZVN opcode handlers. */
#include "proof.h"
#include "lzfse_internal.h"
static uintmax_t proof_extract(uintmax_t container,unsigned lsb,unsigned width)
__CPROVER_requires(lsb<64 && width>0 && width<64 && lsb+width<=64)
__CPROVER_assigns()
__CPROVER_ensures(__CPROVER_return_value==
    ((__CPROVER_old(container)>>__CPROVER_old(lsb)) &
      (((uintmax_t)1<<__CPROVER_old(width))-1)))
__CPROVER_ensures(__CPROVER_return_value<((uintmax_t)1<<__CPROVER_old(width)))
{
    return extract(container,lsb,width);
}
uint64_t nondet_u64(void);
unsigned nondet_unsigned(void);
void harness(void)
{
    unsigned lsb=nondet_unsigned(),width=nondet_unsigned();
    uint64_t result=proof_extract(nondet_u64(),lsb,width);
    PROOF_REACHABLE(lsb==2 && width==14,"medium distance bits");
    PROOF_REACHABLE(lsb==0 && width==63 && result==(((uint64_t)1<<63)-1),"upper bit-field range");
}
