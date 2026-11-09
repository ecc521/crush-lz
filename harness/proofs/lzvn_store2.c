/* Exact footprint used by the Frama-C literal-emitter composition. */
#include "proof.h"
#include "lzfse_internal.h"

static void proof_store2(void *destination, uint16_t value)
__CPROVER_requires(__CPROVER_w_ok(destination, 2))
__CPROVER_assigns(__CPROVER_object_upto(destination, 2))
{
    store2(destination, value);
}
size_t nondet_size(void);
uint16_t nondet_u16(void);
void harness(void)
{
    size_t size=nondet_size(),offset=nondet_size();
    __CPROVER_assume(size>=2 && size<=PROOF_MAX_OBJECT && offset<=size-2);
    uint8_t *buffer=malloc(size);
    __CPROVER_assume(buffer!=NULL);
    proof_store2(buffer+offset,nondet_u16());
    PROOF_REACHABLE(offset==size-2,"store at exact upper bound");
}
