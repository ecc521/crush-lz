/* Actual integer/pointer alignment arithmetic and its byte footprint. */
#include "proof.h"
#include "crushlz4.c"

size_t nondet_size(void);

void harness(void)
{
    size_t size = nondet_size(), offset = nondet_size();
    __CPROVER_assume(size >= CLZ4_SCRATCH_ALIGN && size <= PROOF_MAX_OBJECT);
    __CPROVER_assume(offset <= size - CLZ4_SCRATCH_ALIGN);
    uint8_t *buffer = malloc(size);
    __CPROVER_assume(buffer != NULL);
    void *p = buffer + offset;
    void *result = clz4_align(p);
    PROOF_REACHABLE(result == p, "already aligned");
    PROOF_REACHABLE(result == (uint8_t *)p + 15, "maximum alignment adjustment");
}
