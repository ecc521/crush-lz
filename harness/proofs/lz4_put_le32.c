/* The shipping four-byte store meets its memory footprint contract. */
#include "proof.h"
#include "crushlz4.c"

uint32_t nondet_u32(void);
size_t nondet_size(void);

void harness(void)
{
    size_t size = nondet_size(), offset = nondet_size();
    __CPROVER_assume(size >= 4 && size <= PROOF_MAX_OBJECT && offset <= size - 4);
    uint8_t *buffer = malloc(size);
    __CPROVER_assume(buffer != NULL);
    put_le32(buffer + offset, nondet_u32());
    PROOF_REACHABLE(offset == 0, "store at beginning");
    PROOF_REACHABLE(offset == size - 4, "store at exact end");
}
