#include "proof.h"
#include "libzbitmap.c"

size_t nondet_size(void);

void harness(void)
{
    size_t n = nondet_size();
    /* The encoder rejects larger sources before reading them. */
    __CPROVER_assume(n <= CRUSHLZBITMAP_MAX_SRC_SIZE);
    size_t chunks = n / CRUSHLZBITMAP_CHUNK_SIZE +
                    (n % CRUSHLZBITMAP_CHUNK_SIZE != 0);
    size_t bound = crushlzbitmap_encode_bound(n);
    __CPROVER_assert(bound == 4 + CRUSHLZBITMAP_LAST_CHUNK_SIZE +
                            chunks * CRUSHLZBITMAP_MAX_CHUNK_SIZE,
                      "bound equals worst-case chunk envelope");
    __CPROVER_assert(bound >= n, "bound cannot wrap below source size");
    PROOF_REACHABLE(n == 0, "empty source");
    PROOF_REACHABLE(n == CRUSHLZBITMAP_CHUNK_SIZE, "exact chunk boundary");
    PROOF_REACHABLE(n == CRUSHLZBITMAP_CHUNK_SIZE + 1, "partial second chunk");
    PROOF_REACHABLE(n == CRUSHLZBITMAP_MAX_SRC_SIZE, "maximum supported source");
}
