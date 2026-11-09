#include "proof.h"
#include "libzbitmap.c"
uint64_t nondet_u64(void);
unsigned nondet_u32(void);
void harness(void)
{
    uint64_t word = nondet_u64(), next = nondet_u64();
    unsigned shift = nondet_u32(), q = nondet_u32();
    __CPROVER_assume(shift < 64 && q < 16);
    uint16_t window = zbm_long_run_window(word, next, shift);
    unsigned pos = shift + q;
    unsigned expected = pos < 64 ? (unsigned)((word >> pos) & 1u) :
                                  (unsigned)((next >> (pos - 64)) & 1u);
    __CPROVER_assert(((window >> q) & 1u) == expected,
        "sixteen-bit fast-path window preserves every selected long-run bit");
    PROOF_REACHABLE(shift == 0, "word-aligned window");
    PROOF_REACHABLE(shift == 48, "window ends exactly at word boundary");
    PROOF_REACHABLE(shift == 49, "window crosses word boundary");
    PROOF_REACHABLE(shift == 63 && q == 15, "maximum shifted lookahead");
}
