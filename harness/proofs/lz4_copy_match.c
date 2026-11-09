/*
 * Proof: copy_match in crates/crushlz4/csrc/crushlz4.c meets its contract.
 *
 * The harness only builds a pointer into a buffer of unconstrained size and
 * passes unconstrained arguments. CBMC assumes copy_match's requires
 * clauses on them (--enforce-contract), and decode_block's proof checks the
 * same clauses at every call site, so nothing here is trusted beyond "d
 * points into some buffer".
 *
 * What CBMC then checks, for all of those inputs at once:
 *   - every pointer and array access stays inside the buffer;
 *   - the function and each loop write only what their assigns clauses
 *     name, so the wide copy's overrun stays in d[0, room);
 *   - every memcpy gets valid, non-overlapping ranges (proof.h);
 *   - each loop invariant holds on entry and is preserved by one iteration,
 *     which covers every iteration count, so mlen is not bounded;
 *   - each loop's decreases clause strictly drops: termination.
 */
#include "proof.h"
#include "crushlz4.c"

size_t nondet_size(void);

void harness(void)
{
    size_t n = nondet_size();
    __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT);
    uint8_t *buf = malloc(n);
    __CPROVER_assume(buf != NULL);
    size_t pos = nondet_size();
    __CPROVER_assume(pos <= n);     /* d is a pointer into buf */

    size_t off = nondet_size();
    size_t mlen = nondet_size();
    size_t room = nondet_size();
    copy_match(buf + pos, off, mlen, room);

    /* Each path must stay reachable under the requires clauses, or the
     * proof would pass without covering it. run.sh fails if any is not. */
    PROOF_REACHABLE(off >= 8 && mlen + CLZ4_COPY_SLACK <= room && mlen > 32,
                    "wide copy, several iterations");
    PROOF_REACHABLE(off >= 8 && mlen + CLZ4_COPY_SLACK > room && mlen > 0,
                    "byte copy at the end of the buffer");
    PROOF_REACHABLE(off < 8 && mlen > off, "byte copy of a short period");
    PROOF_REACHABLE(mlen > ((size_t)1 << 40), "match longer than 2^40");
}
