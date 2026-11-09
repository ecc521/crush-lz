#include "proof.h"
#include "libzbitmap.c"

uint64_t nondet_u64(void);
unsigned nondet_u32(void);
_Bool nondet_bool(void);

/* Independent adjacent-edge model, indexed across three words. */
static unsigned edge(uint64_t previous, uint64_t current, uint64_t next, int pos)
{
    if(pos < 0) return (unsigned)((previous >> (pos + 64)) & 1u);
    if(pos >= 64) return (unsigned)((next >> (pos - 64)) & 1u);
    return (unsigned)((current >> pos) & 1u);
}

void harness(void)
{
    uint64_t previous = nondet_u64(), current = nondet_u64(), next = nondet_u64();
    _Bool first = nondet_bool(), last = nondet_bool();
    if(first) previous = 0;
    if(last) next = 0;
    unsigned q = nondet_u32();
    __CPROVER_assume(q < 64);
    uint64_t prev_starts = first ? 0 : zbm_long_run_starts(previous, current);
    uint64_t starts = zbm_long_run_starts(current, next);
    uint64_t mask = zbm_long_run_spread(starts, prev_starts);
    unsigned expected = 0;
    for(int before = 0; before < 4; ++before) {
        unsigned all = 1;
        for(int step = 0; step < 3; ++step)
            all &= edge(previous, current, next, (int)q - before + step);
        expected |= all;
    }
    __CPROVER_assert(((mask >> q) & 1u) == expected,
        "long mask marks precisely blocks covered by four-block equal windows");
    PROOF_REACHABLE(first && last, "single boundary word");
    PROOF_REACHABLE(!first && !last && current == UINT64_MAX && mask == UINT64_MAX,
        "interior full long run");
    PROOF_REACHABLE(!first && q == 0 && previous == (UINT64_C(7) << 61) && current == 0 && expected,
        "long window starting in previous word");
    PROOF_REACHABLE(!last && q == 63 && current == (UINT64_C(3) << 62) && next == 1 && expected,
        "long window ending in next word");
    PROOF_REACHABLE(first && q == 0 && current == 3 && next == 0 && !expected,
        "three-block run stays unmarked");
    PROOF_REACHABLE(last && q == 63 && current == (UINT64_C(3) << 62) && !expected,
        "last word does not invent next-word edges");
}
