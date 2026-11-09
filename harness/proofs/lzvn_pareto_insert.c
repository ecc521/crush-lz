/*
 * One row of the shipping LZVN optimal parser's Pareto front. The width
 * spans its complete supported range; outer row-offset arithmetic is open.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

int32_t nondet_int32(void);

void harness(void)
{
    int32_t pos = 0;
    int32_t cap = nondet_int32();
    __CPROVER_assume(1 <= cap && cap <= LZVN_PARETO_MAX_K);

    size_t rows = (size_t)pos + 1;
    size_t nslots = rows * (size_t)cap;
    lzvn_pareto_scratch p = {0};
    p.k_cap = cap;
    p.count = malloc(rows * sizeof(*p.count));
    p.worst_cost = malloc(rows * sizeof(*p.worst_cost));
    p.slots = malloc(nslots * sizeof(*p.slots));
    __CPROVER_assume(p.count != NULL && p.worst_cost != NULL && p.slots != NULL);

    int32_t count = nondet_int32();
    __CPROVER_assume(0 <= count && count <= cap);
    p.count[pos] = count;

    int32_t out = lzvn_pareto_insert(&p, pos, nondet_int32(),
                                     nondet_int32(), nondet_int32(),
                                     nondet_int32(), nondet_int32(),
                                     nondet_int32(), nondet_int32(),
                                     nondet_int32());
    __CPROVER_assert(0 <= p.count[pos] && p.count[pos] <= cap,
                     "front count remains within capacity");
    __CPROVER_assert(out == -1 || (0 <= out && out < p.count[pos]),
                     "returned slot is live");

    PROOF_REACHABLE(count == 0 && out == 0, "first slot inserted");
    PROOF_REACHABLE(count > 0 && count < cap && out >= 0,
                    "non-full front grows");
    PROOF_REACHABLE(count == cap && out >= 0,
                    "full front replaced");
    PROOF_REACHABLE(count > 0 && out == -1,
                    "candidate rejected");
}
