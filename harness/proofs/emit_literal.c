/*
 * Proof: emit_literal in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

size_t nondet_size(void);

void harness(void)
{
    size_t sn = nondet_size(), so = nondet_size();
    __CPROVER_assume(sn > 0 && sn <= PROOF_MAX_OBJECT && so <= sn);
    uint8_t *sbuf = malloc(sn);
    __CPROVER_assume(sbuf != NULL);

    size_t dn = nondet_size(), dof = nondet_size();
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT && dof <= dn);
    uint8_t *dbuf = malloc(dn);
    __CPROVER_assume(dbuf != NULL);

    size_t L = nondet_size();
#ifdef PROOF_LITERAL_TAIL
    __CPROVER_assume(L <= 15);
#endif
#ifndef LZVN_EXACT_EMIT
    __CPROVER_assume(L <= 800);
#endif
    __CPROVER_assume(L <= sn - so);

    uint8_t *q = dbuf + dof;
    uint8_t *q1 = dbuf + dn;

    unsigned char *ret = emit_literal(sbuf + so, q, q1, L);

    __CPROVER_assert(ret == q1 || (ret >= q && ret <= q1), "return pointer in range");

    PROOF_REACHABLE(L == 0, "L == 0 empty literal");
    PROOF_REACHABLE(L > 0 && L <= 15 && ret != q1, "L in 1..15 fits");
#ifndef PROOF_LITERAL_TAIL
    PROOF_REACHABLE(L > 15 && L <= 271 && ret != q1, "L in 16..271 single large chunk");
    PROOF_REACHABLE(L > 271 && ret != q1, "L > 271 multi-chunk literal");
#endif
    PROOF_REACHABLE(ret == q1, "output full branch");
}
