/*
 * Proof: emit in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
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
    size_t M = nondet_size();
    size_t D = nondet_size();
    size_t D_prev = nondet_size();

#ifdef PROOF_MATCH_TAIL
    __CPROVER_assume(L <= 3 && M <= 10-2*L);
#endif
    __CPROVER_assume(L <= 800);
    __CPROVER_assume(M >= 3 && M <= 800);
    __CPROVER_assume(D >= 1 && D <= LZVN_ENCODE_MAX_DISTANCE);
    __CPROVER_assume(L + 8 <= sn - so);

    uint8_t *q = dbuf + dof;
    uint8_t *q1 = dbuf + dn;

    unsigned char *ret = emit(sbuf + so, q, q1, L, M, D, D_prev);

    __CPROVER_assert(ret == q1 || (ret >= q && ret <= q1), "return pointer in range");

    PROOF_REACHABLE(ret == q1, "output full");
    PROOF_REACHABLE(ret != q1 && D == D_prev && L == 0, "D == D_prev match with L == 0");
    PROOF_REACHABLE(ret != q1 && D == D_prev && L > 0, "D == D_prev match with L > 0");
    PROOF_REACHABLE(ret != q1 && D != D_prev && D < 2048 - 2 * 256, "short distance match");
    PROOF_REACHABLE(ret != q1 && D >= (1 << 14), "long distance match");
#ifndef PROOF_MATCH_TAIL
    PROOF_REACHABLE(ret != q1 && M > 15, "long match with extension bytes");
#endif
}
