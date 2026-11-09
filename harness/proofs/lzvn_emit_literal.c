/*
 * Proof: lzvn_emit_literal in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
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

    lzvn_encoder_state state;
    memset(&state, 0, sizeof(state));
    state.src = sbuf;
    state.src_begin = 0;
    state.src_end = (lzvn_offset)sn;
    state.src_literal = (lzvn_offset)so;
    state.dst = dbuf + dof;
    state.dst_begin = dbuf;
    state.dst_end = dbuf + dn;

    lzvn_offset n = nondet_size();
    __CPROVER_assume(n >= 0 && (size_t)n <= sn - so);

    lzvn_offset ret = lzvn_emit_literal(&state, n);

    __CPROVER_assert(state.dst <= state.dst_end, "dst <= dst_end");

    PROOF_REACHABLE(ret > 0, "literals emitted successfully");
    PROOF_REACHABLE(ret == 0, "destination full");
}
