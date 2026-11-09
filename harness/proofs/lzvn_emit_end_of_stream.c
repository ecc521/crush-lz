/*
 * Proof: lzvn_emit_end_of_stream in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

size_t nondet_size(void);

void harness(void)
{
    size_t dn = nondet_size(), dof = nondet_size();
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT && dof <= dn);
    uint8_t *dbuf = malloc(dn);
    __CPROVER_assume(dbuf != NULL);

    lzvn_encoder_state state;
    memset(&state, 0, sizeof(state));
    state.dst = dbuf + dof;
    state.dst_end = dbuf + dn;

    lzvn_offset ret = lzvn_emit_end_of_stream(&state);

    __CPROVER_assert(ret == 0 || ret == 8, "ret is 0 or 8");
    __CPROVER_assert(state.dst <= state.dst_end, "dst <= dst_end");

    PROOF_REACHABLE(ret == 8, "end of stream emitted");
    PROOF_REACHABLE(ret == 0, "destination full");
}
