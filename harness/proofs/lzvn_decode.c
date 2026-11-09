/*
 * Proof: lzvn_decode in crates/crushlzfse/csrc/lzvn_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_decode_base.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t sn = nondet_size(), so = nondet_size();
    size_t dn = nondet_size(), dof = nondet_size();
    __CPROVER_assume(sn > 0 && sn <= PROOF_MAX_OBJECT && so <= sn);
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT && dof <= dn);
    uint8_t *sbuf = NULL, *dbuf = NULL;
    _Bool shared = nondet_bool();
    size_t gap = 0, lead = 0;
    if (shared) {
        __CPROVER_assume(sn <= PROOF_MAX_OBJECT - dn);
        gap = nondet_size();
        lead = nondet_size();
        __CPROVER_assume(gap <= PROOF_MAX_OBJECT - sn - dn);
        __CPROVER_assume(lead <= PROOF_MAX_OBJECT - sn - dn - gap);
        uint8_t *arena = malloc(lead + sn + gap + dn);
        __CPROVER_assume(arena != NULL);
        uint8_t *first = arena + lead;
        if (nondet_bool()) {
            sbuf = first;
            dbuf = first + sn + gap;
        } else {
            dbuf = first;
            sbuf = first + dn + gap;
        }
    } else {
        sbuf = malloc(sn);
        dbuf = malloc(dn);
        __CPROVER_assume(sbuf != NULL && dbuf != NULL);
    }

    size_t src_len = nondet_size();
    __CPROVER_assume(src_len <= sn - so);
    size_t dst_len = nondet_size();
    __CPROVER_assume(dst_len <= dn - dof);

    size_t d_pos = nondet_size();
    __CPROVER_assume(d_pos <= dst_len);

    lzvn_decoder_state *state = malloc(sizeof(*state));
    __CPROVER_assume(state != NULL);
    state->src = sbuf + so;
    state->src_end = sbuf + so + src_len;
    state->dst_begin = dbuf + dof;
    state->dst = dbuf + dof + d_pos;
    state->dst_end = dbuf + dof + dst_len;
    size_t d_prev = nondet_size();
    __CPROVER_assume(d_prev <= d_pos);
    state->d_prev = d_prev;
    state->end_of_stream = 0;
    state->truncated_mid_op = 0;

    lzvn_decode(state);

    PROOF_REACHABLE(state->end_of_stream == 1, "end of stream decoded");
    PROOF_REACHABLE(shared && state->end_of_stream == 1, "shared allocation end of stream");
    PROOF_REACHABLE(shared && gap > 0 && lead > 0 && state->end_of_stream == 1,
                    "shared allocation end of stream with leading offset and gap");
    PROOF_REACHABLE(state->dst == state->dst_end && !state->end_of_stream, "destination full");
    PROOF_REACHABLE(state->truncated_mid_op == 1, "truncated mid op");
    PROOF_REACHABLE(state->src == state->src_end, "source exhausted");
}
