/*
 * Proof: lzvn_greedy_wide_step in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

size_t nondet_size(void);
int32_t nondet_int32(void);
lzvn_offset nondet_offset(void);

void harness(void)
{
    size_t sn = nondet_size();
    __CPROVER_assume(sn >= 8 && sn <= LZVN_ENCODE_MAX_SRC_SIZE);
    uint8_t *sbuf = malloc(sn);
    __CPROVER_assume(sbuf != NULL);

    size_t dn = nondet_size(), dof = nondet_size();
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT && dof <= dn);
    uint8_t *dbuf = malloc(dn);
    __CPROVER_assume(dbuf != NULL);

    int32_t hash_bits = nondet_int32();
    __CPROVER_assume(hash_bits >= 10 && hash_bits <= 16);
    int32_t hash_width = nondet_int32();
    __CPROVER_assume(hash_width >= 1 && hash_width <= 64);

    size_t n_hash = (size_t)1 << hash_bits;
    size_t table_entries = n_hash * (size_t)hash_width;
    int32_t *hist_pos = malloc(table_entries * sizeof(int32_t));
    uint32_t *hist_value = malloc(table_entries * sizeof(uint32_t));
    uint16_t *hist_cursor = malloc(n_hash * sizeof(uint16_t));
    __CPROVER_assume(hist_pos != NULL && hist_value != NULL && hist_cursor != NULL);

    lzvn_encoder_state state;
    memset(&state, 0, sizeof(state));
    state.src = sbuf;
    state.src_begin = nondet_offset();
    state.src_end = (lzvn_offset)sn;
    state.src_current = nondet_offset();
    state.src_current_end = nondet_offset();
    state.src_literal = nondet_offset();
    state.dst = dbuf + dof;
    state.dst_begin = dbuf;
    state.dst_end = dbuf + dn;
    state.pending.m_begin = nondet_offset();
    state.pending.m_end = nondet_offset();
    state.pending.M = nondet_offset();
    state.pending.D = nondet_offset();
    state.pending.K = nondet_offset();
    state.d_prev = nondet_offset();

    lzvn_offset sentinel_pos = nondet_offset();
    uint32_t sentinel_val = (uint32_t)nondet_offset();

    int stop = lzvn_greedy_wide_step(&state, hash_bits, hash_width, hist_pos, hist_value, hist_cursor,
                                     sentinel_pos, sentinel_val);

    PROOF_REACHABLE(stop == 1, "destination full");
    PROOF_REACHABLE(stop == 0 && state.pending.M != 0, "match pending");
    PROOF_REACHABLE(stop == 0 && state.pending.M == 0 && state.src_literal > 0, "match emitted");
    PROOF_REACHABLE(stop == 0 && state.src_current < state.src_literal, "inside an emitted match");
}
