#include "zbm_encoder_state.h"
#include "zbm_state.h"

/*
 * The fast tier's per-chunk index rebuild, for any chunk position inside a
 * source of any size, any epoch and any table contents. PROOF_TAB_BITS
 * proves the table-size cap it and the row tier share instead.
 */
void harness(void)
{
    struct zbm_compress_state *state = zbm_any_encoder_state();
    size_t bn;

    state->buf_base = zbm_any_buffer(&bn);
    state->buf_len = nondet_size();
    __CPROVER_assume(state->buf_len <= bn);
#ifdef PROOF_TAB_BITS
    int hash_bits = nondet_int();
    int bits = zbm_tab_bits(state, hash_bits);
    PROOF_REACHABLE(hash_bits == 16 && bits == 16, "full table for a large input");
    PROOF_REACHABLE(hash_bits == 16 && bits == 9, "capped table for a small input");
#else
    uint32_t chunk_start = nondet_u32();
    uint32_t epoch0 = state->row_epoch;

    zbm_fast_prepare_index(state, chunk_start);
    PROOF_REACHABLE(chunk_start > ZBM_GREEDY_REACH + 64 && state->row_epoch == epoch0 + 1, "reach indexed, epoch advanced");
    PROOF_REACHABLE(epoch0 == 255 && state->row_epoch == 1, "epoch wrap clears the table");
    PROOF_REACHABLE(chunk_start == 0, "first chunk, nothing behind it");
#endif
}
