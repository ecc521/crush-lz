#include "zbm_encoder_state.h"
#include "zbm_state.h"

/*
 * The row tier's index: one range of inserts (PROOF_ROW_RANGE) or the
 * per-chunk rebuild, for any source size, range, epoch and table contents.
 * The second index is absent, its own allocation, or the caller scratch
 * just past the state, as zbm_state_begin carves it for DP and beam.
 */
void harness(void)
{
    size_t bn;
    struct zbm_compress_state *state;

    if(nondet_bool()) {
        state = zbm_any_encoder_state();
        state->row_tab2 = nondet_bool() ? NULL : malloc(ZBM_ROW2_BYTES);
    } else {
        state = zbm_any_encoder_scratch();
    }
    state->buf_base = zbm_any_buffer(&bn);
    state->buf_len = nondet_size();
    __CPROVER_assume(state->buf_len <= bn);
#ifdef PROOF_ROW_RANGE
    uint32_t from = nondet_u32(), to = nondet_u32();

    zbm_row_index_range(state, from, to);
    PROOF_REACHABLE(state->row_tab2 != NULL && to > from + 8 && state->buf_len > (size_t)to + 8 &&
                    state->row_ways == 16, "both indexes, sixteen ways");
    PROOF_REACHABLE(state->buf_len < (size_t)to, "range clipped at the buffer end");
#else
    uint32_t chunk_start = nondet_u32();
    uint32_t epoch0 = state->row_epoch;

    zbm_row_prepare_index(state, chunk_start);
    PROOF_REACHABLE(epoch0 == 255 && state->row_tab2 != NULL, "epoch wrap clears both tables");
    PROOF_REACHABLE(chunk_start > ZBM_GREEDY_REACH && state->row_epoch == epoch0 + 1, "reach indexed");
#endif
}
