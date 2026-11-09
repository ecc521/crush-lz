#include "proof.h"
#include "libzbitmap.c"

crushlzbitmap_params nondet_params(void);
int nondet_int(void);

void harness(void)
{
    crushlzbitmap_params params = nondet_params();
    __CPROVER_assume(zbm_validate_params(&params) == 0);
    size_t size = crushlzbitmap_scratch_size(&params);
    __CPROVER_assert(size >= sizeof(struct zbm_compress_state), "scratch includes state");
    int supplied = nondet_int();
    __CPROVER_assume(supplied == 0 || supplied == 1);
    void *scratch = supplied ? malloc(size) : NULL;
    __CPROVER_assume(!supplied || scratch != NULL);
    struct zbm_compress_state *state = zbm_state_begin(scratch, &params);
    if(state == NULL) {
        __CPROVER_assert(scratch == NULL, "only internal allocation may fail");
        PROOF_REACHABLE(state == NULL, "internal allocation failure");
        return;
    }
    __CPROVER_assert(!supplied || state == scratch, "caller owns returned state");
    __CPROVER_assert(state->index_live == 0 && state->dp_recording == 0,
                      "scratch initialization resets index and recording");
    if(params.strategy == CRUSHLZBITMAP_STRATEGY_DP ||
       params.strategy == CRUSHLZBITMAP_STRATEGY_BEAM) {
        int n = params.strategy == CRUSHLZBITMAP_STRATEGY_DP ?
                params.p.dp.max_candidates : params.p.beam.max_candidates;
        __CPROVER_assert(state->dp_cand_stride == n, "candidate stride matches allocation");
        __CPROVER_assert(__CPROVER_w_ok(state->row_tab2, ZBM_ROW2_BYTES),
                          "second row index fits scratch");
        __CPROVER_assert(__CPROVER_w_ok(state->dp_cand,
                            sizeof(uint16_t) * ZBM_MAX_BITMAP_COUNT * (size_t)n),
                          "candidate table fits scratch");
        if(params.strategy == CRUSHLZBITMAP_STRATEGY_DP)
            __CPROVER_assert(__CPROVER_w_ok(state->dp_parent,
                                ZBM_MAX_BITMAP_COUNT * (size_t)n), "DP parent table fits scratch");
        else {
            __CPROVER_assert(__CPROVER_w_ok(state->beam_trace,
                                sizeof(struct zbm_beam_trace) * ZBM_MAX_BITMAP_COUNT *
                                (size_t)params.p.beam.beam_width), "beam trace fits scratch");
            __CPROVER_assert(__CPROVER_w_ok(state->beam_seen,
                                sizeof(struct zbm_beam_seen) << ZBM_BEAM_SEEN_BITS),
                              "beam deduplication table fits scratch");
        }
    } else {
        __CPROVER_assert(size == sizeof(*state) && state->row_tab2 == NULL &&
                            state->dp_cand == NULL && state->dp_parent == NULL &&
                            state->beam_trace == NULL && state->beam_seen == NULL,
                          "row and fast use state-only scratch");
    }
    PROOF_REACHABLE(params.strategy == CRUSHLZBITMAP_STRATEGY_ROW, "row scratch");
    PROOF_REACHABLE(supplied, "caller scratch ownership");
    PROOF_REACHABLE(!supplied, "internal scratch ownership");
    PROOF_REACHABLE(params.strategy == CRUSHLZBITMAP_STRATEGY_FAST, "fast scratch");
    PROOF_REACHABLE(params.strategy == CRUSHLZBITMAP_STRATEGY_DP &&
                      params.p.dp.max_candidates == CRUSHLZBITMAP_MAX_DP_CANDS,
                      "maximum DP scratch");
    PROOF_REACHABLE(params.strategy == CRUSHLZBITMAP_STRATEGY_BEAM &&
                      params.p.beam.beam_width == CRUSHLZBITMAP_MAX_BEAM_WIDTH &&
                      params.p.beam.max_candidates == CRUSHLZBITMAP_MAX_DP_CANDS,
                      "maximum beam scratch");
    zbm_state_end(state, scratch);
    free(scratch);
}
