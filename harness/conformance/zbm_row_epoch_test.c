// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/* Force index rebuilds: chunk boundaries alone may carry the existing index
 * forward without advancing its epoch. */
#include "libzbitmap.c"
#include <stdio.h>

int main(void)
{
    /* 7 is a DP level and 12 a beam level: both keep a second index. */
    const int levels[] = {-2, 0, 3, 7, 12};
    unsigned wraps = 0, rebuilds = 0;
    /* An empty input gets the smallest table, a 64 KiB one the level's
     * whole table; either way the active one is what must be cleared. */
    for (unsigned k = 0; k < 2 * sizeof(levels) / sizeof(*levels); k++) {
        crushlzbitmap_params params;
        crushlzbitmap_params_for_level(levels[k / 2], &params);
        size_t need = crushlzbitmap_scratch_size(&params);
        void *scratch = malloc(need);
        if (!scratch) abort();
        memset(scratch, 0xa5, need);
        struct zbm_compress_state *state = zbm_state_begin(scratch, &params);
        if (!state) abort();
        state->params = params;
        state->buf_base = NULL;
        state->buf_len = k % 2 ? (size_t)1 << 16 : 0;
        size_t entries = 0, entries2 = 0;
        uint32_t marker = 0;
        const int two = params.strategy == CRUSHLZBITMAP_STRATEGY_DP ||
                        params.strategy == CRUSHLZBITMAP_STRATEGY_BEAM;
        for (unsigned rebuild = 0; rebuild < 768; rebuild++) {
            state->index_live = 0;
            zbm_row_prepare_index(state, 0);
            entries = (size_t)state->row_ways << (32 - state->row_sh);
            rebuilds++;
            if (two != (state->row_tab2 != NULL)) {
                fprintf(stderr, "second row index %s at level %d\n",
                        two ? "missing" : "unexpected", levels[k / 2]);
                return 1;
            }
            if (two)
                entries2 = (size_t)ZBM_ROW2_WAYS << (32 - state->row_sh2);
            unsigned expected_epoch = rebuild % 255 + 1;
            if (state->row_epoch != expected_epoch) {
                fprintf(stderr, "unexpected epoch: level=%d rebuild=%u epoch=%u\n",
                        levels[k / 2], rebuild, state->row_epoch);
                return 1;
            }
            if (expected_epoch == 1) {
                for (size_t i = 0; i < entries; i++) {
                    if (state->row_tab[i] != 0) {
                        fprintf(stderr, "active row table not cleared at first use/wrap\n");
                        return 1;
                    }
                }
                for (size_t i = 0; i < entries2; i++) {
                    if (state->row_tab2[i] != 0) {
                        fprintf(stderr, "second row index not cleared at first use/wrap\n");
                        return 1;
                    }
                }
                wraps++;
                marker = 1u << 24;
                state->row_tab[entries - 1] = marker;
                if (two)
                    state->row_tab2[entries2 - 1] = marker;
            } else if (state->row_tab[entries - 1] != marker ||
                       (two && state->row_tab2[entries2 - 1] != marker)) {
                fprintf(stderr, "row table changed between epoch wraps\n");
                return 1;
            }
        }
        zbm_state_end(state, scratch);
        free(scratch);
    }
    printf("%u index rebuilds and %u initial/wrap clears passed\n", rebuilds, wraps);
    return 0;
}
