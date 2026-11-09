/*
 * Proof: crushlzvn_scratch_size, crushlzvn_carve_greedy, and
 * crushlzvn_carve_optimal in crates/crushlzfse/csrc/crushlzvn.c.
 */
#include "proof.h"
#include "crushlzvn.c"

crushlzvn_encode_params nondet_params(void);
int nondet_int(void);
_Bool nondet_bool(void);

void harness(void)
{
    crushlzvn_encode_params p = nondet_params();
    __CPROVER_assume(crushlzvn_params_valid(&p) == 1);

    size_t sz = crushlzvn_scratch_size(&p);
    __CPROVER_assert(sz > 0 && sz <= PROOF_MAX_OBJECT, "scratch size in valid range");

    uint8_t *scratch = malloc(sz);
    __CPROVER_assume(scratch != NULL);

    if (p.strategy == CRUSHLZVN_STRATEGY_GREEDY) {
        int32_t hb = p.p.greedy.hash_bits;
        int32_t hw = p.p.greedy.hash_width;
        crushlzvn_regions r = crushlzvn_carve_greedy(scratch, hb, hw);

        size_t n_hash = (size_t)1 << hb;
        __CPROVER_assert(__CPROVER_rw_ok(r.hist_pos, n_hash * (size_t)hw * sizeof(int32_t)),
                         "hist_pos fits within scratch");
        __CPROVER_assert(__CPROVER_rw_ok(r.hist_value, n_hash * (size_t)hw * sizeof(uint32_t)),
                         "hist_value fits within scratch");
        __CPROVER_assert(__CPROVER_rw_ok(r.hist_cursor, n_hash * sizeof(uint16_t)),
                         "hist_cursor fits within scratch");
        /* The greedy loop's three writable table ranges must be disjoint,
         * even though all three pointers belong to one scratch object. */
        __CPROVER_assert((size_t)((uint8_t *)r.hist_pos - (uint8_t *)scratch) +
                         n_hash * (size_t)hw * sizeof(int32_t) <=
                         (size_t)((uint8_t *)r.hist_value - (uint8_t *)scratch),
                         "greedy position and value tables do not overlap");
        __CPROVER_assert((size_t)((uint8_t *)r.hist_value - (uint8_t *)scratch) +
                         n_hash * (size_t)hw * sizeof(uint32_t) <=
                         (size_t)((uint8_t *)r.hist_cursor - (uint8_t *)scratch),
                         "greedy value and cursor tables do not overlap");

        PROOF_REACHABLE(p.strategy == CRUSHLZVN_STRATEGY_GREEDY, "carve greedy");
    } else if (p.strategy == CRUSHLZVN_STRATEGY_FAST) {
        size_t entries = (size_t)1 << p.p.fast.hash_bits;
        size_t tbl_bytes = (p.p.fast.long_table ? 2 : 1) * entries * sizeof(uint16_t);
        __CPROVER_assert(__CPROVER_rw_ok(scratch, tbl_bytes),
                         "fast table fits within scratch");

        PROOF_REACHABLE(p.strategy == CRUSHLZVN_STRATEGY_FAST, "carve fast");
    } else if (p.strategy == CRUSHLZVN_STRATEGY_OPTIMAL) {
        int32_t cand_cap = cand_capacity_for(&p);
        crushlzvn_regions r = crushlzvn_carve_optimal(scratch, cand_cap,
                                                      p.p.optimal.hash_bits,
                                                      p.p.optimal.pareto_k);

        size_t zopt_sz = lzvn_zopt_scratch_size(cand_cap, p.p.optimal.hash_bits);
        size_t pareto_sz = lzvn_pareto_scratch_size(p.p.optimal.pareto_k);
        size_t padded_sz = (size_t)LZVN_ZOPT_BLOCK_SIZE + LZVN_ZOPT_SRC_PADDING;
        size_t alt_cap = alt_tmp_size_for();

        __CPROVER_assert(__CPROVER_rw_ok(r.zopt, zopt_sz),
                         "zopt fits within scratch");
        __CPROVER_assert(__CPROVER_rw_ok(r.pareto, pareto_sz),
                         "pareto fits within scratch");
        __CPROVER_assert(__CPROVER_rw_ok(r.padded_src, padded_sz),
                         "padded_src fits within scratch");
        __CPROVER_assert(__CPROVER_rw_ok(r.alt_tmp, alt_cap),
                         "alt_tmp fits within scratch");

        size_t alt_n = (size_t)1 << CRUSHLZVN_GREEDY_NARROW_HASH_BITS;
        __CPROVER_assert(__CPROVER_rw_ok(r.alt_hist_pos, alt_n * (size_t)CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH * sizeof(int32_t)),
                         "alt_hist_pos fits within scratch");
        __CPROVER_assert(__CPROVER_rw_ok(r.alt_hist_value, alt_n * (size_t)CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH * sizeof(uint32_t)),
                         "alt_hist_value fits within scratch");
        __CPROVER_assert(__CPROVER_rw_ok(r.alt_hist_cursor, alt_n * sizeof(uint16_t)),
                         "alt_hist_cursor fits within scratch");
        /* The alternate greedy parse writes its output and tables in the
         * same scratch allocation; prove their live ranges do not overlap. */
        __CPROVER_assert((size_t)(r.alt_tmp - (uint8_t *)scratch) + alt_cap <=
                         (size_t)((uint8_t *)r.alt_hist_pos - (uint8_t *)scratch),
                         "alternate output and position table do not overlap");
        __CPROVER_assert((size_t)((uint8_t *)r.alt_hist_pos - (uint8_t *)scratch) +
                         alt_n * (size_t)CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH * sizeof(int32_t) <=
                         (size_t)((uint8_t *)r.alt_hist_value - (uint8_t *)scratch),
                         "alternate position and value tables do not overlap");
        __CPROVER_assert((size_t)((uint8_t *)r.alt_hist_value - (uint8_t *)scratch) +
                         alt_n * (size_t)CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH * sizeof(uint32_t) <=
                         (size_t)((uint8_t *)r.alt_hist_cursor - (uint8_t *)scratch),
                         "alternate value and cursor tables do not overlap");

        PROOF_REACHABLE(p.strategy == CRUSHLZVN_STRATEGY_OPTIMAL, "carve optimal");
    }

    free(scratch);
}
