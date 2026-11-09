/*
 * Proof: crushlzvn_params_valid, crushlzvn_params_for_level,
 * crushlzvn_get_capabilities, and crushlzvn_scratch_size in
 * crates/crushlzfse/csrc/crushlzvn.c.
 */
#include "proof.h"
#include "crushlzvn.c"

crushlzvn_encode_params nondet_params(void);
int nondet_int(void);

static int is_greedy_valid(const crushlzvn_encode_params *p)
{
    return p->p.greedy.hash_bits >= CRUSHLZVN_GREEDY_MIN_HASH_BITS &&
           p->p.greedy.hash_bits <= CRUSHLZVN_GREEDY_MAX_HASH_BITS &&
           p->p.greedy.hash_width >= 1 &&
           p->p.greedy.hash_width <= CRUSHLZVN_GREEDY_MAX_HASH_WIDTH;
}

static int is_optimal_valid(const crushlzvn_encode_params *p)
{
    return p->p.optimal.search_depth >= 1 &&
           p->p.optimal.search_depth <= LZVN_ZOPT_MAX_SEARCH_DEPTH &&
           p->p.optimal.store_limit >= 1 &&
           p->p.optimal.store_limit <= LZVN_ZOPT_MAX_STORE_LIMIT &&
           p->p.optimal.hash_bits >= LZVN_ZOPT_MIN_HASH_BITS &&
           p->p.optimal.hash_bits <= LZVN_ZOPT_MAX_HASH_BITS &&
           p->p.optimal.pareto_k >= 1 &&
           p->p.optimal.pareto_k <= LZVN_PARETO_MAX_K;
}

static int is_fast_valid(const crushlzvn_encode_params *p)
{
    int hb = p->p.fast.hash_bits;
    int mm = p->p.fast.min_match;
    int ss = p->p.fast.skip_shift;
    int ms = p->p.fast.max_step;
    int lt = p->p.fast.long_table;
    int lazy = p->p.fast.lazy;
    int mm_max = (lt || lazy) ? CRUSHLZFSE_FAST_MAX_MIN_MATCH_MODES : CRUSHLZFSE_FAST_MAX_MIN_MATCH;
    return hb >= CRUSHLZFSE_FAST_MIN_HASH_BITS && hb <= CRUSHLZFSE_FAST_MAX_HASH_BITS &&
           mm >= CRUSHLZFSE_FAST_MIN_MIN_MATCH && mm <= mm_max &&
           ss >= CRUSHLZFSE_FAST_MIN_SKIP_SHIFT && ss <= CRUSHLZFSE_FAST_MAX_SKIP_SHIFT &&
           ms >= CRUSHLZFSE_FAST_MIN_MAX_STEP && ms <= CRUSHLZFSE_FAST_MAX_MAX_STEP &&
           (lt == 0 || lt == 1) && (lazy == 0 || lazy == 1);
}

void harness(void)
{
    /* 1. Null handling */
    __CPROVER_assert(crushlzvn_params_for_level(0, NULL) == CRUSHLZVN_LEVEL_INVALID,
                     "null out returns CRUSHLZVN_LEVEL_INVALID");
    __CPROVER_assert(crushlzvn_scratch_size(NULL) == 0,
                     "null params scratch size is 0");

    /* 2. Parameter validation domain */
    crushlzvn_encode_params p = nondet_params();
    int expected_valid = 0;
    if (p.strategy == CRUSHLZVN_STRATEGY_GREEDY)
        expected_valid = is_greedy_valid(&p);
    else if (p.strategy == CRUSHLZVN_STRATEGY_OPTIMAL)
        expected_valid = is_optimal_valid(&p);
    else if (p.strategy == CRUSHLZVN_STRATEGY_FAST)
        expected_valid = is_fast_valid(&p);

    int actual_valid = crushlzvn_params_valid(&p);
    __CPROVER_assert(actual_valid == expected_valid,
                     "crushlzvn_params_valid matches public parameter domain");

    if (actual_valid) {
        size_t s = crushlzvn_scratch_size(&p);
        __CPROVER_assert(s > 0, "valid params have positive scratch size");
    }

    /* 3. Level clamping and valid presets */
    int level = nondet_int();
    crushlzvn_encode_params preset;
    int used = crushlzvn_params_for_level(level, &preset);
    int clamped = level < CRUSHLZVN_LEVEL_MIN ? CRUSHLZVN_LEVEL_MIN :
                  level > CRUSHLZVN_LEVEL_MAX ? CRUSHLZVN_LEVEL_MAX : level;
    __CPROVER_assert(used == clamped, "level clamped correctly");
    __CPROVER_assert(crushlzvn_params_valid(&preset) == 1,
                     "every preset level produces valid params");
    __CPROVER_assert(crushlzvn_scratch_size(&preset) > 0,
                     "every preset level has positive scratch size");

    /* 4. Capabilities consistency */
    crushlzvn_capabilities caps = crushlzvn_get_capabilities();
    __CPROVER_assert(caps.level_min == CRUSHLZVN_LEVEL_MIN, "caps level_min matches");
    __CPROVER_assert(caps.level_max == CRUSHLZVN_LEVEL_MAX, "caps level_max matches");
    __CPROVER_assert(caps.greedy_hash_bits_min == CRUSHLZVN_GREEDY_MIN_HASH_BITS, "caps greedy_min matches");
    __CPROVER_assert(caps.greedy_hash_bits_max == CRUSHLZVN_GREEDY_MAX_HASH_BITS, "caps greedy_max matches");

    PROOF_REACHABLE(expected_valid && p.strategy == CRUSHLZVN_STRATEGY_GREEDY, "valid greedy params");
    PROOF_REACHABLE(expected_valid && p.strategy == CRUSHLZVN_STRATEGY_OPTIMAL, "valid optimal params");
    PROOF_REACHABLE(expected_valid && p.strategy == CRUSHLZVN_STRATEGY_FAST, "valid fast params");
    PROOF_REACHABLE(!expected_valid, "invalid params rejected");
    PROOF_REACHABLE(level < CRUSHLZVN_LEVEL_MIN, "underflow level clamped");
    PROOF_REACHABLE(level > CRUSHLZVN_LEVEL_MAX, "overflow level clamped");
    PROOF_REACHABLE(level >= CRUSHLZVN_LEVEL_MIN && level <= CRUSHLZVN_LEVEL_MAX, "in-range level exact");
}
