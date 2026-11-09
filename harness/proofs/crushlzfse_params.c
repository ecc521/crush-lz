/*
 * Proof: crushlzfse_params_for_level, crushlzfse_get_capabilities,
 * lazy_params_valid, fast_params_valid, and optimal_params_valid in
 * crates/crushlzfse/csrc/crushlzfse.c.
 */
#include "proof.h"
#include <string.h>
#include "crushlzvn.h"

/* The shipping LZVN dispatch layer, included as is. It and crushlzfse.c
 * both define these file-static names, so rename the LZVN ones while
 * crushlzvn.c is included. */
#define cand_capacity_for lzvn_cand_capacity_for
#define encode_block lzvn_encode_block
#define fast_params_valid lzvn_fast_params_valid
#define optimal_params_valid lzvn_optimal_params_valid
#define LEVEL_TABLE lzvn_LEVEL_TABLE
#include "crushlzvn.c"
#undef cand_capacity_for
#undef encode_block
#undef fast_params_valid
#undef optimal_params_valid
#undef LEVEL_TABLE

#include "crushlzfse.c"

crushlzfse_encode_params nondet_params(void);
int nondet_int(void);

static int is_fast_valid(const crushlzfse_encode_params *p) {
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

static int is_lazy_valid(const crushlzfse_encode_params *p) {
    int hb = p->p.lazy.hash_bits;
    int hw = p->p.lazy.hash_width;
    int la = p->p.lazy.lookahead;
    return hb >= CRUSHLZFSE_LAZY_MIN_HASH_BITS && hb <= CRUSHLZFSE_LAZY_MAX_HASH_BITS &&
           hw >= 1 && hw <= CRUSHLZFSE_LAZY_MAX_HASH_WIDTH &&
           la >= 0 && la <= CRUSHLZFSE_LAZY_MAX_LOOKAHEAD;
}

static int is_optimal_valid(const crushlzfse_encode_params *p) {
    int search_depth = p->p.optimal.search_depth;
    int iterations = p->p.optimal.iterations;
    int enable_reparse = p->p.optimal.enable_reparse;
    int32_t split_max_blocks = p->p.optimal.split_max_blocks;
    int32_t hash_bits = p->p.optimal.hash_bits;
    int32_t store_limit = p->p.optimal.store_limit;
    int32_t max_live_buckets = p->p.optimal.max_live_buckets;
    int32_t tuple_tax = p->p.optimal.tuple_tax;
    int32_t table_search = p->p.optimal.table_search;
    return search_depth >= 1 && search_depth <= ZOPT_MAX_SEARCH_DEPTH &&
           iterations >= 1 && iterations <= ZOPT_MAX_ITERATIONS &&
           (enable_reparse == 0 || enable_reparse == 1) &&
           split_max_blocks >= 1 && split_max_blocks <= ZOPT_MAX_SPLIT_MAX_BLOCKS &&
           hash_bits >= ZOPT_MIN_HASH_BITS && hash_bits <= ZOPT_MAX_HASH_BITS &&
           store_limit >= 1 && store_limit <= ZOPT_MAX_STORE_LIMIT &&
           max_live_buckets >= 1 && max_live_buckets <= LZFSE_ENCODE_L_SYMBOLS &&
           tuple_tax >= 0 && tuple_tax <= ZOPT_MAX_TUPLE_TAX &&
           table_search >= 0 && table_search <= ZOPT_MAX_TABLE_SEARCH;
}

void harness(void)
{
    /* 1. Null handling */
    __CPROVER_assert(crushlzfse_params_for_level(0, NULL) == CRUSHLZFSE_LEVEL_INVALID,
                     "null out returns CRUSHLZFSE_LEVEL_INVALID");
    __CPROVER_assert(crushlzfse_scratch_size(NULL) == 0,
                     "null params scratch size is 0");

    /* 2. Parameter validation domain */
    crushlzfse_encode_params p = nondet_params();
    int actual_valid = 0;
    int expected_valid = 0;

    if (p.strategy == CRUSHLZFSE_STRATEGY_FAST) {
        expected_valid = is_fast_valid(&p);
        actual_valid = fast_params_valid(&p);
    } else if (p.strategy == CRUSHLZFSE_STRATEGY_LAZY) {
        expected_valid = is_lazy_valid(&p);
        actual_valid = lazy_params_valid(&p);
    } else if (p.strategy == CRUSHLZFSE_STRATEGY_OPTIMAL) {
        expected_valid = is_optimal_valid(&p);
        actual_valid = optimal_params_valid(&p);
    }

    __CPROVER_assert(actual_valid == expected_valid,
                     "params validation matches specification");

    if (actual_valid) {
        size_t s = crushlzfse_scratch_size(&p);
        __CPROVER_assert(s > 0, "valid params have positive scratch size");
    }

    /* 3. Level clamping and valid presets */
    int level = nondet_int();
    crushlzfse_encode_params preset;
    int used = crushlzfse_params_for_level(level, &preset);
    int clamped = level < CRUSHLZFSE_LEVEL_MIN ? CRUSHLZFSE_LEVEL_MIN :
                  level > CRUSHLZFSE_LEVEL_MAX ? CRUSHLZFSE_LEVEL_MAX : level;
    __CPROVER_assert(used == clamped, "level clamped correctly");

    int preset_valid = 0;
    if (preset.strategy == CRUSHLZFSE_STRATEGY_FAST) {
        preset_valid = fast_params_valid(&preset);
    } else if (preset.strategy == CRUSHLZFSE_STRATEGY_LAZY) {
        preset_valid = lazy_params_valid(&preset);
    } else if (preset.strategy == CRUSHLZFSE_STRATEGY_OPTIMAL) {
        preset_valid = optimal_params_valid(&preset);
    }
    __CPROVER_assert(preset_valid == 1,
                     "every preset level produces valid params");
    __CPROVER_assert(crushlzfse_scratch_size(&preset) > 0,
                     "every preset level has positive scratch size");

    /* 4. Capabilities consistency */
    crushlzfse_capabilities caps = crushlzfse_get_capabilities();
    __CPROVER_assert(caps.level_min == CRUSHLZFSE_LEVEL_MIN, "caps level_min matches");
    __CPROVER_assert(caps.level_max == CRUSHLZFSE_LEVEL_MAX, "caps level_max matches");
    __CPROVER_assert(caps.level_default == CRUSHLZFSE_LEVEL_DEFAULT, "caps level_default matches");
    __CPROVER_assert(caps.search_depth_min == 1 && caps.search_depth_max == ZOPT_MAX_SEARCH_DEPTH, "caps search_depth matches");
    __CPROVER_assert(caps.iterations_min == 1 && caps.iterations_max == ZOPT_MAX_ITERATIONS, "caps iterations matches");
    __CPROVER_assert(caps.fast_hash_bits_min == CRUSHLZFSE_FAST_MIN_HASH_BITS, "caps fast_hash_bits_min matches");
    __CPROVER_assert(caps.fast_hash_bits_max == CRUSHLZFSE_FAST_MAX_HASH_BITS, "caps fast_hash_bits_max matches");
    __CPROVER_assert(caps.lazy_hash_bits_min == CRUSHLZFSE_LAZY_MIN_HASH_BITS, "caps lazy_hash_bits_min matches");
    __CPROVER_assert(caps.lazy_hash_bits_max == CRUSHLZFSE_LAZY_MAX_HASH_BITS, "caps lazy_hash_bits_max matches");
    __CPROVER_assert(caps.optimal_hash_bits_min == ZOPT_MIN_HASH_BITS, "caps optimal_hash_bits_min matches");
    __CPROVER_assert(caps.optimal_hash_bits_max == ZOPT_MAX_HASH_BITS, "caps optimal_hash_bits_max matches");

    PROOF_REACHABLE(expected_valid && p.strategy == CRUSHLZFSE_STRATEGY_FAST, "valid fast params");
    PROOF_REACHABLE(expected_valid && p.strategy == CRUSHLZFSE_STRATEGY_LAZY, "valid lazy params");
    PROOF_REACHABLE(expected_valid && p.strategy == CRUSHLZFSE_STRATEGY_OPTIMAL, "valid optimal params");
    PROOF_REACHABLE(!expected_valid, "invalid params rejected");
    PROOF_REACHABLE(level < CRUSHLZFSE_LEVEL_MIN, "underflow level clamped");
    PROOF_REACHABLE(level > CRUSHLZFSE_LEVEL_MAX, "overflow level clamped");
    PROOF_REACHABLE(level >= CRUSHLZFSE_LEVEL_MIN && level <= CRUSHLZFSE_LEVEL_MAX, "in-range level exact");
}
