// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * The C side reporting its own ABI, so the mirrors in rust/ffi.rs can be
 * checked against it rather than by eye. A tag+union params struct that
 * drifts out of sync with its Rust mirror is memory-unsafe, not a compile
 * error: an undersized union lets the library write past caller storage,
 * and a field in the wrong position makes every field after it read as
 * garbage.
 *
 * Each size_t descriptor puts sizeof in slot 0 and then every field offset
 * in declaration order, so a reorder, an insertion and a truncation are all
 * visible. The int descriptors list the header's constants.
 */
#include <stddef.h>
#include "crushlzfse.h"
#include "crushlzvn.h"

#define REPORT(v)                                             \
    do {                                                      \
        size_t i, cnt = sizeof(v) / sizeof((v)[0]);           \
        for (i = 0; i < cnt && i < n; ++i) out[i] = (v)[i];   \
        return cnt;                                           \
    } while (0)

/* --- LZFSE ----------------------------------------------------------- */

size_t crushlzfse_abi_params(size_t *out, size_t n);
size_t crushlzfse_abi_params(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlzfse_encode_params),
        offsetof(crushlzfse_encode_params, strategy),
        offsetof(crushlzfse_encode_params, p),
        sizeof(((crushlzfse_encode_params *)0)->p),        /* the union */
        sizeof(((crushlzfse_encode_params *)0)->p.lazy),
        sizeof(((crushlzfse_encode_params *)0)->p.optimal),
        sizeof(((crushlzfse_encode_params *)0)->p.fast),
    };
    REPORT(v);
}

size_t crushlzfse_abi_lazy(size_t *out, size_t n);
size_t crushlzfse_abi_lazy(size_t *out, size_t n)
{
#define OFF(f) (offsetof(crushlzfse_encode_params, p.lazy.f) - offsetof(crushlzfse_encode_params, p.lazy))
    const size_t v[] = {
        sizeof(((crushlzfse_encode_params *)0)->p.lazy),
        OFF(hash_bits), OFF(hash_width), OFF(lookahead),
    };
#undef OFF
    REPORT(v);
}

size_t crushlzfse_abi_optimal(size_t *out, size_t n);
size_t crushlzfse_abi_optimal(size_t *out, size_t n)
{
#define OFF(f) (offsetof(crushlzfse_encode_params, p.optimal.f) - offsetof(crushlzfse_encode_params, p.optimal))
    const size_t v[] = {
        sizeof(((crushlzfse_encode_params *)0)->p.optimal),
        OFF(search_depth), OFF(iterations), OFF(enable_reparse),
        OFF(split_max_blocks), OFF(hash_bits), OFF(store_limit), OFF(tuple_tax),
        OFF(max_live_buckets), OFF(table_search),
    };
#undef OFF
    REPORT(v);
}

size_t crushlzfse_abi_fast(size_t *out, size_t n);
size_t crushlzfse_abi_fast(size_t *out, size_t n)
{
#define OFF(f) (offsetof(crushlzfse_encode_params, p.fast.f) - offsetof(crushlzfse_encode_params, p.fast))
    const size_t v[] = {
        sizeof(((crushlzfse_encode_params *)0)->p.fast),
        OFF(hash_bits), OFF(min_match), OFF(skip_shift), OFF(max_step),
        OFF(long_table), OFF(lazy),
    };
#undef OFF
    REPORT(v);
}

size_t crushlzfse_abi_caps(size_t *out, size_t n);
size_t crushlzfse_abi_caps(size_t *out, size_t n)
{
#define OFF(f) offsetof(crushlzfse_capabilities, f)
    const size_t v[] = {
        sizeof(crushlzfse_capabilities),
        OFF(level_min), OFF(level_max), OFF(level_default),
        OFF(search_depth_min), OFF(search_depth_max),
        OFF(iterations_min), OFF(iterations_max),
        OFF(enable_reparse_min), OFF(enable_reparse_max),
        OFF(split_max_blocks_min), OFF(split_max_blocks_max),
        OFF(optimal_hash_bits_min), OFF(optimal_hash_bits_max),
        OFF(store_limit_min), OFF(store_limit_max),
        OFF(tuple_tax_min), OFF(tuple_tax_max),
        OFF(max_live_buckets_min), OFF(max_live_buckets_max),
        OFF(table_search_min), OFF(table_search_max),
        OFF(lazy_hash_bits_min), OFF(lazy_hash_bits_max),
        OFF(lazy_hash_width_min), OFF(lazy_hash_width_max),
        OFF(lazy_lookahead_min), OFF(lazy_lookahead_max),
        OFF(fast_hash_bits_min), OFF(fast_hash_bits_max),
        OFF(fast_min_match_min), OFF(fast_min_match_max),
        OFF(fast_skip_shift_min), OFF(fast_skip_shift_max),
        OFF(fast_max_step_min), OFF(fast_max_step_max),
        OFF(fast_long_table_min), OFF(fast_long_table_max),
        OFF(fast_lazy_min), OFF(fast_lazy_max),
    };
#undef OFF
    REPORT(v);
}

/* sizeof, the offset of opaque, then CRUSHLZFSE_STATS_WORDS. */
size_t crushlzfse_abi_stats(size_t *out, size_t n);
size_t crushlzfse_abi_stats(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlzfse_stats),
        offsetof(crushlzfse_stats, opaque),
        CRUSHLZFSE_STATS_WORDS,
    };
    REPORT(v);
}

size_t crushlzfse_abi_consts(int *out, size_t n);
size_t crushlzfse_abi_consts(int *out, size_t n)
{
    const int v[] = {
        CRUSHLZFSE_LEVEL_MIN,
        CRUSHLZFSE_LEVEL_MAX,
        CRUSHLZFSE_LEVEL_DEFAULT,
        CRUSHLZFSE_STRATEGY_LAZY,
        CRUSHLZFSE_STRATEGY_OPTIMAL,
        CRUSHLZFSE_STRATEGY_FAST,
        CRUSHLZFSE_INVALID,
        CRUSHLZFSE_OUTPUT_TOO_SMALL,
    };
    REPORT(v);
}

/* --- LZVN ------------------------------------------------------------ */

size_t crushlzvn_abi_params(size_t *out, size_t n);
size_t crushlzvn_abi_params(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlzvn_encode_params),
        offsetof(crushlzvn_encode_params, strategy),
        offsetof(crushlzvn_encode_params, p),
        sizeof(((crushlzvn_encode_params *)0)->p),        /* the union */
        sizeof(((crushlzvn_encode_params *)0)->p.greedy),
        sizeof(((crushlzvn_encode_params *)0)->p.optimal),
        sizeof(((crushlzvn_encode_params *)0)->p.fast),
    };
    REPORT(v);
}

size_t crushlzvn_abi_fast(size_t *out, size_t n);
size_t crushlzvn_abi_fast(size_t *out, size_t n)
{
#define OFF(f) (offsetof(crushlzvn_encode_params, p.fast.f) - offsetof(crushlzvn_encode_params, p.fast))
    const size_t v[] = {
        sizeof(((crushlzvn_encode_params *)0)->p.fast),
        OFF(hash_bits), OFF(min_match), OFF(skip_shift), OFF(max_step), OFF(long_table), OFF(lazy),
    };
#undef OFF
    REPORT(v);
}

size_t crushlzvn_abi_greedy(size_t *out, size_t n);
size_t crushlzvn_abi_greedy(size_t *out, size_t n)
{
#define OFF(f) (offsetof(crushlzvn_encode_params, p.greedy.f) - offsetof(crushlzvn_encode_params, p.greedy))
    const size_t v[] = {
        sizeof(((crushlzvn_encode_params *)0)->p.greedy),
        OFF(hash_bits), OFF(hash_width),
    };
#undef OFF
    REPORT(v);
}

size_t crushlzvn_abi_optimal(size_t *out, size_t n);
size_t crushlzvn_abi_optimal(size_t *out, size_t n)
{
#define OFF(f) (offsetof(crushlzvn_encode_params, p.optimal.f) - offsetof(crushlzvn_encode_params, p.optimal))
    const size_t v[] = {
        sizeof(((crushlzvn_encode_params *)0)->p.optimal),
        OFF(search_depth), OFF(store_limit), OFF(hash_bits), OFF(pareto_k),
    };
#undef OFF
    REPORT(v);
}

size_t crushlzvn_abi_caps(size_t *out, size_t n);
size_t crushlzvn_abi_caps(size_t *out, size_t n)
{
#define OFF(f) offsetof(crushlzvn_capabilities, f)
    const size_t v[] = {
        sizeof(crushlzvn_capabilities),
        OFF(level_min), OFF(level_max), OFF(level_default),
        OFF(greedy_hash_bits_min), OFF(greedy_hash_bits_max),
        OFF(greedy_hash_width_min), OFF(greedy_hash_width_max),
        OFF(search_depth_min), OFF(search_depth_max),
        OFF(store_limit_min), OFF(store_limit_max),
        OFF(hash_bits_min), OFF(hash_bits_max),
        OFF(pareto_k_min), OFF(pareto_k_max),
        OFF(fast_hash_bits_min), OFF(fast_hash_bits_max),
        OFF(fast_min_match_min), OFF(fast_min_match_max),
        OFF(fast_skip_shift_min), OFF(fast_skip_shift_max),
        OFF(fast_max_step_min), OFF(fast_max_step_max),
        OFF(fast_long_table_min), OFF(fast_long_table_max),
        OFF(fast_lazy_min), OFF(fast_lazy_max),
    };
#undef OFF
    REPORT(v);
}

size_t crushlzvn_abi_consts(int *out, size_t n);
size_t crushlzvn_abi_consts(int *out, size_t n)
{
    const int v[] = {
        CRUSHLZVN_LEVEL_MIN,
        CRUSHLZVN_LEVEL_MAX,
        CRUSHLZVN_LEVEL_DEFAULT,
        CRUSHLZVN_STRATEGY_GREEDY,
        CRUSHLZVN_STRATEGY_OPTIMAL,
        CRUSHLZVN_STRATEGY_FAST,
        CRUSHLZVN_INVALID,
        CRUSHLZVN_OUTPUT_TOO_SMALL,
    };
    REPORT(v);
}
