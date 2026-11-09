// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * The C side reporting its own ABI, so the Rust mirrors in rust/ffi.rs can
 * be checked against it instead of by eye. A misordered field, a missing
 * one, or an undersized union is memory-unsafe and never a compile error,
 * so sizes, field offsets and constants are emitted here and a test asserts
 * on them.
 *
 * Descriptor convention: the callee fills at most min(its own count, n)
 * slots and returns its TRUE count, so the Rust side sees a descriptor
 * that grew as a length mismatch rather than silently comparing a prefix.
 * For layouts, slot 0 is sizeof and the rest are field offsets in
 * declaration order.
 */
#include <stddef.h>
#include "crushlzbitmap.h"

size_t zbm_abi_beam(size_t *out, size_t n);
size_t zbm_abi_beam(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlzbitmap_beam_params),
        offsetof(crushlzbitmap_beam_params, row),
        offsetof(crushlzbitmap_beam_params, max_candidates),
        offsetof(crushlzbitmap_beam_params, beam_width),
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

size_t zbm_abi_dp(size_t *out, size_t n);
size_t zbm_abi_dp(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlzbitmap_dp_params),
        offsetof(crushlzbitmap_dp_params, row),
        offsetof(crushlzbitmap_dp_params, max_candidates),
        offsetof(crushlzbitmap_dp_params, iterations),
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

size_t zbm_abi_row(size_t *out, size_t n);
size_t zbm_abi_row(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlzbitmap_row_params),
        offsetof(crushlzbitmap_row_params, hash_bits),
        offsetof(crushlzbitmap_row_params, depth),
        offsetof(crushlzbitmap_row_params, dist_cache_size),
        offsetof(crushlzbitmap_row_params, accept_diff),
        offsetof(crushlzbitmap_row_params, scan_window),
        offsetof(crushlzbitmap_row_params, lookahead),
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

size_t zbm_abi_fast(size_t *out, size_t n);
size_t zbm_abi_fast(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlzbitmap_fast_params),
        offsetof(crushlzbitmap_fast_params, hash_bits),
        offsetof(crushlzbitmap_fast_params, windows),
        offsetof(crushlzbitmap_fast_params, dist_cache_size),
        offsetof(crushlzbitmap_fast_params, accept_diff),
        offsetof(crushlzbitmap_fast_params, skip_shift),
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

/* The outer struct: its size, the offsets of its two members, the size of
 * the union itself, then the size of every union arm. */
size_t zbm_abi_params(size_t *out, size_t n);
size_t zbm_abi_params(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlzbitmap_params),
        offsetof(crushlzbitmap_params, strategy),
        offsetof(crushlzbitmap_params, p),
        sizeof(((crushlzbitmap_params *)0)->p),
        sizeof(crushlzbitmap_dp_params),
        sizeof(crushlzbitmap_row_params),
        sizeof(crushlzbitmap_fast_params),
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

void zbm_abi_levels(int *lo, int *hi, int *dflt);
void zbm_abi_levels(int *lo, int *hi, int *dflt)
{
    *lo = CRUSHLZBITMAP_LEVEL_MIN;
    *hi = CRUSHLZBITMAP_LEVEL_MAX;
    *dflt = CRUSHLZBITMAP_LEVEL_DEFAULT;
}

/* Status codes, chunk sizes, strategy tags and the params bounds, in
 * header declaration order. */
size_t zbm_abi_constants(int *out, size_t n);
size_t zbm_abi_constants(int *out, size_t n)
{
    const int v[] = {
        CRUSHLZBITMAP_INVALID,
        CRUSHLZBITMAP_OUTPUT_TOO_SMALL,
        CRUSHLZBITMAP_CHUNK_SIZE,
        CRUSHLZBITMAP_MAX_CHUNK_SIZE,
        CRUSHLZBITMAP_LAST_CHUNK_SIZE,
        CRUSHLZBITMAP_STRATEGY_BEAM,
        CRUSHLZBITMAP_MAX_BEAM_WIDTH,
        CRUSHLZBITMAP_STRATEGY_DP,
        CRUSHLZBITMAP_STRATEGY_ROW,
        CRUSHLZBITMAP_STRATEGY_FAST,
        CRUSHLZBITMAP_MAX_ITERATIONS,
        CRUSHLZBITMAP_MAX_DP_CANDS,
        CRUSHLZBITMAP_MIN_ROW_HASH_BITS,
        CRUSHLZBITMAP_MAX_ROW_HASH_BITS,
        CRUSHLZBITMAP_MAX_ROW_DEPTH,
        CRUSHLZBITMAP_MAX_ROW_SCAN,
        CRUSHLZBITMAP_MIN_FAST_HASH_BITS,
        CRUSHLZBITMAP_MAX_FAST_HASH_BITS,
        CRUSHLZBITMAP_MAX_FAST_WINDOWS,
        CRUSHLZBITMAP_MAX_FAST_DIST_CACHE,
        CRUSHLZBITMAP_MAX_FAST_ACCEPT_DIFF,
        CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT,
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

/* crushlzbitmap_capabilities: returned by value, so a mirror with the wrong
 * size or field order reads the ranges off the end of the struct. */
size_t zbm_abi_capabilities(size_t *out, size_t n);
size_t zbm_abi_capabilities(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlzbitmap_capabilities),
        offsetof(crushlzbitmap_capabilities, level_min),
        offsetof(crushlzbitmap_capabilities, level_max),
        offsetof(crushlzbitmap_capabilities, level_default),
        offsetof(crushlzbitmap_capabilities, row_hash_bits_min),
        offsetof(crushlzbitmap_capabilities, row_hash_bits_max),
        offsetof(crushlzbitmap_capabilities, row_depth_min),
        offsetof(crushlzbitmap_capabilities, row_depth_max),
        offsetof(crushlzbitmap_capabilities, row_lookahead_min),
        offsetof(crushlzbitmap_capabilities, row_lookahead_max),
        offsetof(crushlzbitmap_capabilities, row_dist_cache_size_min),
        offsetof(crushlzbitmap_capabilities, row_dist_cache_size_max),
        offsetof(crushlzbitmap_capabilities, row_scan_window_min),
        offsetof(crushlzbitmap_capabilities, row_scan_window_max),
        offsetof(crushlzbitmap_capabilities, row_accept_diff_min),
        offsetof(crushlzbitmap_capabilities, row_accept_diff_max),
        offsetof(crushlzbitmap_capabilities, dp_max_candidates_min),
        offsetof(crushlzbitmap_capabilities, dp_max_candidates_max),
        offsetof(crushlzbitmap_capabilities, dp_iterations_min),
        offsetof(crushlzbitmap_capabilities, dp_iterations_max),
        offsetof(crushlzbitmap_capabilities, beam_width_min),
        offsetof(crushlzbitmap_capabilities, beam_width_max),
        offsetof(crushlzbitmap_capabilities, fast_hash_bits_min),
        offsetof(crushlzbitmap_capabilities, fast_hash_bits_max),
        offsetof(crushlzbitmap_capabilities, fast_windows_min),
        offsetof(crushlzbitmap_capabilities, fast_windows_max),
        offsetof(crushlzbitmap_capabilities, fast_dist_cache_size_min),
        offsetof(crushlzbitmap_capabilities, fast_dist_cache_size_max),
        offsetof(crushlzbitmap_capabilities, fast_accept_diff_min),
        offsetof(crushlzbitmap_capabilities, fast_accept_diff_max),
        offsetof(crushlzbitmap_capabilities, fast_skip_shift_min),
        offsetof(crushlzbitmap_capabilities, fast_skip_shift_max),
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}
