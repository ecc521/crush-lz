// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * The C side reporting its own ABI, so the Rust mirrors in rust/ffi.rs can
 * be checked against it instead of by eye. What is emitted is what can drift
 * silently: the scalar widths at the boundary, the status codes, the level
 * range, the frame constants, and the layout of the two structs the header
 * declares. A struct added to crushlz4.h needs a size/offset descriptor here
 * in the shape below, or its Rust mirror goes unchecked.
 *
 * Descriptor convention: the callee fills at most min(its own count, n)
 * slots and returns its TRUE count, so the Rust side sees a descriptor
 * that grew as a length mismatch rather than silently comparing a prefix.
 * For layouts, slot 0 is sizeof and the rest are field offsets in
 * declaration order.
 */
#include <stddef.h>
#include "crushlz4.h"

/* Every entry point is built from int, size_t and a pointer. */
size_t clz4_abi_scalars(size_t *out, size_t n);
size_t clz4_abi_scalars(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(int),
        sizeof(size_t),
        sizeof(void *),
        _Alignof(size_t),
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

/* The decoder's status codes, in header declaration order. */
size_t clz4_abi_errors(int *out, size_t n);
size_t clz4_abi_errors(int *out, size_t n)
{
    const int v[] = {
        CRUSHLZ4_INVALID,
        CRUSHLZ4_OUTPUT_TOO_SMALL,
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

void clz4_abi_levels(int *lo, int *hi, int *dflt);
void clz4_abi_levels(int *lo, int *hi, int *dflt)
{
    *lo = CRUSHLZ4_LEVEL_MIN;
    *hi = CRUSHLZ4_LEVEL_MAX;
    *dflt = CRUSHLZ4_LEVEL_DEFAULT;
}

/* Frame and block constants, which the Rust tests assert emitted streams
 * against. */
size_t clz4_abi_format(size_t *out, size_t n);
size_t clz4_abi_format(size_t *out, size_t n)
{
    const size_t v[] = {
        CRUSHLZ4_BLOCK_SIZE,
        CRUSHLZ4_MIN_MATCH,
        CRUSHLZ4_MAX_OFFSET,
        CRUSHLZ4_MAGIC_COMPRESSED,
        CRUSHLZ4_MAGIC_STORED,
        CRUSHLZ4_MAGIC_END,
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

/* crushlz4_encode_params: a caller builds one of these by hand for
 * crushlz4_encode_buffer_advanced, so a desynced mirror misreads every
 * field rather than failing to link. */
size_t clz4_abi_params(size_t *out, size_t n);
size_t clz4_abi_params(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlz4_encode_params),
        offsetof(crushlz4_encode_params, mode),
        offsetof(crushlz4_encode_params, acceleration),
        offsetof(crushlz4_encode_params, hc_level),
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}

/* crushlz4_capabilities: returned by value, so a mirror with the wrong size
 * or field order reads the ranges off the end of the struct. */
size_t clz4_abi_capabilities(size_t *out, size_t n);
size_t clz4_abi_capabilities(size_t *out, size_t n)
{
    const size_t v[] = {
        sizeof(crushlz4_capabilities),
        offsetof(crushlz4_capabilities, level_min),
        offsetof(crushlz4_capabilities, level_max),
        offsetof(crushlz4_capabilities, level_default),
        offsetof(crushlz4_capabilities, mode_min),
        offsetof(crushlz4_capabilities, mode_max),
        offsetof(crushlz4_capabilities, acceleration_min),
        offsetof(crushlz4_capabilities, acceleration_max),
        offsetof(crushlz4_capabilities, hc_level_min),
        offsetof(crushlz4_capabilities, hc_level_max),
    };
    size_t i, cnt = sizeof(v) / sizeof(v[0]);
    for(i = 0; i < cnt && i < n; ++i) out[i] = v[i];
    return cnt;
}
