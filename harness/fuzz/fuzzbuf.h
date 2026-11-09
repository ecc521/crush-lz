// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#ifndef FUZZ_BUFFER_H
#define FUZZ_BUFFER_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "guardbuf.h"

/* Exact heap allocations expose both source bounds to ASan, including
 * non-aligned starts that page-backed back placement cannot fully poison.
 * Each slot owns one allocation and replaces it on the next call. */
typedef struct { uint8_t *data; } fuzzbuf_t;
static inline uint8_t *fuzz_resize(fuzzbuf_t *b, size_t n)
{
    free(b->data);
    b->data = malloc(n ? n : 1);
    if (!b->data) abort();
#ifdef FUZZ_ASAN
    if (!n) __asan_poison_memory_region(b->data, 1);
#endif
    return b->data;
}
/* MSan: the n bytes a call reports as written must be initialized; bytes
 * past them may stay uninitialized. */
static inline void fuzz_check_written(const void *p, size_t n)
{
#ifdef FUZZ_MSAN
    if (n) __msan_check_mem_is_initialized(p, n);
#else
    (void)p; (void)n;
#endif
}
/* MSan: treat reused memory as uninitialized again, so a call that reads
 * what an earlier call left there is reported. */
static inline void fuzz_poison(void *p, size_t n)
{
#ifdef FUZZ_MSAN
    if (n) __msan_poison(p, n);
#else
    (void)p; (void)n;
#endif
}
static inline uint8_t *fuzz_copy(fuzzbuf_t *b, const void *src, size_t n)
{
    uint8_t *p = fuzz_resize(b, n);
    if (n) memcpy(p, src, n);
    return p;
}
#endif
