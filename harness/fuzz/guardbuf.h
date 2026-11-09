// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/* Page guards protect uninstrumented accesses. ASan poisoning protects the
 * unused writable span for instrumented code. Run each corpus in both
 * default back placement and FUZZ_GUARD_FRONT=1 placement: page granularity
 * cannot put an arbitrary-length buffer flush against both guards at once.
 * ASan cannot represent a poisoned prefix within an otherwise valid shadow
 * granule; back placement may leave up to seven leading bytes accessible.
 * Front placement has an aligned start and catches that remaining gap. */
#ifndef FUZZ_GUARDBUF_H
#define FUZZ_GUARDBUF_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#if defined(__has_feature)
# if __has_feature(address_sanitizer)
#  define FUZZ_ASAN 1
# endif
#endif
#if defined(__SANITIZE_ADDRESS__)
# define FUZZ_ASAN 1
#endif
#ifdef FUZZ_ASAN
#include <sanitizer/asan_interface.h>
#endif
#if defined(__has_feature)
# if __has_feature(memory_sanitizer)
#  define FUZZ_MSAN 1
#  include <sanitizer/msan_interface.h>
# endif
#endif

typedef struct {
    uint8_t *base;
    uint8_t *end;
    size_t span;
} guardbuf_t;

static inline void guardbuf_init(guardbuf_t *g, size_t capacity)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    if (capacity > SIZE_MAX - 3 * page) abort();
    size_t span = ((capacity + page - 1) / page) * page;
    if (!span) span = page;
    uint8_t *mapping = mmap(NULL, span + 2 * page, PROT_NONE,
                            MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED) abort();
    g->base = mapping + page;
    g->end = g->base + span;
    g->span = span;
    if (mprotect(g->base, span, PROT_READ | PROT_WRITE) != 0) abort();
}

/* Selecting a new view invalidates the previous view in this mapping.
 * Scratch callers must keep its naturally aligned front placement. */
static inline uint8_t *guard_view(const guardbuf_t *g, size_t len, int front)
{
    if (len > g->span) abort();
    uint8_t *p = front ? g->base : g->end - len;
#ifdef FUZZ_ASAN
    __asan_poison_memory_region(g->base, g->span);
    __asan_unpoison_memory_region(p, len);
#endif
    return p;
}

static inline uint8_t *guard_dst(const guardbuf_t *g, size_t len)
{
    static int front = -1;
    if (front < 0) {
        const char *value = getenv("FUZZ_GUARD_FRONT");
        front = value && value[0] == '1';
    }
    return guard_view(g, len, front);
}

static inline void guardbuf_destroy(guardbuf_t *g)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
#ifdef FUZZ_ASAN
    __asan_unpoison_memory_region(g->base, g->span);
#endif
    if (munmap(g->base - page, g->span + 2 * page) != 0) abort();
    g->base = g->end = NULL;
    g->span = 0;
}

static inline void guardbuf_selftest(const guardbuf_t *g)
{
    volatile uint8_t *p = g->end;
    *p = 1;
}
#endif
