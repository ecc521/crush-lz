// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/* Deliberately invalid accesses, each run in a disposable subprocess. */
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "undefined")) {
        volatile int a = INT_MAX, b = 1;
        volatile int result = a + b;
        (void)result;
        return 0;
    }
    if (!strcmp(argv[1], "uninitialized")) {
        volatile int *p = malloc(sizeof(*p));
        if (!p) return 2;
        if (*p) puts("uninitialized value was consumed");
        free((void *)p);
        return 0;
    }
    volatile uint8_t *p = malloc(64);
    if (!p) return 2;
    p[0] = 42;
    if (!strcmp(argv[1], "overflow")) p[64] = 43;
    else if (!strcmp(argv[1], "freed")) {
        free((void *)p);
        p[0] = 44;
        return 0;
    } else if (!strcmp(argv[1], "tag")) {
        /* ARM MTE's allocation tag occupies bits 59..56. Flip one tag bit
         * while retaining the allocation's address for a guaranteed mismatch. */
        volatile uint8_t *bad = (uint8_t *)((uintptr_t)p ^ (UINT64_C(1) << 56));
        *bad = 44;
    } else if (strcmp(argv[1], "valid")) return 2;
    free((void *)p);
    return 0;
}
