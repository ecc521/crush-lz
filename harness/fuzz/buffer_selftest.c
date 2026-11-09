// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/* Run failing probes as subprocesses; a successful probe is a broken guard. */
#include "fuzzbuf.h"
#include <stdio.h>
int main(int argc, char **argv)
{
    if (argc != 6) return 2;
    size_t len = (size_t)strtoul(argv[3], NULL, 10);
    guardbuf_t g;
    fuzzbuf_t heap = {0};
    volatile uint8_t *p;
    int is_heap = strcmp(argv[1], "heap") == 0;
    if (is_heap) p = fuzz_resize(&heap, len);
    else {
        guardbuf_init(&g, len + 16);
        p = guard_view(&g, len, strcmp(argv[2], "front") == 0);
    }
    if (strcmp(argv[4], "valid") == 0) {
        for (size_t i = 0; i < len; i++) p[i] = (uint8_t)i;
        for (size_t i = 0; i < len; i++) if (p[i] != (uint8_t)i) return 3;
    } else {
        volatile uint8_t *bad = strcmp(argv[4], "under") == 0 ? p - 1 : p + len;
        if (strcmp(argv[5], "read") == 0) {
            volatile uint8_t value = *bad;
            (void)value;
        } else *bad = 42;
    }
    if (is_heap) free(heap.data);
    else guardbuf_destroy(&g);
    return 0;
}
