// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test: crushlzbitmap_decode_buffer() only wrote *out_len on
// success, leaving it untouched on every error path. A C caller whose local
// is uninitialized (or left over from a previous call) sees garbage rather
// than 0 after a reported failure. Fixed by zeroing *out_len up front.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crushlzbitmap.h"

int main(void) {
    int failures = 0;

    // Bad magic: the very first check in the decode path, guaranteed to
    // fail before anything else runs.
    uint8_t stream[8] = {'X', 'X', 'X', 'X', 0, 0, 0, 0};
    uint8_t dst[16];

    size_t out_len = 0xDEADBEEFu; // poison, as an uninitialized local might read
    int rc = crushlzbitmap_decode_buffer(dst, sizeof dst, stream, sizeof stream, &out_len);

    printf("decode of malformed stream: rc=%d out_len=%zu\n", rc, out_len);
    if (rc == 0) {
        printf("FAIL: malformed stream was accepted\n");
        failures++;
    }
    if (out_len != 0) {
        printf("FAIL: out_len left at %zu on error, expected 0\n", out_len);
        failures++;
    }

    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
