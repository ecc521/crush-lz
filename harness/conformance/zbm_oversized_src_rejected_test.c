// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test for an out-of-bounds read past a >4 GiB source buffer.
// The encoder's row-hash windowing packs a source position into a
// uint32_t (state->preread + read, cast down); for a call whose position
// tracking would exceed UINT32_MAX, that wraps to a small value, and the
// bound check it feeds (nbuf, guarding a 16-byte vector load) stops
// binding: the vector loop then reads past the caller's real buffer.
//
// Fixed by rejecting any call whose src_size exceeds
// CRUSHLZBITMAP_MAX_SRC_SIZE outright, before any of that arithmetic runs,
// rather than widening the position tracking to be sound at arbitrary
// scale: nothing legitimate needs more than a few tens of KiB (a macOS
// resource fork's uncompressed size cannot exceed 4 GiB in the first
// place, and decmpfs stores files as independent 32 KiB chunks regardless).
//
// This test cannot allocate a real >4 GiB buffer, and does not need to:
// the fix rejects on src_size alone, before ever touching src, so a tiny
// real buffer with an inflated claimed size exercises the same check a
// real oversized buffer would hit. If this regresses to reading src, ASan
// catches the corresponding heap-buffer-overflow directly.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzbitmap.h"

int main(void) {
    int failures = 0;

    uint8_t tiny_src[16];
    memset(tiny_src, 0x42, sizeof tiny_src);
    uint8_t dst[1024];

    size_t n = crushlzbitmap_encode_buffer(dst, sizeof dst, tiny_src,
                                           CRUSHLZBITMAP_MAX_SRC_SIZE + 1,
                                           NULL, 0, CRUSHLZBITMAP_LEVEL_DEFAULT);
    if (n != 0) {
        printf("FAIL: encode_buffer accepted src_size past CRUSHLZBITMAP_MAX_SRC_SIZE\n");
        failures++;
    }

    n = crushlzbitmap_encode_buffer_advanced(dst, sizeof dst, tiny_src,
                                             CRUSHLZBITMAP_MAX_SRC_SIZE + 1,
                                             NULL, 0, NULL);
    if (n != 0) {
        printf("FAIL: encode_buffer_advanced (NULL params) accepted an oversized src_size\n");
        failures++;
    }

    // The chunk API's src_size means the same thing (the whole logical
    // buffer, not just the one chunk being emitted), so it needs the same
    // guard: at a large index, the existing shift-overflow check does not
    // catch this (it guards size_t-scale overflow, far past where
    // uint32_t position tracking already wrapped).
    n = crushlzbitmap_encode_chunk(dst, sizeof dst, tiny_src,
                                   CRUSHLZBITMAP_MAX_SRC_SIZE + 1, 1000,
                                   NULL, 0, CRUSHLZBITMAP_LEVEL_DEFAULT);
    if (n != 0) {
        printf("FAIL: encode_chunk accepted an oversized src_size\n");
        failures++;
    }

    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
