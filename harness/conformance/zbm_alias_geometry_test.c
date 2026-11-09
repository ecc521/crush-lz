// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Native check of the public decoder's documented disjoint-range geometry.
// Source, destination and out_len occupy one allocation without sharing bytes.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crushlzbitmap.h"

int main(void) {
    // Magic; one uncompressed three-byte chunk; zero-output terminator.
    static const uint8_t stream[] = {
        'Z', 'B', 'M', 0x09,
        9, 0, 0, 3, 0, 0, 'a', 'b', 'c',
        6, 0, 0, 0, 0, 0,
    };
    size_t arena[24] = {0};
    uint8_t *bytes = (uint8_t *)arena;
    uint8_t *dst = bytes + 8 * sizeof(size_t);
    size_t *out_len = &arena[16];
    memcpy(bytes, stream, sizeof stream);
    dst[3] = 0xa5;
    *out_len = SIZE_MAX;

    int rc = crushlzbitmap_decode_buffer(dst, 3, bytes, sizeof stream, out_len);
    if(rc != 0 || *out_len != 3 || memcmp(dst, "abc", 3) != 0 ||
       dst[3] != 0xa5 ||
       memcmp(bytes, stream, sizeof stream) != 0) {
        fprintf(stderr, "disjoint ranges in one allocation: rc=%d len=%zu\n", rc, *out_len);
        return 1;
    }

    // The output-length range also remains writable after an early error.
    bytes[0] = 'X';
    *out_len = SIZE_MAX;
    rc = crushlzbitmap_decode_buffer(dst, 3, bytes, sizeof stream, out_len);
    if(rc != CRUSHLZBITMAP_INVALID || *out_len != 0) {
        fprintf(stderr, "early error in one allocation: rc=%d len=%zu\n", rc, *out_len);
        return 1;
    }
    puts("ok");
    return 0;
}
