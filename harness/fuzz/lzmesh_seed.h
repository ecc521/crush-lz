// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#ifndef FUZZ_LZMESH_SEED_H
#define FUZZ_LZMESH_SEED_H

/*
 * Real LZMESH streams for the decoder harnesses to damage. data[1..7] pick
 * the content and level: mixes of a small alphabet, repeats at near and far
 * distances, and noise, so that streams carry Huffman lanes, RLE and raw
 * streams, far-distance bits, raw blocks, and (above about 100 KB of
 * literals) several compressed blocks chained by their rep distances.
 */
#include <stdint.h>
#include <string.h>
#include "crushlzmesh.h"

static size_t lzmesh_seed_stream(const uint8_t *data, size_t size, uint8_t *out, size_t cap)
{
    static uint8_t seed[192 * 1024];
    if (size < 8) return 0;
    size_t n = ((size_t)data[1] << 8 | data[2]) % 4096 + 1;
    if (data[3] & 1) n *= 1 + data[3] % 48;
    if (n > sizeof seed) n = sizeof seed;
    unsigned alphabet = 2 + data[4] % 64, noise = data[5] % 8;
    uint32_t x = 0x9E3779B9u ^ data[6];
    for (size_t i = 0; i < n; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        unsigned pick = x >> 28;
        if (i > 64 && pick < 6) {
            // Copy from near (rep-friendly) or far back.
            size_t d = pick < 4 ? 1 + (x & 15) * (1 + data[7] % 8) : 1 + (x >> 4) % i;
            seed[i] = seed[i - (d > i ? i : d)];
        } else if (pick < 6 + noise) {
            seed[i] = (uint8_t)x;
        } else {
            seed[i] = (uint8_t)('a' + (x >> 8) % alphabet);
        }
    }
    crushlzmesh_params prm;
    int level = (int)(data[7] >> 4) % 11;
    if (level > 5 && n > 32 * 1024) level = 5;
    crushlzmesh_params_for_level(level, &prm);
    if (crushlzmesh_encode_bound(n) > cap) return 0;
    return crushlzmesh_encode_buffer(out, cap, seed, n, NULL, &prm);
}

#endif
