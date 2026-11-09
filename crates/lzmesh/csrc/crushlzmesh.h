// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

#ifndef CRUSHLZMESH_H
#define CRUSHLZMESH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRUSHLZMESH_LEVEL_MIN (-5)
#define CRUSHLZMESH_LEVEL_MAX 10
#define CRUSHLZMESH_LEVEL_DEFAULT 0

#define CRUSHLZMESH_STATUS_OK 0
#define CRUSHLZMESH_INVALID (-1)
#define CRUSHLZMESH_OUTPUT_TOO_SMALL (-2)

#define CRUSHLZMESH_BLOCK_RAW 0x00
#define CRUSHLZMESH_BLOCK_COMP 0x01
#define CRUSHLZMESH_EOS 0xFF

typedef enum {
    CRUSHLZMESH_STRAT_FAST = 1,
    CRUSHLZMESH_STRAT_LAZY = 2,
    CRUSHLZMESH_STRAT_OPTIMAL = 3,
} crushlzmesh_strategy;

typedef struct {
    crushlzmesh_strategy strategy;
    int hash_bits;
    int min_match;
    int max_depth;
    int lookahead;
    int search_depth;
    int iterations;
} crushlzmesh_params;

size_t crushlzmesh_encode_bound(size_t src_size);
size_t crushlzmesh_encode_scratch_buffer_size(const crushlzmesh_params *params);
size_t crushlzmesh_decode_scratch_buffer_size(void);

int crushlzmesh_params_for_level(int level, crushlzmesh_params *out);

size_t crushlzmesh_encode_buffer(
    uint8_t *dst,
    size_t dst_size,
    const uint8_t *src,
    size_t src_size,
    void *scratch,
    const crushlzmesh_params *params
);

int crushlzmesh_decode_buffer(
    uint8_t *dst,
    size_t dst_size,
    const uint8_t *src,
    size_t src_size,
    size_t *decoded_size
);

#ifdef __cplusplus
}
#endif

#endif /* CRUSHLZMESH_H */
