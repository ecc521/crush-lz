// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#ifndef CRUSHLZ_HARNESS_ORACLE_H
#define CRUSHLZ_HARNESS_ORACLE_H

#include <stddef.h>
#include <stdint.h>

#include "engines.h"

/* Cross-decoder verification: every decoder that understands a format must
 * decode a given stream to the same original bytes. A plain round-trip cannot
 * catch an encoder and decoder agreeing on something the format does not
 * mean; an independently written decoder can. */

typedef struct oracle oracle;

typedef struct {
    int checked;                 /* decoders that ran */
    int agreed;                  /* decoders that reproduced the original */
    const char *first_failure;   /* name of the first disagreeing decoder */
    size_t first_failure_len;    /* length it returned */
} oracle_result;

oracle *oracle_new(size_t max_block);
void    oracle_free(oracle *o);

/* Decode `comp` with every available decoder for `producer`'s format
 * (including `producer`'s own) and require each to reproduce `orig`.
 * Returns 0 when they all agree. */
int oracle_verify(oracle *o, const engine *producer,
                  const uint8_t *orig, size_t olen,
                  const uint8_t *comp, size_t clen,
                  oracle_result *out);

/* How many decoders would run for this format; 1 means only ours. */
size_t oracle_decoder_count(format_id f);

#endif /* CRUSHLZ_HARNESS_ORACLE_H */
