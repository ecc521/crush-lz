// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#include "oracle.h"

#include <stdlib.h>
#include <string.h>

#define MAX_DECODERS 8

struct oracle {
    uint8_t *scratch;
    size_t   scratch_cap;
    /* One decoder state per registry entry, created on first use. Engines
     * whose state_new is NULL are stateless and stay NULL here. */
    void   **states;
    size_t   nstates;
};

oracle *oracle_new(size_t max_block) {
    size_t n;
    engines_all(&n);

    oracle *o = calloc(1, sizeof(*o));
    if (!o) return NULL;
    o->scratch = malloc(max_block);
    o->states = calloc(n, sizeof(void *));
    if (!o->scratch || !o->states) { oracle_free(o); return NULL; }
    o->scratch_cap = max_block;
    o->nstates = n;
    return o;
}

void oracle_free(oracle *o) {
    if (!o) return;
    size_t n;
    const engine *all = engines_all(&n);
    if (o->states) {
        for (size_t i = 0; i < o->nstates && i < n; i++)
            if (o->states[i] && all[i].state_free) all[i].state_free(o->states[i]);
        free(o->states);
    }
    free(o->scratch);
    free(o);
}

static void *state_for(oracle *o, const engine *e) {
    size_t n;
    const engine *all = engines_all(&n);
    size_t idx = (size_t)(e - all);
    if (idx >= o->nstates) return NULL;
    /* Decode-only, and decoders take no scratch, so the level is immaterial. */
    if (!o->states[idx] && e->state_new) o->states[idx] = e->state_new(e->level_default);
    return o->states[idx];
}

size_t oracle_decoder_count(format_id f) {
    const engine *d[MAX_DECODERS];
    return engines_decoders_for_format(f, d, MAX_DECODERS);
}

int oracle_verify(oracle *o, const engine *producer,
                  const uint8_t *orig, size_t olen,
                  const uint8_t *comp, size_t clen,
                  oracle_result *out) {
    oracle_result r = { 0, 0, NULL, 0 };

    if (olen > o->scratch_cap) {
        r.first_failure = "oracle-scratch-too-small";
        if (out) *out = r;
        return -1;
    }

    const engine *decoders[MAX_DECODERS];
    size_t n = engines_decoders_for_format(producer->format, decoders, MAX_DECODERS);

    for (size_t i = 0; i < n; i++) {
        const engine *d = decoders[i];
        /* Poison the buffer so a decoder that writes nothing and returns a
         * plausible length cannot pass by leaving the previous result behind. */
        memset(o->scratch, 0xA5, olen);

        size_t got = d->decode(state_for(o, d), o->scratch, olen, comp, clen);
        r.checked++;
        if (got == olen && memcmp(o->scratch, orig, olen) == 0) {
            r.agreed++;
        } else if (!r.first_failure) {
            r.first_failure = d->name;
            r.first_failure_len = got;
        }
    }

    if (out) *out = r;
    return (r.checked > 0 && r.agreed == r.checked) ? 0 : -1;
}
