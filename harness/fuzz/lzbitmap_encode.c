// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Fuzz harness for the LZBITMAP encoder. The fuzzer's bytes are a program
 * that synthesizes periodic content, since random bytes never engage the
 * bitmap mechanism. Our decoder must round-trip the output. On macOS,
 * both encoder outputs must round-trip under both decoders.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzbitmap.h"
#include "guardbuf.h"
#include "apple_oracle.h"
#include "fuzzbuf.h"

#ifdef __APPLE__
#include <compression.h>
#endif

#define SYNTH_MAX (256 * 1024)

static uint8_t synth[SYNTH_MAX];
static uint8_t comp[SYNTH_MAX * 2 + 4096];
static uint8_t chunk_comp[SYNTH_MAX * 2 + 4096];
/* The crush decoder destination is guarded; Apple uses apple_oracle.h. */
static guardbuf_t back_gb;
static uint8_t *back;

/* Interpret `prog` as opcodes building periodic content. op & 7 selects a
 * behaviour; the following bytes are its operands. */
static size_t synthesize(const uint8_t *prog, size_t plen) {
    static const int periods[] = { 1, 2, 3, 4, 8, 12, 16, 24, 32, 40, 48, 64, 96, 390 };
    size_t n = 0;
    size_t i = 0;
    uint8_t seed = 0x5A;

    while (i < plen && n < SYNTH_MAX - 1024) {
        uint8_t op = prog[i++];
        uint8_t a = (i < plen) ? prog[i++] : 0;
        uint8_t b = (i < plen) ? prog[i++] : 0;
        size_t len = 64 + ((size_t)a << 4);
        if (n + len > SYNTH_MAX - 1024) len = SYNTH_MAX - 1024 - n;

        switch (op & 7) {
        case 0: { /* pure period */
            int p = periods[b % (int)(sizeof periods / sizeof periods[0])];
            for (size_t k = 0; k < len; k++, n++) synth[n] = (uint8_t)((k % (size_t)p) * 37u + seed);
            break;
        }
        case 1: { /* period with periodic literal breaks */
            int p = periods[b % (int)(sizeof periods / sizeof periods[0])];
            unsigned cadence = 3u + (a & 15u);
            for (size_t k = 0; k < len; k++, n++) {
                synth[n] = (k % cadence == 0) ? (uint8_t)(seed + k)
                                              : (uint8_t)((k % (size_t)p) * 37u + seed);
            }
            break;
        }
        case 2: /* constant run */
            memset(synth + n, b, len);
            n += len;
            break;
        case 3: /* incompressible */
            for (size_t k = 0; k < len; k++, n++) {
                seed = (uint8_t)(seed * 31u + 17u);
                synth[n] = seed;
            }
            break;
        case 4: { /* slow drift over a period */
            int p = periods[b % (int)(sizeof periods / sizeof periods[0])];
            for (size_t k = 0; k < len; k++, n++)
                synth[n] = (uint8_t)((k % (size_t)p) * 37u + (uint8_t)(k >> 9));
            break;
        }
        case 5: /* zero fill */
            memset(synth + n, 0, len);
            n += len;
            break;
        case 6: { /* two interleaved periods */
            int p = periods[b % (int)(sizeof periods / sizeof periods[0])];
            int q = periods[a % (int)(sizeof periods / sizeof periods[0])];
            for (size_t k = 0; k < len; k++, n++)
                synth[n] = (uint8_t)(((k % (size_t)p) * 37u) ^ ((k % (size_t)q) * 11u));
            break;
        }
        default: { /* lengths near the 0x8000 decompressed-chunk limit */
            size_t target = 0x8000 - 32 + (b % 64);
            if (n + target > SYNTH_MAX - 1024) target = SYNTH_MAX - 1024 - n;
            for (size_t k = 0; k < target; k++, n++) synth[n] = (uint8_t)(k & 0x3F);
            break;
        }
        }
        seed = (uint8_t)(seed + 1u);
    }
    return n;
}

static void run_one(const uint8_t *data, size_t size) {
    if (size < 4) return;

    if (!back) { guardbuf_init(&back_gb, SYNTH_MAX); back = guard_dst(&back_gb, SYNTH_MAX); }

    size_t n = synthesize(data, size);
    if (n == 0) return;

    int level = (int)(data[0] % (unsigned)(CRUSHLZBITMAP_LEVEL_MAX - CRUSHLZBITMAP_LEVEL_MIN + 1))
                + CRUSHLZBITMAP_LEVEL_MIN;

    /* Bit 1 selects custom params. Include table-width boundaries in DP and
     * beam, rather than only the few widths the level presets happen to use. */
    crushlzbitmap_params params;
    crushlzbitmap_params_for_level(level, &params);
    if (data[1] & 2) {
      if (params.strategy == CRUSHLZBITMAP_STRATEGY_FAST) {
        params.p.fast.hash_bits = CRUSHLZBITMAP_MIN_FAST_HASH_BITS +
            (data[2] & 7) % (CRUSHLZBITMAP_MAX_FAST_HASH_BITS - CRUSHLZBITMAP_MIN_FAST_HASH_BITS + 1);
        params.p.fast.windows = 1 << (data[2] >> 3 & 3);
        params.p.fast.dist_cache_size = (data[2] >> 5) % (CRUSHLZBITMAP_MAX_FAST_DIST_CACHE + 1);
        params.p.fast.accept_diff = (data[3] & 7) % (CRUSHLZBITMAP_MAX_FAST_ACCEPT_DIFF + 1);
        params.p.fast.skip_shift = (data[3] >> 3) % (CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT + 1);
      } else {
        static const int widths[] = {1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255};
        crushlzbitmap_row_params *row = params.strategy == CRUSHLZBITMAP_STRATEGY_DP ?
            &params.p.dp.row : params.strategy == CRUSHLZBITMAP_STRATEGY_BEAM ?
            &params.p.beam.row : &params.p.row;
        unsigned log_depth = (data[2] & 7) % 5;
        int max_hash = 18 - (int)log_depth;
        if (max_hash > CRUSHLZBITMAP_MAX_ROW_HASH_BITS) max_hash = CRUSHLZBITMAP_MAX_ROW_HASH_BITS;
        row->hash_bits = CRUSHLZBITMAP_MIN_ROW_HASH_BITS +
            data[3] % (max_hash - CRUSHLZBITMAP_MIN_ROW_HASH_BITS + 1);
        row->depth = 1 << log_depth;
        row->lookahead = params.strategy == CRUSHLZBITMAP_STRATEGY_ROW ? (data[2] >> 3) & 1 : 1;
        row->dist_cache_size = (data[2] >> 4) % (row->lookahead ? 9 : 5);
        row->scan_window = 16 * ((data[3] >> 3) % (row->lookahead ? 17 : 3));
        row->accept_diff = data[0] % 9;
        if (params.strategy == CRUSHLZBITMAP_STRATEGY_DP) {
            params.p.dp.max_candidates = widths[data[2] % (sizeof widths / sizeof widths[0])];
            params.p.dp.iterations = 1 + data[3] % 3;
        } else if (params.strategy == CRUSHLZBITMAP_STRATEGY_BEAM) {
            params.p.beam.max_candidates = widths[data[2] % (sizeof widths / sizeof widths[0])];
            params.p.beam.beam_width = 1 << (data[3] % 7);
        }
        /* Keep wide custom searches affordable while retaining a chunk
         * boundary and a partial final block in the campaign. */
        if (n > CRUSHLZBITMAP_CHUNK_SIZE + 1) n = CRUSHLZBITMAP_CHUNK_SIZE + 1;
      }
    }

    static fuzzbuf_t input_buf, packed_buf, scratch_buf, limited_buf;
    const uint8_t *exact_input = fuzz_copy(&input_buf, synth, n);
    size_t scratch_size = crushlzbitmap_scratch_size(&params);
    void *scratch = NULL;
    if (data[1] & 4) {
        scratch = fuzz_resize(&scratch_buf, scratch_size);
        memset(scratch, data[3], scratch_size);
        fuzz_poison(scratch, scratch_size);
    }
    size_t out = crushlzbitmap_encode_buffer_advanced(comp, sizeof comp, exact_input, n,
                                                     scratch, scratch ? scratch_size : 0, &params);
    if (out == 0) {
        fprintf(stderr, "FUZZ FAILURE: valid encoder params rejected (strategy %d, %zu bytes)\n",
                params.strategy, n);
        abort();
    }
    fuzz_check_written(comp, out);

    /* An exact, short destination exposes writes during failed chunk
     * attempts. A reused caller scratch also checks per-call initialization. */
    size_t cap = (data[2] & 1) ? out - 1 : data[3] % 32;
    uint8_t *limited = fuzz_resize(&limited_buf, cap);
    size_t limited_out = crushlzbitmap_encode_buffer_advanced(limited, cap, exact_input, n,
                                                scratch, scratch ? scratch_size : 0, &params);
    if (limited_out > cap) abort();
    fuzz_check_written(limited, limited_out);
    if (limited_out != 0) {
        size_t got = 0;
        back = guard_dst(&back_gb, n);
        int rc = crushlzbitmap_decode_buffer(back, n, limited, limited_out, &got);
        if (rc || got != n || memcmp(back, exact_input, n)) {
            fprintf(stderr, "FUZZ FAILURE: limited-capacity encoder round-trip mismatch\n");
            abort();
        }
    }

    /* Concatenating crushlzbitmap_encode_chunk's chunks 0..N in index order
     * must give exactly what the whole-buffer encode above produced. */
    if (data[1] & 1) {
        size_t chunk_out = 0;
        size_t index = 0;
        size_t max_index = n / CRUSHLZBITMAP_CHUNK_SIZE + 2; // +1 real, +1 terminator, +1 slack
        for (; index <= max_index; index++) {
            if (chunk_out + CRUSHLZBITMAP_MAX_CHUNK_SIZE > sizeof chunk_comp) {
                fprintf(stderr, "FUZZ FAILURE: chunk API ran past its expected chunk count "
                                "(level %d, %zu bytes, index %zu)\n", level, n, index);
                abort();
            }
            size_t sz = crushlzbitmap_encode_chunk(chunk_comp + chunk_out, CRUSHLZBITMAP_MAX_CHUNK_SIZE,
                                                    exact_input, n, index, scratch,
                                                    scratch ? scratch_size : 0, &params);
            if (sz == 0) {
                fprintf(stderr, "FUZZ FAILURE: encode_chunk failed (level %d, %zu bytes, index %zu)\n",
                        level, n, index);
                abort();
            }
            fuzz_check_written(chunk_comp + chunk_out, sz);
            chunk_out += sz;
            if (index > 0 && sz == CRUSHLZBITMAP_LAST_CHUNK_SIZE) break; // terminating chunk
        }
        if (chunk_out != out || memcmp(chunk_comp, comp, out) != 0) {
            fprintf(stderr, "FUZZ FAILURE: chunk API disagrees with encode_buffer "
                            "(level %d, %zu bytes, chunk_out=%zu out=%zu)\n",
                    level, n, chunk_out, out);
            abort();
        }
    }

    /* Oracle 1: our own decoder round-trips. */
    const uint8_t *exact_packed = fuzz_copy(&packed_buf, comp, out);
    back = guard_dst(&back_gb, n);
    size_t got = 0;
    int drc = crushlzbitmap_decode_buffer(back, n, exact_packed, out, &got);
    fuzz_check_written(back, got);
    if (drc != 0 || got != n ||
        memcmp(back, exact_input, n) != 0) {
        fprintf(stderr, "FUZZ FAILURE: self round-trip mismatch (level %d, %zu bytes)\n", level, n);
        abort();
    }

#ifdef __APPLE__
    apple_oracle(COMPRESSION_LZBITMAP, crushlzbitmap_decode_buffer, exact_input, n, exact_packed, out);
#endif
}

#include "driver.h"
