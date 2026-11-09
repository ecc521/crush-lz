// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Differential fuzz harness: our LZFSE and raw LZVN decoders against
 * Apple's, on the same bytes. compression.h has no COMPRESSION_LZVN;
 * raw LZVN has no documented public algorithm ID, but Apple's dispatcher
 * accepts 0x900 for it undocumented; confirmed empirically (round-tripped
 * real crushlzvn output through compression_decode_buffer with algorithm
 * 0x900 and it matched byte for byte) before relying on it here. Where
 * both succeed, lengths and bytes must match (contract 1); where only one
 * succeeds, that is reported (contracts 2 and 3), non-fatal by default
 * since a permissive/strict split between implementations on malformed
 * input is not by itself a bug; see lzbitmap_decode_diff_vs_apple.c,
 * which established this pattern first.
 *
 * A quarter of the budget builds a hostile V1-format block: V1 is a wire
 * format both decoders must accept but that no encoder here (ours or
 * Apple's) ever emits, so it otherwise gets zero coverage from real-stream
 * seeds, which are always V2. See build_hostile_v1_stream() in
 * crushlzfse_decode.c for the fuller rationale; this is a leaner
 * standalone copy; keeping it self-contained here matches how
 * lzbitmap_decode_diff_vs_apple.c and lz4_decode_diff_vs_apple.c each
 * carry their own generators rather than sharing one across drivers.
 *
 * macOS only; elsewhere this compiles to a harness that does nothing.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzfse.h"
#include "crushlzvn.h"
#include "guardbuf.h"
#include "fuzzbuf.h"
#include "lzfse.h"
#include "lzfse_internal.h"

#if defined(__APPLE__)
#include <compression.h>
#define HAVE_APPLE_DECODER 1
#else
#define HAVE_APPLE_DECODER 0
#endif

#define MAX_IN  (256 * 1024)
#define MAX_OUT (4 * 1024 * 1024)

static uint8_t stream[MAX_IN];
static uint8_t out_ours[MAX_OUT];
static uint8_t seed_data[64 * 1024];
/* Apple's destination is guarded; see guardbuf.h. */
static guardbuf_t apple_gb;
static uint8_t *out_apple;

#if HAVE_APPLE_DECODER

static unsigned long long ours_only_hits, apple_only_hits;

/* Damage a valid stream by byte flips, truncation, both, or extension. */
static size_t damage(size_t len, const uint8_t *prog, size_t plen) {
    if (len == 0 || plen < 8) return len;
    switch ((prog[0] >> 3) & 3) {
    case 0:
        for (size_t i = 4; i + 1 < plen && i < 64; i += 2)
            stream[((size_t)prog[i] << 8 | prog[i + 1]) % len] ^= prog[(i + 1) % plen];
        break;
    case 1:
        len = 1 + (((size_t)prog[4] << 8 | prog[5]) % len);
        break;
    case 2:
        len = 1 + (((size_t)prog[4] << 8 | prog[5]) % len);
        for (size_t i = 6; i + 1 < plen && i < 64; i += 2)
            stream[((size_t)prog[i] << 8 | prog[i + 1]) % len] ^= prog[(i + 1) % plen];
        break;
    default:
        for (size_t i = 4; i < plen && i < 40 && len < MAX_IN; i++)
            stream[len++] = prog[i];
        break;
    }
    return len;
}

static size_t damage_valid_lzfse_stream(const uint8_t *prog, size_t plen) {
    if (plen < 4) return 0;
    unsigned period = 1u + (prog[1] % 64u);
    size_t n = 512 + ((size_t)prog[2] << 6);
    if (n > sizeof seed_data) n = sizeof seed_data;
    for (size_t i = 0; i < n; i++) seed_data[i] = (uint8_t)((i % period) * 37u);
    static const int LEVEL_MIX[16] = {-5, -4, -3, -2, -1, 0, 0, 1, 1, 2, 3, 4, 5, 6, 8, 99};
    size_t len = crushlzfse_encode_buffer(stream, sizeof stream, seed_data, n, NULL, 0, LEVEL_MIX[prog[3] & 15]);
    if (len == 0) return 0;
    return damage(len, prog, plen);
}

static size_t damage_valid_lzvn_stream(const uint8_t *prog, size_t plen) {
    if (plen < 4) return 0;
    unsigned period = 1u + (prog[1] % 64u);
    size_t n = 512 + ((size_t)prog[2] << 6);
    if (n > sizeof seed_data) n = sizeof seed_data;
    for (size_t i = 0; i < n; i++) seed_data[i] = (uint8_t)((i % period) * 37u);
    static const int LEVEL_MIX[16] = {-2, -1, -1, 0, 0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 8, 99};
    size_t len = crushlzvn_encode_buffer(stream, sizeof stream, seed_data, n, NULL, 0, LEVEL_MIX[prog[3] & 15]);
    if (len == 0) return 0;
    return damage(len, prog, plen);
}

/* See the file comment: a structurally-plausible V1 header with fuzzer-
 * driven fields, since real encoder output is never V1 and random bytes
 * essentially never pass lzfse_check_block_header_v1(). */
static size_t build_hostile_v1_stream(const uint8_t *prog, size_t plen) {
    if (plen < 24) return 0;

    lzfse_compressed_block_header_v1 h;
    memset(&h, 0, sizeof h);
    h.magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
    h.n_literals = (uint32_t)(((size_t)prog[0] << 8 | prog[1]) % (LZFSE_LITERALS_PER_BLOCK + 8));
    h.n_matches = (uint32_t)(((size_t)prog[2] << 8 | prog[3]) % (LZFSE_MATCHES_PER_BLOCK + 8));
    h.n_literal_payload_bytes = (uint32_t)(((size_t)prog[4] << 8 | prog[5]) % (sizeof seed_data));
    h.n_lmd_payload_bytes = (uint32_t)(((size_t)prog[6] << 8 | prog[7]) % (sizeof seed_data));
    h.n_payload_bytes = h.n_literal_payload_bytes + h.n_lmd_payload_bytes;
    h.literal_bits = (int32_t)((int8_t)prog[8]) % 12 - 4;
    h.lmd_bits = (int32_t)((int8_t)prog[9]) % 12 - 4;
    if ((prog[10] & 7) == 0) h.literal_bits = (int32_t)(prog[11] | (uint32_t)prog[12] << 8 | (uint32_t)prog[13] << 16 | (uint32_t)prog[14] << 24);
    if ((prog[10] & 7) == 1) h.lmd_bits = (int32_t)(prog[11] | (uint32_t)prog[12] << 8 | (uint32_t)prog[13] << 16 | (uint32_t)prog[14] << 24);

    uint16_t lit_state[4];
    for (int i = 0; i < 4; i++) lit_state[i] = (uint16_t)(prog[15 + i] * 4u % (LZFSE_ENCODE_LITERAL_STATES + 4));
    memcpy(h.literal_state, lit_state, sizeof lit_state);
    h.l_state = (uint16_t)(prog[19] % (LZFSE_ENCODE_L_STATES + 2));
    h.m_state = (uint16_t)(prog[20] % (LZFSE_ENCODE_M_STATES + 2));
    h.d_state = (uint16_t)(prog[21] % (LZFSE_ENCODE_D_STATES + 2));

    h.literal_freq[prog[22] % LZFSE_ENCODE_LITERAL_SYMBOLS] = LZFSE_ENCODE_LITERAL_STATES;
    h.l_freq[prog[23] % LZFSE_ENCODE_L_SYMBOLS] = LZFSE_ENCODE_L_STATES;
    h.m_freq[prog[23] % LZFSE_ENCODE_M_SYMBOLS] = LZFSE_ENCODE_M_STATES;
    h.d_freq[prog[23] % LZFSE_ENCODE_D_SYMBOLS] = LZFSE_ENCODE_D_STATES;

    size_t payload = h.n_payload_bytes;
    if (4 + sizeof h + payload + 4 > MAX_IN) return 0;

    size_t pos = 0;
    memcpy(stream + pos, &h, sizeof h); pos += sizeof h;
    for (size_t i = 0; i < payload && pos < MAX_IN; i++, pos++)
        stream[pos] = prog[(24 + i) % plen];
    if (pos + 4 <= MAX_IN) { store4(stream + pos, LZFSE_ENDOFSTREAM_BLOCK_MAGIC); pos += 4; }

    return damage(pos, prog, plen);
}

/* Apple's dispatcher accepts this undocumented value for raw LZVN; see the
 * file comment. Not in compression.h under any name. */
#define APPLE_ALGORITHM_LZVN ((compression_algorithm)0x900)

static void run_one(const uint8_t *data, size_t size) {
    if (size < 4) return;
    if (!out_apple) { guardbuf_init(&apple_gb, MAX_OUT); out_apple = guard_dst(&apple_gb, MAX_OUT); }

    /* bit 2: LZFSE (V1-hostile or a damaged real V2 stream, picked by bit 0)
     * or raw LZVN (a damaged real stream only; there is no hostile-header
     * generator for LZVN, which has no comparable structured header). */
    int use_lzvn = data[0] & 4;
    int mode = data[0] & 1;

    size_t len;
    if (use_lzvn) len = damage_valid_lzvn_stream(data, size);
    else len = mode == 0 ? build_hostile_v1_stream(data, size) : damage_valid_lzfse_stream(data, size);
    if (len == 0) return;

    static fuzzbuf_t source_buf;
    const uint8_t *exact_stream = fuzz_copy(&source_buf, stream, len);
    size_t olen = 0;
    int orc = use_lzvn ? crushlzvn_decode_buffer(out_ours, sizeof out_ours, exact_stream, len, &olen)
                        : crushlzfse_decode_buffer(out_ours, sizeof out_ours, exact_stream, len, &olen);

    memset(out_apple, 0xA5, 64);
    size_t alen = compression_decode_buffer(out_apple, MAX_OUT, exact_stream, len, NULL,
                                            use_lzvn ? APPLE_ALGORITHM_LZVN : COMPRESSION_LZFSE);

    int apple_ok = (alen > 0) || (orc == 0 && olen == 0);
    int ours_ok = (orc == 0);

    if (ours_ok && apple_ok && alen > 0) {
        if (olen != alen || memcmp(out_ours, out_apple, olen) != 0) {
            fprintf(stderr, "DIVERGE: %s, both accepted, ours=%zu apple=%zu, bytes differ\n",
                    use_lzvn ? "lzvn" : "lzfse", olen, alen);
            abort();
        }
        return;
    }
    if (ours_ok && !apple_ok) {
        unsigned long long h = ++ours_only_hits;
        if ((h & (h - 1)) == 0)
            fprintf(stderr, "contract 2: we accept, Apple refuses (%llu so far)\n", h);
        return;
    }
    if (!ours_ok && apple_ok && alen > 0) {
        unsigned long long h = ++apple_only_hits;
        if ((h & (h - 1)) == 0)
            fprintf(stderr, "contract 3: Apple accepts, we refuse rc=%d (%llu so far)\n", orc, h);
        return;
    }
}

#else

static void run_one(const uint8_t *data, size_t size) { (void)data; (void)size; }

#endif

#include "driver.h"
