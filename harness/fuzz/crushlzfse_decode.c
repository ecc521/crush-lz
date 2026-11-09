// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Fuzz harness for the LZFSE and raw LZVN decoders on hostile input. The
 * contract is that a decode returns an error or a correct length and never
 * touches memory outside its buffers; ASan and UBSan are the judges.
 *
 * The first input byte picks the format. Random bytes rarely pass a header
 * check, so half the budget goes to real streams damaged under the fuzzer's
 * control (see damage()).
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

#define MAX_IN  (256 * 1024)
#define MAX_OUT (512 * 1024)

static uint8_t stream[MAX_IN];
static uint8_t seed_data[64 * 1024];
/* Our own decoders are ASan-instrumented, so a write past a plain array's
 * true allocation is already caught — the gap a fixed oversized `out`
 * leaves is an overflow that stays inside that allocation but past the
 * *logical* length the decoder reports. A guarded, exactly-sized destination
 * turns that into a fault too. */
static guardbuf_t out_gb;
static uint8_t *out;

/* Level mix for seed streams, weighted toward cheap levels; 99 is out of
 * range to keep the clamp path under test. */
static const int LZFSE_LEVEL_MIX[16] = {-5, -4, -3, -2, -1, 0, 0, 1, 1, 2, 3, 4, 5, 6, 8, 99};
static const int LZVN_LEVEL_MIX[16] = {-2, -1, -1, 0, 0, 1, 1, 2, 2, 3, 3, 4, 5, 6, 8, 99};

/* Damage a valid stream by byte flips, truncation, both, or extension past
 * the end. Truncation reaches the partial-read paths that flips cannot;
 * extension catches a decoder trusting a length over its buffer. */
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

/* Build a real LZFSE stream and damage it. Returns its length, or 0. */
static size_t damage_valid_lzfse_stream(const uint8_t *prog, size_t plen) {
    if (plen < 4) return 0;

    unsigned period = 1u + (prog[1] % 64u);
    size_t n = 512 + ((size_t)prog[2] << 6);
    if (n > sizeof seed_data) n = sizeof seed_data;
    for (size_t i = 0; i < n; i++) seed_data[i] = (uint8_t)((i % period) * 37u);

    int level = LZFSE_LEVEL_MIX[prog[3] & 15];
    size_t len = crushlzfse_encode_buffer(stream, sizeof stream, seed_data, n, NULL, 0, level);
    if (len == 0) return 0;

    return damage(len, prog, plen);
}

/* Same idea for raw LZVN. */
static size_t damage_valid_lzvn_stream(const uint8_t *prog, size_t plen) {
    if (plen < 4) return 0;

    unsigned period = 1u + (prog[1] % 64u);
    size_t n = 512 + ((size_t)prog[2] << 6);
    if (n > sizeof seed_data) n = sizeof seed_data;
    for (size_t i = 0; i < n; i++) seed_data[i] = (uint8_t)((i % period) * 37u);

    int level = LZVN_LEVEL_MIX[prog[3] & 15];
    size_t len = crushlzvn_encode_buffer(stream, sizeof stream, seed_data, n, NULL, 0, level);
    if (len == 0) return 0;

    return damage(len, prog, plen);
}

/* V1 is a format the decoder must accept (Apple's decoder does) but that no
 * encoder here (ours or Apple's) ever emits, so it gets zero coverage
 * from every other seed in this driver, which are all real encoder output.
 * Random bytes essentially never pass lzfse_check_block_header_v1() either
 * (a fixed 772-byte struct with several range checks and four frequency
 * tables that must each sum correctly), so prepending the "bvx1" magic to
 * raw fuzzer bytes (the prepend_magic path below already tries this)
 * almost never reaches real decode work. Build a header that mostly
 * validates instead, with the fuzzer driving the fields structurally
 * interesting bugs live in: n_literals/n_matches vs. the payload byte
 * counts that must actually hold them, the state values, and
 * literal_bits/lmd_bits (raw int32_t here, unlike a V2 stream where they
 * can only ever be -7..0; see lzfse_check_block_header_v1). */
static size_t build_hostile_v1_stream(const uint8_t *prog, size_t plen) {
    if (plen < 24) return 0;

    lzfse_compressed_block_header_v1 h;
    memset(&h, 0, sizeof h);
    h.magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;

    /* Mostly in-range, occasionally pushed to or past the edge. */
    h.n_literals = (uint32_t)(((size_t)prog[0] << 8 | prog[1]) % (LZFSE_LITERALS_PER_BLOCK + 8));
    h.n_matches = (uint32_t)(((size_t)prog[2] << 8 | prog[3]) % (LZFSE_MATCHES_PER_BLOCK + 8));
    h.n_literal_payload_bytes = (uint32_t)(((size_t)prog[4] << 8 | prog[5]) % (sizeof seed_data));
    h.n_lmd_payload_bytes = (uint32_t)(((size_t)prog[6] << 8 | prog[7]) % (sizeof seed_data));
    h.n_payload_bytes = h.n_literal_payload_bytes + h.n_lmd_payload_bytes;
    h.literal_bits = (int32_t)((int8_t)prog[8]) % 12 - 4; /* mostly near -7..0, sometimes past it */
    h.lmd_bits = (int32_t)((int8_t)prog[9]) % 12 - 4;
    /* One byte in eight lets a field escape to a wide extreme instead. */
    if ((prog[10] & 7) == 0) h.literal_bits = (int32_t)(prog[11] | (uint32_t)prog[12] << 8 | (uint32_t)prog[13] << 16 | (uint32_t)prog[14] << 24);
    if ((prog[10] & 7) == 1) h.lmd_bits = (int32_t)(prog[11] | (uint32_t)prog[12] << 8 | (uint32_t)prog[13] << 16 | (uint32_t)prog[14] << 24);

    uint16_t lit_state[4];
    for (int i = 0; i < 4; i++) lit_state[i] = (uint16_t)(prog[15 + i] * 4u % (LZFSE_ENCODE_LITERAL_STATES + 4));
    memcpy(h.literal_state, lit_state, sizeof lit_state);
    h.l_state = (uint16_t)(prog[19] % (LZFSE_ENCODE_L_STATES + 2));
    h.m_state = (uint16_t)(prog[20] % (LZFSE_ENCODE_M_STATES + 2));
    h.d_state = (uint16_t)(prog[21] % (LZFSE_ENCODE_D_STATES + 2));

    /* Valid-summing degenerate tables by default (single symbol owns every
     * state), so the header usually clears fse_check_freq and reaches real
     * decode work; damage() below can still corrupt these bytes directly. */
    h.literal_freq[prog[22] % LZFSE_ENCODE_LITERAL_SYMBOLS] = LZFSE_ENCODE_LITERAL_STATES;
    h.l_freq[prog[23] % LZFSE_ENCODE_L_SYMBOLS] = LZFSE_ENCODE_L_STATES;
    h.m_freq[prog[23] % LZFSE_ENCODE_M_SYMBOLS] = LZFSE_ENCODE_M_STATES;
    h.d_freq[prog[23] % LZFSE_ENCODE_D_SYMBOLS] = LZFSE_ENCODE_D_STATES;

    size_t payload = h.n_payload_bytes;
    size_t n = 4 + sizeof h + payload + 4;
    if (n > MAX_IN) return 0;

    size_t pos = 0;
    memcpy(stream + pos, &h, sizeof h); pos += sizeof h;
    for (size_t i = 0; i < payload && pos < MAX_IN; i++, pos++)
        stream[pos] = prog[(24 + i) % plen];
    if (pos + 4 <= MAX_IN) { store4(stream + pos, LZFSE_ENDOFSTREAM_BLOCK_MAGIC); pos += 4; }

    return damage(pos, prog, plen);
}

static void run_one(const uint8_t *data, size_t size) {
    if (size < 4) return;

    if (!out) { guardbuf_init(&out_gb, MAX_OUT); out = guard_dst(&out_gb, MAX_OUT); }

    /* bit 0: LZFSE or raw LZVN. bit 1: damaged stream or raw bytes.
     * bit 2 (LZFSE raw bytes only): prepend a real block magic.
     * bit 4 (LZFSE damaged-stream only): a hostile V1 header instead of a
     * real (always-V2) encoder stream; see build_hostile_v1_stream(). */
    int use_lzvn = data[0] & 1;
    int use_damage = data[0] & 2;
    int prepend_magic = data[0] & 4;
    int use_v1 = data[0] & 16;
    /* Real streams begin 'b' (0x62), whose bit 1 would pick the damage path
     * and read the stream as a program. Decode them as given. */
    if (memcmp(data, "bvx", 3) == 0) { use_lzvn = 0; use_damage = 0; prepend_magic = 0; }

    size_t len;
    if (use_damage) {
        len = use_lzvn ? damage_valid_lzvn_stream(data, size)
             : use_v1  ? build_hostile_v1_stream(data, size)
                       : damage_valid_lzfse_stream(data, size);
        if (len == 0) return;
    } else {
        len = size < MAX_IN ? size : MAX_IN;
        memcpy(stream, data, len);
        if (!use_lzvn && prepend_magic && len >= 4) {
            static const char *magics[] = {"bvx-", "bvx1", "bvx2", "bvxn", "bvx$"};
            memcpy(stream, magics[(data[0] >> 3) % 5], 4);
        }
    }

    out = guard_dst(&out_gb, MAX_OUT);
    static fuzzbuf_t source_buf;
    const uint8_t *exact_stream = fuzz_copy(&source_buf, stream, len);
    size_t got = 0;
    if (use_lzvn) {
        int rc = crushlzvn_decode_buffer(out, MAX_OUT, exact_stream, len, &got);
        fuzz_check_written(out, got);
        if (rc == 0 && got > MAX_OUT) {
            fprintf(stderr, "FUZZ FAILURE: lzvn reported %zu bytes into a %zu-byte buffer\n",
                    got, (size_t)MAX_OUT);
            abort();
        }
        if (rc == 0 && got > 0) {
            uint8_t *tight_dst = guard_dst(&out_gb, got);
            size_t tight_got = 0;
            int trc = crushlzvn_decode_buffer(tight_dst, got, exact_stream, len, &tight_got);
            fuzz_check_written(tight_dst, tight_got);
            if (trc != 0 || tight_got != got) {
                fprintf(stderr, "FUZZ FAILURE: lzvn exact-fit decode disagreed (rc=%d got=%zu vs %zu)\n",
                        trc, tight_got, got);
                abort();
            }
            uint8_t *short_dst = guard_dst(&out_gb, got - 1);
            size_t short_got = 0;
            (void)crushlzvn_decode_buffer(short_dst, got - 1, exact_stream, len, &short_got);
            fuzz_check_written(short_dst, short_got);
        }
    } else {
        int rc = crushlzfse_decode_buffer(out, MAX_OUT, exact_stream, len, &got);
        fuzz_check_written(out, got);
        if (rc == 0 && got > MAX_OUT) {
            fprintf(stderr, "FUZZ FAILURE: lzfse reported %zu bytes into a %zu-byte buffer\n",
                    got, (size_t)MAX_OUT);
            abort();
        }
        if (rc == 0 && got > 0) {
            uint8_t *tight_dst = guard_dst(&out_gb, got);
            size_t tight_got = 0;
            int trc = crushlzfse_decode_buffer(tight_dst, got, exact_stream, len, &tight_got);
            fuzz_check_written(tight_dst, tight_got);
            if (trc != 0 || tight_got != got) {
                fprintf(stderr, "FUZZ FAILURE: lzfse exact-fit decode disagreed (rc=%d got=%zu vs %zu)\n",
                        trc, tight_got, got);
                abort();
            }
            uint8_t *short_dst = guard_dst(&out_gb, got - 1);
            size_t short_got = 0;
            (void)crushlzfse_decode_buffer(short_dst, got - 1, exact_stream, len, &short_got);
            fuzz_check_written(short_dst, short_got);
        }
    }
}

#include "driver.h"
