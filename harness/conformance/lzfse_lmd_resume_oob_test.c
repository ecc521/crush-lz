// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test for an out-of-bounds read in lzfse_decode_lmd(): its
// backward bit reader was bounded by s->src_begin (the whole frame's start)
// instead of s->src (this block's own LMD payload start), so a block whose
// declared n_lmd_payload_bytes is too small for its n_matches/frequency
// tables could keep pulling bits from earlier blocks' payloads and the frame
// header rather than failing once its own payload ran out.
//
// That is a real out-of-bounds read whenever it happens to run past
// s->src_begin (bounded only from below by the start of the whole buffer),
// and separately, if the block also hits LZFSE_STATUS_DST_FULL while its
// reader is below s->src, the saved resume offset
// (bs->lmd_in_buf = src - s->src, a uint32_t) goes negative and wraps to a
// value close to UINT32_MAX; a subsequent resume then reconstructs
// s->src + lmd_in_buf as a pointer roughly 4 GiB past the source buffer.
// An actual ASan report from this regression:
//
//   AddressSanitizer: BUS on unknown address ...
//   caused by a dereference of a high value address
//       #0 fse_in_checked_flush64 lzfse_fse.h
//       #1 lzfse_decode_lmd_baseline lzfse_decode_hot.h
//
// This test drives the low-level lzfse_decode() state machine directly
// (rather than through crushlzfse_decode_buffer(), which has no caller today
// that re-enters after DST_FULL) since that is the level at which the bug
// lives and the level any future streaming/resumable wrapper would call.
//
// The fix (lzfse_decode_hot.h) bounds the reader by s->src instead, so a
// block that runs out of its own real payload now fails outright rather
// than borrowing bytes it has no right to read.

#include "lzfse.h"
#include "lzfse_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RAW 2048u
#define LMD_PAY 8u

int main(void) {
    int failures = 0;

    lzfse_compressed_block_header_v1 h;
    memset(&h, 0, sizeof h);
    h.magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
    h.n_raw_bytes = 0;
    h.n_literals = 0;
    h.n_literal_payload_bytes = 0;
    h.n_matches = LZFSE_MATCHES_PER_BLOCK;   // 10000 tuples requested...
    h.n_lmd_payload_bytes = LMD_PAY;         // ...from just 8 real bytes
    h.n_payload_bytes = LMD_PAY;
    h.literal_bits = 0;
    h.lmd_bits = 0;
    h.literal_freq[0] = LZFSE_ENCODE_LITERAL_STATES;
    h.l_freq[0]  = LZFSE_ENCODE_L_STATES;   // L == 0 always, 0 extra bits
    h.m_freq[15] = LZFSE_ENCODE_M_STATES;   // M == 15 always, 0 extra bits
    h.d_freq[4]  = LZFSE_ENCODE_D_STATES;   // D == 4|5, 1 extra bit per tuple

    size_t len = 8 + RAW + sizeof h + LMD_PAY + 4;
    uint8_t *src = malloc(len);
    size_t n = 0;
    store4(src + n, LZFSE_UNCOMPRESSED_BLOCK_MAGIC); n += 4;  // seed 2 KiB of output
    store4(src + n, RAW); n += 4;                             // so D=4 is legal
    for (unsigned i = 0; i < RAW; i++) src[n++] = (uint8_t)i;
    memcpy(src + n, &h, sizeof h); n += sizeof h;
    for (unsigned i = 0; i < LMD_PAY; i++) src[n++] = 0x00;
    store4(src + n, LZFSE_ENDOFSTREAM_BLOCK_MAGIC); n += 4;
    if (n != len) { printf("size mismatch\n"); return 2; }

    // 8 real bytes (~64 bits) is enough for ~60 legitimate tuples at ~1 bit
    // each with these frequency tables, so dst must be sized well past that:
    // otherwise a too-small destination would make a correctly-rejecting
    // decoder indistinguishable from one that legitimately filled it from
    // real bits.
    size_t cap = RAW + 200u * 15u;
    uint8_t *dst = malloc(cap);

    lzfse_decoder_state *s = calloc(1, sizeof *s);
    s->src = src; s->src_begin = src; s->src_end = src + len;
    s->dst = dst; s->dst_begin = dst; s->dst_end = dst + cap;

    int st = lzfse_decode(s);
    size_t produced = (size_t)(s->dst - dst);

    // 8 bytes of real entropy is nowhere near enough for the 10000 requested
    // tuples (each costs >= 1 bit), so a correct decoder must fail once that
    // payload is exhausted rather than reading further left into the frame:
    // status must be an outright error, and produced must not exceed the
    // seeded raw block.
    if (st == LZFSE_STATUS_OK || st == LZFSE_STATUS_DST_FULL) {
        printf("FAIL: decode did not reject the undersized LMD payload "
               "(status=%d produced=%zu) — the reader likely ran past its "
               "own block's payload\n", st, produced);
        failures++;
    }
    if (produced != RAW) {
        printf("FAIL: produced %zu bytes, expected exactly the seeded %u "
               "(any extra means LMD tuples were manufactured from bytes "
               "outside this block's payload)\n", produced, RAW);
        failures++;
    }
    if (!failures)
        printf("undersized LMD payload rejected cleanly: status=%d produced=%zu\n",
               st, produced);

    free(s); free(dst); free(src);

    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
