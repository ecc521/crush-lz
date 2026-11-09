// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test for an out-of-bounds read in lzfse_decode_literals(): its
// backward bit reader was bounded by s->src_begin (the whole frame's start)
// rather than this block's own payload, so a block whose declared
// n_literal_payload_bytes has too little real entropy for its n_literals
// could keep pulling bits from earlier blocks' payloads and still report
// success, instead of failing once its own payload ran out. This is the
// literal-decode sibling of the bug lzfse_lmd_resume_oob_test.c covers on
// the LMD side; 0e95bf2 fixed that one and missed this one.
//
// The fix (lzfse_decode_hot.h) bounds the reader by s->src - 8: the 8-byte
// margin is the reader's own maximum lookahead (its accumulator holds at
// most 63 bits), and that much of this block's own header always precedes
// the literal payload, unlike the unrelated block seeded before it below.
//
// This test drives the low-level lzfse_decode() state machine directly, as
// lzfse_lmd_resume_oob_test.c does, since that is the level the bug lives at.

#include "lzfse.h"
#include "lzfse_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RAW 2048u
#define LIT_PAY 8u

int main(void) {
    int failures = 0;

    lzfse_compressed_block_header_v1 h;
    memset(&h, 0, sizeof h);
    h.magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
    h.n_raw_bytes = 0;
    h.n_literals = LZFSE_LITERALS_PER_BLOCK; // 40000 requested...
    h.n_literal_payload_bytes = LIT_PAY;     // ...from just 8 real bytes
    h.n_matches = 0;
    h.n_lmd_payload_bytes = 0;
    h.n_payload_bytes = LIT_PAY;
    h.literal_bits = 0;
    h.lmd_bits = 0;
    // Two symbols splitting the states evenly (k == 1): each of the 40000/4
    // group decodes actually consumes real entropy, unlike a single dominant
    // symbol (k == 0, free of the stream). Without genuine consumption per
    // decode there would be nothing to run out of, and the bug would be
    // untestable this way.
    h.literal_freq[0] = LZFSE_ENCODE_LITERAL_STATES / 2;
    h.literal_freq[1] = LZFSE_ENCODE_LITERAL_STATES / 2;
    // l/m/d tables are never reached: literal decode fails before the LMD
    // stage starts, so all-zero (a valid, if empty, frequency table) is fine.

    size_t len = 8 + RAW + sizeof h + LIT_PAY + 4;
    uint8_t *src = malloc(len);
    size_t n = 0;
    store4(src + n, LZFSE_UNCOMPRESSED_BLOCK_MAGIC); n += 4; // seed 2 KiB ahead of the block
    store4(src + n, RAW); n += 4;
    for (unsigned i = 0; i < RAW; i++) src[n++] = (uint8_t)i;
    memcpy(src + n, &h, sizeof h); n += sizeof h;
    for (unsigned i = 0; i < LIT_PAY; i++) src[n++] = 0x00;
    store4(src + n, LZFSE_ENDOFSTREAM_BLOCK_MAGIC); n += 4;
    if (n != len) { printf("size mismatch\n"); return 2; }

    size_t cap = RAW;
    uint8_t *dst = malloc(cap);

    lzfse_decoder_state *s = calloc(1, sizeof *s);
    s->src = src; s->src_begin = src; s->src_end = src + len;
    s->dst = dst; s->dst_begin = dst; s->dst_end = dst + cap;

    int st = lzfse_decode(s);

    // 8 real bytes (plus the 8 header bytes immediately before them, which
    // the reader may legitimately draw on) is nowhere near enough entropy
    // for 40000 literals at this frequency table. A correct decoder must
    // fail once that window is exhausted, not succeed by reading further
    // left into the unrelated seeded block.
    if (st != LZFSE_STATUS_ERROR) {
        printf("FAIL: decode did not reject the undersized literal payload "
               "(status=%d) — the reader likely ran past its own block's "
               "payload into the preceding block\n", st);
        failures++;
    } else {
        printf("undersized literal payload rejected cleanly: status=%d\n", st);
    }

    free(s); free(dst); free(src);

    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
