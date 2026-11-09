// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// A V1 block can declare n_literals=0 while its matches still consume
// literal bytes, which the format gives no meaning. The decoder rejects a
// block whose matches consume more literals than it declares.
//
// Found by harness/fuzz/crushlzfse_decode_diff_vs_apple.c: libcompression
// accepted the same stream and produced different bytes. Both decoders
// accepting one stream and disagreeing on its output is the one outcome the
// diff fuzzers never allow.
//
// The check is one comparison at the very end of the LMD decode loop, not
// per tuple, specifically to leave the loop's own per-tuple bound (and the
// lit_budget amortisation it relies on for decode speed) untouched.

#include "lzfse.h"
#include "lzfse_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int decode_stream(const uint8_t *src, size_t len, uint8_t *dst, size_t dst_len) {
    lzfse_decoder_state *s = calloc(1, sizeof *s);
    s->src = src; s->src_begin = src; s->src_end = src + len;
    s->dst = dst; s->dst_begin = dst; s->dst_end = dst + dst_len;
    int st = lzfse_decode(s);
    free(s);
    return st;
}

// The exact 90-byte stream the fuzzer found: build_hostile_v1_stream()'s
// formulas (harness/fuzz/crushlzfse_decode_diff_vs_apple.c) turn this into
// n_literals=0, n_matches=4, every FSE table one-hot at symbol index 4:
// each match's L=4 literal bytes are undeclared.
static const uint8_t fuzz_input[90] = {
    0x00, 0x00, 0x00, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
};

// A structurally-plausible V1 header, otherwise valid, whose degenerate
// one-hot tables are set exactly as build_hostile_v1_stream() would for the
// same n_matches, but with n_literals correctly declared to cover what
// those matches actually consume. This must still decode fine: the fix
// must not reject a block just for having a small/zero n_literals, only
// one whose matches consume more than it declared.
static size_t make_legitimate_stream(uint8_t *buf, size_t cap, uint32_t n_matches,
                                      uint32_t n_literals) {
    lzfse_compressed_block_header_v1 h;
    memset(&h, 0, sizeof h);
    h.magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
    h.n_literals = n_literals;
    h.n_matches = n_matches;
    h.n_literal_payload_bytes = 8;
    h.n_lmd_payload_bytes = 8;
    h.n_payload_bytes = h.n_literal_payload_bytes + h.n_lmd_payload_bytes;
    h.literal_state[0] = h.literal_state[1] = h.literal_state[2] = h.literal_state[3] = 0;
    h.l_state = h.m_state = h.d_state = 4;
    h.literal_freq[4] = LZFSE_ENCODE_LITERAL_STATES;
    h.l_freq[4] = LZFSE_ENCODE_L_STATES;
    h.m_freq[4] = LZFSE_ENCODE_M_STATES;
    h.d_freq[4] = LZFSE_ENCODE_D_STATES;

    size_t n = 0;
    if (sizeof h + h.n_payload_bytes + 4 > cap) return 0;
    memcpy(buf + n, &h, sizeof h); n += sizeof h;
    memset(buf + n, 0x04, h.n_payload_bytes); n += h.n_payload_bytes;
    store4(buf + n, LZFSE_ENDOFSTREAM_BLOCK_MAGIC); n += 4;
    return n;
}

int main(void) {
    int failures = 0;
    uint8_t dst[4096];

    // The exact fuzzer-found shape: n_literals=0 but matches consume 16
    // literal bytes between them. Must now be rejected outright, not
    // silently zero-filled.
    int st = decode_stream(fuzz_input, sizeof fuzz_input, dst, sizeof dst);
    int rejected = (st != LZFSE_STATUS_OK && st != LZFSE_STATUS_DST_FULL);
    printf("under-declared n_literals: status=%d %s\n", st, rejected ? "rejected" : "ACCEPTED");
    if (!rejected) failures++;

    // The same degenerate one-hot shape, but with n_literals correctly
    // covering the 16 bytes 4 matches of L=4 each actually consume: must
    // still decode successfully. Guards against the fix being stricter
    // than the actual invariant (over-consumption, not merely "small or
    // zero n_literals"). The header struct alone is 772 bytes (full FSE
    // frequency tables), so the buffer needs real headroom.
    uint8_t stream[4096];
    size_t len = make_legitimate_stream(stream, sizeof stream, /*n_matches=*/4, /*n_literals=*/16);
    if (len == 0) { printf("FAILED: could not build the legitimate-stream fixture\n"); return 1; }
    st = decode_stream(stream, len, dst, sizeof dst);
    int accepted = (st == LZFSE_STATUS_OK || st == LZFSE_STATUS_DST_FULL);
    printf("correctly-declared n_literals: status=%d %s\n", st, accepted ? "accepted" : "REJECTED");
    if (!accepted) failures++;

    printf("%d failures\n", failures);
    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
