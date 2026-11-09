// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test: lzfse_check_block_header_v1() validated every header
// field except literal_bits/lmd_bits. A V2 stream can only ever produce -7..0
// there (a 3-bit field minus 7 — see the v2-to-v1 expansion in
// lzfse_decode_base.c), but a block that claims to *be* V1
// (LZFSE_COMPRESSEDV1_BLOCK_MAGIC) is memcpy'd whole from the wire, so those
// two fields arrive as raw attacker-controlled int32_t. They flow into
// fse_in_checked_init64() as `n`, which computes `n + 64` — signed integer
// overflow (undefined behavior) for n near INT32_MAX, and a trap under
// UBSan:
//
//   lzfse_fse.h:285:24: runtime error: signed integer overflow:
//     2147483647 + 64 cannot be represented in type 'int'
//
// The fix adds range checks for both fields alongside the header's other
// range checks in lzfse_check_block_header_v1(). This test constructs a V1
// block with each field driven to its extremes and confirms the header is
// rejected before any decode work begins, rather than only avoided by luck
// of which values happen not to overflow.

#include "lzfse.h"
#include "lzfse_internal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A structurally-plausible V1 header, otherwise valid, with literal_bits and
// lmd_bits set by the caller.
static void make_header(lzfse_compressed_block_header_v1 *h, int32_t literal_bits,
                         int32_t lmd_bits) {
    memset(h, 0, sizeof *h);
    h->magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
    h->n_lmd_payload_bytes = 8;
    h->n_payload_bytes = 8;
    h->literal_bits = literal_bits;
    h->lmd_bits = lmd_bits;
    h->literal_freq[0] = LZFSE_ENCODE_LITERAL_STATES;
    h->l_freq[0] = LZFSE_ENCODE_L_STATES;
    h->m_freq[0] = LZFSE_ENCODE_M_STATES;
    h->d_freq[0] = LZFSE_ENCODE_D_STATES;
}

static int try_one(const char *label, int32_t literal_bits, int32_t lmd_bits) {
    lzfse_compressed_block_header_v1 h;
    make_header(&h, literal_bits, lmd_bits);

    size_t len = 8 + sizeof h + h.n_lmd_payload_bytes + 4;
    uint8_t *src = malloc(len);
    size_t n = 0;
    store4(src + n, LZFSE_UNCOMPRESSED_BLOCK_MAGIC); n += 4;
    store4(src + n, 0); n += 4;
    memcpy(src + n, &h, sizeof h); n += sizeof h;
    memset(src + n, 0, h.n_lmd_payload_bytes); n += h.n_lmd_payload_bytes;
    store4(src + n, LZFSE_ENDOFSTREAM_BLOCK_MAGIC); n += 4;

    uint8_t *dst = malloc(64);
    lzfse_decoder_state *s = calloc(1, sizeof *s);
    s->src = src; s->src_begin = src; s->src_end = src + len;
    s->dst = dst; s->dst_begin = dst; s->dst_end = dst + 64;

    // The property under test is simply that this returns *at all* without
    // tripping UBSan's signed-overflow trap inside fse_in_checked_init64; a
    // build without UBSan would just see this pass trivially, so this test
    // is meant to run under harness/build/asan (UBSan is enabled there).
    int st = lzfse_decode(s);
    int rejected = (st != LZFSE_STATUS_OK && st != LZFSE_STATUS_DST_FULL);

    printf("%-28s literal_bits=%-12d lmd_bits=%-12d status=%d %s\n", label,
           literal_bits, lmd_bits, st, rejected ? "rejected" : "ACCEPTED");

    free(s); free(dst); free(src);
    return rejected;
}

int main(void) {
    int failures = 0;

    // In-range values (-7..0) are exercised too, just not asserted on here:
    // whether this particular synthetic header round-trips depends on its
    // other fields, and that is not what this test is checking. The point is
    // only that it must not itself trip UBSan, same as every case below.
    try_one("in-range literal_bits=0 lmd_bits=-3", 0, -3);

    // The malicious/extreme values: must be rejected, not merely "happen not
    // to crash". Any of these previously reached the UBSan trap directly.
    if (!try_one("literal_bits=INT32_MAX", INT32_MAX, 0)) failures++;
    if (!try_one("lmd_bits=INT32_MAX", 0, INT32_MAX)) failures++;
    if (!try_one("literal_bits=INT32_MIN", INT32_MIN, 0)) failures++;
    if (!try_one("both=2^30", (int32_t)(1 << 30), (int32_t)(1 << 30))) failures++;
    if (!try_one("literal_bits=1 (just out of range)", 1, 0)) failures++;
    if (!try_one("lmd_bits=-8 (just out of range)", 0, -8)) failures++;

    printf("%d failures\n", failures);
    if (failures) { printf("FAILED\n"); return 1; }
    printf("ok\n");
    return 0;
}
