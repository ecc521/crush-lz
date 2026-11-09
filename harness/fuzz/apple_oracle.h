// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#ifndef FUZZ_APPLE_ORACLE_H
#define FUZZ_APPLE_ORACLE_H

#ifdef __APPLE__
#include <compression.h>
#include <stdio.h>
#include <string.h>
#include "fuzzbuf.h"

/* All encoder harnesses synthesize at most 256 KiB. Destinations use the
 * selected guard placement because libcompression is not instrumented. */
#define APPLE_ORACLE_MAX_INPUT (256 * 1024)
/* Raw LZVN is implemented by libcompression but absent from the SDK enum. */
#define APPLE_ORACLE_LZVN ((compression_algorithm)0x900)
typedef int (*oracle_decoder)(void *, size_t, const void *, size_t, size_t *);

static void apple_oracle_fail(const char *stage, size_t n, size_t got) {
    fprintf(stderr, "FUZZ FAILURE: %s (input %zu bytes, returned %zu)\n", stage, n, got);
    abort();
}

/* Both encoders' output must decode exactly to the input under both
 * decoders. This is separate from acceptance parity on damaged streams. */
static void apple_oracle(compression_algorithm algorithm, oracle_decoder decode,
                         const uint8_t *src, size_t n,
                         const uint8_t *ours, size_t ours_len) {
    static guardbuf_t packed_gb, back_gb;
    static int ready;
    static uint8_t *scratch;
    static size_t scratch_size;
    if (n > APPLE_ORACLE_MAX_INPUT) abort();
    if (!ready) {
        guardbuf_init(&packed_gb, APPLE_ORACLE_MAX_INPUT * 2 + 4096);
        guardbuf_init(&back_gb, APPLE_ORACLE_MAX_INPUT + 1);
        scratch_size = compression_decode_scratch_buffer_size(algorithm);
        scratch = calloc(1, scratch_size ? scratch_size : 1);
        if (!scratch) abort();
        ready = 1;
    }
    /* n+1 distinguishes a full result from an overlong result truncated
     * by compression_decode_buffer. Zero remains ambiguous for empty input. */
    uint8_t *back = guard_dst(&back_gb, n + 1);
    memset(back, 0xA5, n + 1);
    memset(scratch, 0, scratch_size);
    size_t got = compression_decode_buffer(back, n + 1, ours, ours_len,
                                           scratch, algorithm);
    if (got != n || memcmp(back, src, n) != 0)
        apple_oracle_fail("Apple decoder rejected or changed crush output", n, got);

    size_t cap = n * 2 + 4096;
    uint8_t *packed = guard_dst(&packed_gb, cap);
    size_t len = compression_encode_buffer(packed, cap, src, n, NULL, algorithm);
    if (!len) {
        /* Zero is ambiguous for empty input. Apple's raw LZVN encoder also
         * requires at least eight source bytes (LZVN_ENCODE_MIN_SRC_SIZE in
         * the Apple-derived source; confirmed on macOS 27.2). */
        if (n == 0 || (algorithm == APPLE_ORACLE_LZVN && n < 8)) return;
        apple_oracle_fail("Apple encoder failed with a generous destination", n, len);
    }
    static fuzzbuf_t apple_stream, ours_back;
    const uint8_t *exact_packed = fuzz_copy(&apple_stream, packed, len);
    uint8_t *exact_back = fuzz_resize(&ours_back, n);
    memset(back, 0xA5, n + 1);
    got = 0;
    if (decode(exact_back, n, exact_packed, len, &got) != 0 || got != n || memcmp(exact_back, src, n) != 0)
        apple_oracle_fail("crush decoder rejected or changed Apple output", n, got);
    memset(back, 0xA5, n + 1);
    memset(scratch, 0, scratch_size);
    got = compression_decode_buffer(back, n + 1, exact_packed, len, scratch, algorithm);
    if (got != n || memcmp(back, src, n) != 0)
        apple_oracle_fail("Apple encoder/decoder round-trip mismatch", n, got);
}
#endif
#endif
