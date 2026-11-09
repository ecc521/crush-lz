// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Differential fuzz harness: our LZBITMAP decoder against Apple's, on the
 * same bytes. Where both succeed, lengths and bytes must match (contract 1);
 * where we succeed and Apple fails, that is reported (contract 2); where
 * Apple succeeds and we fail, the stream is printed (contract 3). Contracts 2
 * and 3 are informational: acceptance may differ by design, and contract 3
 * includes every stream with a period below 8, which we reject on purpose.
 * Contract 3 hits are what to read for a stream Apple decodes that we should.
 *
 * libcompression mishandles LZBITMAP copy periods below 8 on all macOS
 * versions. Our decoder rejects these periods.
 *
 * macOS only; elsewhere this compiles to a harness that does nothing.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzbitmap.h"
#include "guardbuf.h"
#include "fuzzbuf.h"

#if defined(__APPLE__)
#include <compression.h>
#define HAVE_APPLE_DECODER 1
#else
#define HAVE_APPLE_DECODER 0
#endif

#define MAX_IN  (256 * 1024)
#define MAX_OUT (512 * 1024)

static uint8_t stream[MAX_IN];
static uint8_t out_ours[MAX_OUT];
/* Apple's destinations are guarded (see guardbuf.h). The tight probe needs its
 * own region: a tight destination from apple_gb would overlap out_apple. */
static guardbuf_t apple_gb;
static uint8_t *out_apple;
static guardbuf_t tight_gb;
static uint8_t seed_data[64 * 1024];

#if HAVE_APPLE_DECODER

static guardbuf_t apple_scratch_gb;
static uint8_t *apple_scratch;
static size_t apple_scratch_size;

/* Contract 2 and 3 hits, reported at powers of two. */
static unsigned long long permissive_hits;
static unsigned long long strict_hits;

static void apple_scratch_init(void) {
    if (apple_scratch) return;
    apple_scratch_size = compression_decode_scratch_buffer_size(COMPRESSION_LZBITMAP);
    guardbuf_init(&apple_scratch_gb, apple_scratch_size ? apple_scratch_size : 1);
    apple_scratch = guard_view(&apple_scratch_gb, apple_scratch_size, 1);
    /* One extra byte distinguishes a complete MAX_OUT-byte result from
     * a longer result truncated by Apple's destination capacity. */
    guardbuf_init(&apple_gb, MAX_OUT + 1);
    out_apple = guard_dst(&apple_gb, MAX_OUT + 1);
    guardbuf_init(&tight_gb, MAX_OUT);
}

/* Random bytes rarely pass the magic check, so half the budget goes to real
 * streams the fuzzer then damages. */
static size_t corrupt_valid_stream(const uint8_t *prog, size_t plen) {
    if (plen < 4) return 0;

    unsigned period = 1u + (prog[1] % 64u);
    size_t n = 4096 + ((size_t)prog[2] << 6);
    if (n > sizeof seed_data) n = sizeof seed_data;
    for (size_t i = 0; i < n; i++) seed_data[i] = (uint8_t)((i % period) * 37u);

    size_t len = 0;
    len = crushlzbitmap_encode_buffer(stream, sizeof stream, seed_data, n, NULL, 0,
                                      CRUSHLZBITMAP_LEVEL_DEFAULT);
    if (len == 0) return 0;

    for (size_t i = 3; i + 1 < plen && i < 64; i += 2) {
        size_t pos = ((size_t)prog[i] << 8 | prog[i + 1]) % len;
        stream[pos] ^= prog[(i + 1) % plen];
    }
    return len;
}

static void dump(const uint8_t *s, size_t len) {
    fprintf(stderr, "stream (%zu bytes):", len);
    for (size_t i = 0; i < len && i < 512; i++) {
        if (i % 16 == 0) fprintf(stderr, "\n  ");
        fprintf(stderr, "%02x ", s[i]);
    }
    fprintf(stderr, "\n");
}

static void report(const char *what, const uint8_t *s, size_t len) {
    fprintf(stderr, "FUZZ FAILURE: %s\nstream (%zu bytes):", what, len);
    for (size_t i = 0; i < len && i < 512; i++) {
        if (i % 16 == 0) fprintf(stderr, "\n  ");
        fprintf(stderr, "%02x ", s[i]);
    }
    fprintf(stderr, "\n");
    abort();
}

static void run_one(const uint8_t *data, size_t size) {
    size_t len, ours_len = 0, apple_len;
    int ours_ok;

    if (size < 2) return;
    apple_scratch_init();

    if (data[0] & 1) {
        len = corrupt_valid_stream(data, size);
        if (len == 0) return;
    } else {
        len = size < MAX_IN ? size : MAX_IN;
        memcpy(stream, data, len);
        if ((data[0] & 2) && len >= 4) memcpy(stream, "ZBM\x09", 4);
    }

    static fuzzbuf_t source_buf;
    const uint8_t *exact_stream = fuzz_copy(&source_buf, stream, len);
    memset(out_ours, 0, sizeof out_ours);
    ours_ok = (crushlzbitmap_decode_buffer(out_ours, sizeof out_ours, exact_stream, len, &ours_len) == 0);
    if (!ours_ok) {
        memset(apple_scratch, 0, apple_scratch_size);
        apple_len = compression_decode_buffer(out_apple, MAX_OUT + 1,
                                              exact_stream, len, apple_scratch,
                                              COMPRESSION_LZBITMAP);
        if (apple_len != 0) {
            ++strict_hits;
            if ((strict_hits & (strict_hits - 1)) == 0) {
                fprintf(stderr, "[note] rejected %llu stream(s) Apple decodes; "
                        "latest decodes to %zu bytes on Apple's side\n",
                        strict_hits, apple_len);
                dump(stream, len);
            }
        }
        return;
    }

    if (ours_len > sizeof out_ours)
        report("our decoder reported more bytes than the buffer holds", stream, len);

    /* compression_decode_buffer returns 0 for both failure and an empty
     * result, so a zero-length decode cannot be compared. */
    if (ours_len == 0)
        return;

    /* The scratch buffer is owned and zeroed per call so that Apple's
     * accept/reject answer on malformed input is a function of the stream
     * alone and any disagreement is reproducible. */
    memset(out_apple, 0, MAX_OUT + 1);
    memset(apple_scratch, 0, apple_scratch_size);
    apple_len = compression_decode_buffer(out_apple, MAX_OUT + 1,
                                          exact_stream, len, apple_scratch,
                                          COMPRESSION_LZBITMAP);

    /* Second decode into a tight guarded destination, as a crash
     * oracle only: nothing is compared, the question is whether a byte lands
     * past the end. Must use tight_gb, since out_apple is still read below. */
    {
        size_t tight = ours_len ? (size_t)(stream[0] % 4u) * ours_len / 3u : 0;
        if (tight > MAX_OUT) tight = MAX_OUT;
        uint8_t *td = guard_dst(&tight_gb, tight);
        memset(apple_scratch, 0, apple_scratch_size);
        (void)compression_decode_buffer(td, tight, exact_stream, len, apple_scratch,
                                        COMPRESSION_LZBITMAP);
    }

    if (apple_len == 0) {
        /* Acceptance differences are informational, not correctness failures. */
        ++permissive_hits;
        if ((permissive_hits & (permissive_hits - 1)) == 0)
            fprintf(stderr, "[note] accepted %llu stream(s) Apple rejects\n",
                    permissive_hits);
        return;
    }
    /* Acceptance may differ, but two successful complete decodes must
     * agree on lengths and bytes, even for damaged input. */
    size_t shared = apple_len < ours_len ? apple_len : ours_len;
    if (memcmp(out_ours, out_apple, shared) != 0)
        report("BYTE disagreement in the shared decoded prefix", stream, len);
    if (apple_len == MAX_OUT + 1)
        return; /* Apple's buffer API may have truncated an overlong result. */
    if (apple_len != ours_len)
        report("LENGTH disagreement between our decoder and Apple's", stream, len);
    if (memcmp(out_ours, out_apple, ours_len) != 0)
        report("BYTE disagreement between our decoder and Apple's", stream, len);
}

#else /* !HAVE_APPLE_DECODER */

static void run_one(const uint8_t *data, size_t size) {
    (void)data;
    (void)size;
}

#endif

#include "driver.h"
