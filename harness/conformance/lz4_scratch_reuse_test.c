// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * The encoder's chain-level (depth > 1) hash tables outlive the encode that
 * filled them: positions are stored with a stream origin added, and the
 * origin advances far enough between calls that everything the last one
 * wrote falls outside the match window. That removes the per-call clear for
 * those levels. The depth-1 levels (-2 to 0) instead clear their table on
 * every call: a hit there is confirmed on a stored key, not by re-reading
 * the source, which is only safe starting from an empty table, so for them
 * every case below holds trivially, by construction, rather than through the
 * origin trick. This puts four things on the line that a single round trip
 * does not reach:
 *
 *   1. A scratch reused across calls must not let one buffer's positions
 *      match into another's. The encode would still decode: every
 *      candidate is confirmed on the source bytes, so the failure this
 *      catches is a wrong offset, not a wrong decode.
 *   2. A scratch reused across *levels* changes the table's shape under it,
 *      and may change which of the two designs above a given region means.
 *   3. A scratch full of arbitrary bytes must encode correctly, because
 *      nothing but the caller promises it was ever ours.
 *   4. The chain tables' origin has to be restarted before it climbs past
 *      32 bits, which only happens after tens of thousands of calls.
 *
 * Every case here checks the same thing in the end: what came back out is
 * what went in, and the stream says so at the size it reports.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlz4.h"

static int failures, checks;

static void fail(const char *what, const char *detail)
{
    printf("FAIL %s (%s)\n", what, detail);
    failures++;
}

/* Encodes with the given scratch and asserts the stream decodes to src. */
static void round_trip(const char *what, const uint8_t *src, size_t n,
                       void *scratch, size_t scratch_n, int level)
{
    size_t cap = crushlz4_encode_bound(n);
    uint8_t *enc = malloc(cap ? cap : 1);
    uint8_t *dec = malloc(n ? n : 1);
    size_t out, len = 0;
    char detail[128];

    checks++;
    if (!enc || !dec) { fail(what, "out of memory"); free(enc); free(dec); return; }

    out = crushlz4_encode_buffer(enc, cap, src, n, scratch, scratch_n, level);
    if (out == 0) {
        snprintf(detail, sizeof detail, "encode refused %zu bytes at level %d", n, level);
        fail(what, detail);
    } else if (crushlz4_decode_buffer(dec, n, enc, out, &len) != 0) {
        snprintf(detail, sizeof detail, "decode rejected its own %zu-byte stream", out);
        fail(what, detail);
    } else if (len != n) {
        snprintf(detail, sizeof detail, "decoded %zu bytes, wanted %zu", len, n);
        fail(what, detail);
    } else if (n && memcmp(dec, src, n) != 0) {
        snprintf(detail, sizeof detail, "decoded %zu bytes that differ at level %d", n, level);
        fail(what, detail);
    }
    free(enc);
    free(dec);
}

/* Pseudo-random but compressible: a small alphabet with repeated runs, so
 * every buffer is full of matches and a stale table entry has somewhere
 * wrong to point. */
static void fill(uint8_t *p, size_t n, uint32_t seed)
{
    size_t i = 0;
    while (i < n) {
        seed = seed * 1103515245u + 12345u;
        if ((seed >> 28) < 6 && i > 64) {
            /* Copy an earlier run, so the buffer has real matches in it. */
            size_t back = 1 + (seed >> 8) % (i < 4096 ? i : 4096);
            size_t run  = 4 + (seed >> 20) % 60;
            if (run > n - i) run = n - i;
            for (size_t k = 0; k < run; k++, i++) p[i] = p[i - back];
        } else {
            p[i++] = (uint8_t)('a' + ((seed >> 16) % 7));
        }
    }
}

/* This test reuses one buffer at every level, so it sizes for the largest.
 * The API offers no such query by design; walking the ladder is the answer. */
static size_t lz4_ladder_max_scratch(void)
{
    size_t max = 0;
    for (int lv = CRUSHLZ4_LEVEL_MIN; lv <= CRUSHLZ4_LEVEL_MAX; lv++) {
        crushlz4_encode_params p;
        size_t n;
        crushlz4_params_for_level(lv, &p);
        n = crushlz4_scratch_size(&p);
        if (n > max) max = n;
    }
    return max;
}

int main(void)
{
    const size_t big = 300 * 1024;         /* several 64 KiB blocks */
    size_t scratch_n = lz4_ladder_max_scratch();
    void *scratch = malloc(scratch_n);
    uint8_t *a = malloc(big), *b = malloc(big);

    if (!scratch || !a || !b) { printf("FAIL out of memory\n"); return 1; }
    fill(a, big, 0x5eed);
    fill(b, big, 0xfeed);

    /* 1. The same scratch across different buffers, at every level. */
    memset(scratch, 0, scratch_n);
    for (int level = CRUSHLZ4_LEVEL_MIN; level <= CRUSHLZ4_LEVEL_MAX; level++) {
        round_trip("reuse across buffers", a, big, scratch, scratch_n, level);
        round_trip("reuse across buffers", b, big, scratch, scratch_n, level);
        /* A buffer of a different length shifts every position under the
         * table entries the last call left. */
        round_trip("reuse across sizes", b, big / 3, scratch, scratch_n, level);
        round_trip("reuse across sizes", a, 1024, scratch, scratch_n, level);
    }

    /* 2. The same scratch across levels, which changes the table's shape. */
    memset(scratch, 0, scratch_n);
    for (int level = CRUSHLZ4_LEVEL_MIN; level <= CRUSHLZ4_LEVEL_MAX; level++) {
        round_trip("reuse across levels", a, big, scratch, scratch_n, level);
        round_trip("reuse across levels", b, 70000, scratch, scratch_n, CRUSHLZ4_LEVEL_MAX - level);
    }

    /* 3. A scratch the encoder has no reason to trust. Every byte pattern
     * below has been a plausible "uninitialised buffer" at some point. */
    static const int patterns[] = { 0x00, 0xff, 0xcd, 0xa5 };
    for (size_t pi = 0; pi < sizeof patterns / sizeof patterns[0]; pi++) {
        for (int level = CRUSHLZ4_LEVEL_MIN; level <= CRUSHLZ4_LEVEL_MAX; level++) {
            memset(scratch, patterns[pi], scratch_n);
            round_trip("untrusted scratch", a, big, scratch, scratch_n, level);
        }
    }
    {   /* And one filled with noise rather than a repeated byte. */
        uint8_t *p = scratch;
        uint32_t seed = 0x1234567u;
        for (size_t i = 0; i < scratch_n; i++) {
            seed = seed * 1103515245u + 12345u;
            p[i] = (uint8_t)(seed >> 24);
        }
        for (int level = CRUSHLZ4_LEVEL_MIN; level <= CRUSHLZ4_LEVEL_MAX; level++)
            round_trip("untrusted scratch", a, big, scratch, scratch_n, level);
    }

    /* 4. Enough calls to walk the origin past what 32 bits hold and force it
     * to start over. It advances by the input length plus a full window each
     * call, so a 1 KiB input needs about 64K calls to get there; this runs
     * past that and keeps checking on the way. */
    {
        const size_t small = 1024;
        const long calls = 70000;
        int level = 3;
        memset(scratch, 0, scratch_n);
        for (long i = 0; i < calls; i++) {
            /* Alternate the contents so a stale entry has a wrong answer to
             * give, and check a sample rather than all 70000 round trips. */
            const uint8_t *src = (i & 1) ? a : b;
            if (i % 997 == 0 || i > calls - 8)
                round_trip("origin restart", src, small, scratch, scratch_n, level);
            else {
                uint8_t enc[4096];
                if (crushlz4_encode_buffer(enc, sizeof enc, src, small, scratch, scratch_n, level) == 0)
                    fail("origin restart", "encode refused mid-run");
            }
        }
    }

    free(scratch);
    free(a);
    free(b);
    printf("%s  (%d checks, %d failures)\n",
           failures ? "lz4_scratch_reuse_test FAILED" : "lz4_scratch_reuse_test ok",
           checks, failures);
    return failures ? 1 : 0;
}
