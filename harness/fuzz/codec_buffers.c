// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/* API bounds and scratch initialization/reuse for the codecs we implement.
 * One scratch allocation survives across inputs, codecs, levels and sizes.
 * MSan sees its uninitialized bytes; ASan sees only each call's logical span. */
#include "crushlzfse.h"
#include "crushlzvn.h"
#include "crushlzbitmap.h"
#include "crushlz4.h"
#include "fuzzbuf.h"
#include <stdio.h>

typedef size_t (*encoder)(void *, size_t, const void *, size_t, void *, size_t, int);
typedef int (*decoder)(void *, size_t, const void *, size_t, size_t *);
static uint8_t *scratch;
static size_t scratch_capacity;

static void fail(const char *why, unsigned codec, int level, size_t n)
{
    fprintf(stderr, "FUZZ FAILURE: %s (codec=%u level=%d input=%zu)\n", why, codec, level, n);
    abort();
}

static void run_one(const uint8_t *data, size_t size)
{
    if (size < 4) return;
    static const size_t boundaries[] = {0, 1, 7, 8, 15, 16, 31, 32, 4095,
        4096, 32767, 32768, 65535, 65536, 65537};
    unsigned codec = data[0] % 4;
    int level_min = codec == 0 ? CRUSHLZBITMAP_LEVEL_MIN :
                    codec == 1 ? CRUSHLZFSE_LEVEL_MIN :
                    codec == 2 ? CRUSHLZVN_LEVEL_MIN : CRUSHLZ4_LEVEL_MIN;
    int level_max = codec == 0 ? CRUSHLZBITMAP_LEVEL_MAX :
                    codec == 1 ? CRUSHLZFSE_LEVEL_MAX :
                    codec == 2 ? CRUSHLZVN_LEVEL_MAX : CRUSHLZ4_LEVEL_MAX;
    int level = level_min + (int)(data[1] % (unsigned)(level_max - level_min + 1));
    size_t n = boundaries[data[2] % (sizeof boundaries / sizeof boundaries[0])];
    if (data[2] & 128) n = ((size_t)data[2] << 8 | data[3]) % 65538;
    encoder encode;
    decoder decode;
    size_t need, bound;
    if (codec == 0) {
        crushlzbitmap_params p;
        crushlzbitmap_params_for_level(level, &p);
        need = crushlzbitmap_scratch_size(&p);
        bound = crushlzbitmap_encode_bound(n);
        encode = crushlzbitmap_encode_buffer; decode = crushlzbitmap_decode_buffer;
    } else if (codec == 1) {
        crushlzfse_encode_params p;
        crushlzfse_params_for_level(level, &p);
        need = crushlzfse_scratch_size(&p);
        bound = crushlzfse_encode_bound(n, &p);
        encode = crushlzfse_encode_buffer; decode = crushlzfse_decode_buffer;
    } else if (codec == 2) {
        crushlzvn_encode_params p;
        crushlzvn_params_for_level(level, &p);
        need = crushlzvn_scratch_size(&p);
        bound = crushlzvn_encode_bound(n, &p);
        encode = crushlzvn_encode_buffer; decode = crushlzvn_decode_buffer;
    } else {
        crushlz4_encode_params p;
        crushlz4_params_for_level(level, &p);
        need = crushlz4_scratch_size(&p);
        bound = crushlz4_encode_bound(n);
        encode = crushlz4_encode_buffer; decode = crushlz4_decode_buffer;
    }
    static fuzzbuf_t src_buf, fresh_buf, dst_buf, reused_buf, packed_buf, back_buf, small_buf;
    uint8_t *src = fuzz_resize(&src_buf, n);
    unsigned period = 1 + data[3] % 64;
    for (size_t i = 0; i < n; i++)
        src[i] = size > 4 ? data[4 + (i % period) % (size - 4)] : (uint8_t)(i % period);
    uint8_t *fresh = fuzz_resize(&fresh_buf, need);
    /* Do not initialize fresh scratch: MSan must see any missing initialization. */
    uint8_t *dst = fuzz_resize(&dst_buf, bound);
    size_t len = encode(dst, bound, src, n, fresh, need, level);
    if (len > bound) fail("encode exceeded bound", codec, level, n);
    fuzz_check_written(dst, len);
#ifdef FUZZ_ASAN
    if (scratch) __asan_unpoison_memory_region(scratch, scratch_capacity);
#endif
    if (scratch_capacity < need || !scratch) {
        uint8_t *grown = realloc(scratch, need ? need : 1);
        if (!grown) abort();
        scratch = grown; scratch_capacity = need ? need : 1;
    }
#ifdef FUZZ_ASAN
    if (scratch_capacity > need)
        __asan_poison_memory_region(scratch + need, scratch_capacity - need);
#endif
    uint8_t *reused = fuzz_resize(&reused_buf, bound);
    size_t rlen = encode(reused, bound, src, n, scratch, need, level);
    if (rlen != len || (len && memcmp(dst, reused, len)))
        fail("fresh/reused scratch disagree", codec, level, n);
    static guardbuf_t scratch_guard;
    if (!scratch_guard.base || scratch_guard.span < need) {
        if (scratch_guard.base) guardbuf_destroy(&scratch_guard);
        guardbuf_init(&scratch_guard, need);
    }
    /* Keep the documented 16-byte scratch alignment. Back placement is
     * useful only when the queried size preserves it. */
    uint8_t *guarded = need % 16 ? guard_view(&scratch_guard, need, 1)
                               : guard_dst(&scratch_guard, need);
    if (need) memset(guarded, data[3], need);
    size_t glen = encode(reused, bound, src, n, guarded, need, level);
    if (glen != len || (len && memcmp(dst, reused, len)))
        fail("scratch initialization changes output", codec, level, n);
    if (need) {
        uint8_t *short_scratch = fuzz_resize(&small_buf, need - 1);
        if (encode(reused, bound, src, n, short_scratch, need - 1, level))
            fail("accepted undersized scratch", codec, level, n);
    }
    if (!len) return;
    const uint8_t *packed = fuzz_copy(&packed_buf, dst, len);
    size_t capacities[] = {0, n ? n - 1 : 0, n, n + 1};
    for (size_t j = 0; j < 4; j++) {
        size_t cap = capacities[j], got = 0;
        uint8_t *back = fuzz_resize(&back_buf, cap);
        int rc = decode(back, cap, packed, len, &got);
        if (got > cap) fail("decode reported beyond capacity", codec, level, n);
        fuzz_check_written(back, got);
        if (rc == 0 && (got != n || (got && memcmp(back, src, got))))
            fail("decode returned wrong bytes", codec, level, n);
        if (cap >= n && rc != 0) fail("decode rejected sufficient capacity", codec, level, n);
    }
    /* An encoder may choose a different representation in a smaller buffer.
     * Check any emitted stream instead of assuming it must fail. */
    size_t encode_caps[] = {0, len - 1, len};
    for (size_t j = 0; j < 3; j++) {
        size_t cap = encode_caps[j];
        uint8_t *small = fuzz_resize(&small_buf, cap);
        fuzz_poison(scratch, need);
        size_t written = encode(small, cap, src, n, scratch, need, level);
        if (written > cap) fail("small encode exceeded capacity", codec, level, n);
        fuzz_check_written(small, written);
        if (written) {
            uint8_t *back = fuzz_resize(&back_buf, n);
            size_t got = 0;
            if (decode(back, n, small, written, &got) || got != n || (n && memcmp(back, src, n)))
                fail("small encode produced invalid output", codec, level, n);
        }
    }
}
#include "driver.h"
