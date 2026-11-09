// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
/*
 * Hand-built LZBITMAP streams at the edges of the format, decoded by
 * CrushLZBITMAP and, on macOS, by Apple's libcompression. Each case is one
 * question the format spec (docs/lzbitmap-format.md) has to answer; Apple's
 * result is the evidence. Prints one line per case:
 *
 *   case  crush=<status> len=<n> hash=<h>  apple=len=<n> hash=<h>  same|DIFFERENT
 *
 * Apple's compression_decode_buffer returns 0 both for an error and for empty
 * output, so "apple=0" reads as rejected for every case here (none decodes to
 * nothing). Pass -v to also print each stream and output in hex.
 *
 * The original all-literal prefix made question cases larger than their
 * stored form, so Apple rejected even the baseline. Question cases now use
 * an actually compressed prefix. size_* still distinguishes tiny and
 * oversized encodings; it does not isolate a separate minimum-size rule.
 *
 *   zbm_edge_cases [-v]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzbitmap.h"

#ifdef __APPLE__
#include <compression.h>
#endif

#define CHUNK 32768

/* ---- stream builder ------------------------------------------------------ */

static uint8_t stream[3 * CHUNK];
static size_t slen;

static void put(const void *p, size_t n) { memcpy(stream + slen, p, n); slen += n; }
static void put_u24(uint32_t v) {
    uint8_t b[3] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16) };
    put(b, 3);
}
static void begin(void) { slen = 0; put("ZBM\x09", 4); }
static void end_chunk(void) { put_u24(6); put_u24(0); }

/* A stored chunk: header then the bytes as they are. */
static void stored(const uint8_t *data, uint32_t n) {
    put_u24(n + 6);
    put_u24(n);
    put(data, n);
}

/* One compressed chunk. The table has twelve entries, selected by nibbles
 * 3..14; nibbles 0..2 take an explicit bitmap from meta2 with that many
 * period bytes from meta1. */
struct cchunk {
    uint32_t decmp_len;
    const uint8_t *lits; size_t nlits;
    const uint8_t *m1; size_t nm1;
    const uint8_t *m2; size_t nm2;
    const uint8_t *nib; size_t nnib;
    uint8_t bmp[12], pbc[12];
    size_t m1_unused, m2_unused, m3_unused;  /* trailing bytes left unread */
    uint8_t tail[2];                         /* table bytes 15 and 16 */
    int overlap;  /* final selector nibbles read from the start of the table */
    unsigned lead; /* all-literal blocks first, via table entry 11 */
};

static uint8_t lit[CHUNK], filler[CHUNK];

/* Prefix @c with one literal block (entry 11) and lead-1 copy blocks
 * (entry 10). Merely adding literals leaves len > decmp_len+6, which Apple
 * rejects regardless of chunk size and masks the question being tested. */
static struct cchunk with_lead(const struct cchunk *c, uint8_t *nib, uint8_t *lits) {
    struct cchunk d = *c;
    size_t n = 0;

    if (!c->lead) return d;
    if (c->bmp[11] || c->pbc[11] || c->bmp[10] || c->pbc[10]) {
        fprintf(stderr, "a lead needs table entries 10 and 11 free\n");
        exit(2);
    }
    /* One block, then a run of lead - 1: 4 + the nibbles after the 0xf. */
    nib[n++] = 14;
    if (c->lead - 1 >= 4) {
        unsigned r = c->lead - 1 - 4;
        nib[n++] = 13;
        nib[n++] = 0xf;
        while (r >= 15) { nib[n++] = 0xf; r -= 15; }
        nib[n++] = (uint8_t)r;
    } else {
        for (unsigned i = 1; i < c->lead; i++) nib[n++] = 13;
    }
    memcpy(nib + n, c->nib, c->nnib);
    d.nib = nib; d.nnib = n + c->nnib;
    memcpy(lits, filler, 8);
    memcpy(lits + 8, c->lits, c->nlits);
    d.lits = lits; d.nlits = 8 + c->nlits;
    d.decmp_len = c->decmp_len + c->lead * 8;
    d.bmp[11] = 0xff;
    return d;
}

static void compressed(const struct cchunk *orig) {
    static uint8_t lead_nib[CHUNK], lead_lits[CHUNK];
    struct cchunk led = with_lead(orig, lead_nib, lead_lits);
    const struct cchunk *c = &led;
    uint8_t m3[CHUNK], table[17] = {0};
    size_t nm3 = 0, nnib = c->nnib - (size_t)c->overlap;

    for (size_t i = 0; i < nnib; i++) {
        if (i % 2 == 0) m3[nm3++] = c->nib[i] & 0xf;
        else m3[nm3 - 1] |= (uint8_t)(c->nib[i] << 4);
    }
    for (int i = 0; i < 12; i++) {
        uint32_t v = c->bmp[i] | (uint32_t)c->pbc[i] << 8;
        for (int b = 0; b < 10; b++)
            if (v >> b & 1) table[(10 * i + b) / 8] |= (uint8_t)(1u << (10 * i + b) % 8);
    }
    table[15] = c->tail[0];
    table[16] = c->tail[1];
    for (int i = 0; i < c->overlap; ++i)
        if (((table[i / 2] >> (4 * (i % 2))) & 0xf) != c->nib[nnib + (size_t)i]) {
            fprintf(stderr, "overlap case needs table nibbles to match\n");
            exit(2);
        }

    uint32_t off1 = 15 + (uint32_t)c->nlits;
    uint32_t off2 = off1 + (uint32_t)(c->nm1 + c->m1_unused);
    uint32_t off3 = off2 + (uint32_t)(c->nm2 + c->m2_unused);
    uint32_t len = off3 + (uint32_t)(nm3 + c->m3_unused) + 17;
    static const uint8_t zero[64];

    put_u24(len); put_u24(c->decmp_len);
    put_u24(off1); put_u24(off2); put_u24(off3);
    put(c->lits, c->nlits);
    put(c->m1, c->nm1); put(zero, c->m1_unused);
    put(c->m2, c->nm2); put(zero, c->m2_unused);
    put(m3, nm3); put(zero, c->m3_unused);
    put(table, 17);
}

/* ---- decoding and reporting ---------------------------------------------- */

static int verbose;

static uint64_t fnv1a(const uint8_t *p, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 1099511628211ull;
    return h;
}

static void hex(const char *label, const uint8_t *p, size_t n) {
    printf("    %s (%zu):", label, n);
    for (size_t i = 0; i < n && i < 96; i++) printf(" %02x", p[i]);
    printf(n > 96 ? " ...\n" : "\n");
}

static void run(const char *name, const char *question) {
    static uint8_t out[4 * CHUNK];
    size_t got = 0;
    int rc = crushlzbitmap_decode_buffer(out, sizeof out, stream, slen, &got);
    const char *st = rc == 0 ? "ok" : rc == CRUSHLZBITMAP_INVALID ? "INVALID" : "TOO_SMALL";
    uint64_t h = rc == 0 ? fnv1a(out, got) : 0;

    printf("%-28s crush=%-7s len=%-6zu hash=%016llx", name, st, rc == 0 ? got : 0,
           (unsigned long long)h);
#ifdef __APPLE__
    static uint8_t aout[4 * CHUNK];
    size_t alen = compression_decode_buffer(aout, sizeof aout, stream, slen, NULL,
                                            COMPRESSION_LZBITMAP);
    uint64_t ah = alen ? fnv1a(aout, alen) : 0;
    int same = (rc == 0) ? (alen == got && ah == h) : (alen == 0);
    printf("  apple=len=%-6zu hash=%016llx  %s", alen, (unsigned long long)ah,
           same ? "same" : "DIFFERENT");
#endif
    printf("\n");
    if (verbose) {
        printf("    %s\n", question);
        hex("stream", stream, slen);
        if (rc == 0) hex("crush ", out, got);
#ifdef __APPLE__
        if (alen) hex("apple ", aout, alen);
#endif
    }
}

/* The baseline compressed chunk: 24 bytes as three blocks, after a lead of
 * LEAD blocks with a repeated eight-byte pattern. Blocks 1 and 2 are all literal (table entry 1,
 * nibble 4); block 3 uses table entry 0 (nibble 3), bitmap 0x03: two
 * literals, six bytes copied from 8 back. */
#define LEAD 20
static struct cchunk base24(void) {
    static const uint8_t nib[] = { 4, 4, 3 };
    struct cchunk c = {0};
    c.decmp_len = 24;
    c.lits = lit; c.nlits = 18;
    c.nib = nib; c.nnib = 3;
    c.bmp[0] = 0x03; c.bmp[1] = 0xff;
    c.lead = LEAD;
    return c;
}

/* A chunk of n all-literal blocks and nothing else, no lead. */
static void literal_chunk(unsigned blocks) {
    static uint8_t nib[64];
    struct cchunk c = {0};
    size_t k = 0;
    nib[k++] = 4;
    if (blocks >= 5) {
        unsigned r = blocks - 1 - 4;
        nib[k++] = 4; nib[k++] = 0xf;
        while (r >= 15) { nib[k++] = 0xf; r -= 15; }
        nib[k++] = (uint8_t)r;
    } else {
        for (unsigned i = 1; i < blocks; i++) nib[k++] = 4;
    }
    c.decmp_len = blocks * 8; c.lits = lit; c.nlits = blocks * 8;
    c.nib = nib; c.nnib = k; c.bmp[1] = 0xff;
    compressed(&c);
}

int main(int argc, char **argv) {
    verbose = argc > 1 && strcmp(argv[1], "-v") == 0;
    for (int i = 0; i < CHUNK; i++) {
        lit[i] = (uint8_t)(0x41 + i % 26);
        filler[i] = (uint8_t)(i * 7 + 1);
    }

    struct cchunk c;
    char name[64];

    /* ---- the smallest compressed chunk Apple decodes ---- */
    static const unsigned sizes[] = { 1, 2, 3, 4, 5, 6, 8, 12, 16, 20, 32 };
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        begin(); literal_chunk(sizes[i]); end_chunk();
        snprintf(name, sizeof name, "size_literal_%u", sizes[i] * 8);
        run(name, "One compressed chunk of all-literal blocks. Smallest Apple decodes?");
    }
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        static uint8_t nib[64];
        unsigned blocks = sizes[i];
        size_t k = 0;
        nib[k++] = 3;
        if (blocks >= 5) {
            unsigned r = blocks - 1 - 4;
            nib[k++] = 3; nib[k++] = 0xf;
            while (r >= 15) { nib[k++] = 0xf; r -= 15; }
            nib[k++] = (uint8_t)r;
        } else {
            for (unsigned j = 1; j < blocks; j++) nib[k++] = 3;
        }
        begin();
        stored(filler, 8);
        c = (struct cchunk){0};
        c.decmp_len = blocks * 8; c.nib = nib; c.nnib = k; c.bmp[0] = 0x00;
        compressed(&c);
        end_chunk();
        snprintf(name, sizeof name, "size_copy_%u", blocks * 8);
        run(name, "8 stored bytes, then a compressed chunk of blocks copied from 8 back. "
                  "Smallest Apple decodes?");
    }

    /* ---- the questions, each compressed chunk behind a repeated 160-byte lead ---- */
    begin(); c = base24(); compressed(&c); end_chunk();
    run("baseline", "Control: a plain valid chunk. Must decode the same on both.");

    /* The overlap needs an odd nibble count; a 35-block lead gives one. */
    begin(); c = base24(); c.lead = 35; compressed(&c); end_chunk();
    run("meta3_overlap_control", "Baseline with a 35-block lead: the overlap case's control.");

    begin(); c = base24(); c.lead = 35; c.overlap = 1; compressed(&c); end_chunk();
    run("meta3_overlaps_table",
        "Same output as its control, but the last block selector is the low nibble "
        "of the bitmap table's first byte instead of its own meta3 byte. Accepted?");

    {
        static const uint8_t nib[] = {4, 4, 3, 3};
        begin(); c = base24(); c.lead = 35; c.decmp_len = 32;
        c.nib = nib; c.nnib = 4; c.bmp[0] = 0x33; c.nlits = 24;
        compressed(&c); end_chunk();
        run("meta3_two_nibble_control", "Two mixed final blocks, separate selector bytes.");
        begin(); c.overlap = 2; compressed(&c); end_chunk();
        run("meta3_two_table_nibbles", "Same blocks, both selectors in table byte 0.");
    }

    {
        /* The lead's first selector byte is 0xde: literal entry 11, then
         * copy entry 10. Reading that byte as the second bitmap needs six
         * literals, so both the control and overlap supply those literals. */
        static const uint8_t nib[] = {0, 0}, m2[] = {0, 0xde};
        begin(); c = (struct cchunk){0}; c.lead = LEAD; c.decmp_len = 16;
        c.nib = nib; c.nnib = 2; c.m2 = m2; c.nm2 = 2;
        c.lits = lit; c.nlits = 6;
        compressed(&c); end_chunk();
        run("meta2_overlap_control", "Two explicit bitmaps in their own area.");
        begin(); c.nm2 = 1; compressed(&c); end_chunk();
        run("meta2_reads_meta3", "Second explicit bitmap is the first selector byte.");
    }

    {
        /* Explicit selectors run 16 times. With no separate bitmap area,
         * the bytes read are de ff 00 cf (selectors), then 12 table bytes.
         * The latter are zero here. Their popcounts consume 20 literals. */
        static const uint8_t nib[] = {0, 0xf, 12};
        static const uint8_t m2[16] = {0xde, 0xff, 0, 0xcf};
        begin(); c = (struct cchunk){0}; c.lead = LEAD; c.decmp_len = 128;
        c.nib = nib; c.nnib = 3; c.lits = lit; c.nlits = 20;
        c.m2 = m2; c.nm2 = sizeof m2;
        compressed(&c); end_chunk();
        run("meta2_table_control", "Sixteen explicit bitmaps in separate storage.");
        begin(); c.nm2 = 0; compressed(&c); end_chunk();
        run("meta2_reads_table", "Bitmaps reuse four selector bytes and twelve table bytes.");
    }

    for (unsigned blocks = 4; blocks <= 16; ++blocks) {
        uint8_t nib[] = {0, 0xf, (uint8_t)(blocks - 4)};
        uint8_t last = (uint8_t)(0xf | ((blocks - 4) << 4));
        begin(); c = (struct cchunk){0}; c.lead = LEAD; c.decmp_len = blocks * 8;
        c.nib = nib; c.nnib = 3; c.lits = lit;
        c.nlits = 14 + (size_t)__builtin_popcount(last);
        compressed(&c); end_chunk();
        snprintf(name, sizeof name, "meta2_table_bytes_%u", blocks - 4);
        run(name, "Explicit bitmaps reuse selector storage and this many table bytes.");
    }

    {
        /* LEAD=20 ends with count nibble 0. Apple's standalone 0xf
         * reportedly reuses that nibble as explicit selector 0. */
        static const uint8_t normal[] = {0, 0xf, 0}, reuse[] = {0xf, 1};
        static const uint8_t m2[4] = {0, 0, 0, 0};
        begin(); c = (struct cchunk){0}; c.lead = LEAD; c.decmp_len = 32;
        c.nib = normal; c.nnib = 3; c.m2 = m2; c.nm2 = 4;
        compressed(&c); end_chunk();
        run("selector_f_control", "Four explicit copy blocks with the ordinary run form.");
        begin(); c.nib = reuse; c.nnib = 2; compressed(&c); end_chunk();
        run("selector_f_reuses_count", "Standalone 0xf reuses the previous run's terminal count nibble.");
    }

    for (unsigned prefix = 1; prefix < 8; ++prefix) {
        /* Every actual copy is from produced output, although the block's
         * start is closer than eight bytes to the beginning of output. */
        static const uint8_t nib[] = {3, 4, 0xf, 11};
        uint8_t expect[135];
        unsigned literals = 8 - prefix;
        begin(); stored(filler, prefix); c = (struct cchunk){0};
        c.decmp_len = 128; c.nib = nib; c.nnib = 4;
        c.bmp[0] = (uint8_t)((1u << literals) - 1);
        c.lits = lit; c.nlits = literals;
        compressed(&c); end_chunk();
        snprintf(name, sizeof name, "copy_after_literals_prefix_%u", prefix);
        run(name, "Literal prefix makes each live copy valid, despite the block-start distance.");
        memcpy(expect, filler, prefix);
        for (unsigned j = 0; j < 128; ++j)
            expect[prefix + j] = j < literals ? lit[j] : expect[prefix + j - 8];
        if (verbose)
            printf("    semantic len=%u hash=%016llx\n", prefix + 128,
                   (unsigned long long)fnv1a(expect, prefix + 128));
    }

    begin(); c = base24(); compressed(&c); end_chunk(); put("\x01\x02\x03\x04\x05", 5);
    run("trailing_bytes", "Baseline plus 5 bytes after the end chunk. Ignored or rejected?");

    {   /* A 180-byte chunk, then a chunk whose blocks copy from its end. */
        static const uint8_t nibA[] = { 4, 4, 4 }, nibB[] = { 2, 3 };
        static const uint8_t m1B[] = { (LEAD * 8 + 20) & 0xff, (LEAD * 8 + 20) >> 8 };
        static const uint8_t m2B[] = { 0x00 };
        begin();
        c = (struct cchunk){0};
        c.decmp_len = 20; c.lits = lit; c.nlits = 20; c.nib = nibA; c.nnib = 3;
        c.bmp[1] = 0xff; c.lead = LEAD;
        compressed(&c);
        c = (struct cchunk){0};
        c.decmp_len = 16; c.m1 = m1B; c.nm1 = 2; c.m2 = m2B; c.nm2 = 1;
        c.nib = nibB; c.nnib = 2; c.bmp[0] = 0x00; c.lead = LEAD;
        compressed(&c);
        end_chunk();
        run("short_chunk_then_copy",
            "A 180-byte chunk (not 32 KiB, not a multiple of 8), then a chunk whose "
            "last blocks copy from the first chunk's last 20 bytes. Same bytes?");
    }

    {   /* A full stored chunk, then copies reaching back into it. */
        static const uint8_t nib[] = { 2, 3 };
        static const uint8_t m1[] = { (LEAD * 8 + 300) & 0xff, (LEAD * 8 + 300) >> 8 };
        static const uint8_t m2[] = { 0x00 };
        begin();
        stored(filler, CHUNK);
        c = (struct cchunk){0};
        c.decmp_len = 16; c.m1 = m1; c.nm1 = 2; c.m2 = m2; c.nm2 = 1;
        c.nib = nib; c.nnib = 2; c.bmp[0] = 0x00; c.lead = LEAD;
        compressed(&c);
        end_chunk();
        run("copy_across_chunks",
            "Copies whose source lies 300 bytes into the previous chunk. Does "
            "history carry across chunks?");
    }

    {   /* Chunk A sets period 300; chunk B copies without setting one. */
        static const uint8_t nibA[] = { 2 }, m1A[] = { 0x2c, 0x01 }, m2A[] = { 0x00 };
        static const uint8_t nibB[] = { 3 };
        begin();
        stored(filler, 400);
        c = (struct cchunk){0};
        c.decmp_len = 8; c.m1 = m1A; c.nm1 = 2; c.m2 = m2A; c.nm2 = 1;
        c.nib = nibA; c.nnib = 1; c.lead = LEAD;
        compressed(&c);
        c = (struct cchunk){0};
        c.decmp_len = 8; c.nib = nibB; c.nnib = 1; c.bmp[0] = 0x00; c.lead = LEAD;
        compressed(&c);
        end_chunk();
        run("period_at_chunk_start",
            "Chunk A ends with period 300; chunk B's last block copies with no period "
            "of its own. Crush uses 8 (reset per chunk). Same bytes from Apple?");
    }

    begin(); c = base24(); c.pbc[9] = 3; compressed(&c); end_chunk();
    run("unused_table_entry_pbc3",
        "Baseline, but table entry 9 (never selected) has period byte count 3. "
        "Crush rejects the chunk. Apple?");

    begin(); c = base24(); c.tail[0] = 0xff; c.tail[1] = 0xff; compressed(&c); end_chunk();
    run("table_tail_bytes_set",
        "Baseline with the two unused bytes after the 120-bit table set to 0xff. "
        "Ignored?");

    {   /* An explicit bitmap repeated: does each repetition read a new byte? */
        static const uint8_t nib[] = { 0, 0xf, 0 }, m2[] = { 0xff, 0x0f, 0xf0, 0x00 };
        begin();
        c = (struct cchunk){0};
        c.decmp_len = 32; c.lits = lit; c.nlits = 16; c.m2 = m2; c.nm2 = 4;
        c.nib = nib; c.nnib = 3; c.lead = LEAD;
        compressed(&c);
        end_chunk();
        run("explicit_bitmap_repeated",
            "Explicit-bitmap nibble 0 repeated 4 times. Crush reads a new meta2 "
            "bitmap for each repetition. Same bytes from Apple?");
    }

    {   /* A run naming more blocks than the chunk has output left. */
        static const uint8_t nib[] = { 4, 0xf, 5 };
        begin();
        c = (struct cchunk){0};
        c.decmp_len = 12; c.lits = lit; c.nlits = 12; c.nib = nib; c.nnib = 3;
        c.bmp[1] = 0xff; c.lead = LEAD;
        compressed(&c);
        end_chunk();
        run("run_past_chunk_end",
            "A 9-block run with 12 bytes of the chunk left. Crush ignores the "
            "surplus blocks (Apple's encoder emits these). Control.");
    }

    {   /* Surplus blocks must not consume another explicit bitmap. */
        static const uint8_t nib[] = { 0, 0xf, 5 }, m2[] = { 0x00, 0x00 };
        begin(); c = (struct cchunk){0};
        c.decmp_len = 12; c.nib = nib; c.nnib = 3;
        c.m2 = m2; c.nm2 = 2; c.lead = LEAD;
        compressed(&c); end_chunk();
        run("run_past_end_explicit",
            "A 9-block explicit run with only 12 output bytes and two bitmaps left.");
    }

    {   /* Nor should they consume another period update. */
        static const uint8_t nib[] = { 3, 0xf, 5 }, m1[] = { 8, 8 };
        begin(); c = (struct cchunk){0};
        c.decmp_len = 12; c.nib = nib; c.nnib = 3;
        c.bmp[0] = 0; c.pbc[0] = 1;
        c.m1 = m1; c.nm1 = 2; c.lead = LEAD;
        compressed(&c); end_chunk();
        run("run_past_end_period",
            "A 9-block table run with only 12 output bytes and two periods left.");
    }

    {   /* A trailing partial block whose bitmap has literal bits past its end. */
        static const uint8_t nib[] = { 4 };
        begin();
        c = (struct cchunk){0};
        c.decmp_len = 4; c.lits = lit; c.nlits = 4; c.nib = nib; c.nnib = 1;
        c.bmp[1] = 0xff; c.lead = LEAD;
        compressed(&c);
        end_chunk();
        run("partial_block_extra_bits",
            "A final 4-byte partial block using bitmap 0xff: literal bits past the "
            "chunk's end consume nothing, so 4 literal bytes. Accepted?");
    }

    begin(); c = base24(); c.m2_unused = 3; compressed(&c); end_chunk();
    run("meta2_unused_bytes", "Baseline with 3 unread bytes at the end of meta2. Accepted?");

    begin(); c = base24(); c.m3_unused = 2; compressed(&c); end_chunk();
    run("meta3_unused_bytes", "Baseline with 2 unread bytes at the end of meta3. Accepted?");

    begin(); c = base24(); c.nlits = 19; compressed(&c); end_chunk();
    run("literal_unused_byte",
        "Baseline with one literal byte never consumed. Crush rejects. Apple?");

    begin(); c = base24(); c.m1_unused = 1; compressed(&c); end_chunk();
    run("meta1_unused_byte",
        "Baseline with one meta1 byte never consumed. Crush rejects. Apple?");

    /* ---- already settled with small chunks: both sides agreed ---- */
    {   /* 5 blocks copied at period 8 in 14 bytes of areas: len == decmp + 6. */
        static const uint8_t nib[] = { 3, 0xf, 1 };
        for (int pad = 11; pad <= 12; pad++) {
            begin();
            stored(filler, 8);
            c = (struct cchunk){0};
            c.decmp_len = 40; c.nib = nib; c.nnib = 3; c.bmp[0] = 0x00;
            c.m2_unused = (size_t)pad;
            compressed(&c);
            end_chunk();
            run(pad == 11 ? "compressed_len_decmp_plus_5" : "compressed_len_decmp_plus_6",
                "A compressed chunk whose length is decmp_len + 5 (control) or + 6, "
                "the stored-chunk length. Crush decodes + 6 as stored bytes. Apple?");
        }
    }

    {   /* A copy before any output exists. */
        static const uint8_t nib[] = { 3 };
        begin();
        c = (struct cchunk){0};
        c.decmp_len = 8; c.lits = lit; c.nlits = 2; c.nib = nib; c.nnib = 1;
        c.bmp[0] = 0x03;
        compressed(&c);
        end_chunk();
        run("copy_before_output_start",
            "First block copies 6 bytes from 8 back, before any output. Crush "
            "rejects. Apple?");
    }

    begin(); stored(filler, CHUNK + 1); end_chunk();
    run("stored_chunk_over_32k",
        "One stored chunk of 32769 bytes, one past the chunk size. Crush rejects. "
        "Apple?");

    return 0;
}
