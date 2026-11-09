// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Checks that the LZFSE decoder never reads past the end of its input; the
// mirror of lzfse_decode_extent_test, which guards the destination.
//
// Streams are truncated at each block's payload end and decoded with the
// input ending on a PROT_NONE guard page, so the test means something in a
// plain build as well as under ASan. The run fails if the truncations did not
// cover every final bit alignment.

#include "lzfse.h"
#include "lzfse_internal.h" // block magics and the v2 header layout
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

// Large enough that the encoder emits many blocks, so every odd-bit alignment
// of a block's LMD stream comes up across the payloads.
#define PAYLOAD_LEN (1u << 20)
#define N_PAYLOADS 4
#define MAX_BOUNDARIES 4096

// Content shaped to compress differently, so block lengths, and with them
// the bit alignment each block's stream ends on, vary between payloads.
static size_t make_payload(int which, uint8_t *buf, size_t cap) {
    uint32_t x = 2463534242u + (uint32_t)which * 7919u;
    for (size_t n = 0; n < cap; n++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        uint8_t b;
        switch (which) {
        case 0:  b = (uint8_t)((n % 97) < 40 ? 'a' + (n % 26) : (x >> 16)); break;
        case 1:  b = (uint8_t)(((n / 3) & 1) ? 0 : (x >> 8)); break;
        case 2:  b = (uint8_t)((x % 5) ? 0xff : (x >> 20)); break;
        default: b = (uint8_t)(n * 31 + (x >> 28)); break;
        }
        buf[n] = b;
    }
    return cap;
}

static uint32_t field(uint64_t v, int offset, int nbits) {
    return nbits == 32 ? (uint32_t)(v >> offset)
                       : (uint32_t)((v >> offset) & ((1u << nbits) - 1));
}

// Offsets at which some block's payload ends. Returns how many were found, or
// -1 if the stream held a block shape this walk does not know.
//
// Each piece the caller joined (see encode_multi_block below) is on its own
// complete LZFSE stream before joining, so a piece whose own content did not
// favour the V2 path (raw or LZVN-in-LZFSE, both of which crushlzfse.c
// still falls back to per piece) shows up here too. Neither carries the
// LMD bit-alignment this walk is fuzzing, so both are skipped over rather
// than recorded as a boundary; only a V2 block's end goes in `out`.
static int payload_ends(const uint8_t *s, size_t len, size_t *out, int cap,
                        int *lmd_bits_seen) {
    int n = 0;
    size_t p = 0;
    while (p + 4 <= len && n < cap) {
        uint32_t magic;
        memcpy(&magic, s + p, 4);
        if (magic == LZFSE_ENDOFSTREAM_BLOCK_MAGIC) return n;

        if (magic == LZFSE_UNCOMPRESSED_BLOCK_MAGIC) {
            if (p + sizeof(uncompressed_block_header) > len) return n;
            uncompressed_block_header h;
            memcpy(&h, s + p, sizeof h);
            p += sizeof(h) + h.n_raw_bytes;
            if (p > len) return n;
            continue;
        }
        if (magic == LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC) {
            if (p + sizeof(lzvn_compressed_block_header) > len) return n;
            lzvn_compressed_block_header h;
            memcpy(&h, s + p, sizeof h);
            p += sizeof(h) + h.n_payload_bytes;
            if (p > len) return n;
            continue;
        }
        if (magic != LZFSE_COMPRESSEDV2_BLOCK_MAGIC) return -1;
        if (p + sizeof(lzfse_compressed_block_header_v2) > len) return n;

        lzfse_compressed_block_header_v2 h;
        memcpy(&h, s + p, sizeof h);
        uint32_t header_size = field(h.packed_fields[2], 0, 32);
        uint32_t lit_bytes = field(h.packed_fields[0], 20, 20);
        uint32_t lmd_bytes = field(h.packed_fields[1], 40, 20);
        // The LMD stream's odd-bit count, biased by 7 in the header.
        lmd_bits_seen[field(h.packed_fields[1], 60, 3)] = 1;

        p += (size_t)header_size + lit_bytes + lmd_bytes;
        if (p > len) return n;
        out[n++] = p;
    }
    return n;
}

// lzfse_encode_buffer (CrushLZFSE level 0) now accepts at most one
// already-independent LZFSE_ZOPT_BLOCK_SIZE (65536-byte) piece per call and
// rejects anything larger outright: it no longer chunks a large payload
// into one joined multi-block stream itself. This test's whole point is to
// throw a stream with many physical LZFSE blocks at the decoder, so it
// builds one here the same way the encoder used to internally: encode each
// <=65536-byte piece on its own and concatenate the results, dropping every
// end-of-stream marker but the last. The decoder does not care how a
// multi-block stream was produced, only that it is well-formed, so this
// changes nothing about what is actually being tested.
static size_t encode_multi_block(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t n,
                                 void *scratch) {
    static uint8_t piece[65536 * 2 + 4096];
    size_t in = 0, out = 0;
    do {
        size_t chunk = n - in < 65536 ? n - in : 65536;
        size_t sz = lzfse_encode_buffer(piece, sizeof(piece), src + in, chunk, scratch);
        if (sz == 0 || out + sz > dst_cap) return 0;
        memcpy(dst + out, piece, sz);
        in += chunk;
        out += sz;
        if (in < n) out -= 4; // drop this piece's bvx$ but the stream's last
    } while (in < n);
    return out;
}

int main(void) {
    uint8_t *raw = malloc(PAYLOAD_LEN);
    size_t enc_cap = (size_t)PAYLOAD_LEN * 2 + 4096;
    uint8_t *enc = malloc(enc_cap);
    void *escratch = malloc(lzfse_encode_scratch_size());
    size_t dss = lzfse_decode_scratch_size();
    void *dscratch = malloc(dss ? dss : 1);
    uint8_t *dst = malloc(PAYLOAD_LEN);
    size_t *ends = malloc(MAX_BOUNDARIES * sizeof *ends);
    int lmd_bits_seen[8] = {0};
    long decodes = 0, boundaries = 0;
    int failures = 0;

    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t span = ((enc_cap + page - 1) / page) * page;
    uint8_t *base = mmap(NULL, span + page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 2; }
    if (mprotect(base + span, page, PROT_NONE) != 0) { perror("mprotect"); return 2; }
    uint8_t *guard_end = base + span;

    // An unarmed guard and a decoder that never over-reads look identical from
    // here, so prove the guard faults before trusting a clean run.
    {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 2; }
        if (pid == 0) { volatile uint8_t v = guard_end[0]; (void)v; _exit(0); }
        int st = 0;
        if (waitpid(pid, &st, 0) != pid) { perror("waitpid"); return 2; }
        // The child does nothing but the read, so any exit other than clean
        // means it faulted (a signal bare, a non-zero exit under ASan).
        int armed = WIFSIGNALED(st) || (WIFEXITED(st) && WEXITSTATUS(st) != 0);
        if (!armed) {
            printf("GUARD NOT ARMED: a read past the mapping did not fault\n");
            return 2;
        }
        printf("guard armed (a read past the mapping %s)\n",
               WIFSIGNALED(st) ? "raised a signal" : "was trapped by a sanitizer");
    }

    for (int p = 0; p < N_PAYLOADS; p++) {
        size_t n = make_payload(p, raw, PAYLOAD_LEN);
        size_t enc_len = encode_multi_block(enc, enc_cap, raw, n, escratch);
        if (enc_len == 0) { printf("payload %d: encoder refused, skipped\n", p); continue; }

        int nb = payload_ends(enc, enc_len, ends, MAX_BOUNDARIES, lmd_bits_seen);
        if (nb < 0) {
            printf("payload %d: unrecognised block shape, not walked\n", p);
            failures++;
            continue;
        }

        // Each payload end, plus a short window below it.
        for (int i = 0; i < nb; i++) {
            for (size_t d = 0; d < 4; d++) {
                if (ends[i] <= d) continue;
                size_t t = ends[i] - d;
                uint8_t *src = guard_end - t;   // last source byte abuts the guard
                memcpy(src, enc, t);
                (void)lzfse_decode_buffer(dst, PAYLOAD_LEN, src, t, dscratch);
                decodes++;
            }
        }
        boundaries += nb;
        printf("payload %d len=%zu enc=%zu  %d block boundaries truncated to\n",
               p, n, enc_len, nb);
    }

    // Reaching only some alignments does not test what this file is for.
    int alignments = 0;
    for (int i = 0; i < 8; i++) alignments += lmd_bits_seen[i];
    printf("LMD odd-bit alignments reached: %d of 8\n", alignments);
    if (alignments < 8) {
        printf("COVERAGE SHORTFALL: some final bit alignments are untested\n");
        failures++;
    }

    printf("%ld decodes over %ld block boundaries, no read past the end of the input\n",
           decodes, boundaries);
    printf("%s\n", failures ? "FAILED" : "ok");
    free(raw); free(enc); free(escratch); free(dscratch); free(dst); free(ends);
    munmap(base, span + page);
    return failures != 0;
}
