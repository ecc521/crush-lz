// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Validates lzvn_zopt_build_candidates (the match-tree candidate search)
// feeding lzvn_pareto_run_dp at pareto_k=1:
//   1. A constructed 3-byte-only match (4th byte differs) is found, since
//      LZVN can encode 3-byte matches and a 4-byte-keyed search would miss it.
//   2. Round-trip through the real lzvn_decode() across repetitive, random
//      and structured content.
//   3. A sanity floor against Apple's real LZVN encoder on repetitive
//      content (macOS only, via libcompression).

#include "lzvn_encode_base.c"
#include "lzvn_decode_base.c"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <compression.h>
#define CRUSHLZVN_CANDIDATE_HAVE_APPLE 1
/* COMPRESSION_LZVN was dropped from the public enum in recent SDKs, but
 * libcompression still implements it at its long-stable value. */
#ifndef COMPRESSION_LZVN
#define COMPRESSION_LZVN ((compression_algorithm)0x900)
#endif
#endif

static int g_failures = 0;
static int g_cases = 0;

// Round-trips a buffer through build candidates -> DP -> commit and the real
// decoder. Returns the payload size (excluding the end-of-stream marker), or
// -1 on a failure already printed. The DP scratch is always sized for the one
// fixed LZVN_ZOPT_BLOCK_SIZE, regardless of this call's own (smaller) `n`, so
// it is malloc'd fresh each time rather than kept in a fixed-size static.
static int32_t roundtrip_optimal(const char *label, const unsigned char *src,
                                 int32_t n, int32_t depth, int32_t hash_bits) {
  g_cases++;
  int32_t cand_capacity = depth < 32 ? depth : 32;
  if (cand_capacity < 1) cand_capacity = 1;
  size_t need = lzvn_zopt_scratch_size(cand_capacity, hash_bits);
  lzvn_zopt_scratch *z = (lzvn_zopt_scratch *)malloc(need);
  if (!z) {
    printf("FAIL %s: zopt scratch allocation failed (%zu bytes)\n", label, need);
    g_failures++;
    return -1;
  }
  lzvn_zopt_scratch_init(z, cand_capacity, hash_bits);
  z->search_depth = depth;
  size_t pneed = lzvn_pareto_scratch_size(1);
  lzvn_pareto_scratch *p = (lzvn_pareto_scratch *)malloc(pneed);
  if (!p) {
    printf("FAIL %s: pareto scratch allocation failed (%zu bytes)\n", label, pneed);
    g_failures++;
    free(z);
    return -1;
  }
  lzvn_pareto_scratch_init(p, 1);

  // build_candidates' load4 margin and the DP's repeat-distance probe need
  // real bytes past the logical end.
  static unsigned char padded[(1 << 16) + 32];
  memcpy(padded, src, (size_t)n);
  memset(padded + n, 0, 32);

  lzvn_zopt_build_candidates(z, padded, n + 32, n);
  if (!lzvn_pareto_run_dp(z, p, padded, n + 32, 0, n)) {
    printf("FAIL %s: tuple overflow\n", label);
    g_failures++;
    free(z); free(p);
    return -1;
  }

  static unsigned char dst[1 << 17];
  size_t dst_used = lzvn_zopt_commit(padded, dst, sizeof(dst), z, 0);
  if (dst_used == 0 && n > 0) {
    printf("FAIL %s: commit failed\n", label);
    g_failures++;
    free(z); free(p);
    return -1;
  }

  static unsigned char decoded[1 << 16];
  lzvn_decoder_state dstate;
  memset(&dstate, 0, sizeof(dstate));
  dstate.src = dst;
  dstate.src_end = dst + dst_used;
  dstate.dst_begin = decoded;
  dstate.dst = decoded;
  dstate.dst_end = decoded + n;
  lzvn_decode(&dstate);

  int32_t result = (int32_t)(dst_used > 8 ? dst_used - 8 : 0);
  if ((int32_t)(dstate.dst - decoded) != n || memcmp(decoded, src, (size_t)n) != 0) {
    printf("FAIL %s: round-trip mismatch (decoded %ld of %d bytes)\n", label,
           (long)(dstate.dst - decoded), n);
    g_failures++;
    result = -1;
  }
  free(z);
  free(p);
  return result;
}

// ---------------------------------------------------------------
// Check 1: a 3-byte-only match must be found and used.

static void check_three_byte_match(void) {
  // "ABCxABCyABCz...": "ABC" repeats every 4 bytes with the 4th byte
  // always differing.
  unsigned char src[64];
  for (int i = 0; i < 16; i++) {
    src[i * 4 + 0] = 'A';
    src[i * 4 + 1] = 'B';
    src[i * 4 + 2] = 'C';
    src[i * 4 + 3] = (unsigned char)('x' + (i % 3));
  }

  // The candidate menu at position 4 must hold a 3-byte match against 0.
  // The scratch is always sized for the fixed LZVN_ZOPT_BLOCK_SIZE, not this
  // test's own 64-byte input, so it is malloc'd rather than kept static.
  int32_t cand_capacity = 8;
  size_t need = lzvn_zopt_scratch_size(cand_capacity, LZVN_ZOPT_MIN_HASH_BITS);
  lzvn_zopt_scratch *z = (lzvn_zopt_scratch *)malloc(need);
  if (!z) {
    printf("FAIL three-byte: scratch allocation failed (%zu bytes)\n", need);
    g_failures++;
    return;
  }
  lzvn_zopt_scratch_init(z, cand_capacity, LZVN_ZOPT_MIN_HASH_BITS);
  z->search_depth = 32; // scratch_init does not set this

  unsigned char padded[64 + 16];
  memcpy(padded, src, 64);
  memset(padded + 64, 0, 16);
  lzvn_zopt_build_candidates(z, padded, 64 + 16, 64);

  int found = 0;
  for (int32_t k = 0; k < z->cand_count[4]; k++) {
    if (z->cand_dist[4 * cand_capacity + k] == 4 &&
        z->cand_len[4 * cand_capacity + k] >= 3) {
      found = 1;
    }
  }
  g_cases++;
  if (!found) {
    printf("FAIL three_byte_match: no length>=3 dist=4 candidate found at position 4 "
           "(cand_count=%u)\n", z->cand_count[4]);
    g_failures++;
  }
  free(z);

  int32_t compressed = roundtrip_optimal("three_byte_match_e2e", src, 64, 32, LZVN_ZOPT_MIN_HASH_BITS);
  if (compressed < 0)
    return;
  if (compressed >= 64) {
    printf("FAIL three_byte_match_e2e: compressed=%d >= raw 64: candidate search found nothing useful\n",
           compressed);
    g_failures++;
  }
}

// ---------------------------------------------------------------
// Check 2: round-trip correctness across varied content and search depths.

static uint32_t g_rng = 987654321u;
static uint32_t next_rand(void) {
  g_rng ^= g_rng << 13;
  g_rng ^= g_rng >> 17;
  g_rng ^= g_rng << 5;
  return g_rng;
}

static void check_roundtrip_corpus(void) {
  int32_t lengths[] = {0, 1, 2, 3, 4, 8, 15, 16, 17, 100, 1000, 8192, 65000};
  int32_t depths[] = {1, 4, 32, 128};

  for (size_t li = 0; li < sizeof(lengths) / sizeof(lengths[0]); li++) {
    int32_t n = lengths[li];
    if (n > (1 << 16) - 32) continue;

    // Highly repetitive, with a period break every 517 bytes (prime, so it
    // never aligns with the 4-byte repeat).
    static unsigned char rep[1 << 16];
    for (int32_t i = 0; i < n; i++)
      rep[i] = (i % 517 == 516) ? (unsigned char)'!'
                                : (unsigned char)("ABCD"[i % 4]);

    // Fully random content.
    static unsigned char rnd[1 << 16];
    for (int32_t i = 0; i < n; i++)
      rnd[i] = (unsigned char)(next_rand() & 0xFF);

    // Structured/mixed: repetitive runs interspersed with random noise.
    static unsigned char mix[1 << 16];
    for (int32_t i = 0; i < n; i++)
      mix[i] = (i / 8) % 3 == 0 ? (unsigned char)(next_rand() & 0xFF)
                                : (unsigned char)('a' + (i % 5));

    for (size_t ci = 0; ci < sizeof(depths) / sizeof(depths[0]); ci++) {
      char label[64];
      snprintf(label, sizeof(label), "rep_n%d_c%d", n, depths[ci]);
      roundtrip_optimal(label, rep, n, depths[ci], LZVN_ZOPT_DEFAULT_HASH_BITS);
      snprintf(label, sizeof(label), "rnd_n%d_c%d", n, depths[ci]);
      roundtrip_optimal(label, rnd, n, depths[ci], LZVN_ZOPT_DEFAULT_HASH_BITS);
      snprintf(label, sizeof(label), "mix_n%d_c%d", n, depths[ci]);
      roundtrip_optimal(label, mix, n, depths[ci], LZVN_ZOPT_DEFAULT_HASH_BITS);
    }
  }
}

// ---------------------------------------------------------------
// Check 3: sanity floor against Apple's real LZVN encoder on repetitive
// content (macOS only, via libcompression). Only fails if dramatically
// worse: this drives the candidate search and DP without the full encoder's
// extra passes, so some gap is expected.

static void check_vs_stock(void) {
  int32_t n = 8192;
  static unsigned char src[8192];
  for (int32_t i = 0; i < n; i++)
    src[i] = (unsigned char)("The quick brown fox jumps over the lazy dog. "[i % 46]);

  int32_t crush_size = roundtrip_optimal("vs_stock_crush", src, n, 64, LZVN_ZOPT_DEFAULT_HASH_BITS);
  if (crush_size < 0)
    return;

#ifdef CRUSHLZVN_CANDIDATE_HAVE_APPLE
  static unsigned char apple_dst[1 << 14];
  size_t apple_size = compression_encode_buffer(apple_dst, sizeof(apple_dst), src, (size_t)n, NULL, COMPRESSION_LZVN);

  printf("vs_apple: crush=%d apple=%zu (raw=%d)\n", crush_size, apple_size, n);
  g_cases++;
  if (apple_size > 0 && (size_t)crush_size > apple_size * 3) {
    printf("FAIL vs_apple: CrushLZVN (%d) is more than 3x Apple's real LZVN (%zu) on repetitive content\n",
           crush_size, apple_size);
    g_failures++;
  }
#else
  printf("vs_apple: crush=%d (raw=%d): skipped, not on macOS\n", crush_size, n);
#endif
}

int main(void) {
  check_three_byte_match();
  check_roundtrip_corpus();
  check_vs_stock();

  if (g_failures == 0) {
    printf("PASS: %d cases: 3-byte matches found, round-trips clean, sane vs. Apple\n",
           g_cases);
    return 0;
  }
  printf("FAIL: %d/%d cases failed\n", g_failures, g_cases);
  return 1;
}
