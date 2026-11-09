// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Asserts that CrushLZVN's optimal parse stays linear on degenerate input.
// The candidate search, where every position matches every earlier one in
// its phase: the match tree's walk (bt_match.h) must stop at the first match
// reaching the end of the block, and a long match's interior must be
// skipped. The DP's repeat probe, on a Fibonacci word, where the parse
// states carry many distances that all keep matching: each probe's
// extension must stay bounded. Counts match_extend calls and bytes
// (LZFSE_COUNT_MATCH_EXTEND) instead of wall-clock time so the assertions
// are deterministic.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

size_t g_match_extend_calls = 0, g_match_extend_bytes = 0;
#define LZFSE_COUNT_MATCH_EXTEND
#include "lzvn_encode_base.c"

static int g_failures = 0;

// Builds candidates over one block and returns the match_extend call count.
static size_t run_build_candidates(const unsigned char *content, int32_t n,
                                   int32_t search_depth) {
  const int32_t cand_capacity = 8;
  const int32_t hash_bits = LZVN_ZOPT_DEFAULT_HASH_BITS;
  size_t need = lzvn_zopt_scratch_size(cand_capacity, hash_bits);
  static unsigned char scratch_buf[1 << 24];
  if (need > sizeof(scratch_buf)) {
    printf("FAIL: scratch too small (need %zu, have %zu)\n", need, sizeof(scratch_buf));
    g_failures++;
    return 0;
  }
  lzvn_zopt_scratch *z = (lzvn_zopt_scratch *)scratch_buf;
  lzvn_zopt_scratch_init(z, cand_capacity, hash_bits);
  z->search_depth = search_depth;

  // build_candidates' load4 margin needs real bytes past the logical end.
  static unsigned char padded[65536 + 32];
  memcpy(padded, content, (size_t)n);
  memset(padded + n, 0, 32);

  g_match_extend_calls = 0;
  lzvn_zopt_build_candidates(z, padded, n + 32, n);
  return g_match_extend_calls;
}

// Deeper than any level in CrushLZVN's level table.
#define TEST_SEARCH_DEPTH 512
#define TEST_N 65536

// Bounded, match_extend runs at most a small constant number of times per
// position, independent of search_depth; unbounded, up to search_depth
// times. On a single run the skip covers almost every position, so a
// handful of calls is right; the floor only catches a miswired counter.
#define CALLS_UPPER_BOUND ((size_t)TEST_N * 16)
#define CALLS_LOWER_BOUND ((size_t)1)

static void check_degenerate(const char *label, const unsigned char *content) {
  size_t calls = run_build_candidates(content, TEST_N, TEST_SEARCH_DEPTH);
  printf("%-24s calls=%-10zu (floor=%zu ceiling=%zu, unbounded would be ~%zu)\n",
         label, calls, (size_t)CALLS_LOWER_BOUND, (size_t)CALLS_UPPER_BOUND,
         (size_t)TEST_N * (size_t)TEST_SEARCH_DEPTH);
  if (calls < CALLS_LOWER_BOUND) {
    printf("FAIL %s: match_extend called suspiciously few times (%zu < %zu): "
           "counter likely not wired up, not evidence of a fast short-circuit\n",
           label, calls, (size_t)CALLS_LOWER_BOUND);
    g_failures++;
  }
  if (calls > CALLS_UPPER_BOUND) {
    printf("FAIL %s: match_extend called %zu times over %d positions (limit %zu): "
           "the match tree's walk is not bounded, "
           "candidate search has gone quadratic again\n",
           label, calls, TEST_N, (size_t)CALLS_UPPER_BOUND);
    g_failures++;
  }
}

// Bytes the whole optimal parse may compare per position. Bounded repeat
// probes measure about 500 on the Fibonacci word, unbounded about 13000.
#define DP_BYTES_PER_POS 2048

// Runs the full optimal parse at the top level's pareto_k and asserts the
// total bytes match_extend compared.
static void check_dp_bytes(const char *label, const unsigned char *content) {
  const int32_t cand_capacity = 8, k = 6;
  const int32_t hash_bits = LZVN_ZOPT_DEFAULT_HASH_BITS;
  static unsigned char zbuf[1 << 24], pbuf[1 << 24];
  if (lzvn_zopt_scratch_size(cand_capacity, hash_bits) > sizeof(zbuf) ||
      lzvn_pareto_scratch_size(k) > sizeof(pbuf)) {
    printf("FAIL: scratch too small\n");
    g_failures++;
    return;
  }
  lzvn_zopt_scratch *z = (lzvn_zopt_scratch *)zbuf;
  lzvn_pareto_scratch *p = (lzvn_pareto_scratch *)pbuf;
  lzvn_zopt_scratch_init(z, cand_capacity, hash_bits);
  z->search_depth = 32;
  lzvn_pareto_scratch_init(p, k);
  static unsigned char padded[TEST_N + LZVN_ZOPT_SRC_PADDING];
  memcpy(padded, content, TEST_N);
  memset(padded + TEST_N, 0, LZVN_ZOPT_SRC_PADDING);
  static unsigned char dst[2 * TEST_N];

  g_match_extend_bytes = 0;
  size_t out = lzvn_encode_optimal_buffer_pareto(dst, sizeof(dst), padded, TEST_N, z, p);
  size_t limit = (size_t)TEST_N * DP_BYTES_PER_POS;
  printf("%-24s dp bytes=%-10zu (ceiling=%zu)\n", label, g_match_extend_bytes, limit);
  if (out == 0) {
    printf("FAIL %s: optimal encode failed\n", label);
    g_failures++;
  }
  if (g_match_extend_bytes > limit) {
    printf("FAIL %s: the optimal parse compared %zu bytes over %d positions (limit %zu): "
           "a probe is re-measuring whole runs again\n",
           label, g_match_extend_bytes, TEST_N, limit);
    g_failures++;
  }
}

int main(void) {
  // One continuous run: every position hashes to the same bucket.
  static unsigned char zeros[TEST_N];
  memset(zeros, 0, sizeof(zeros));
  check_degenerate("zeros", zeros);

  // Period 4: positions split across a few roots, each tree deeper than
  // search_depth well before the block ends.
  static unsigned char rep4[TEST_N];
  for (int32_t i = 0; i < TEST_N; i += 4) memcpy(rep4 + i, "\xDE\xAD\xBE\xEF", 4);
  check_degenerate("period4", rep4);

  // Near-duplicate 150-byte records, each differing in a counter byte:
  // matches stay below the skip length, so every position walks the tree.
  static unsigned char records[TEST_N];
  for (int32_t i = 0; i < TEST_N; i++) records[i] = (unsigned char)("crushlz record "[i % 15]);
  for (int32_t r = 0; r * 150 < TEST_N; r++) records[r * 150] = (unsigned char)r;
  check_degenerate("records", records);

  // Fibonacci word: S(k) = S(k-1) S(k-2), built by appending the prefix
  // that was the whole string one step earlier.
  static unsigned char fib[TEST_N];
  fib[0] = 'a';
  fib[1] = 'b';
  size_t len = 2, prev = 1;
  while (len < TEST_N) {
    size_t add = prev < TEST_N - len ? prev : TEST_N - len;
    memcpy(fib + len, fib, add);
    prev = len;
    len += add;
  }
  check_degenerate("fibonacci", fib);
  check_dp_bytes("fibonacci", fib);
  check_dp_bytes("zeros", zeros);

  if (g_failures == 0) {
    printf("PASS: match_extend work stays bounded on every shape\n");
    return 0;
  }
  printf("FAIL: %d check(s) failed\n", g_failures);
  return 1;
}
