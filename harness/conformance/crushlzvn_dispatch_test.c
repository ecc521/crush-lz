// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Validates the public crushlzvn.h dispatch layer: level table sanity, the
// scratch API, a NULL scratch, the "never worse than Apple's real LZVN
// encoder" guarantee (macOS only, via libcompression), params validation
// (reject, not clamp), and round-trips at every level.

#include "crushlzvn.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <compression.h>
#define CRUSHLZVN_DISPATCH_HAVE_APPLE 1
/* COMPRESSION_LZVN was dropped from the public enum in recent SDKs, but
 * libcompression still implements it at its long-stable value. */
#ifndef COMPRESSION_LZVN
#define COMPRESSION_LZVN ((compression_algorithm)0x900)
#endif
#endif

static int g_failures = 0;
static int g_cases = 0;

static uint32_t g_rng = 111222333u;
static uint32_t next_rand(void) {
  g_rng ^= g_rng << 13;
  g_rng ^= g_rng >> 17;
  g_rng ^= g_rng << 5;
  return g_rng;
}

// Round-trips crushlzvn_encode_buffer(level) through lzvn_decode_buffer and
// checks it is never worse than Apple's real LZVN encoder.
static size_t decode_all(uint8_t *dst, size_t dst_size, const uint8_t *src, size_t n) {
  size_t out = 0;
  return crushlzvn_decode_buffer(dst, dst_size, src, n, &out) == 0 ? out : (size_t)-1;
}

static size_t max_scratch_size(void) {
  size_t most = 0;
  for (int l = CRUSHLZVN_LEVEL_MIN; l <= CRUSHLZVN_LEVEL_MAX; l++) {
    crushlzvn_encode_params p;
    crushlzvn_params_for_level(l, &p);
    size_t n = crushlzvn_scratch_size(&p);
    if (n > most) most = n;
  }
  return most;
}

static void check_level(const char *label, const uint8_t *src, size_t n,
                        int level, void *scratch, size_t scratch_bytes) {
  g_cases++;
  if (getenv("CRUSHLZVN_TRACE")) { printf("running %s level=%d\n", label, level); fflush(stdout); }
  static uint8_t dst[1 << 17];
  static uint8_t decoded[1 << 16];

  size_t used = crushlzvn_encode_buffer(dst, sizeof(dst), src, n, scratch, scratch_bytes, level);
  if (used == 0 && n > 0) {
    printf("FAIL %s level=%d: crushlzvn_encode_buffer failed\n", label, level);
    g_failures++;
    return;
  }

  size_t decoded_len = decode_all(decoded, sizeof(decoded), dst, used);
  if (decoded_len != n || memcmp(decoded, src, n) != 0) {
    printf("FAIL %s level=%d: round-trip mismatch (decoded %zu of %zu)\n",
           label, level, decoded_len, n);
    g_failures++;
    return;
  }

  // The "never worse than Apple" guarantee only applies to the optimal
  // strategy (see crushlzvn.h); greedy levels skip the comparison. Checked
  // via the strategy, not the level's sign. Apple-only: needs libcompression.
  crushlzvn_encode_params p;
  crushlzvn_params_for_level(level, &p);
  if (p.strategy != CRUSHLZVN_STRATEGY_OPTIMAL)
    return;

#ifdef CRUSHLZVN_DISPATCH_HAVE_APPLE
  static uint8_t apple_dst[1 << 17];
  size_t apple_used = compression_encode_buffer(apple_dst, sizeof(apple_dst), src, n, NULL, COMPRESSION_LZVN);
  if (apple_used > 0 && used > apple_used) {
    printf("FAIL %s level=%d: crush=%zu worse than Apple=%zu\n", label, level,
           used, apple_used);
    g_failures++;
  }
#endif
}

static void check_all_levels(void) {
  int32_t lengths[] = {0, 1, 3, 8, 100, 1000, 8192, 65536};
  static uint8_t scratch[1 << 26];

  for (size_t li = 0; li < sizeof(lengths) / sizeof(lengths[0]); li++) {
    int32_t n = lengths[li];
    static uint8_t rep[1 << 16], rnd[1 << 16], text[1 << 16];
    for (int32_t i = 0; i < n; i++) {
      rep[i] = (i % 517 == 516) ? (uint8_t)'!' : (uint8_t)("ABCD"[i % 4]);
      rnd[i] = (uint8_t)(next_rand() & 0xFF);
      text[i] = (i % 1013 == 1012) ? (uint8_t)'#'
                                    : (uint8_t)("The quick brown fox jumps over the lazy dog. "[i % 46]);
    }
    // Every level at small sizes; only min/default/max at the largest, which
    // is slow under the sanitizers.
    int full_sweep = n <= 8192;
    for (int level = CRUSHLZVN_LEVEL_MIN; level <= CRUSHLZVN_LEVEL_MAX; level++) {
      if (!full_sweep && level != CRUSHLZVN_LEVEL_MIN &&
          level != CRUSHLZVN_LEVEL_DEFAULT && level != CRUSHLZVN_LEVEL_MAX)
        continue;
      char label[32];
      snprintf(label, sizeof(label), "rep_n%d", n);
      check_level(label, rep, (size_t)n, level, scratch, sizeof scratch);
      snprintf(label, sizeof(label), "rnd_n%d", n);
      check_level(label, rnd, (size_t)n, level, scratch, sizeof scratch);
      snprintf(label, sizeof(label), "text_n%d", n);
      check_level(label, text, (size_t)n, level, scratch, sizeof scratch);
    }
  }
}

// Level table sanity: monotone effort, default in range, capabilities
// self-consistent.
static void check_level_table_sanity(void) {
  g_cases++;
  crushlzvn_capabilities caps = crushlzvn_get_capabilities();
  if (caps.level_min != CRUSHLZVN_LEVEL_MIN || caps.level_max != CRUSHLZVN_LEVEL_MAX) {
    printf("FAIL capabilities: level range mismatch\n");
    g_failures++;
  }
  if (CRUSHLZVN_LEVEL_DEFAULT < CRUSHLZVN_LEVEL_MIN || CRUSHLZVN_LEVEL_DEFAULT > CRUSHLZVN_LEVEL_MAX) {
    printf("FAIL: default level out of range\n");
    g_failures++;
  }

  g_cases++;
  // Effort is two-dimensional (search_depth and pareto_k): across the optimal
  // levels neither axis may decrease and at least one must increase.
  int32_t prev_depth = 0, prev_k = 0;
  for (int lvl = CRUSHLZVN_LEVEL_MIN; lvl <= CRUSHLZVN_LEVEL_MAX; lvl++) {
    crushlzvn_encode_params p;
    crushlzvn_params_for_level(lvl, &p);
    if (p.strategy == CRUSHLZVN_STRATEGY_FAST) {
      if (p.p.fast.hash_bits < caps.fast_hash_bits_min || p.p.fast.hash_bits > caps.fast_hash_bits_max ||
          p.p.fast.min_match < caps.fast_min_match_min || p.p.fast.min_match > caps.fast_min_match_max ||
          p.p.fast.skip_shift < caps.fast_skip_shift_min || p.p.fast.skip_shift > caps.fast_skip_shift_max ||
          p.p.fast.max_step < caps.fast_max_step_min || p.p.fast.max_step > caps.fast_max_step_max) {
        printf("FAIL: level %d fast params outside reported capabilities\n", lvl);
        g_failures++;
      }
      continue;
    }
    if (p.strategy == CRUSHLZVN_STRATEGY_GREEDY) {
      if (p.p.greedy.hash_bits < caps.greedy_hash_bits_min || p.p.greedy.hash_bits > caps.greedy_hash_bits_max ||
          p.p.greedy.hash_width < caps.greedy_hash_width_min || p.p.greedy.hash_width > caps.greedy_hash_width_max) {
        printf("FAIL: level %d greedy params outside reported capabilities\n", lvl);
        g_failures++;
      }
      continue;
    }
    if (p.p.optimal.search_depth < prev_depth || p.p.optimal.pareto_k < prev_k ||
        (p.p.optimal.search_depth == prev_depth && p.p.optimal.pareto_k == prev_k)) {
      printf("FAIL: level %d effort (depth=%d, k=%d) not increasing from previous (depth=%d, k=%d)\n",
             lvl, p.p.optimal.search_depth, p.p.optimal.pareto_k, prev_depth, prev_k);
      g_failures++;
    }
    prev_depth = p.p.optimal.search_depth;
    prev_k = p.p.optimal.pareto_k;
    if (p.p.optimal.search_depth < caps.search_depth_min || p.p.optimal.search_depth > caps.search_depth_max ||
        p.p.optimal.store_limit < caps.store_limit_min || p.p.optimal.store_limit > caps.store_limit_max ||
        p.p.optimal.hash_bits < caps.hash_bits_min || p.p.optimal.hash_bits > caps.hash_bits_max ||
        p.p.optimal.pareto_k < caps.pareto_k_min || p.p.optimal.pareto_k > caps.pareto_k_max) {
      printf("FAIL: level %d params outside reported capabilities\n", lvl);
      g_failures++;
    }
  }

  // Clamping out-of-range levels, not undefined behavior.
  g_cases++;
  crushlzvn_encode_params p_lo, p_hi, p_min, p_max;
  crushlzvn_params_for_level(CRUSHLZVN_LEVEL_MIN - 5, &p_lo);
  crushlzvn_params_for_level(CRUSHLZVN_LEVEL_MIN, &p_min);
  crushlzvn_params_for_level(CRUSHLZVN_LEVEL_MAX + 5, &p_hi);
  crushlzvn_params_for_level(CRUSHLZVN_LEVEL_MAX, &p_max);
  if (memcmp(&p_lo, &p_min, sizeof(p_lo)) != 0 || memcmp(&p_hi, &p_max, sizeof(p_hi)) != 0) {
    printf("FAIL: out-of-range level did not clamp to the nearest valid level\n");
    g_failures++;
  }
}

// Params validation: crushlzvn_encode_buffer_advanced must reject, not
// clamp. Bad values derive from crushlzvn_get_capabilities().
static void check_params_validation(void) {
  // CRUSHLZVN_LEVEL_DEFAULT is a greedy level, so optimal-strategy cases
  // start from CRUSHLZVN_LEVEL_MAX; reading .p.optimal.* off a greedy
  // union would read the wrong fields.
  crushlzvn_encode_params optimal_good;
  crushlzvn_params_for_level(CRUSHLZVN_LEVEL_MAX, &optimal_good);
  crushlzvn_encode_params greedy_good;
  crushlzvn_params_for_level(CRUSHLZVN_LEVEL_DEFAULT, &greedy_good);
  crushlzvn_capabilities caps = crushlzvn_get_capabilities();
  crushlzvn_encode_params fast_good;
  crushlzvn_params_for_level(CRUSHLZVN_LEVEL_MIN, &fast_good);
  crushlzvn_encode_params fast_bad[5];
  for (int i = 0; i < 5; i++) fast_bad[i] = fast_good;
  fast_bad[0].p.fast.hash_bits = caps.fast_hash_bits_max + 1;
  fast_bad[1].p.fast.min_match = caps.fast_min_match_min - 1;
  fast_bad[2].p.fast.max_step = caps.fast_max_step_max + 1;
  fast_bad[3].p.fast.lazy = 2;
  fast_bad[4].p.fast.long_table = 1; // with min_match past the modes' ceiling of 6
  fast_bad[4].p.fast.min_match = caps.fast_min_match_max;

  // Sized from the level table, since the worst case shifts as it is tuned.
  size_t scratch_size = max_scratch_size();
  uint8_t *scratch = malloc(scratch_size);
  static uint8_t dst[4096];
  uint8_t src[64];
  memset(src, 'x', sizeof(src));

  struct { const char *label; crushlzvn_encode_params p; } bad_cases[] = {
    {"depth_zero", {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {0, optimal_good.p.optimal.store_limit, optimal_good.p.optimal.hash_bits, optimal_good.p.optimal.pareto_k}}}},
    {"depth_negative", {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {-1, optimal_good.p.optimal.store_limit, optimal_good.p.optimal.hash_bits, optimal_good.p.optimal.pareto_k}}}},
    {"store_limit_zero", {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {optimal_good.p.optimal.search_depth, 0, optimal_good.p.optimal.hash_bits, optimal_good.p.optimal.pareto_k}}}},
    {"hash_bits_too_low", {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {optimal_good.p.optimal.search_depth, optimal_good.p.optimal.store_limit, caps.hash_bits_min - 1, optimal_good.p.optimal.pareto_k}}}},
    {"hash_bits_too_high", {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {optimal_good.p.optimal.search_depth, optimal_good.p.optimal.store_limit, caps.hash_bits_max + 1, optimal_good.p.optimal.pareto_k}}}},
    {"pareto_k_zero", {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {optimal_good.p.optimal.search_depth, optimal_good.p.optimal.store_limit, optimal_good.p.optimal.hash_bits, 0}}}},
    {"pareto_k_too_high", {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {optimal_good.p.optimal.search_depth, optimal_good.p.optimal.store_limit, optimal_good.p.optimal.hash_bits, caps.pareto_k_max + 1}}}},
    {"greedy_hash_width_zero", {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {greedy_good.p.greedy.hash_bits, 0}}}},
    {"greedy_hash_bits_too_low", {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {caps.greedy_hash_bits_min - 1, greedy_good.p.greedy.hash_width}}}},
    {"greedy_hash_width_too_high", {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {greedy_good.p.greedy.hash_bits, caps.greedy_hash_width_max + 1}}}},
    {"fast_hash_bits_too_high", fast_bad[0]},
    {"fast_min_match_too_low", fast_bad[1]},
    {"fast_max_step_too_high", fast_bad[2]},
    {"fast_lazy_not_a_flag", fast_bad[3]},
    {"fast_long_table_min_match_8", fast_bad[4]},
  };
  for (size_t i = 0; i < sizeof(bad_cases) / sizeof(bad_cases[0]); i++) {
    g_cases++;
    size_t used = crushlzvn_encode_buffer_advanced(dst, sizeof(dst), src, sizeof(src),
                                                   scratch, scratch_size, &bad_cases[i].p);
    if (used != 0) {
      printf("FAIL params_validation %s: expected rejection (0), got %zu\n",
             bad_cases[i].label, used);
      g_failures++;
    }
  }

  // Oversized src (bigger than the documented fixed 64 KiB block, see
  // crushlzvn.h) must be a hard failure now, for either strategy: no call
  // chunks or streams multi-block input internally any more.
  const size_t oversized = 65536 + 1;
  uint8_t *huge_src = malloc(oversized);
  memset(huge_src, 'x', oversized);

  g_cases++;
  size_t used = crushlzvn_encode_buffer_advanced(dst, sizeof(dst), huge_src, oversized,
                                                 scratch, scratch_size, &optimal_good);
  if (used != 0) {
    printf("FAIL params_validation oversized_src_optimal: expected rejection (0) for >64KiB Optimal input, got %zu\n", used);
    g_failures++;
  }

  g_cases++;
  used = crushlzvn_encode_buffer_advanced(dst, sizeof(dst), huge_src, oversized,
                                          scratch, scratch_size, &greedy_good);
  if (used != 0) {
    printf("FAIL params_validation oversized_src_greedy: expected rejection (0) for >64KiB Greedy input, got %zu\n", used);
    g_failures++;
  }

  free(huge_src);
  free(scratch);
}

// A NULL scratch is allocated internally at every level.
static void check_null_scratch(void) {
  g_cases++;
  uint8_t src[2000];
  for (size_t i = 0; i < sizeof(src); i++)
    src[i] = (uint8_t)("abcdefgh"[i % 8]);
  static uint8_t dst[1 << 16];
  static uint8_t decoded[sizeof(src)];

  for (int level = CRUSHLZVN_LEVEL_MIN; level <= CRUSHLZVN_LEVEL_MAX; level++) {
    size_t used = crushlzvn_encode_buffer(dst, sizeof(dst), src, sizeof(src), NULL, 0, level);
    if (used == 0) {
      printf("FAIL null_scratch level=%d: encode failed\n", level);
      g_failures++;
      continue;
    }
    size_t decoded_len = decode_all(decoded, sizeof(decoded), dst, used);
    if (decoded_len != sizeof(src) || memcmp(decoded, src, sizeof(src)) != 0) {
      printf("FAIL null_scratch level=%d: round-trip mismatch\n", level);
      g_failures++;
    }
  }
}

static void check_null_empty_buffers(void) {
  uint8_t byte = 0;
  crushlzvn_encode_params p;
  crushlzvn_params_for_level(CRUSHLZVN_LEVEL_DEFAULT, &p);
  g_cases += 2;
  if (crushlzvn_encode_buffer_advanced(&byte, 1, NULL, 0, NULL, 0, &p) != 0) {
    printf("FAIL null_empty_buffers: NULL source was accepted\n");
    g_failures++;
  }
  if (crushlzvn_encode_buffer_advanced(NULL, 0, &byte, 1, NULL, 0, &p) != 0) {
    printf("FAIL null_empty_buffers: NULL destination was accepted\n");
    g_failures++;
  }
}

// The LZFSE fallback places output immediately after caller-owned LZVN
// scratch in one allocation. Both ranges must remain independently usable.
static void check_adjacent_scratch_output(void) {
  g_cases++;
  uint8_t src[4096], decoded[sizeof(src)];
  for (size_t i = 0; i < sizeof(src); i++)
    src[i] = (uint8_t)("abcdefab"[i % 8]);

  crushlzvn_encode_params p;
  crushlzvn_params_for_level(CRUSHLZVN_LEVEL_DEFAULT, &p);
  size_t scratch_size = crushlzvn_scratch_size(&p);
  size_t cap = crushlzvn_encode_bound(sizeof(src), &p);
  if (scratch_size == 0 || cap == 0 || cap == SIZE_MAX ||
      scratch_size > SIZE_MAX - cap - 1) {
    printf("FAIL adjacent_scratch_output: invalid sizes\n");
    g_failures++;
    return;
  }
  uint8_t *arena = malloc(scratch_size + cap + 1);
  if (!arena) {
    printf("FAIL adjacent_scratch_output: allocation failed\n");
    g_failures++;
    return;
  }
  memset(arena, 0xa5, scratch_size + cap + 1);
  uint8_t *dst = arena + scratch_size;
  dst[cap] = 0x5a;
  size_t used = crushlzvn_encode_buffer_advanced(dst, cap, src, sizeof(src),
                                                  arena, scratch_size, &p);
  size_t n = used ? decode_all(decoded, sizeof(decoded), dst, used) : (size_t)-1;
  if (used == 0 || used > cap || n != sizeof(src) ||
      memcmp(decoded, src, sizeof(src)) != 0 || dst[cap] != 0x5a) {
    printf("FAIL adjacent_scratch_output: encoded=%zu decoded=%zu\n", used, n);
    g_failures++;
  }
  free(arena);
}

// Runtime pareto_k: exercises crushlzvn_scratch_size across the full valid
// k_cap range. Each k_cap gets its own exactly sized scratch so a too-small
// size shows up under ASan rather than hiding in shared slack.
static void check_pareto_k_variation(void) {
  crushlzvn_capabilities caps = crushlzvn_get_capabilities();
  int32_t k_values[] = {caps.pareto_k_min, 1, 2, 8, 17, caps.pareto_k_max};

  uint8_t src[3000];
  for (size_t i = 0; i < sizeof(src); i++)
    src[i] = (uint8_t)("The quick brown fox jumps over the lazy dog. "[i % 46]);
  static uint8_t dst[1 << 16];
  static uint8_t decoded[sizeof(src)];

  for (size_t ki = 0; ki < sizeof(k_values) / sizeof(k_values[0]); ki++) {
    int32_t k = k_values[ki];
    if (k < caps.pareto_k_min || k > caps.pareto_k_max)
      continue;

    g_cases++;
    crushlzvn_encode_params p;
    crushlzvn_params_for_level(CRUSHLZVN_LEVEL_MAX, &p);
    p.p.optimal.pareto_k = k;

    size_t scratch_size = crushlzvn_scratch_size(&p);
    uint8_t *scratch = malloc(scratch_size);
    if (!scratch) {
      printf("FAIL pareto_k_variation k=%d: scratch alloc failed\n", k);
      g_failures++;
      continue;
    }

    size_t used = crushlzvn_encode_buffer_advanced(dst, sizeof(dst), src, sizeof(src), scratch, scratch_size, &p);
    if (used == 0) {
      printf("FAIL pareto_k_variation k=%d: encode failed\n", k);
      g_failures++;
      free(scratch);
      continue;
    }
    size_t decoded_len = decode_all(decoded, sizeof(decoded), dst, used);
    if (decoded_len != sizeof(src) || memcmp(decoded, src, sizeof(src)) != 0) {
      printf("FAIL pareto_k_variation k=%d: round-trip mismatch\n", k);
      g_failures++;
    }
    free(scratch);
  }
}

int main(void) {
  check_level_table_sanity();
  check_params_validation();
  check_null_scratch();
  check_null_empty_buffers();
  check_adjacent_scratch_output();
  check_pareto_k_variation();
  check_all_levels();

  if (g_failures == 0) {
#ifdef CRUSHLZVN_DISPATCH_HAVE_APPLE
    printf("PASS: %d cases: dispatch layer round-trips, never worse than "
           "Apple's real LZVN, validates params, NULL scratch works at every level\n",
           g_cases);
#else
    printf("PASS: %d cases: dispatch layer round-trips, validates params, "
           "NULL scratch works at every level (Apple comparison skipped: not on macOS)\n",
           g_cases);
#endif
    return 0;
  }
  printf("FAIL: %d/%d cases failed\n", g_failures, g_cases);
  return 1;
}
