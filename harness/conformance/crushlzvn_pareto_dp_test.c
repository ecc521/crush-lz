// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Differential test for the Pareto-front multi-state DP (lzvn_zopt_pareto.h
// and the lzvn_pareto_* functions in lzvn_encode_base.c): a hand-fed
// candidate menu goes through the production DP and through an exhaustively
// memoized reference optimum over the same menu. Hard invariant:
// reference_optimum <= pareto_cost. Every committed output must also
// round-trip through the real lzvn_decode().

#include "lzvn_encode_base.c"
#include "lzvn_decode_base.c"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures = 0;
static int g_cases = 0;

// pareto vs reference
static double g_pareto_overhead_sum = 0.0;
static int g_pareto_overhead_n = 0;
static double g_pareto_overhead_max = 0.0;

#define MAX_N 96
// The most candidates the DP's scratch can hold per position.
#define MAX_CAND_PER_POS LZVN_ZOPT_MAX_STORE_LIMIT

static int32_t g_cand_len[MAX_N][MAX_CAND_PER_POS];
static int32_t g_cand_dist[MAX_N][MAX_CAND_PER_POS];
static int32_t g_cand_count[MAX_N];

static void build_candidate_menu(const unsigned char *src, int32_t n,
                                 int32_t max_dist) {
  for (int32_t i = 0; i < n; i++) {
    int32_t cnt = 0;
    for (int32_t i0 = i - 1; i0 >= 0 && i - i0 <= max_dist &&
                             cnt < MAX_CAND_PER_POS;
        i0--) {
      int32_t len = 0;
      while (i + len < n && src[i0 + len] == src[i + len])
        len++;
      if (len >= LZVN_ZOPT_MIN_MATCH_LEN) {
        g_cand_len[i][cnt] = len;
        g_cand_dist[i][cnt] = i - i0;
        cnt++;
      }
    }
    g_cand_count[i] = cnt;
  }
}

#define MAX_DISTINCT_DIST 96
static int32_t g_distinct_dist[MAX_DISTINCT_DIST];
static int32_t g_n_distinct_dist;
static int32_t g_memo[MAX_N + 1][MAX_DISTINCT_DIST + 1];
static int32_t g_n_ref;
// Set by check_case so brute_cost's repeat-distance branch can measure the
// real match length at (pos, pos-last_dist), which the menu never models.
static const unsigned char *g_ref_src;

static int32_t dist_index(int32_t d) {
  for (int32_t i = 0; i < g_n_distinct_dist; i++)
    if (g_distinct_dist[i] == d)
      return i + 1;
  g_distinct_dist[g_n_distinct_dist] = d;
  return g_n_distinct_dist++ + 1;
}

static int32_t brute_cost(int32_t pos, int32_t last_dist) {
  if (pos == g_n_ref)
    return 0;
  int32_t di = last_dist == 0 ? 0 : dist_index(last_dist);
  if (g_memo[pos][di] >= 0)
    return g_memo[pos][di];

  int32_t best = INT32_MAX / 2;
  for (int32_t r = 0; pos + r <= g_n_ref; r++) {
    int32_t tail;
    int32_t prefix = lzvn_literal_prefix_cost(r, &tail);
    if (pos + r == g_n_ref) {
      int32_t total = lzvn_literal_final_cost(r);
      if (total < best)
        best = total;
      continue;
    }
    int32_t landing = pos + r;

    // Repeat-distance branch (D==D_prev), floored at
    // LZVN_ZOPT_MIN_REPEAT_MATCH_LEN only when tail==0. Not window-clamped:
    // the reference must have at least as much freedom as the DP.
    if (last_dist > 0 && landing - last_dist >= 0) {
      int32_t repeat_min =
          (tail == 0) ? LZVN_ZOPT_MIN_REPEAT_MATCH_LEN : LZVN_ZOPT_MIN_MATCH_LEN;
      int32_t real_len = 0;
      while (landing + real_len < g_n_ref &&
             g_ref_src[landing - last_dist + real_len] ==
                 g_ref_src[landing + real_len])
        real_len++;
      for (int32_t M = repeat_min; M <= real_len; M++) {
        if (landing + M > g_n_ref)
          break;
        int32_t mcost = lzvn_match_op_cost(tail, M, last_dist, last_dist);
        int32_t rest = brute_cost(landing + M, last_dist);
        int32_t total = prefix + mcost + rest;
        if (total < best)
          best = total;
      }
    }

    for (int32_t k = 0; k < g_cand_count[landing]; k++) {
      int32_t M_max = g_cand_len[landing][k];
      int32_t D = g_cand_dist[landing][k];
      int32_t m_lo = M_max - LZVN_ZOPT_SUBLEN_WINDOW;
      if (m_lo < LZVN_ZOPT_MIN_MATCH_LEN)
        m_lo = LZVN_ZOPT_MIN_MATCH_LEN;
      for (int32_t M = m_lo; M <= M_max; M++) {
        if (landing + M > g_n_ref)
          continue;
        int32_t mcost = lzvn_match_op_cost(tail, M, D, last_dist);
        int32_t rest = brute_cost(landing + M, D);
        int32_t total = prefix + mcost + rest;
        if (total < best)
          best = total;
      }
    }
  }
  g_memo[pos][di] = best;
  return best;
}

static int32_t reference_optimum(int32_t n) {
  g_n_distinct_dist = 0;
  g_n_ref = n;
  for (int32_t i = 0; i <= n; i++)
    for (int32_t j = 0; j <= MAX_DISTINCT_DIST; j++)
      g_memo[i][j] = -1;
  return brute_cost(0, 0);
}

// Structural invariant on the committed tuple sequence: LZVN can only
// represent M < LZVN_ZOPT_MIN_MATCH_LEN for a D==D_prev match when there is
// no embedded literal tail (see LZVN_ZOPT_MIN_REPEAT_MATCH_LEN in
// lzvn_zopt.h). Checked directly rather than left to the round trip.
static int check_repeat_floor_invariant(const char *label, const char *leg,
                                        const uint32_t *tup_L,
                                        const uint32_t *tup_M,
                                        const uint32_t *tup_D,
                                        int32_t n_tuples) {
  int32_t d_prev = 0;
  for (int32_t t = 0; t < n_tuples; t++) {
    uint32_t L = tup_L[t], M = tup_M[t], D = tup_D[t];
    if (M > 0 && (int32_t)M < LZVN_ZOPT_MIN_MATCH_LEN) {
      int32_t tail_dummy;
      lzvn_literal_prefix_cost((int32_t)L, &tail_dummy);
      int tail_is_zero = (L == 0 || L >= 4);
      if ((int32_t)D != d_prev || !tail_is_zero) {
        printf("FAIL %s (%s): tuple %d has M=%u < LZVN_ZOPT_MIN_MATCH_LEN=%d "
               "with D=%u d_prev=%d L=%u (tail_is_zero=%d): format cannot "
               "represent this, corrupt bitstream\n",
               label, leg, t, M, LZVN_ZOPT_MIN_MATCH_LEN, D, d_prev, L,
               tail_is_zero);
        return 0;
      }
    }
    if (M > 0)
      d_prev = (int32_t)D;
  }
  return 1;
}

// The DP scratch is always sized for the fixed LZVN_ZOPT_BLOCK_SIZE, not this
// test's own tiny (<=MAX_N) inputs, so it is malloc'd per case rather than
// kept in a fixed-size static.
static void check_case(const char *label, const unsigned char *src, int32_t n,
                       int32_t max_dist, int32_t k_cap) {
  g_cases++;
  build_candidate_menu(src, n, max_dist);

  int32_t cand_capacity = MAX_CAND_PER_POS;
  size_t need = lzvn_zopt_scratch_size(cand_capacity, LZVN_ZOPT_MIN_HASH_BITS);
  lzvn_zopt_scratch *z = (lzvn_zopt_scratch *)malloc(need);
  if (!z) {
    printf("FAIL %s: zopt scratch allocation failed (%zu bytes)\n", label, need);
    g_failures++;
    return;
  }
  lzvn_zopt_scratch_init(z, cand_capacity, LZVN_ZOPT_MIN_HASH_BITS);

  size_t pneed = lzvn_pareto_scratch_size(k_cap);
  lzvn_pareto_scratch *p = (lzvn_pareto_scratch *)malloc(pneed);
  if (!p) {
    printf("FAIL %s: pareto scratch allocation failed (%zu bytes)\n", label, pneed);
    g_failures++;
    free(z);
    return;
  }
  lzvn_pareto_scratch_init(p, k_cap);

  for (int32_t i = 0; i < n; i++) {
    z->cand_count[i] = (uint16_t)g_cand_count[i];
    for (int32_t k = 0; k < g_cand_count[i]; k++) {
      z->cand_len[(size_t)i * cand_capacity + k] = g_cand_len[i][k];
      z->cand_dist[(size_t)i * cand_capacity + k] = g_cand_dist[i][k];
    }
  }

  static unsigned char padded[MAX_N + 32];
  memcpy(padded, src, (size_t)n);
  memset(padded + n, 0, 32);

  // --- Leg 1: the Pareto DP. pareto_total applies the dangling-final-run
  // correction if the winning path ends on a bare literal run. ---
  if (!lzvn_pareto_run_dp(z, p, padded, n + 32, 0, n)) {
    printf("FAIL %s: pareto tuple overflow\n", label);
    g_failures++;
    free(z); free(p);
    return;
  }
  int32_t pareto_total = lzvn_pareto_total_cost(p, n);
  if (z->n_tuples > 0 && z->tup_M[z->n_tuples - 1] == 0) {
    int32_t L = (int32_t)z->tup_L[z->n_tuples - 1];
    int32_t tail;
    pareto_total += lzvn_literal_final_cost(L) - lzvn_literal_prefix_cost(L, &tail);
  }
  if (!check_repeat_floor_invariant(label, "pareto", z->tup_L, z->tup_M,
                                    z->tup_D, z->n_tuples)) {
    g_failures++;
    free(z); free(p);
    return;
  }

  // Round-trip and byte-count cross-check before leg 2 touches z->tup_*.
  static unsigned char dst[1 << 16];
  static unsigned char decoded[MAX_N];
  size_t dst_used = lzvn_zopt_commit(src, dst, sizeof(dst), z, 0);
  if (dst_used == 0 && n > 0) {
    printf("FAIL %s: pareto commit failed (dst full?)\n", label);
    g_failures++;
    free(z); free(p);
    return;
  }
  size_t committed_payload = dst_used > 8 ? dst_used - 8 : 0;
  if ((int32_t)committed_payload != pareto_total) {
    printf("FAIL %s: pareto committed=%zu pareto_total=%d mismatch\n", label,
           committed_payload, pareto_total);
    g_failures++;
    free(z); free(p);
    return;
  }
  lzvn_decoder_state dstate;
  memset(&dstate, 0, sizeof(dstate));
  dstate.src = dst;
  dstate.src_end = dst + dst_used;
  dstate.dst_begin = decoded;
  dstate.dst = decoded;
  dstate.dst_end = decoded + n;
  lzvn_decode(&dstate);
  if ((int32_t)(dstate.dst - decoded) != n || memcmp(decoded, src, n) != 0) {
    printf("FAIL %s: pareto round-trip mismatch (decoded %ld of %d bytes)\n",
           label, (long)(dstate.dst - decoded), n);
    g_failures++;
    free(z); free(p);
    return;
  }

  // --- Leg 2: independent reference optimum over the identical menu ---
  g_ref_src = src;
  int32_t ref_total = reference_optimum(n);

  if (pareto_total < ref_total) {
    printf("FAIL %s: pareto_total=%d < ref_total=%d (n=%d): claimed BETTER than true optimum, real bug\n",
           label, pareto_total, ref_total, n);
    g_failures++;
    free(z); free(p);
    return;
  }
  if (pareto_total > ref_total && ref_total > 0) {
    double overhead = (double)(pareto_total - ref_total) / (double)ref_total;
    g_pareto_overhead_sum += overhead;
    g_pareto_overhead_n++;
    if (overhead > g_pareto_overhead_max)
      g_pareto_overhead_max = overhead;
  }
  free(z);
  free(p);
}

static uint32_t g_rng = 12345;
static uint32_t next_rand(void) {
  g_rng ^= g_rng << 13;
  g_rng ^= g_rng >> 17;
  g_rng ^= g_rng << 5;
  return g_rng;
}

// Runs the full differential suite at one k_cap.
static void run_suite(int32_t k_cap) {
  g_pareto_overhead_sum = 0.0; g_pareto_overhead_n = 0; g_pareto_overhead_max = 0.0;
  {
    unsigned char src[] = "abcdabcdabcdabcd";
    check_case("simple_repeat", src, (int32_t)strlen((char *)src), 64, k_cap);
  }
  {
    unsigned char src[] = "XXXXXAABBBAAXXXXXAABBBAA";
    check_case("repeat_distance", src, (int32_t)strlen((char *)src), 64, k_cap);
  }
  {
    unsigned char src[1] = {0};
    check_case("empty", src, 0, 64, k_cap);
  }
  {
    unsigned char src[] = "ab";
    check_case("too_short_for_any_match", src, (int32_t)strlen((char *)src), 64, k_cap);
  }

  // --- Hand-built cases for LZVN_ZOPT_MIN_REPEAT_MATCH_LEN: a repeat-distance
  // match whose true length is below LZVN_ZOPT_MIN_MATCH_LEN, under both the
  // legal (tail==0) and illegal (tail>0) framing. ---
  {
    // Pool, a D=8 M=7 match, a 1-byte literal "Z", then a length-2 repeat at
    // D=8 landing with tail=1: the forbidden case.
    unsigned char src[] = "abcdefghabcdefgZab";
    check_case("repeat_tie_short_tail_nonzero", src,
              (int32_t)strlen((char *)src), 64, k_cap);
  }
  {
    // Same, but the length-2 repeat lands with tail==0: the legal case.
    unsigned char src[] = "abcdefghabcdefghZZZZab";
    check_case("repeat_tie_short_tail_zero", src,
              (int32_t)strlen((char *)src), 64, k_cap);
  }
  {
    // M=1 repeat with tail==0: a 4-byte literal run always ends with tail==0.
    unsigned char src[] = "0123456789012345678ZZZZ0X";
    check_case("repeat_tie_len1_tail_zero", src,
              (int32_t)strlen((char *)src), 64, k_cap);
  }

  int32_t lengths[] = {8, 16, 24, 40, 64, 90};
  int32_t alphabets[] = {2, 3, 4, 6};
  for (size_t li = 0; li < sizeof(lengths) / sizeof(lengths[0]); li++) {
    for (size_t ai = 0; ai < sizeof(alphabets) / sizeof(alphabets[0]); ai++) {
      for (int32_t trial = 0; trial < 20; trial++) {
        int32_t n = lengths[li];
        int32_t alphabet = alphabets[ai];
        unsigned char src[MAX_N];
        for (int32_t i = 0; i < n; i++)
          src[i] = (unsigned char)('A' + (next_rand() % alphabet));
        char label[64];
        snprintf(label, sizeof(label), "rand_n%d_a%d_t%d", n, alphabet, trial);
        check_case(label, src, n, 64, k_cap);
      }
    }
  }

  // Small alphabets at short lengths, where short repeat-distance ties are
  // densest.
  {
    int32_t short_lengths[] = {4, 5, 6, 7, 8, 9, 10, 12, 14};
    int32_t small_alphabets[] = {2, 3};
    for (size_t li = 0; li < sizeof(short_lengths) / sizeof(short_lengths[0]); li++) {
      for (size_t ai = 0; ai < sizeof(small_alphabets) / sizeof(small_alphabets[0]); ai++) {
        for (int32_t trial = 0; trial < 40; trial++) {
          int32_t n = short_lengths[li];
          int32_t alphabet = small_alphabets[ai];
          unsigned char src[MAX_N];
          for (int32_t i = 0; i < n; i++)
            src[i] = (unsigned char)('A' + (next_rand() % alphabet));
          char label[64];
          snprintf(label, sizeof(label), "short_rand_n%d_a%d_t%d", n, alphabet, trial);
          check_case(label, src, n, 64, k_cap);
        }
      }
    }
  }

  printf("k_cap=%d\n", k_cap);
  if (g_pareto_overhead_n > 0)
    printf("pareto(K=%d)  overhead vs true optimum: avg %.2f%%, max %.2f%%, over %d/%d cases\n",
           k_cap, 100.0 * g_pareto_overhead_sum / g_pareto_overhead_n, 100.0 * g_pareto_overhead_max,
           g_pareto_overhead_n, g_cases);
  else
    printf("pareto(K=%d)  overhead vs true optimum: 0.00%% over all cases (matched reference every time)\n", k_cap);
}

int main(void) {
  // Both ends of the valid k_cap range plus the deepest level's value, since
  // k_cap drives lzvn_pareto_scratch's per-position width.
  int32_t k_values[] = {1, 8, LZVN_PARETO_MAX_K};
  for (size_t i = 0; i < sizeof(k_values) / sizeof(k_values[0]); i++)
    run_suite(k_values[i]);

  if (g_failures == 0) {
    printf("PASS: %d cases (across k_cap in {1,8,%d}): pareto never below true "
           "optimum, always round-trips\n",
           g_cases, LZVN_PARETO_MAX_K);
    return 0;
  }
  printf("FAIL: %d/%d cases failed\n", g_failures, g_cases);
  return 1;
}
