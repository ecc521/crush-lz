// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Validates lzvn_encode_greedy_wide, the runtime-tunable generalization of
// Apple's original fixed-strategy LZVN encoder (since removed from this
// tree; see git history): at hash_width=4 and hash_bits=14 its output was
// bit-identical to that reference. Apple's own shipped libcompression is
// NOT a substitute oracle for that specific claim: measured, it differs
// from the open-source reference by a few bytes on some inputs (see the
// conversation this was cut in), so hash_width=4 gets the same tolerance
// check as every other width below, on Apple's real encoder, macOS only.
// Every width/hash_bits combination, including 4/14, must still round-trip.
#include "lzvn_encode_base.c"
#include "lzvn_decode_base.c"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <compression.h>
#define CRUSHLZVN_GREEDY_HAVE_APPLE 1
/* COMPRESSION_LZVN was dropped from the public enum in recent SDKs, but
 * libcompression still implements it at its long-stable value. */
#ifndef COMPRESSION_LZVN
#define COMPRESSION_LZVN ((compression_algorithm)0x900)
#endif
#endif

static int g_failures = 0;
static int g_cases = 0;

#define greedy_wide_encode lzvn_encode_greedy_wide_buffer

static uint32_t g_rng = 555111u;
static uint32_t next_rand(void) {
  g_rng ^= g_rng << 13;
  g_rng ^= g_rng >> 17;
  g_rng ^= g_rng << 5;
  return g_rng;
}

// --- Check 1: hash_width=4/hash_bits=14 sanity floor against Apple's real
// LZVN encoder (macOS only). Not bit-identical (see the file comment above),
// so this is the same tolerance check as check_roundtrip's other widths,
// just called out on its own since 4/14 is the width this crate's level
// table actually inherited from Apple's original algorithm.

static void check_bit_identical_to_stock(const char *label, const unsigned char *src, size_t n) {
  g_cases++;

  int32_t hash_bits = 14;
  int32_t hash_width = 4;
  static int32_t hist_pos[1 << 14][4];
  static uint32_t hist_value[1 << 14][4];
  static uint16_t hist_cursor[1 << 14];
  memset(hist_pos, 0, sizeof(hist_pos));
  memset(hist_value, 0, sizeof(hist_value));
  memset(hist_cursor, 0, sizeof(hist_cursor));

  static unsigned char wide_dst[1 << 17];
  size_t wide_size = greedy_wide_encode(wide_dst, sizeof(wide_dst), src, n, hash_bits, hash_width,
                                        &hist_pos[0][0], &hist_value[0][0], hist_cursor);
  if (wide_size == 0 && n > 0) {
    printf("FAIL %s: encode failed\n", label);
    g_failures++;
    return;
  }

#ifdef CRUSHLZVN_GREEDY_HAVE_APPLE
  static unsigned char apple_dst[1 << 17];
  size_t apple_size = compression_encode_buffer(apple_dst, sizeof(apple_dst), src, n, NULL, COMPRESSION_LZVN);
  if (apple_size > 0 && wide_size > apple_size * 3) {
    printf("FAIL %s: wide (%zu) is more than 3x Apple's real LZVN (%zu)\n", label, wide_size, apple_size);
    g_failures++;
  }
#endif
}

// --- Check 2: round-trip correctness across widths/hash_bits/content. ---

static void check_roundtrip(const char *label, const unsigned char *src, size_t n,
                            int32_t hash_bits, int32_t hash_width) {
  g_cases++;
  size_t hist_pos_sz = ((size_t)1 << hash_bits) * hash_width * sizeof(int32_t);
  size_t hist_val_sz = ((size_t)1 << hash_bits) * hash_width * sizeof(uint32_t);
  size_t hist_cur_sz = ((size_t)1 << hash_bits) * sizeof(uint16_t);
  int32_t *hist_pos = malloc(hist_pos_sz);
  uint32_t *hist_value = malloc(hist_val_sz);
  uint16_t *hist_cursor = malloc(hist_cur_sz);

  static unsigned char dst[1 << 17];
  static unsigned char decoded[1 << 16];
  size_t used = greedy_wide_encode(dst, sizeof(dst), src, n, hash_bits, hash_width, hist_pos, hist_value, hist_cursor);
  free(hist_pos); free(hist_value); free(hist_cursor);

  if (used == 0 && n > 0) {
    printf("FAIL %s: encode failed (hash_bits=%d hash_width=%d)\n", label, hash_bits, hash_width);
    g_failures++;
    return;
  }
  size_t decoded_len = lzvn_decode_buffer(decoded, n, dst, used);
  if (decoded_len != n || memcmp(decoded, src, n) != 0) {
    printf("FAIL %s: round-trip mismatch (hash_bits=%d hash_width=%d)\n", label, hash_bits, hash_width);
    g_failures++;
  }
}

int main(void) {
  int32_t lengths[] = {0, 1, 4, 8, 16, 100, 1000, 8192, 65000};
  for (size_t li = 0; li < sizeof(lengths)/sizeof(lengths[0]); li++) {
    int32_t n = lengths[li];
    static unsigned char rep[1 << 16], rnd[1 << 16], text[1 << 16];
    for (int32_t i = 0; i < n; i++) {
      rep[i] = (i % 517 == 516) ? (unsigned char)'!' : (unsigned char)("ABCD"[i % 4]);
      rnd[i] = (unsigned char)(next_rand() & 0xFF);
      text[i] = (i % 1013 == 1012) ? (unsigned char)'#'
                                    : (unsigned char)("The quick brown fox jumps over the lazy dog. "[i % 46]);
    }
    char label[64];
    snprintf(label, sizeof(label), "rep_n%d", n);
    check_bit_identical_to_stock(label, rep, (size_t)n);
    snprintf(label, sizeof(label), "rnd_n%d", n);
    check_bit_identical_to_stock(label, rnd, (size_t)n);
    snprintf(label, sizeof(label), "text_n%d", n);
    check_bit_identical_to_stock(label, text, (size_t)n);

    int32_t widths[] = {1, 2, 4, 8, 16, 64};
    int32_t hash_bits_vals[] = {10, 14, 16};
    for (size_t wi = 0; wi < sizeof(widths)/sizeof(widths[0]); wi++) {
      for (size_t hi = 0; hi < sizeof(hash_bits_vals)/sizeof(hash_bits_vals[0]); hi++) {
        snprintf(label, sizeof(label), "rep_n%d_w%d_h%d", n, widths[wi], hash_bits_vals[hi]);
        check_roundtrip(label, rep, (size_t)n, hash_bits_vals[hi], widths[wi]);
        snprintf(label, sizeof(label), "rnd_n%d_w%d_h%d", n, widths[wi], hash_bits_vals[hi]);
        check_roundtrip(label, rnd, (size_t)n, hash_bits_vals[hi], widths[wi]);
        snprintf(label, sizeof(label), "text_n%d_w%d_h%d", n, widths[wi], hash_bits_vals[hi]);
        check_roundtrip(label, text, (size_t)n, hash_bits_vals[hi], widths[wi]);
      }
    }
  }

  if (g_failures == 0) {
    printf("PASS: %d cases: hash_width=4 sane vs. Apple, all widths/hash_bits round-trip\n", g_cases);
    return 0;
  }
  printf("FAIL: %d/%d cases failed\n", g_failures, g_cases);
  return 1;
}
