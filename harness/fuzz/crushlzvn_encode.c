// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Fuzz harness for the standalone CrushLZVN encoder. crushlzfse_encode.c
// reaches LZVN only through crushlzfse_encode_buffer()'s small-input
// fallback, which runs two fixed settings (one fast, one greedy) and never
// LZVN's optimal strategy, its other levels or its advanced params.
//
// Random bytes are incompressible and rarely stress the DP's match-finding,
// so the fuzzer's bytes are interpreted as an opcode program that
// synthesizes adversarial content (see synthesize(), adapted from
// crushlzfse_encode.c's). Every encode that succeeds must decode back to
// the exact input, and must never exceed crushlzvn_encode_bound().

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzvn.h"
#include "apple_oracle.h"
#include "fuzzbuf.h"

#define FUZZ_MAX_INPUT 70000

// ---------------------------------------------------------------- opcode src

typedef struct {
  const uint8_t *p;
  size_t n;
  size_t i;
} opsrc;

static uint8_t op_u8(opsrc *s) { return s->i < s->n ? s->p[s->i++] : 0; }

static size_t op_u16(opsrc *s) {
  size_t hi = op_u8(s);
  return (hi << 8) | op_u8(s);
}

// ---------------------------------------------------------------- synthesizer

static size_t synthesize(const uint8_t *data, size_t size, uint8_t *out, size_t cap) {
  opsrc s = {data, size, 0};
  size_t n = 0;

  uint32_t alphabet = 4;
  uint32_t lcg = 0x2545F491u;

  while (s.i < s.n && n < cap) {
    uint8_t opcode = op_u8(&s);
    size_t room = cap - n;
    if (room == 0) break;

    switch (opcode & 7) {
      case 0: { // Literal run from a small alphabet.
        size_t len = (op_u16(&s) % 400) + 1;
        if (len > room) len = room;
        for (size_t k = 0; k < len; k++) {
          lcg = lcg * 1664525u + 1013904223u;
          out[n++] = (uint8_t)((lcg >> 16) % (alphabet ? alphabet : 1));
        }
        break;
      }
      case 1: { // Run of one repeated byte.
        size_t len = (op_u16(&s) % 2048) + 1;
        if (len > room) len = room;
        memset(out + n, op_u8(&s), len);
        n += len;
        break;
      }
      case 2: { // Back-copy at a chosen distance.
        size_t len = (op_u16(&s) % 512) + 1;
        size_t dist = n ? (op_u16(&s) % n) + 1 : 0;
        if (dist == 0) break;
        if (len > room) len = room;
        for (size_t k = 0; k < len; k++, n++) out[n] = out[n - dist];
        break;
      }
      case 3: { // Incompressible island inside otherwise-compressible data.
        size_t len = (op_u16(&s) % 1024) + 1;
        if (len > room) len = room;
        for (size_t k = 0; k < len; k++) {
          lcg = lcg * 1664525u + 1013904223u;
          out[n++] = (uint8_t)(lcg >> 24);
        }
        break;
      }
      case 4: { // Alphabet shift: change the entropy regime in place.
        uint8_t a = op_u8(&s);
        alphabet = (a & 1) ? 2 + (a % 6) : 16 + (a % 240);
        break;
      }
      case 5: { // Short matches at long distances: the shape that broke
                // crushlzvn_encode_bound()'s margin at level 8.
        size_t reps = (op_u16(&s) % 256) + 1;
        for (size_t r = 0; r < reps && n + 4 <= cap; r++) {
          size_t dist = n > 16 ? 17 + (op_u16(&s) % (n - 16)) : 0;
          if (dist && n >= dist) {
            for (int k = 0; k < 3 && n < cap; k++, n++) out[n] = out[n - dist];
          }
          if (n < cap) { lcg = lcg * 1664525u + 1013904223u; out[n++] = (uint8_t)(lcg >> 24); }
        }
        break;
      }
      default: { // Size edge: jump straight to a boundary length.
        static const size_t edges[] = {0, 1, 2, 3, 8191, 8192, 8193, 65535, 65536, 65537};
        size_t want = edges[op_u8(&s) % (sizeof(edges) / sizeof(edges[0]))];
        if (want > cap) want = cap;
        if (want > n) {
          while (n < want) {
            lcg = lcg * 1664525u + 1013904223u;
            out[n++] = (uint8_t)((lcg >> 16) % (alphabet ? alphabet : 1));
          }
        } else {
          n = want;
        }
        break;
      }
    }
  }
  return n;
}

// ---------------------------------------------------------------- the check

static void die(const char *what, int level, size_t n, size_t enc, size_t bound) {
  fprintf(stderr, "FUZZ FAILURE: %s (level=%d input=%zu encoded=%zu bound=%zu)\n",
          what, level, n, enc, bound);
  abort();
}

static void run_one(const uint8_t *data, size_t size) {
  static uint8_t in[FUZZ_MAX_INPUT];
  size_t n = synthesize(data, size, in, FUZZ_MAX_INPUT);
  if (size < 2) return;

  // Byte 0 selects the level (every distinct one, plus one out-of-range
  // value to keep the clamp path under test); byte 1 jitters the advanced
  // API's knobs on a fraction of runs: search_depth/hash_bits/pareto_k for
  // the optimal levels, hash_bits/min_match/max_step for the fast ones.
  static const int LEVEL_MIX[16] = {-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 8, 8, 9, 9, 10, 99};
  int level = LEVEL_MIX[data[0] & 15];

  crushlzvn_encode_params params;
  crushlzvn_params_for_level(level, &params);
  int use_advanced = (data[1] & 3) == 0 && params.strategy != CRUSHLZVN_STRATEGY_GREEDY;
  if (use_advanced && params.strategy == CRUSHLZVN_STRATEGY_FAST) {
    static const int HASH_BITS[] = {10, 12, 16};
    static const int MAX_STEPS[] = {1, 4, 64};
    params.p.fast.hash_bits = HASH_BITS[(data[1] >> 2) % 3];
    params.p.fast.min_match = 4 + (data[1] >> 4) % 3;
    params.p.fast.max_step = MAX_STEPS[(data[1] >> 6) % 3];
  } else if (use_advanced) {
    static const int32_t DEPTHS[] = {1, 2, 8, 32, 128, 256};
    static const int32_t HASH_BITS[] = {10, 12, 16, 20};
    static const int32_t PARETO_KS[] = {1, 2, 6, 32};
    params.p.optimal.search_depth = DEPTHS[data[1] % (sizeof(DEPTHS) / sizeof(DEPTHS[0]))];
    params.p.optimal.hash_bits = HASH_BITS[(data[1] >> 2) % (sizeof(HASH_BITS) / sizeof(HASH_BITS[0]))];
    params.p.optimal.pareto_k = PARETO_KS[(data[1] >> 4) % (sizeof(PARETO_KS) / sizeof(PARETO_KS[0]))];
  }

  size_t bound = crushlzvn_encode_bound(n, &params);
  uint8_t *dst = (uint8_t *)malloc(bound ? bound : 1);
  if (!dst) abort();

  static fuzzbuf_t input_buf, packed_buf, back_buf;
  const uint8_t *exact_input = fuzz_copy(&input_buf, in, n);
  size_t enc = use_advanced
                   ? crushlzvn_encode_buffer_advanced(dst, bound, exact_input, n, NULL, 0, &params)
                   : crushlzvn_encode_buffer(dst, bound, exact_input, n, NULL, 0, level);
  fuzz_check_written(dst, enc);

  if (enc > bound)
    die("encode exceeded its own encode_bound()", level, n, enc, bound);

  // Every strategy is now bounded to one already-independent 65536-byte
  // piece per call; anything larger must be a hard failure (0), never a
  // silent partial encode, a stream, or an abort.
  if (n > 65536 && enc != 0)
    die("accepted an oversized (>65536) input instead of rejecting it", level, n, enc, bound);

  if (enc != 0) {
    uint8_t *back = fuzz_resize(&back_buf, n);

    const uint8_t *exact_packed = fuzz_copy(&packed_buf, dst, enc);
    size_t dec = 0;
    int rc = crushlzvn_decode_buffer(back, n, exact_packed, enc, &dec);
    fuzz_check_written(back, dec);
    if (rc != 0) die("decoder rejected the stream", level, n, enc, bound);
    if (dec != n) die("round-trip length mismatch", level, n, enc, bound);
    if (n && memcmp(back, exact_input, n) != 0) die("round-trip content mismatch", level, n, enc, bound);

#ifdef __APPLE__
    apple_oracle(APPLE_ORACLE_LZVN, crushlzvn_decode_buffer, exact_input, n, exact_packed, enc);
#endif
  }

  free(dst);
}

// ---------------------------------------------------------------- entry points

#include "driver.h"
