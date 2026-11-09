// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Fuzz harness for the CrushLZFSE encoder. Random bytes are incompressible
// and never reach the DP, so the fuzzer's bytes are interpreted as an opcode
// program that synthesizes compressible, adversarial input (see synthesize()).
// Every encode that succeeds must decode back to the exact input.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crushlzfse.h"
#include "apple_oracle.h"
#include "fuzzbuf.h"

// Slightly past one 64 KiB block, so every level's hard rejection above
// LZFSE_ZOPT_BLOCK_SIZE (65536, see crushlzfse.h) is exercised for every
// strategy.
#define FUZZ_MAX_INPUT 70000

// ---------------------------------------------------------------- opcode src

typedef struct {
  const uint8_t *p;
  size_t n;
  size_t i;
} opsrc;

// Reads past the end yield 0, so a truncated program is still a valid one.
static uint8_t op_u8(opsrc *s) { return s->i < s->n ? s->p[s->i++] : 0; }

static size_t op_u16(opsrc *s) {
  size_t hi = op_u8(s);
  return (hi << 8) | op_u8(s);
}

// ---------------------------------------------------------------- synthesizer

// Builds structured content into `out`, returning its length.
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
      case 5: { // Literal run of 313..317 bytes, around LZFSE_ENCODE_MAX_L_VALUE.
        size_t len = 313 + (op_u8(&s) % 5);
        if (len > room) len = room;
        for (size_t k = 0; k < len; k++) {
          lcg = lcg * 1664525u + 1013904223u;
          out[n++] = (uint8_t)((lcg >> 16) % (alphabet ? alphabet : 1));
        }
        break;
      }
      case 6: { // Short-match spam: maximizes tuple count per byte.
        size_t reps = (op_u16(&s) % 256) + 1;
        for (size_t r = 0; r < reps && n + 4 <= cap; r++) {
          out[n++] = 'a';
          out[n++] = 'b';
          out[n++] = (uint8_t)(r & 0xff);
          out[n++] = 'a';
        }
        break;
      }
      default: { // Size edge: jump straight to a boundary length.
        static const size_t edges[] = {0, 1, 2, 3, 315, 316, 65535, 65536, 65537};
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

static void die(const char *what, int level, size_t n, size_t enc, size_t dec) {
  fprintf(stderr, "FUZZ FAILURE: %s (level=%d input=%zu encoded=%zu decoded=%zu)\n",
          what, level, n, enc, dec);
  abort();
}

// Decodes enc with ours and Apple's and checks it is exactly src[0, n).
static void check_stream(int level, const uint8_t *src, size_t n, const uint8_t *enc, size_t enc_len) {
  static fuzzbuf_t packed_buf, back_buf;
  uint8_t *back = fuzz_resize(&back_buf, n);
  const uint8_t *exact_packed = fuzz_copy(&packed_buf, enc, enc_len);
  size_t dec = 0;
  int rc = crushlzfse_decode_buffer(back, n, exact_packed, enc_len, &dec);
  fuzz_check_written(back, dec);
  if (rc != 0) die("decoder rejected the stream", level, n, enc_len, dec);
  if (dec != n) die("round-trip length mismatch", level, n, enc_len, dec);
  if (n && memcmp(back, src, n) != 0) die("round-trip content mismatch", level, n, enc_len, dec);
#ifdef __APPLE__
  apple_oracle(COMPRESSION_LZFSE, crushlzfse_decode_buffer, src, n, exact_packed, enc_len);
#endif
}

// A genuine stats header, from one encode, so fuzzed counts reach the seed
// loader's scaling rather than all being rejected at the header. Word 0 is
// the header in crushlzfse.c's layout.
static uint32_t genuine_stats_header(void) {
  static uint32_t header;
  if (!header) {
    static uint8_t text[4096], out[8192];
    for (size_t i = 0; i < sizeof text; i++) text[i] = (uint8_t)"chained stats "[i % 14] + (uint8_t)(i / 997);
    crushlzfse_encode_params params;
    crushlzfse_params_for_level(CRUSHLZFSE_LEVEL_DEFAULT, &params);
    crushlzfse_stats st;
    memset(&st, 0, sizeof st);
    if (!crushlzfse_encode_buffer_chained(out, sizeof out, text, sizeof text, NULL, 0, &params, &st) || !st.opaque[0])
      abort();
    header = st.opaque[0];
  }
  return header;
}

static void run_one(const uint8_t *data, size_t size) {
  static uint8_t in[FUZZ_MAX_INPUT];
  size_t n = synthesize(data, size, in, FUZZ_MAX_INPUT);

  // The first program byte selects the level. Slow levels are sampled
  // sparsely; 99 is out of range to keep the clamp path under test, and
  // FAST_PARAMS draws fast-strategy params from the next three bytes, so
  // every valid combination is reachable, not only the level table's.
  enum { FAST_PARAMS = 1000 };
  static const int LEVEL_MIX[16] = {-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 6, 8, 9, 10,
                                    99, FAST_PARAMS};
  int level = size ? LEVEL_MIX[data[0] & 15] : CRUSHLZFSE_LEVEL_DEFAULT;
  crushlzfse_encode_params params;
  crushlzfse_params_for_level(level, &params);
  if (level == FAST_PARAMS) {
    crushlzfse_capabilities c = crushlzfse_get_capabilities();
    uint8_t b1 = size > 1 ? data[1] : 0;
    uint8_t b2 = size > 2 ? data[2] : 0;
    uint8_t b3 = size > 3 ? data[3] : 0;
    int long_table = b1 >> 6 & 1, lazy = b1 >> 7;
    // long_table and lazy cap min_match at 6.
    int mm_max = (long_table || lazy) ? 6 : c.fast_min_match_max;
    crushlzfse_params_for_level(CRUSHLZFSE_LEVEL_MIN, &params);
    params.p.fast.hash_bits = c.fast_hash_bits_min + (b1 & 7) % (c.fast_hash_bits_max - c.fast_hash_bits_min + 1);
    params.p.fast.min_match = c.fast_min_match_min + (b1 >> 3 & 7) % (mm_max - c.fast_min_match_min + 1);
    params.p.fast.skip_shift = c.fast_skip_shift_min + b2 % (c.fast_skip_shift_max - c.fast_skip_shift_min + 1);
    params.p.fast.max_step = c.fast_max_step_min + b3 % (c.fast_max_step_max - c.fast_max_step_min + 1);
    params.p.fast.long_table = long_table;
    params.p.fast.lazy = lazy;
  } else if (params.strategy == CRUSHLZFSE_STRATEGY_OPTIMAL && size > 1 && (data[1] & 3) == 0) {
    // A quarter of the optimal runs draw table_search from byte 1.
    crushlzfse_capabilities c = crushlzfse_get_capabilities();
    params.p.optimal.table_search = c.table_search_min + (data[1] >> 2) % (c.table_search_max - c.table_search_min + 1);
  }

  // Generous destination, so a too-small dst never masks a finding.
  size_t dst_cap = n + (n / 2) + 4096;
  uint8_t *dst = (uint8_t *)malloc(dst_cap);
  if (!dst) abort();

  // The last program byte picks the entry point: half the runs take
  // _advanced, a quarter _chained with stats made of fuzz bytes (over a
  // genuine header half the time), and a quarter chain two halves of the
  // input from zeroed stats.
  uint8_t mode = size ? data[size - 1] : 0;
  crushlzfse_stats stats;
  memset(&stats, 0, sizeof stats);
  if ((mode & 3) == 2) {
    for (size_t i = 0; i < sizeof stats; i++)
      ((uint8_t *)&stats)[i] = size > 4 ? data[(i + 4) % size] ^ (uint8_t)(i * 151) : 0xff;
    if (mode & 4) stats.opaque[0] = genuine_stats_header();
  }

  static fuzzbuf_t input_buf;
  const uint8_t *exact_input = fuzz_copy(&input_buf, in, n);
  if ((mode & 3) == 3 && n <= 65536) {
    static fuzzbuf_t half_buf;
    size_t half = n / 2;
    for (int part = 0; part < 2; part++) {
      size_t len = part ? n - half : half;
      const uint8_t *src = fuzz_copy(&half_buf, exact_input + (part ? half : 0), len);
      size_t enc = crushlzfse_encode_buffer_chained(dst, dst_cap, src, len, NULL, 0, &params, &stats);
      fuzz_check_written(dst, enc);
      fuzz_check_written(&stats, sizeof stats);
      if (enc == 0) die("chained encode of a half failed", level, len, enc, 0);
      check_stream(level, src, len, dst, enc);
    }
    free(dst);
    return;
  }

  size_t enc = (mode & 3) == 2
                   ? crushlzfse_encode_buffer_chained(dst, dst_cap, exact_input, n, NULL, 0, &params, &stats)
                   : crushlzfse_encode_buffer_advanced(dst, dst_cap, exact_input, n, NULL, 0, &params);
  fuzz_check_written(dst, enc);
  fuzz_check_written(&stats, sizeof stats);

  // Every level is bounded to one already-independent 65536-byte piece per
  // call, whatever the strategy; anything larger must be a hard failure
  // (0), never a silent partial encode or a stream.
  if (n > 65536 && enc != 0)
    die("accepted an oversized (>65536) input instead of rejecting it", level, n, enc, 0);
  for (size_t i = 0; enc == 0 && i < CRUSHLZFSE_STATS_WORDS; i++)
    if (stats.opaque[i]) die("a failed chained encode kept its stats", level, n, enc, 0);

  if (enc != 0) check_stream(level, exact_input, n, dst, enc);

  free(dst);
}

// ---------------------------------------------------------------- entry points

#include "driver.h"
