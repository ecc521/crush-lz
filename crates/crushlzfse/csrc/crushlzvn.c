// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// CrushLZVN dispatch layer; crushlzvn.h has the public contract.

#include "crushlzvn.h"
#include "lzvn_encode_base.h"
#include "lzvn_decode_base.h"
#include "fast_match.h"
#include <stdlib.h>
#include <string.h>

// crushlzvn_get_capabilities must report exactly what greedy_params_valid enforces.
#ifndef CRUSHLZVN_GREEDY_MIN_HASH_BITS
#define CRUSHLZVN_GREEDY_MIN_HASH_BITS 10
#endif
#ifndef CRUSHLZVN_GREEDY_MAX_HASH_BITS
#define CRUSHLZVN_GREEDY_MAX_HASH_BITS 16
#endif
#ifndef CRUSHLZVN_GREEDY_MAX_HASH_WIDTH
#define CRUSHLZVN_GREEDY_MAX_HASH_WIDTH 64
#endif

static size_t align8(size_t x) { return (x + 7u) & ~(size_t)7u; }

// --- Params validation (reject, don't clamp) -------------------------

static int greedy_params_valid(const crushlzvn_encode_params *params) {
  if (params->p.greedy.hash_bits < CRUSHLZVN_GREEDY_MIN_HASH_BITS ||
      params->p.greedy.hash_bits > CRUSHLZVN_GREEDY_MAX_HASH_BITS)
    return 0;
  if (params->p.greedy.hash_width < 1 ||
      params->p.greedy.hash_width > CRUSHLZVN_GREEDY_MAX_HASH_WIDTH)
    return 0;
  return 1;
}

static int optimal_params_valid(const crushlzvn_encode_params *params) {
  if (params->p.optimal.search_depth < 1 || params->p.optimal.search_depth > LZVN_ZOPT_MAX_SEARCH_DEPTH)
    return 0;
  if (params->p.optimal.store_limit < 1 || params->p.optimal.store_limit > LZVN_ZOPT_MAX_STORE_LIMIT)
    return 0;
  if (params->p.optimal.hash_bits < LZVN_ZOPT_MIN_HASH_BITS || params->p.optimal.hash_bits > LZVN_ZOPT_MAX_HASH_BITS)
    return 0;
  if (params->p.optimal.pareto_k < 1 || params->p.optimal.pareto_k > LZVN_PARETO_MAX_K)
    return 0;
  return 1;
}

static int fast_params_valid(const crushlzvn_encode_params *params) {
  return crushlzfse_fast_params_valid(params->p.fast.hash_bits, params->p.fast.min_match, params->p.fast.skip_shift,
                                      params->p.fast.max_step, params->p.fast.long_table, params->p.fast.lazy);
}

static int crushlzvn_params_valid(const crushlzvn_encode_params *params) {
  if (params->strategy == CRUSHLZVN_STRATEGY_GREEDY)
    return greedy_params_valid(params);
  if (params->strategy == CRUSHLZVN_STRATEGY_OPTIMAL)
    return optimal_params_valid(params);
  if (params->strategy == CRUSHLZVN_STRATEGY_FAST)
    return fast_params_valid(params);
  return 0; // not a valid enum value
}

// Candidates stored per position, clamped to search_depth: a walk of d nodes
// reports at most d matches. Range rejection already happened in
// optimal_params_valid.
static int32_t cand_capacity_for(const crushlzvn_encode_params *params) {
  int32_t c = params->p.optimal.store_limit;
  if (c < 1) c = 1;
  if (c > LZVN_ZOPT_MAX_STORE_LIMIT) c = LZVN_ZOPT_MAX_STORE_LIMIT;
  if (params->p.optimal.search_depth >= 1 && c > params->p.optimal.search_depth) c = params->p.optimal.search_depth;
  return c;
}

// --- Scratch region carving --------------------------------------------

// Hash_bits for the OPTIMAL strategy's own alternate-parse check below, and
// for the level table's narrow GREEDY levels further down: at hash_bits=14
// a 64 KiB block has as many positions as the table has slots, so eviction
// is constant. Needed here, ahead of the level table, because
// optimal_region_size/crushlzvn_carve_optimal use it too.
#define CRUSHLZVN_GREEDY_NARROW_HASH_BITS 16

// The main table, then the long table when there is one.
static size_t fast_region_size(const crushlzvn_encode_params *params) {
  int hb = params->p.fast.hash_bits;
  if (hb < CRUSHLZFSE_FAST_MIN_HASH_BITS) hb = CRUSHLZFSE_FAST_MIN_HASH_BITS;
  if (hb > CRUSHLZFSE_FAST_MAX_HASH_BITS) hb = CRUSHLZFSE_FAST_MAX_HASH_BITS;
  return ((size_t)(params->p.fast.long_table ? 2 : 1) << hb) * sizeof(uint16_t);
}

static size_t greedy_region_size(int32_t hash_bits, int32_t hash_width) {
  size_t n_hash = (size_t)1 << hash_bits;
  size_t off = align8(n_hash * (size_t)hash_width * sizeof(int32_t));   // hist_pos
  off = align8(off + n_hash * (size_t)hash_width * sizeof(uint32_t));  // hist_value
  off = align8(off + n_hash * sizeof(uint16_t));                       // hist_cursor
  return off;
}

// Bound on the alternate parse's output for the fixed block size: the format
// loses 2 bytes per 271-byte literal chunk, plus a flat constant for tiny
// inputs.
static size_t alt_tmp_size_for(void) {
  return (size_t)LZVN_ZOPT_BLOCK_SIZE + (size_t)LZVN_ZOPT_BLOCK_SIZE / 8 + 4096;
}

// The OPTIMAL strategy's own diversity check: a full greedy parse alongside
// the DP, in case the DP's bounded search_depth/store_limit/pareto_k miss a match a
// plain linear scan would catch. Same wide matcher and hash_bits as the
// level table's narrow GREEDY levels (CRUSHLZVN_GREEDY_NARROW_HASH_BITS);
// width 4 matches level 0's. Measured: on both a 500-file real-world corpus
// and hand-built degenerate inputs, this wins essentially never (0-0.3% of
// blocks, saving <0.01% of bytes when it does): cheap insurance
// against a case the DP's bounds could in principle miss, not a routine
// contributor to ratio.
#define CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH 4

// Sizing and carving must pass the identical (cand_capacity, hash_bits,
// pareto_k) tuple; the block itself is the one fixed LZVN_ZOPT_BLOCK_SIZE.
//
// The alternate parse runs after the DP has already written its result to
// dst; zopt, pareto and padded_src are dead by then, nothing reads them
// again, so its own tables are carved to overlap that region instead of
// following it. Take the larger of the two, not the sum, the same pattern
// crushlzfse_scratch_size uses for its own strategy-vs-fallback regions.
static size_t optimal_region_size(int32_t cand_capacity, int32_t hash_bits, int32_t pareto_k) {
  size_t dp_region = align8(lzvn_zopt_scratch_size(cand_capacity, hash_bits));
  dp_region = align8(dp_region + lzvn_pareto_scratch_size(pareto_k));
  dp_region = align8(dp_region + (size_t)LZVN_ZOPT_BLOCK_SIZE + LZVN_ZOPT_SRC_PADDING);

  size_t alt_region = align8(alt_tmp_size_for());
  alt_region = align8(alt_region + greedy_region_size(CRUSHLZVN_GREEDY_NARROW_HASH_BITS, CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH));

  return dp_region > alt_region ? dp_region : alt_region;
}

typedef struct {
  int32_t *hist_pos;      // GREEDY only
  uint32_t *hist_value;   // GREEDY only
  uint16_t *hist_cursor;  // GREEDY only
  lzvn_zopt_scratch *zopt; // OPTIMAL only
  lzvn_pareto_scratch *pareto; // OPTIMAL only
  unsigned char *padded_src; // OPTIMAL only: the block, then padding
  unsigned char *alt_tmp;      // OPTIMAL only: the alternate parse's candidate output
  int32_t *alt_hist_pos;       // OPTIMAL only: the alternate parse's own table
  uint32_t *alt_hist_value;    // OPTIMAL only
  uint16_t *alt_hist_cursor;   // OPTIMAL only
} crushlzvn_regions;

static crushlzvn_regions crushlzvn_carve_greedy(void *base, int32_t hash_bits, int32_t hash_width) {
  crushlzvn_regions r;
  memset(&r, 0, sizeof(r));
  uint8_t *b = (uint8_t *)base;
  size_t n_hash = (size_t)1 << hash_bits;
  size_t off = 0;

  r.hist_pos = (int32_t *)(b + off);
  off = align8(off + n_hash * (size_t)hash_width * sizeof(int32_t));

  r.hist_value = (uint32_t *)(b + off);
  off = align8(off + n_hash * (size_t)hash_width * sizeof(uint32_t));

  r.hist_cursor = (uint16_t *)(b + off);
  return r;
}

static crushlzvn_regions crushlzvn_carve_optimal(void *base, int32_t cand_capacity,
                                                 int32_t hash_bits, int32_t pareto_k) {
  crushlzvn_regions r;
  memset(&r, 0, sizeof(r));
  uint8_t *b = (uint8_t *)base;
  size_t off = 0;

  r.zopt = (lzvn_zopt_scratch *)(b + off);
  off = align8(off + lzvn_zopt_scratch_size(cand_capacity, hash_bits));

  r.pareto = (lzvn_pareto_scratch *)(b + off);
  off = align8(off + lzvn_pareto_scratch_size(pareto_k));

  r.padded_src = b + off;
  // off deliberately not carried forward: zopt, pareto and padded_src are
  // all dead by the time the alternate parse runs (see optimal_region_size),
  // so it overlaps them from the base instead of sitting after them.

  size_t alt_off = 0;
  r.alt_tmp = b + alt_off;
  alt_off = align8(alt_off + alt_tmp_size_for());

  size_t alt_n = (size_t)1 << CRUSHLZVN_GREEDY_NARROW_HASH_BITS;
  r.alt_hist_pos = (int32_t *)(b + alt_off);
  alt_off = align8(alt_off + alt_n * (size_t)CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH * sizeof(int32_t));

  r.alt_hist_value = (uint32_t *)(b + alt_off);
  alt_off = align8(alt_off + alt_n * (size_t)CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH * sizeof(uint32_t));

  r.alt_hist_cursor = (uint16_t *)(b + alt_off);
  return r;
}

// --- Level table ------------------------------------------------------
//
// Levels -5 to -3 run the fast strategy (fast_match.h): it beats level -2
// outright on text but not on binaries, where three-byte matches and a
// wider search pay. Greedy widths saturate at 64, so levels 4-7 share one
// configuration; levels 8-10 run the Pareto DP (lzvn_zopt_pareto.h).
#define CRUSHLZVN_STORE_CAP(depth) ((depth) < LZVN_ZOPT_DEFAULT_STORE_LIMIT ? (depth) : LZVN_ZOPT_DEFAULT_STORE_LIMIT)
#define CRUSHLZVN_GREEDY_DEFAULT_HASH_BITS 14 // matches Apple's original LZVN encoder's fixed hash width
// CRUSHLZVN_GREEDY_NARROW_HASH_BITS (defined above, with the scratch carving
// that also needs it): narrow-width levels get a 16-bit table, stopping at
// width 4 to bound the scratch cost.

static const crushlzvn_encode_params LEVEL_TABLE[CRUSHLZVN_LEVEL_MAX - CRUSHLZVN_LEVEL_MIN + 1] = {
  /*  -5 */ {.strategy = CRUSHLZVN_STRATEGY_FAST, .p = {.fast = {13, 6, 3, 12, 0, 0}}},
  /*  -4 */ {.strategy = CRUSHLZVN_STRATEGY_FAST, .p = {.fast = {14, 4, 5, 8, 0, 0}}},
  /*  -3 */ {.strategy = CRUSHLZVN_STRATEGY_FAST, .p = {.fast = {14, 4, 6, 4, 0, 1}}},
  /*  -2 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_NARROW_HASH_BITS, 1}}},
  /*  -1 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_NARROW_HASH_BITS, 2}}},
  /*   0 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_NARROW_HASH_BITS, 4}}},
  /*   1 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_DEFAULT_HASH_BITS, 8}}},
  /*   2 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_DEFAULT_HASH_BITS, 16}}},
  /*   3 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_DEFAULT_HASH_BITS, 32}}},
  /*   4 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_DEFAULT_HASH_BITS, 64}}}, // widest greedy tier
  /*   5 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_DEFAULT_HASH_BITS, 64}}}, // alias of level 4
  /*   6 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_DEFAULT_HASH_BITS, 64}}}, // alias of level 4
  /*   7 */ {.strategy = CRUSHLZVN_STRATEGY_GREEDY, .p = {.greedy = {CRUSHLZVN_GREEDY_DEFAULT_HASH_BITS, 64}}}, // alias of level 4
  /*   8 */ {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {16, CRUSHLZVN_STORE_CAP(16), LZVN_ZOPT_DEFAULT_HASH_BITS, 2}}},  // first DP level
  /*   9 */ {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {16, CRUSHLZVN_STORE_CAP(16), LZVN_ZOPT_DEFAULT_HASH_BITS, 4}}},
  /*  10 */ {.strategy = CRUSHLZVN_STRATEGY_OPTIMAL, .p = {.optimal = {32, CRUSHLZVN_STORE_CAP(32), LZVN_ZOPT_DEFAULT_HASH_BITS, 6}}},
};

int crushlzvn_params_for_level(int level, crushlzvn_encode_params *out) {
  if (!out) return CRUSHLZVN_LEVEL_INVALID;
  if (level < CRUSHLZVN_LEVEL_MIN) level = CRUSHLZVN_LEVEL_MIN;
  if (level > CRUSHLZVN_LEVEL_MAX) level = CRUSHLZVN_LEVEL_MAX;
  *out = LEVEL_TABLE[level - CRUSHLZVN_LEVEL_MIN];
  return level;
}

crushlzvn_capabilities crushlzvn_get_capabilities(void) {
  crushlzvn_capabilities c;
  c.level_min = CRUSHLZVN_LEVEL_MIN;
  c.level_max = CRUSHLZVN_LEVEL_MAX;
  c.level_default = CRUSHLZVN_LEVEL_DEFAULT;
  c.greedy_hash_bits_min = CRUSHLZVN_GREEDY_MIN_HASH_BITS;
  c.greedy_hash_bits_max = CRUSHLZVN_GREEDY_MAX_HASH_BITS;
  c.greedy_hash_width_min = 1;
  c.greedy_hash_width_max = CRUSHLZVN_GREEDY_MAX_HASH_WIDTH;
  c.search_depth_min = 1;
  c.search_depth_max = LZVN_ZOPT_MAX_SEARCH_DEPTH;
  c.store_limit_min = 1;
  c.store_limit_max = LZVN_ZOPT_MAX_STORE_LIMIT;
  c.hash_bits_min = LZVN_ZOPT_MIN_HASH_BITS;
  c.hash_bits_max = LZVN_ZOPT_MAX_HASH_BITS;
  c.pareto_k_min = 1;
  c.pareto_k_max = LZVN_PARETO_MAX_K;
  c.fast_hash_bits_min = CRUSHLZFSE_FAST_MIN_HASH_BITS;
  c.fast_hash_bits_max = CRUSHLZFSE_FAST_MAX_HASH_BITS;
  c.fast_min_match_min = CRUSHLZFSE_FAST_MIN_MIN_MATCH;
  c.fast_min_match_max = CRUSHLZFSE_FAST_MAX_MIN_MATCH;
  c.fast_skip_shift_min = CRUSHLZFSE_FAST_MIN_SKIP_SHIFT;
  c.fast_skip_shift_max = CRUSHLZFSE_FAST_MAX_SKIP_SHIFT;
  c.fast_max_step_min = CRUSHLZFSE_FAST_MIN_MAX_STEP;
  c.fast_max_step_max = CRUSHLZFSE_FAST_MAX_MAX_STEP;
  c.fast_long_table_min = 0;
  c.fast_long_table_max = 1;
  c.fast_lazy_min = 0;
  c.fast_lazy_max = 1;
  return c;
}

size_t crushlzvn_scratch_size(const crushlzvn_encode_params *params) {
  if (!params) return 0;
  if (params->strategy == CRUSHLZVN_STRATEGY_FAST) return fast_region_size(params);
  if (params->strategy == CRUSHLZVN_STRATEGY_GREEDY) {
    int32_t hash_bits = params->p.greedy.hash_bits;
    int32_t hash_width = params->p.greedy.hash_width;
    if (hash_bits < CRUSHLZVN_GREEDY_MIN_HASH_BITS) hash_bits = CRUSHLZVN_GREEDY_MIN_HASH_BITS;
    if (hash_bits > CRUSHLZVN_GREEDY_MAX_HASH_BITS) hash_bits = CRUSHLZVN_GREEDY_MAX_HASH_BITS;
    if (hash_width < 1) hash_width = 1;
    if (hash_width > CRUSHLZVN_GREEDY_MAX_HASH_WIDTH) hash_width = CRUSHLZVN_GREEDY_MAX_HASH_WIDTH;
    return greedy_region_size(hash_bits, hash_width);
  }
  int32_t cand_capacity = cand_capacity_for(params);
  int32_t hash_bits = params->p.optimal.hash_bits;
  if (hash_bits < LZVN_ZOPT_MIN_HASH_BITS) hash_bits = LZVN_ZOPT_MIN_HASH_BITS;
  if (hash_bits > LZVN_ZOPT_MAX_HASH_BITS) hash_bits = LZVN_ZOPT_MAX_HASH_BITS;
  int32_t pareto_k = params->p.optimal.pareto_k;
  if (pareto_k < 1) pareto_k = 1;
  if (pareto_k > LZVN_PARETO_MAX_K) pareto_k = LZVN_PARETO_MAX_K;
  return optimal_region_size(cand_capacity, hash_bits, pareto_k);
}


// Encodes one piece as a complete LZVN stream ending in the end-of-stream op.
// Every call is the whole encode: both strategies are bounded to one
// already-independent LZVN_ZOPT_BLOCK_SIZE piece by
// crushlzvn_encode_buffer_advanced, matching decmpfs's own chunk size.
// LZVN's cost model is a tuned heuristic (see lzvn_encode_base.c), not a
// proven-tight one, at every strategy: greedy's own real worst case runs
// well past a naive per-byte estimate, and the optimal parser's bounded
// Pareto front can evict the pure-literal alternative even when it was
// cheaper. Falling back to a literal-only encoding whenever the parse
// found (if any) costs more than that floor makes every block's true cost
// bounded by lzvn_literal_final_cost() exactly, which is what lets
// crushlzvn_encode_bound() below be provable instead of an empirical
// margin over a moving target, mirroring crushlzfse.c's own raw
// fallback, which is exactly why its bound is already provable.
static size_t finish_with_literal_fallback(uint8_t *dst, size_t dst_size,
                                           const uint8_t *src, size_t src_size,
                                           int have_result, size_t best_size) {
  size_t lit_cost = (size_t)lzvn_literal_final_cost((int32_t)src_size) + 8;
  // lzvn_encode_literal_only_buffer needs some slack in dst_size beyond the
  // bytes it actually writes (emit_literal's own internal margin against
  // its wide copies); rather than duplicate that constant here, just try
  // it and fall through on failure; it is cheap and only ever called once
  // per block when it might improve on the real parse.
  if (!have_result || lit_cost < best_size) {
    size_t sz = lzvn_encode_literal_only_buffer(dst, dst_size, src, src_size);
    if (sz > 0) return sz;
  }
  return have_result ? best_size : 0;
}

static size_t encode_block(uint8_t *dst, size_t dst_size,
                           const uint8_t *src, size_t src_size,
                           void *scratch,
                           const crushlzvn_encode_params *params) {

  if (params->strategy == CRUSHLZVN_STRATEGY_FAST) {
    uint16_t *table = (uint16_t *)scratch;
    size_t entries = (size_t)1 << params->p.fast.hash_bits;
    int long_table = params->p.fast.long_table;
    memset(table, 0x00, (long_table ? 2 : 1) * entries * sizeof(uint16_t));
    size_t sz = lzvn_encode_fast_buffer(dst, dst_size, src, src_size, params->p.fast.hash_bits,
                                        params->p.fast.min_match, params->p.fast.skip_shift, params->p.fast.max_step,
                                        long_table, params->p.fast.lazy, table, long_table ? table + entries : NULL);
    return finish_with_literal_fallback(dst, dst_size, src, src_size, sz > 0, sz);
  }

  if (params->strategy == CRUSHLZVN_STRATEGY_GREEDY) {
    crushlzvn_regions r = crushlzvn_carve_greedy(scratch, params->p.greedy.hash_bits, params->p.greedy.hash_width);
    size_t sz = lzvn_encode_greedy_wide_buffer(dst, dst_size, src, src_size,
                                               params->p.greedy.hash_bits, params->p.greedy.hash_width,
                                               r.hist_pos, r.hist_value, r.hist_cursor);
    return finish_with_literal_fallback(dst, dst_size, src, src_size, sz > 0, sz);
  }

  // OPTIMAL strategy.

  int32_t cand_capacity = cand_capacity_for(params);
  crushlzvn_regions r = crushlzvn_carve_optimal(scratch, cand_capacity,
                                                params->p.optimal.hash_bits, params->p.optimal.pareto_k);

  lzvn_zopt_scratch_init(r.zopt, cand_capacity, params->p.optimal.hash_bits);
  r.zopt->search_depth = params->p.optimal.search_depth;
  lzvn_pareto_scratch_init(r.pareto, params->p.optimal.pareto_k);

  // The piece, then padding the candidate search may safely over-read; no
  // history is copied in any more, a call encodes exactly one
  // already-independent piece.
  unsigned char *piece = r.padded_src;
  memcpy(piece, src, src_size);
  memset(piece + src_size, 0, LZVN_ZOPT_SRC_PADDING);

  int have_result = 0;
  size_t best_size = 0;

  size_t dp_size = lzvn_encode_optimal_buffer_pareto(dst, dst_size, piece, src_size, r.zopt, r.pareto);
  if (dp_size > 0) {
    have_result = 1;
    best_size = dp_size;
  }

  // Keep the smaller of the DP and the alternate greedy parse; both are the
  // same bitstream.
  size_t alt_cap = alt_tmp_size_for();
  size_t alt_size = lzvn_encode_greedy_wide_buffer(r.alt_tmp, alt_cap, src, src_size,
                                                    CRUSHLZVN_GREEDY_NARROW_HASH_BITS, CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH,
                                                    r.alt_hist_pos, r.alt_hist_value, r.alt_hist_cursor);
  if (alt_size > 0 && alt_size <= dst_size && (!have_result || alt_size < best_size)) {
    memcpy(dst, r.alt_tmp, alt_size);
    best_size = alt_size;
    have_result = 1;
  }

  return finish_with_literal_fallback(dst, dst_size, src, src_size, have_result, best_size);
}

size_t crushlzvn_encode_buffer_advanced(void *dst_v, size_t dst_size,
                                        const void *src_v, size_t src_size,
                                        void *scratch, size_t scratch_size,
                                        const crushlzvn_encode_params *params) {
  uint8_t *dst = dst_v;
  const uint8_t *src = src_v;
  if (!crushlzvn_params_valid(params))
    return 0;
  // The public contract permits NULL only for an empty buffer. The lower
  // encoder wrappers require real pointers even when the size is zero.
  if (!dst || !src)
    return 0;

  // The caller contract (decmpfs) never hands a call more than one
  // already-independent LZVN_ZOPT_BLOCK_SIZE piece, for either strategy;
  // anything larger is a hard failure rather than silently chunked or
  // streamed.
  if (src_size > (size_t)LZVN_ZOPT_BLOCK_SIZE)
    return 0;

  // The region below is carved from the params, not from the buffer, so a
  // caller who sized for one level and encoded at another would have it run
  // off the end. A NULL scratch is allocated here and carries no extent.
  if (scratch && scratch_size < crushlzvn_scratch_size(params)) return 0;

  void *owned = NULL;
  if (!scratch) {
    owned = malloc(crushlzvn_scratch_size(params));
    if (!owned) return 0;
    scratch = owned;
  }

  // Bounded above to one block, so one call is the whole encode.
  size_t out = encode_block(dst, dst_size, src, src_size, scratch, params);

  free(owned);
  return out;
}

size_t crushlzvn_encode_buffer(void *dst, size_t dst_size,
                               const void *src, size_t src_size,
                               void *scratch, size_t scratch_size, int level) {
  crushlzvn_encode_params params;
  int lvl = crushlzvn_params_for_level(level, &params);
  (void)lvl;
  return crushlzvn_encode_buffer_advanced(dst, dst_size, src, src_size, scratch, scratch_size, &params);
}

size_t crushlzvn_encode_bound(size_t src_size, const crushlzvn_encode_params *params) {
  (void)params; // both strategies now share the one fixed block size
  // The same fixed block crushlzvn_encode_buffer_advanced caps every call
  // to, for both strategies; encode_block()'s literal fallback (above)
  // caps every block's real cost at lzvn_literal_final_cost(L) + 8, so
  // nothing here needs an empirical margin over the parser's cost model.
  // nblocks is 1 for any src_size a real call could actually use (encode
  // rejects anything over LZVN_ZOPT_BLOCK_SIZE outright); this stays a
  // ceiling division rather than a bare check so the formula is still a
  // safe, meaningful bound if ever queried for a larger src_size.
  size_t block = (size_t)LZVN_ZOPT_BLOCK_SIZE;
  size_t nblocks = src_size == 0 ? 1 : (src_size + block - 1) / block;
  // sum over blocks of lzvn_literal_final_cost(L_i) with sum(L_i) ==
  // src_size, L_i > 0, is at most src_size + 2*(src_size/271) + 2*nblocks:
  // floor(a/271)+floor(b/271) <= floor((a+b)/271) for any split, so summing
  // per block never exceeds src_size/271 taken as one term; each block's
  // remainder header costs at most 2 more, and the literal fallback itself
  // needs some dst_size slack beyond what it actually writes (emit_literal's
  // own margin against its wide copies, empirically up to 10 bytes and
  // independent of length) to even attempt succeeding for whichever block
  // needs it: +64 covers all of that with real room to spare, validated by
  // harness/conformance/lzfse_lzvn_bound_exactness_test.c.
  return src_size + 2 * (src_size / 271) + 2 * nblocks + 64;
}

int crushlzvn_decode_buffer(void *dst_v, size_t dst_size,
                            const void *src_v, size_t src_size,
                            size_t *out_len)
#ifdef LZVN_PROOF
__CPROVER_requires(src_size == 0 || (src_v != NULL && __CPROVER_r_ok(src_v, src_size)))
__CPROVER_requires(dst_size == 0 || (dst_v != NULL && __CPROVER_w_ok(dst_v, dst_size)))
__CPROVER_requires(src_size == 0 || dst_size == 0 || CRUSHLZVN_PROOF_RANGES_DISJOINT(src_v, src_size, dst_v, dst_size))
__CPROVER_requires(out_len == NULL || __CPROVER_w_ok(out_len, sizeof *out_len))
__CPROVER_requires(out_len == NULL || src_size == 0 || CRUSHLZVN_PROOF_RANGES_DISJOINT(out_len, sizeof *out_len, src_v, src_size))
__CPROVER_requires(out_len == NULL || dst_size == 0 || CRUSHLZVN_PROOF_RANGES_DISJOINT(out_len, sizeof *out_len, dst_v, dst_size))
__CPROVER_assigns(out_len != NULL: *out_len; dst_v != NULL: __CPROVER_object_upto(dst_v, dst_size))
__CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == CRUSHLZVN_OUTPUT_TOO_SMALL ==>
                 out_len != NULL && *out_len <= dst_size)
#endif
{
  uint8_t *dst = dst_v;
  const uint8_t *src = src_v;
  if (!out_len) return CRUSHLZVN_INVALID;
  if (src_size == 0) return CRUSHLZVN_INVALID;
  // Keep zero-capacity output geometry inside a real object, including when
  // the caller supplies NULL. The decoder still decides EOS versus truncation.
  uint8_t empty_dst;
  if (dst_size == 0) dst = &empty_dst;
  lzvn_decoder_state state;
  memset(&state, 0, sizeof(state));
  state.src = src;
  state.src_end = src + src_size;
  state.dst_begin = dst;
  state.dst = dst;
  state.dst_end = dst + dst_size;
  lzvn_decode(&state);
  if (!state.end_of_stream) {
    size_t left = (size_t)(state.src_end - state.src);
    // The decoder wants output room before it reads the next op, so a stream
    // whose remaining bytes are just the end op is complete when dst is full.
    if (!(left >= 8 && state.src[0] == 0x06 && !state.truncated_mid_op)) {
      if (state.dst == state.dst_end && left > 0) {
        *out_len = (size_t)(state.dst - dst);
        return CRUSHLZVN_OUTPUT_TOO_SMALL;
      }
      return CRUSHLZVN_INVALID;
    }
  }
  *out_len = (size_t)(state.dst - dst);
  return 0;
}
