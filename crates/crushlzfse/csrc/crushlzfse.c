// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

// CrushLZFSE dispatch layer, see crushlzfse.h for the public API this
// implements: init state, pick a strategy, commit, and fall back to an
// LZVN or uncompressed block when that is smaller.
#include "crushlzfse.h"
#include "lzfse_internal.h"
#include "fast_match.h"
#include "crushlzvn.h"
#include "row_hash.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// The lazy params' ranges, which crushlzfse_get_capabilities reports. Each
// level is sized by its own hash_bits/hash_width, so a smaller level never
// pays for a wider one. The width ceiling is what one tag-row compare
// covers (row_hash.h).
#define CRUSHLZFSE_LAZY_MIN_HASH_BITS  10
#define CRUSHLZFSE_LAZY_MAX_HASH_BITS  16
#define CRUSHLZFSE_LAZY_MAX_HASH_WIDTH ROW_HASH_MAX_MASK_WIDTH
#define CRUSHLZFSE_LAZY_MAX_LOOKAHEAD  2


static int fast_hash_bits_for(const crushlzfse_encode_params *params) {
  int hb = params->p.fast.hash_bits;
  if (hb < CRUSHLZFSE_FAST_MIN_HASH_BITS) hb = CRUSHLZFSE_FAST_MIN_HASH_BITS;
  if (hb > CRUSHLZFSE_FAST_MAX_HASH_BITS) hb = CRUSHLZFSE_FAST_MAX_HASH_BITS;
  return hb;
}

static size_t lazy_history_scratch_size(int hash_bits, int hash_width) {
  size_t nbuckets = (size_t)1 << hash_bits;
  // hist_cursor: one round-robin insert slot per bucket. The tag rows are
  // read 16 slots at a time, so the last row needs padding behind it.
  return nbuckets * (size_t)hash_width * (sizeof(int32_t) + sizeof(uint8_t))
       + ROW_HASH_TAG_PADDING + nbuckets * sizeof(uint16_t);
}

// Clamps lazy hash_bits/hash_width; scratch sizing and encoding both use
// this, so they agree on the table size.
static void lazy_dims_for(const crushlzfse_encode_params *params, int *hash_bits, int *hash_width) {
  int hb = params->p.lazy.hash_bits;
  int hw = params->p.lazy.hash_width;
  if (hb < CRUSHLZFSE_LAZY_MIN_HASH_BITS) hb = CRUSHLZFSE_LAZY_MIN_HASH_BITS;
  if (hb > CRUSHLZFSE_LAZY_MAX_HASH_BITS) hb = CRUSHLZFSE_LAZY_MAX_HASH_BITS;
  if (hw < 1) hw = 1;
  if (hw > CRUSHLZFSE_LAZY_MAX_HASH_WIDTH) hw = CRUSHLZFSE_LAZY_MAX_HASH_WIDTH;
  *hash_bits = hb; *hash_width = hw;
}

// Small-input fallback: below LZFSE_ENCODE_LZVN_THRESHOLD the block is also
// tried as LZVN and as raw, and the smallest of the three wins.
// CRUSHLZFSE_LZVN_TMP_SIZE holds the candidate output, so dst is untouched
// unless LZVN wins.
#define CRUSHLZFSE_LZVN_TMP_SIZE \
  (LZFSE_ENCODE_LZVN_THRESHOLD + sizeof(lzvn_compressed_block_header) + 4)

// The fallback runs LZVN level -4's fast search under the fast levels and
// level 0's greedy one (Apple's encoder, wider table aside) under the rest.
// An optimal LZVN parse here measured 0.01 to 0.03 points for twice the
// time: LZFSE itself wins most blocks this short. Its inputs are under
// LZFSE_ENCODE_LZVN_THRESHOLD, so positions fit 12 bits and a bigger table
// only costs clearing.
#define CRUSHLZFSE_LZVN_FALLBACK_HASH_BITS 12

static void lzvn_fallback_params(const crushlzfse_encode_params *params, crushlzvn_encode_params *out) {
  crushlzvn_params_for_level(params->strategy == CRUSHLZFSE_STRATEGY_FAST ? -4 : 0, out);
  if (out->strategy == CRUSHLZVN_STRATEGY_FAST)
    out->p.fast.hash_bits = CRUSHLZFSE_LZVN_FALLBACK_HASH_BITS;
  else
    out->p.greedy.hash_bits = CRUSHLZFSE_LZVN_FALLBACK_HASH_BITS;
}

static size_t lzvn_fallback_region_size(const crushlzfse_encode_params *params) {
  crushlzvn_encode_params fp;
  lzvn_fallback_params(params, &fp);
  return (crushlzvn_scratch_size(&fp) + 7u) & ~(size_t)7u;
}

// DP slot rows per position: the level's own literal-state cap, clamped.
static int32_t nslots_for(const crushlzfse_encode_params *params) {
  if (params->strategy != CRUSHLZFSE_STRATEGY_OPTIMAL) return 1;
  int32_t k = params->p.optimal.max_live_buckets;
  if (k < 1) k = ZOPT_MAX_LIVE_BUCKETS;
  if (k > LZFSE_ENCODE_L_SYMBOLS) k = LZFSE_ENCODE_L_SYMBOLS;
  return k;
}

// Candidate slots per position a given params needs. Only the DP touches
// the candidate arrays, so the other strategies ask for the minimum.
static int32_t cand_capacity_for(const crushlzfse_encode_params *params) {
  if (params->strategy != CRUSHLZFSE_STRATEGY_OPTIMAL) return 1;
  // Storage capacity, from store_limit, clamped to the search depth: a walk
  // of d nodes reports at most d matches. Rejection of bad params happens in
  // crushlzfse_encode_buffer_advanced.
  int32_t c = params->p.optimal.store_limit;
  if (c < 1) c = 1;
  if (c > ZOPT_MAX_STORE_LIMIT) c = ZOPT_MAX_STORE_LIMIT;
  int32_t depth = params->p.optimal.search_depth;
  if (depth >= 1 && c > depth) c = depth;
  return c;
}

size_t crushlzfse_scratch_size(const crushlzfse_encode_params *params) {
  // Fast needs its hash tables, lazy its history table, optimal the DP
  // scratch; each level is sized by its own params.
  size_t strategy_size;
  if (!params) return 0;
  if (params->strategy == CRUSHLZFSE_STRATEGY_FAST) {
    strategy_size = ((size_t)(params->p.fast.long_table ? 2 : 1) << fast_hash_bits_for(params)) * sizeof(uint16_t);
  } else if (params->strategy != CRUSHLZFSE_STRATEGY_OPTIMAL) {
    int hb, hw;
    lazy_dims_for(params, &hb, &hw);
    strategy_size = lazy_history_scratch_size(hb, hw);
  } else {
    strategy_size = lzfse_zopt_scratch_size(cand_capacity_for(params), params->p.optimal.split_max_blocks, params->p.optimal.hash_bits, nslots_for(params), params->p.optimal.table_search);
  }
  // The LZVN/raw fallbacks reuse the same region afterwards, so take the
  // larger of the two, not the sum.
  size_t fallback_size = lzvn_fallback_region_size(params) + (size_t)CRUSHLZFSE_LZVN_TMP_SIZE;
  size_t region_size = strategy_size > fallback_size ? strategy_size : fallback_size;
  return sizeof(lzfse_encoder_state) + region_size;
}


// The level table: fast for -5 to -1, lazy for 0 to 5, the DP for 6 to 11.
// The fast levels trade hashed length for speed: every literal a skipped
// match leaves costs an FSE encode, so a longer min_match (fewer, longer
// matches) buys more speed per ratio than a faster stride does. -2 adds the
// long table and -1 the lazy step. The lazy levels add lookahead first and
// then width. The tree saturates at a search depth of 32, past which
// iterations and reparse (from level 9) and the table search (from level
// 10) are what buy ratio.
static const crushlzfse_encode_params LEVEL_TABLE[CRUSHLZFSE_LEVEL_MAX - CRUSHLZFSE_LEVEL_MIN + 1] = {
  { .strategy = CRUSHLZFSE_STRATEGY_FAST,    .p.fast    = { .hash_bits = 13, .min_match = 8, .skip_shift = 3, .max_step = 12, .long_table = 0, .lazy = 0 } },
  { .strategy = CRUSHLZFSE_STRATEGY_FAST,    .p.fast    = { .hash_bits = 13, .min_match = 6, .skip_shift = 3, .max_step = 12, .long_table = 0, .lazy = 0 } },
  { .strategy = CRUSHLZFSE_STRATEGY_FAST,    .p.fast    = { .hash_bits = 14, .min_match = 5, .skip_shift = 4, .max_step = 16, .long_table = 0, .lazy = 0 } },
  { .strategy = CRUSHLZFSE_STRATEGY_FAST,    .p.fast    = { .hash_bits = 14, .min_match = 5, .skip_shift = 6, .max_step = 4, .long_table = 1, .lazy = 0 } },
  { .strategy = CRUSHLZFSE_STRATEGY_FAST,    .p.fast    = { .hash_bits = 14, .min_match = 4, .skip_shift = 6, .max_step = 4, .long_table = 1, .lazy = 1 } },
  { .strategy = CRUSHLZFSE_STRATEGY_LAZY,    .p.lazy    = { .hash_bits = 14, .hash_width = 4, .lookahead = 0 } },
  { .strategy = CRUSHLZFSE_STRATEGY_LAZY,    .p.lazy    = { .hash_bits = 14, .hash_width = 4, .lookahead = 1 } },
  { .strategy = CRUSHLZFSE_STRATEGY_LAZY,    .p.lazy    = { .hash_bits = 16, .hash_width = 8, .lookahead = 1 } },
  { .strategy = CRUSHLZFSE_STRATEGY_LAZY,    .p.lazy    = { .hash_bits = 16, .hash_width = 8, .lookahead = 2 } },
  { .strategy = CRUSHLZFSE_STRATEGY_LAZY,    .p.lazy    = { .hash_bits = 16, .hash_width = 16, .lookahead = 2 } },
  { .strategy = CRUSHLZFSE_STRATEGY_LAZY,    .p.lazy    = { .hash_bits = 14, .hash_width = 32, .lookahead = 2 } },
  { .strategy = CRUSHLZFSE_STRATEGY_OPTIMAL, .p.optimal = { .search_depth = 4, .iterations = 1, .enable_reparse = 0, .split_max_blocks = 1, .hash_bits = ZOPT_DEFAULT_HASH_BITS, .store_limit = ZOPT_DEFAULT_STORE_LIMIT, .tuple_tax = 512, .max_live_buckets = 1 } },  // first DP level
  { .strategy = CRUSHLZFSE_STRATEGY_OPTIMAL, .p.optimal = { .search_depth = 8, .iterations = 1, .enable_reparse = 0, .split_max_blocks = 1, .hash_bits = ZOPT_DEFAULT_HASH_BITS, .store_limit = ZOPT_DEFAULT_STORE_LIMIT, .tuple_tax = 512, .max_live_buckets = 2 } },
  { .strategy = CRUSHLZFSE_STRATEGY_OPTIMAL, .p.optimal = { .search_depth = 16, .iterations = 1, .enable_reparse = 0, .split_max_blocks = ZOPT_DEFAULT_SPLIT_MAX_BLOCKS, .hash_bits = ZOPT_DEFAULT_HASH_BITS, .store_limit = ZOPT_DEFAULT_STORE_LIMIT, .tuple_tax = 512, .max_live_buckets = 2 } },
  { .strategy = CRUSHLZFSE_STRATEGY_OPTIMAL, .p.optimal = { .search_depth = 32, .iterations = 2, .enable_reparse = 1, .split_max_blocks = ZOPT_DEFAULT_SPLIT_MAX_BLOCKS, .hash_bits = ZOPT_DEFAULT_HASH_BITS, .store_limit = ZOPT_DEFAULT_STORE_LIMIT, .tuple_tax = 256, .max_live_buckets = 4 } },
  { .strategy = CRUSHLZFSE_STRATEGY_OPTIMAL, .p.optimal = { .search_depth = 32, .iterations = 3, .enable_reparse = 1, .split_max_blocks = ZOPT_DEFAULT_SPLIT_MAX_BLOCKS, .hash_bits = ZOPT_DEFAULT_HASH_BITS, .store_limit = ZOPT_DEFAULT_STORE_LIMIT, .tuple_tax = 0, .max_live_buckets = 4, .table_search = 1 } },
  { .strategy = CRUSHLZFSE_STRATEGY_OPTIMAL, .p.optimal = { .search_depth = 32, .iterations = 6, .enable_reparse = 1, .split_max_blocks = ZOPT_DEFAULT_SPLIT_MAX_BLOCKS, .hash_bits = ZOPT_DEFAULT_HASH_BITS, .store_limit = ZOPT_DEFAULT_STORE_LIMIT, .tuple_tax = 0, .max_live_buckets = 8, .table_search = 4 } },
};

int crushlzfse_params_for_level(int level, crushlzfse_encode_params *out) {
  if (!out) return CRUSHLZFSE_LEVEL_INVALID;
  if (level < CRUSHLZFSE_LEVEL_MIN) level = CRUSHLZFSE_LEVEL_MIN;
  if (level > CRUSHLZFSE_LEVEL_MAX) level = CRUSHLZFSE_LEVEL_MAX;
  *out = LEVEL_TABLE[level - CRUSHLZFSE_LEVEL_MIN];
  return level;
}

// Reads the same constants the validators check, so the two cannot drift.
crushlzfse_capabilities crushlzfse_get_capabilities(void) {
  crushlzfse_capabilities c;
  c.level_min = CRUSHLZFSE_LEVEL_MIN;
  c.level_max = CRUSHLZFSE_LEVEL_MAX;
  c.level_default = CRUSHLZFSE_LEVEL_DEFAULT;
  c.search_depth_min = 1;
  c.search_depth_max = ZOPT_MAX_SEARCH_DEPTH;
  c.iterations_min = 1;
  c.iterations_max = ZOPT_MAX_ITERATIONS;
  c.enable_reparse_min = 0;
  c.enable_reparse_max = 1;
  c.split_max_blocks_min = 1;
  c.split_max_blocks_max = ZOPT_MAX_SPLIT_MAX_BLOCKS;
  c.optimal_hash_bits_min = ZOPT_MIN_HASH_BITS;
  c.optimal_hash_bits_max = ZOPT_MAX_HASH_BITS;
  c.store_limit_min = 1;
  c.store_limit_max = ZOPT_MAX_STORE_LIMIT;
  c.tuple_tax_min = 0;
  c.tuple_tax_max = ZOPT_MAX_TUPLE_TAX;
  c.max_live_buckets_min = 1;
  c.max_live_buckets_max = LZFSE_ENCODE_L_SYMBOLS;
  c.table_search_min = 0;
  c.table_search_max = ZOPT_MAX_TABLE_SEARCH;
  c.lazy_hash_bits_min = CRUSHLZFSE_LAZY_MIN_HASH_BITS;
  c.lazy_hash_bits_max = CRUSHLZFSE_LAZY_MAX_HASH_BITS;
  c.lazy_hash_width_min = 1;
  c.lazy_hash_width_max = CRUSHLZFSE_LAZY_MAX_HASH_WIDTH;
  c.lazy_lookahead_min = 0;
  c.lazy_lookahead_max = CRUSHLZFSE_LAZY_MAX_LOOKAHEAD;
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

// Validation, not clamping: crushlzfse_encode_buffer_advanced rejects any
// out-of-range params field. The clamping helpers above exist only for
// scratch sizing.
static int lazy_params_valid(const crushlzfse_encode_params *params) {
  int hb = params->p.lazy.hash_bits;
  int hw = params->p.lazy.hash_width;
  int la = params->p.lazy.lookahead;
  return hb >= CRUSHLZFSE_LAZY_MIN_HASH_BITS && hb <= CRUSHLZFSE_LAZY_MAX_HASH_BITS &&
         hw >= 1 && hw <= CRUSHLZFSE_LAZY_MAX_HASH_WIDTH &&
         la >= 0 && la <= CRUSHLZFSE_LAZY_MAX_LOOKAHEAD;
}

static int fast_params_valid(const crushlzfse_encode_params *params) {
  return crushlzfse_fast_params_valid(params->p.fast.hash_bits, params->p.fast.min_match, params->p.fast.skip_shift,
                                      params->p.fast.max_step, params->p.fast.long_table, params->p.fast.lazy);
}

static int optimal_params_valid(const crushlzfse_encode_params *params) {
  int search_depth = params->p.optimal.search_depth;
  int iterations = params->p.optimal.iterations;
  int enable_reparse = params->p.optimal.enable_reparse;
  int32_t split_max_blocks = params->p.optimal.split_max_blocks;
  int32_t hash_bits = params->p.optimal.hash_bits;
  int32_t store_limit = params->p.optimal.store_limit;
  int32_t max_live_buckets = params->p.optimal.max_live_buckets;
  int32_t tuple_tax = params->p.optimal.tuple_tax;
  int32_t table_search = params->p.optimal.table_search;
  return search_depth >= 1 && search_depth <= ZOPT_MAX_SEARCH_DEPTH &&
         iterations >= 1 && iterations <= ZOPT_MAX_ITERATIONS &&
         (enable_reparse == 0 || enable_reparse == 1) &&
         split_max_blocks >= 1 && split_max_blocks <= ZOPT_MAX_SPLIT_MAX_BLOCKS &&
         hash_bits >= ZOPT_MIN_HASH_BITS && hash_bits <= ZOPT_MAX_HASH_BITS &&
         store_limit >= 1 && store_limit <= ZOPT_MAX_STORE_LIMIT &&
         max_live_buckets >= 1 && max_live_buckets <= LZFSE_ENCODE_L_SYMBOLS &&
         tuple_tax >= 0 && tuple_tax <= ZOPT_MAX_TUPLE_TAX &&
         table_search >= 0 && table_search <= ZOPT_MAX_TABLE_SEARCH;
}

// Raw block escape, so an input no strategy can shrink still yields a
// valid stream.
static size_t write_uncompressed_block(uint8_t *dst, size_t dst_size, const uint8_t *src, size_t src_size)
#ifdef LZFSE_PROOF
LZFSE_REQUIRES(src != NULL && __CPROVER_r_ok(src, src_size))
LZFSE_REQUIRES(dst != NULL && __CPROVER_w_ok(dst, dst_size))
LZFSE_REQUIRES(!__CPROVER_same_object(src, dst))
LZFSE_ASSIGNS(src_size + 12 <= dst_size && src_size < (size_t)INT32_MAX: __CPROVER_object_upto(dst, src_size + 12))
LZFSE_ENSURES(src_size + 12 > dst_size || src_size >= (size_t)INT32_MAX ? __CPROVER_return_value == 0 : __CPROVER_return_value == src_size + 12)
#endif
{
  if (src_size + 12 > dst_size || src_size >= (size_t)INT32_MAX) return 0;
  uncompressed_block_header header = { .magic = LZFSE_UNCOMPRESSED_BLOCK_MAGIC, .n_raw_bytes = (uint32_t)src_size };
  uint8_t *p = dst;
  memcpy(p, &header, sizeof(header));
  p += sizeof(header);
  memcpy(p, src, src_size);
  p += src_size;
  store4(p, LZFSE_ENDOFSTREAM_BLOCK_MAGIC);
  p += 4;
  return (size_t)(p - dst);
}

// Encodes one piece of input as a complete stream (ending in bvx$). Every
// call is the whole encode: every strategy is bounded to one
// already-independent LZFSE_ZOPT_BLOCK_SIZE piece by
// crushlzfse_encode_buffer_advanced, matching decmpfs's own chunk size.
// seed and stats are lzfse_encoder_state's chaining fields, either may be
// NULL. *stats_valid is set when the stream returned is the LZFSE one stats
// tallied, not an LZVN or raw fallback.
static size_t encode_block(uint8_t *dst, size_t dst_size,
                           const uint8_t *src, size_t src_size,
                           void *scratch,
                           const crushlzfse_encode_params *params,
                           const uint32_t *seed, uint32_t *stats, int *stats_valid) {
  uint8_t *scratch_bytes = (uint8_t *)scratch;
  lzfse_encoder_state *state = (lzfse_encoder_state *)scratch_bytes;
  // Only the fields ahead of the L/M/D and literal arrays: those are written
  // before they are read (n_matches and n_literals count what is live).
  // zopt, after them, is set below.
  memset(state, 0x00, offsetof(lzfse_encoder_state, l_values));
  state->lmd_seed = seed;
  state->lmd_stats = stats;
  // The strategy's region follows `state` in the caller's scratch; the layout
  // must match crushlzfse_scratch_size.
  uint8_t *match_tables = NULL;
  if (params->strategy == CRUSHLZFSE_STRATEGY_OPTIMAL) {
    state->zopt = (lzfse_zopt_scratch *)(scratch_bytes + sizeof(lzfse_encoder_state));
    lzfse_zopt_scratch_init(state->zopt, cand_capacity_for(params), params->p.optimal.split_max_blocks, params->p.optimal.hash_bits, nslots_for(params), params->p.optimal.table_search);
  } else {
    state->zopt = NULL; // only the optimal strategy enters the DP
    match_tables = scratch_bytes + sizeof(lzfse_encoder_state);
  }

  // dst holds the smallest candidate seen so far.
  int have_result = 0;
  size_t best_size = 0;

  if (lzfse_encode_init(state) == LZFSE_STATUS_OK) {
    state->dst = dst;
    state->dst_begin = dst;
    state->dst_end = dst + dst_size;
    state->src = src;
    state->src_encode_i = 0;
    state->src_end = (lzfse_offset)src_size;

    int base_ok;
    if (params->strategy == CRUSHLZFSE_STRATEGY_FAST) {
      // Layout: the main table, then the long table when there is one.
      int hb = params->p.fast.hash_bits;
      int long_table = params->p.fast.long_table;
      size_t entries = (size_t)1 << hb;
      uint16_t *table = (uint16_t *)match_tables;
      memset(table, 0x00, (long_table ? 2 : 1) * entries * sizeof(uint16_t));
      base_ok = crushlzfse_encode_base_fast(state, hb, params->p.fast.min_match, params->p.fast.skip_shift,
                                            params->p.fast.max_step, long_table, params->p.fast.lazy,
                                            table, long_table ? table + entries : NULL);
    } else if (params->strategy == CRUSHLZFSE_STRATEGY_LAZY) {
      int hb = params->p.lazy.hash_bits;
      int hw = params->p.lazy.hash_width;
      // Layout: hw*nbuckets positions, then hw*nbuckets tags and their read
      // padding, then nbuckets cursors.
      size_t nbuckets = (size_t)1 << hb;
      int32_t *hist_pos = (int32_t *)match_tables;
      uint8_t *hist_tag = (uint8_t *)(hist_pos + nbuckets * (size_t)hw);
      uint16_t *hist_cursor = (uint16_t *)(hist_tag + nbuckets * (size_t)hw + ROW_HASH_TAG_PADDING);
      // Tags and cursors only: an all-zero tag row is one no key can match,
      // so the positions behind it are never read before they are written.
      memset(hist_tag, 0x00, nbuckets * (size_t)hw + ROW_HASH_TAG_PADDING);
      memset(hist_cursor, 0x00, nbuckets * sizeof(uint16_t));
      base_ok = crushlzfse_encode_base_lazy(state, hb, hw, params->p.lazy.lookahead, hist_pos, hist_tag,
                                            hist_cursor);
    } else {
      state->zopt->search_depth = params->p.optimal.search_depth;
      state->zopt->iterations = params->p.optimal.iterations;
      state->zopt->enable_reparse = params->p.optimal.enable_reparse;
      state->zopt->max_live_buckets = params->p.optimal.max_live_buckets;
      state->zopt->tuple_tax = params->p.optimal.tuple_tax;
      base_ok = lzfse_encode_base(state);
    }
    if (base_ok == LZFSE_STATUS_OK && lzfse_encode_finish(state) == LZFSE_STATUS_OK) {
      best_size = (size_t)(state->dst - dst);
      have_result = 1;
      *stats_valid = 1;
    }
  }

  // Fallback 1: LZVN, reusing the strategy's scratch region.
  if (src_size >= LZVN_ENCODE_MIN_SRC_SIZE && src_size < LZFSE_ENCODE_LZVN_THRESHOLD) {
    crushlzvn_encode_params fp;
    lzvn_fallback_params(params, &fp);
    uint8_t *lzvn_scratch = scratch_bytes + sizeof(lzfse_encoder_state);
    size_t lzvn_scratch_size = lzvn_fallback_region_size(params);
    uint8_t *lzvn_tmp = lzvn_scratch + lzvn_scratch_size;
    size_t extra = sizeof(lzvn_compressed_block_header) + 4;
    size_t payload_cap = (size_t)CRUSHLZFSE_LZVN_TMP_SIZE - extra;
    size_t sz = crushlzvn_encode_buffer_advanced(lzvn_tmp + sizeof(lzvn_compressed_block_header), payload_cap,
                                                 src, src_size, lzvn_scratch, lzvn_scratch_size, &fp);
    // sz == 0 means LZVN declined. Adopt it only if it beats the best so far
    // and fits dst (its temp buffer is sized independently of dst_size).
    if (sz > 0 && sz + extra < (have_result ? best_size : (size_t)-1) && sz + extra <= dst_size) {
      lzvn_compressed_block_header header;
      header.magic = LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC;
      header.n_raw_bytes = (uint32_t)src_size;
      header.n_payload_bytes = (uint32_t)sz;
      memcpy(lzvn_tmp, &header, sizeof(header));
      store4(lzvn_tmp + sizeof(header) + sz, LZFSE_ENDOFSTREAM_BLOCK_MAGIC);
      memcpy(dst, lzvn_tmp, sz + extra);
      best_size = sz + extra;
      have_result = 1;
      *stats_valid = 0;
    }
  }

  // Fallback 2: raw, so an incompressible input never expands.
  if (src_size + 12 <= dst_size && (!have_result || src_size + 12 < best_size)) {
    size_t sz = write_uncompressed_block(dst, dst_size, src, src_size);
    if (sz > 0) { best_size = sz; have_result = 1; *stats_valid = 0; }
  }

  return have_result ? best_size : 0;
}

static size_t encode_checked(void *dst_v, size_t dst_size,
                             const void *src_v, size_t src_size,
                             void *scratch, size_t scratch_size,
                             const crushlzfse_encode_params *params,
                             const uint32_t *seed, uint32_t *stats, int *stats_valid) {
  uint8_t *dst = dst_v;
  const uint8_t *src = src_v;
  if (params->strategy == CRUSHLZFSE_STRATEGY_LAZY) {
    if (!lazy_params_valid(params)) return 0;
  } else if (params->strategy == CRUSHLZFSE_STRATEGY_FAST) {
    if (!fast_params_valid(params)) return 0;
  } else if (params->strategy == CRUSHLZFSE_STRATEGY_OPTIMAL) {
    if (!optimal_params_valid(params)) return 0;
  } else {
    return 0;
  }

  // The caller contract (decmpfs) never hands a call more than one
  // already-independent LZFSE_ZOPT_BLOCK_SIZE piece, whatever the strategy;
  // anything larger is a hard failure rather than silently chunked or
  // streamed.
  if (src_size > (size_t)LZFSE_ZOPT_BLOCK_SIZE)
    return 0;

  // The region below is carved from the params, not from the buffer, so a
  // caller who sized for one level and encoded at another would have it run
  // off the end. A NULL scratch is allocated here and carries no extent.
  if (scratch && scratch_size < crushlzfse_scratch_size(params)) return 0;

  void *owned = NULL;
  if (!scratch) {
    owned = malloc(crushlzfse_scratch_size(params));
    if (!owned) return 0;
    scratch = owned;
  }

  // Bounded above to one block, so one call is the whole encode.
  size_t out = encode_block(dst, dst_size, src, src_size, scratch, params, seed, stats, stats_valid);

  free(owned);
  return out;
}

size_t crushlzfse_encode_buffer_advanced(void *dst, size_t dst_size,
                                          const void *src, size_t src_size,
                                          void *scratch, size_t scratch_size,
                                          const crushlzfse_encode_params *params) {
  int stats_valid = 0;
  return encode_checked(dst, dst_size, src, src_size, scratch, scratch_size, params, NULL, NULL, &stats_valid);
}

// crushlzfse_stats layout: a header word, then the L, M and D symbol counts
// of the chunk's emitted blocks. Any other header means no seed.
#define CRUSHLZFSE_STATS_MAGIC 0x31534d4cu // "LMS1"
typedef char crushlzfse_stats_layout[CRUSHLZFSE_STATS_WORDS == 1 + LZFSE_LMD_STATS_WORDS ? 1 : -1];

// Above any genuine chunk's symbol count, which is at most one per 3 bytes,
// and far below what fse_normalize_freq's 32-bit arithmetic can take.
#define CRUSHLZFSE_SEED_TOTAL_CAP (1u << 16)

#if defined(CRUSHLZFSE_DISPATCH_PROOF)
static int load_seed(const crushlzfse_stats *stats, uint32_t *seed)
__CPROVER_requires(stats != NULL && __CPROVER_r_ok(stats, sizeof *stats))
__CPROVER_requires(seed != NULL && __CPROVER_w_ok(seed, LZFSE_LMD_STATS_WORDS * sizeof *seed))
__CPROVER_requires(!__CPROVER_same_object(stats, seed))
__CPROVER_assigns(__CPROVER_object_upto(seed, LZFSE_LMD_STATS_WORDS * sizeof *seed))
__CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == 1)
__CPROVER_ensures(stats->opaque[0] != CRUSHLZFSE_STATS_MAGIC ==> __CPROVER_return_value == 0)
#else
static int load_seed(const crushlzfse_stats *stats, uint32_t *seed)
#endif
{
  static const int table_size[3] = {LZFSE_ENCODE_L_SYMBOLS, LZFSE_ENCODE_M_SYMBOLS, LZFSE_ENCODE_D_SYMBOLS};
  if (stats->opaque[0] != CRUSHLZFSE_STATS_MAGIC) return 0;
  const uint32_t *in = stats->opaque + 1;
  for (int t = 0; t < 3; t++) {
    int n = table_size[t];
    uint64_t total = 0;
    for (int i = 0; i < n; i++) total += in[i];
    if (total == 0) return 0;
    for (int i = 0; i < n; i++) {
      uint64_t c = in[i];
      if (total > CRUSHLZFSE_SEED_TOTAL_CAP) {
        c = c * CRUSHLZFSE_SEED_TOTAL_CAP / total;
        if (c == 0 && in[i] != 0) c = 1;
      }
      seed[i] = (uint32_t)c;
    }
    in += n;
    seed += n;
  }
  return 1;
}

size_t crushlzfse_encode_buffer_chained(void *dst, size_t dst_size,
                                         const void *src, size_t src_size,
                                         void *scratch, size_t scratch_size,
                                         const crushlzfse_encode_params *params,
                                         crushlzfse_stats *stats) {
  if (!stats) return crushlzfse_encode_buffer_advanced(dst, dst_size, src, src_size, scratch, scratch_size, params);
  // Copied out first, so stats can be overwritten below.
  uint32_t seed[LZFSE_LMD_STATS_WORDS], tally[LZFSE_LMD_STATS_WORDS];
  int have_seed = load_seed(stats, seed);
  memset(tally, 0, sizeof tally);
  int stats_valid = 0;
  size_t out = encode_checked(dst, dst_size, src, src_size, scratch, scratch_size, params,
                              have_seed ? seed : NULL, tally, &stats_valid);
  // An LZVN, raw or empty stream has no LZFSE symbols to pass on, so the
  // next chunk runs unseeded.
  uint32_t any_lmd = 0;
  for (int i = 0; i < LZFSE_ENCODE_L_SYMBOLS; i++) any_lmd |= tally[i];
  memset(stats, 0, sizeof *stats);
  if (out && stats_valid && any_lmd) {
    stats->opaque[0] = CRUSHLZFSE_STATS_MAGIC;
    memcpy(stats->opaque + 1, tally, sizeof tally);
  }
  return out;
}

size_t crushlzfse_encode_buffer(void *dst, size_t dst_size,
                                 const void *src, size_t src_size,
                                 void *scratch, size_t scratch_size, int level) {
  crushlzfse_encode_params params;
  crushlzfse_params_for_level(level, &params);
  return crushlzfse_encode_buffer_advanced(dst, dst_size, src, src_size, scratch, scratch_size, &params);
}

size_t crushlzfse_encode_bound(size_t src_size, const crushlzfse_encode_params *params) {
  (void)params; // every strategy shares the one fixed block size
  // The same fixed block crushlzfse_encode_buffer_advanced caps every call
  // to, whatever the strategy. nblocks is 1 for any src_size a real call
  // could actually use (encode rejects anything over LZFSE_ZOPT_BLOCK_SIZE
  // outright); this stays a ceiling division rather than a bare check so
  // the formula is still a safe, meaningful bound if ever queried for a
  // larger src_size.
  size_t block = (size_t)LZFSE_ZOPT_BLOCK_SIZE;
  size_t nblocks = src_size == 0 ? 1 : (src_size + block - 1) / block;
  // Worst case is one stored block per DP block plus the end marker.
  return src_size + 12 * nblocks + 4;
}

int crushlzfse_decode_buffer(void *dst_v, size_t dst_size,
                             const void *src_v, size_t src_size,
                             size_t *out_len)
#ifdef LZFSE_PROOF
__CPROVER_requires(src_size == 0 || (src_v != NULL && __CPROVER_r_ok(src_v, src_size)))
__CPROVER_requires(dst_size == 0 || (dst_v != NULL && __CPROVER_w_ok(dst_v, dst_size)))
__CPROVER_requires(src_size == 0 || dst_size == 0 ||
                   LZFSE_DISJOINT_RANGES(src_v, src_size, dst_v, dst_size))
__CPROVER_requires(out_len == NULL || __CPROVER_w_ok(out_len, sizeof *out_len))
__CPROVER_requires(out_len == NULL || src_size == 0 ||
                   LZFSE_DISJOINT_RANGES(out_len, sizeof *out_len, src_v, src_size))
__CPROVER_requires(out_len == NULL || dst_size == 0 ||
                   LZFSE_DISJOINT_RANGES(out_len, sizeof *out_len, dst_v, dst_size))
__CPROVER_assigns(lzfse_proof_tables_ok)
__CPROVER_assigns(out_len != NULL: *out_len)
__CPROVER_assigns(dst_size != 0: __CPROVER_object_upto(dst_v, dst_size))
__CPROVER_ensures(__CPROVER_return_value == 0 ||
                  __CPROVER_return_value == CRUSHLZFSE_OUTPUT_TOO_SMALL ||
                  __CPROVER_return_value == CRUSHLZFSE_INVALID)
__CPROVER_ensures((__CPROVER_return_value == 0 ||
                   __CPROVER_return_value == CRUSHLZFSE_OUTPUT_TOO_SMALL) ==>
                  (out_len != NULL && *out_len <= dst_size))
#endif
{
  uint8_t *dst = dst_v;
  const uint8_t *src = src_v;
  if (!out_len) return CRUSHLZFSE_INVALID;
  // No stream fits in zero bytes, and src + 0 is undefined for a NULL src.
  if (src_size == 0) return CRUSHLZFSE_INVALID;
  // Zero-capacity output stays inside a real object, even for a NULL dst.
  uint8_t empty_dst;
  if (dst_size == 0) dst = &empty_dst;
  // Zeroed up to the literal buffer, which is most of the state: the tables
  // must start zeroed (a block whose frequencies sum below nstates leaves
  // entries unwritten), while each block zeroes the literal bytes past its
  // own that the LMD loop's wide copies may read.
  lzfse_decoder_state *s = malloc(sizeof(*s));
  if (!s) return CRUSHLZFSE_INVALID;
  memset(s, 0, offsetof(lzfse_decoder_state, compressed_lzfse_block_state.literals));
#ifdef LZFSE_PROOF
  // Zeroed rows are valid rows; this is where the table ghost starts.
  __CPROVER_assert(LZFSE_PROOF_LITERAL_TABLE_OK(&s->compressed_lzfse_block_state, _z) &&
                       LZFSE_PROOF_VALUE_TABLES_OK(&s->compressed_lzfse_block_state, _z),
                   "zeroed decoder tables are valid");
  lzfse_proof_tables_ok = 1;
#endif
  s->src = src;
  s->src_begin = src;
  s->src_end = src + src_size;
  s->dst = dst;
  s->dst_begin = dst;
  s->dst_end = dst + dst_size;
  int status = lzfse_decode(s);
  size_t written = (size_t)(s->dst - dst);
  free(s);
  if (status == LZFSE_STATUS_DST_FULL) {
    // Everything up to `written` is real, correct decoded output: the
    // decoder tracks this exactly because DST_FULL is also how it supports
    // resuming mid-stream with more room, not something added just for this.
    *out_len = written;
    return CRUSHLZFSE_OUTPUT_TOO_SMALL;
  }
  if (status != LZFSE_STATUS_OK) return CRUSHLZFSE_INVALID;
  *out_len = written;
  return 0;
}
