// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Per-encode scratch for the optimal-parse LZVN encoder's candidate search
// and tuple output; the DP's per-position state lives in lzvn_zopt_pareto.h.
// The block is a fixed size (LZVN_ZOPT_BLOCK_SIZE): the real caller contract
// (decmpfs) never hands an Optimal-strategy call more than one
// already-independent 64 KiB piece.
#ifndef LZVN_ZOPT_H
#define LZVN_ZOPT_H

#include <stdint.h>

// The one block size every Optimal-strategy call is sized for; positions are
// int32_t, so this must stay well under INT32_MAX. Not a runtime choice.
#ifndef LZVN_ZOPT_BLOCK_SIZE
#define LZVN_ZOPT_BLOCK_SIZE 65536
#endif

// Shortest match the hash-based candidate search proposes. Not a format
// floor; see LZVN_ZOPT_MIN_REPEAT_MATCH_LEN.
#define LZVN_ZOPT_MIN_MATCH_LEN 3

// Shortest match the repeat-distance probe may propose, in
// [1, LZVN_ZOPT_MIN_MATCH_LEN]. Only representable when the embedded literal
// tail is 0: a match op with a nonzero tail encodes M with a +3 bias.
#ifndef LZVN_ZOPT_MIN_REPEAT_MATCH_LEN
#define LZVN_ZOPT_MIN_REPEAT_MATCH_LEN 2
#endif

// The shortest tuple any mechanism can produce; the tuple-count bound must
// use this, not LZVN_ZOPT_MIN_MATCH_LEN alone.
#define LZVN_ZOPT_MIN_TUPLE_LEN \
  (LZVN_ZOPT_MIN_MATCH_LEN < LZVN_ZOPT_MIN_REPEAT_MATCH_LEN \
       ? LZVN_ZOPT_MIN_MATCH_LEN \
       : LZVN_ZOPT_MIN_REPEAT_MATCH_LEN)

// Match-tree nodes visited per position (bt_match.h). A walk ends at a leaf
// long before this on real input; the ceiling only bounds degenerate ones.
#ifndef LZVN_ZOPT_MAX_SEARCH_DEPTH
#define LZVN_ZOPT_MAX_SEARCH_DEPTH 4096
#endif

// Candidates kept per position, the longest ones. A walk reports at most
// BT_MAX_MATCHES (64).
#ifndef LZVN_ZOPT_DEFAULT_STORE_LIMIT
#define LZVN_ZOPT_DEFAULT_STORE_LIMIT 8
#endif
#ifndef LZVN_ZOPT_MAX_STORE_LIMIT
#define LZVN_ZOPT_MAX_STORE_LIMIT 64
#endif

// A candidate of length L is also relaxed at the WINDOW lengths below it; 0 disables.
#ifndef LZVN_ZOPT_SUBLEN_WINDOW
#define LZVN_ZOPT_SUBLEN_WINDOW 2
#endif

// A match at least SKIP_LEN long has the positions inside it, up to KEEP
// bytes before its end, take its tail as their only candidate and stay out
// of the tree.
#define LZVN_ZOPT_BT_SKIP_LEN 192
#define LZVN_ZOPT_BT_SKIP_KEEP 32

// Log2 of the match tree's root count; bt_root_bits lowers it for a short
// input.
#ifndef LZVN_ZOPT_DEFAULT_HASH_BITS
#define LZVN_ZOPT_DEFAULT_HASH_BITS 16
#endif
#ifndef LZVN_ZOPT_MIN_HASH_BITS
#define LZVN_ZOPT_MIN_HASH_BITS 10
#endif
#ifndef LZVN_ZOPT_MAX_HASH_BITS
#define LZVN_ZOPT_MAX_HASH_BITS 20
#endif

// Worst-case tuple count for one DP call: every match consumes at least
// LZVN_ZOPT_MIN_TUPLE_LEN bytes, plus one trailing literal tuple.
static inline size_t lzvn_zopt_max_tuples_for(void) {
  return (size_t)LZVN_ZOPT_BLOCK_SIZE / LZVN_ZOPT_MIN_TUPLE_LEN + 1;
}

typedef struct {
  int32_t search_depth;    // tree nodes per position, range-clamped per call
  int32_t cand_capacity;   // candidate slots per position actually allocated
  int32_t max_tuples;      // lzvn_zopt_max_tuples_for(), cached
  int32_t hash_bits;       // this encoder's own candidate hash table size

  // --- Step 1: match candidates, built once per encode call ---
  int32_t *cand_len;
  int32_t *cand_dist;
  int32_t *bt_head;        // one root per three-byte hash
  int32_t *bt_son;         // two child links per position
  uint16_t *cand_count;

  // --- Step 2: the DP's winning tuple sequence, in forward order ---
  uint32_t *tup_L;
  uint32_t *tup_M;
  uint32_t *tup_D;
  int32_t n_tuples;

  // Heap-allocated backtracking buffers; LZVN_ZOPT_BLOCK_SIZE would overflow the stack.
  int32_t *rev_len;
  int32_t *rev_dist;
  int32_t *rev_lit_run;
} lzvn_zopt_scratch;

// Shared by lzvn_zopt_scratch_size and lzvn_zopt_scratch_init.
typedef struct {
  size_t n_pos;   // LZVN_ZOPT_BLOCK_SIZE                , cand_count
  size_t n_son;   // 2 * LZVN_ZOPT_BLOCK_SIZE            , bt_son
  size_t n_tup;   // max_tuples                          , tup_*/rev_*
  size_t n_cand;  // LZVN_ZOPT_BLOCK_SIZE * cand_capacity, cand_len/cand_dist
  size_t n_head;  // 1 << hash_bits                      , bt_head
} lzvn_zopt_region_counts;

static inline lzvn_zopt_region_counts
lzvn_zopt_compute_region_counts(int32_t cand_capacity, int32_t hash_bits) {
  lzvn_zopt_region_counts c;
  c.n_pos = (size_t)LZVN_ZOPT_BLOCK_SIZE;
  c.n_son = 2 * (size_t)LZVN_ZOPT_BLOCK_SIZE;
  c.n_tup = lzvn_zopt_max_tuples_for();
  c.n_cand = (size_t)LZVN_ZOPT_BLOCK_SIZE * (size_t)cand_capacity;
  c.n_head = (size_t)1 << hash_bits;
  return c;
}

static inline size_t lzvn_zopt_align_up(size_t x) {
  return (x + 7u) & ~(size_t)7u;
}

// Callers must pass the same (cand_capacity, hash_bits) to
// lzvn_zopt_scratch_init.
static inline size_t lzvn_zopt_scratch_size(int32_t cand_capacity,
                                            int32_t hash_bits) {
  if (cand_capacity < 1) cand_capacity = 1;
  if (cand_capacity > LZVN_ZOPT_MAX_STORE_LIMIT) cand_capacity = LZVN_ZOPT_MAX_STORE_LIMIT;
  if (hash_bits < LZVN_ZOPT_MIN_HASH_BITS) hash_bits = LZVN_ZOPT_MIN_HASH_BITS;
  if (hash_bits > LZVN_ZOPT_MAX_HASH_BITS) hash_bits = LZVN_ZOPT_MAX_HASH_BITS;
  lzvn_zopt_region_counts c = lzvn_zopt_compute_region_counts(cand_capacity, hash_bits);
  size_t off = lzvn_zopt_align_up(sizeof(lzvn_zopt_scratch));
  off = lzvn_zopt_align_up(off + c.n_cand * sizeof(int32_t));  // cand_len
  off = lzvn_zopt_align_up(off + c.n_cand * sizeof(int32_t));  // cand_dist
  off = lzvn_zopt_align_up(off + c.n_head * sizeof(int32_t));  // bt_head
  off = lzvn_zopt_align_up(off + c.n_son * sizeof(int32_t));   // bt_son
  off = lzvn_zopt_align_up(off + c.n_pos * sizeof(uint16_t));  // cand_count
  off = lzvn_zopt_align_up(off + c.n_tup * sizeof(uint32_t));  // tup_L
  off = lzvn_zopt_align_up(off + c.n_tup * sizeof(uint32_t));  // tup_M
  off = lzvn_zopt_align_up(off + c.n_tup * sizeof(uint32_t));  // tup_D
  off = lzvn_zopt_align_up(off + c.n_tup * sizeof(int32_t));   // rev_len
  off = lzvn_zopt_align_up(off + c.n_tup * sizeof(int32_t));   // rev_dist
  off = lzvn_zopt_align_up(off + c.n_tup * sizeof(int32_t));   // rev_lit_run
  return off;
}

// Must walk the same region order and sizes as lzvn_zopt_scratch_size.
static inline void lzvn_zopt_scratch_init(lzvn_zopt_scratch *z,
                                          int32_t cand_capacity,
                                          int32_t hash_bits) {
  if (cand_capacity < 1) cand_capacity = 1;
  if (cand_capacity > LZVN_ZOPT_MAX_STORE_LIMIT) cand_capacity = LZVN_ZOPT_MAX_STORE_LIMIT;
  if (hash_bits < LZVN_ZOPT_MIN_HASH_BITS) hash_bits = LZVN_ZOPT_MIN_HASH_BITS;
  if (hash_bits > LZVN_ZOPT_MAX_HASH_BITS) hash_bits = LZVN_ZOPT_MAX_HASH_BITS;
  lzvn_zopt_region_counts c = lzvn_zopt_compute_region_counts(cand_capacity, hash_bits);
  z->cand_capacity = cand_capacity;
  z->max_tuples = (int32_t)c.n_tup;
  z->hash_bits = hash_bits;

  uint8_t *base = (uint8_t *)z;
  size_t off = lzvn_zopt_align_up(sizeof(lzvn_zopt_scratch));
  size_t region_start;

  region_start = off; z->cand_len = (int32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_cand * sizeof(int32_t));

  region_start = off; z->cand_dist = (int32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_cand * sizeof(int32_t));

  region_start = off; z->bt_head = (int32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_head * sizeof(int32_t));

  region_start = off; z->bt_son = (int32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_son * sizeof(int32_t));

  region_start = off; z->cand_count = (uint16_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_pos * sizeof(uint16_t));

  region_start = off; z->tup_L = (uint32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_tup * sizeof(uint32_t));

  region_start = off; z->tup_M = (uint32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_tup * sizeof(uint32_t));

  region_start = off; z->tup_D = (uint32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_tup * sizeof(uint32_t));

  region_start = off; z->rev_len = (int32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_tup * sizeof(int32_t));

  region_start = off; z->rev_dist = (int32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_tup * sizeof(int32_t));

  region_start = off; z->rev_lit_run = (int32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + c.n_tup * sizeof(int32_t));
  (void)off; // final position unused, kept for symmetry/future regions
}

#endif // LZVN_ZOPT_H
