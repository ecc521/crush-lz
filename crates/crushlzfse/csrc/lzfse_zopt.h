// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Per-encode scratch for the optimal-parse LZFSE encoder. Reached through
// lzfse_encoder_state.zopt and carved from the caller's scratch buffer, so
// the encoder is reentrant. The block is a fixed size (LZFSE_ZOPT_BLOCK_SIZE):
// the real caller contract (decmpfs) never hands an Optimal-strategy call
// more than one already-independent 64 KiB piece.
#ifndef LZFSE_ZOPT_H
#define LZFSE_ZOPT_H

#include <stdint.h>

// The one block size every Optimal-strategy call is sized for; positions are
// int32_t, so this must stay well under INT32_MAX. Not a runtime choice.
#define LZFSE_ZOPT_BLOCK_SIZE 65536

// Tree nodes visited per position. A walk ends at a leaf long before this
// on any real input; the ceiling only bounds degenerate ones.
#define ZOPT_MAX_SEARCH_DEPTH 4096
// Defaults for a caller that never set search_depth/iterations.
#define ZOPT_DEFAULT_SEARCH_DEPTH 32
#define ZOPT_DEFAULT_ITERATIONS 2
// Sanity ceiling only; iterations sizes no array.
#define ZOPT_MAX_ITERATIONS 65536

// Voluntary block splitting: split_max_blocks caps blocks per chunk (1
// disables). ZOPT_SPLIT_MIN_SIDE rejects split points too close to either
// end of the range being split.
#define ZOPT_DEFAULT_SPLIT_MAX_BLOCKS 8
#define ZOPT_MAX_SPLIT_MAX_BLOCKS 64
#define ZOPT_SPLIT_MIN_SIDE 1024

// A split is taken whenever the priced pair beats the priced whole, however
// narrowly: a minimum saving per split was measured (2026-09) as a pure
// size-for-blocks trade at every level, so there is none. The decoder-side
// knobs are tuple_tax and split_max_blocks.

// Cap on the bucket-states (literal-run states) that may take a literal step
// at a position, cheapest first. LZFSE_ENCODE_L_SYMBOLS keeps all of them.
// Match steps always leave from the cheapest state, so they are unaffected.
// This is only the fallback for a caller that never set max_live_buckets.
#define ZOPT_MAX_LIVE_BUCKETS 4

// Ceiling on table_search passes; a search rarely moves anything after 4.
#define ZOPT_MAX_TABLE_SEARCH 8

// A candidate of length L is also relaxed at the WINDOW lengths below it, at
// the same distance. 0 disables expansion.
#define ZOPT_SUBLEN_WINDOW 4

// store_limit (the scratch's cand_capacity) is how many candidates are kept
// per position, the longest ones, which is what sizes the candidate arrays.
// A walk reports at most BT_MAX_MATCHES (64), so more storage than that is
// never used.
#define ZOPT_DEFAULT_STORE_LIMIT 8
#define ZOPT_MAX_STORE_LIMIT 64

// Prices are fixed-point, 1/(1 << ZOPT_PRICE_SHIFT) of a bit, and a DP cost
// is the sum of one price per position in the block. They are int32_t, so
// the block size is what keeps that sum in range. See ZOPT_MAX_BLOCK_SIZE.
#define ZOPT_PRICE_SHIFT 8
#define ZOPT_PRICE_ONE (1 << ZOPT_PRICE_SHIFT)

// The costliest single position: a literal step pays the literal symbol, at
// most log2(LZFSE_ENCODE_LITERAL_STATES) = 10 bits, plus its run's L symbol
// re-priced, at most log2(LZFSE_ENCODE_L_STATES) = 6 bits and 8 extra bits.
// 24 bits, and no other step shape costs more.
#define ZOPT_MAX_STEP_PRICE (24 * ZOPT_PRICE_ONE)

// Unreachable, and the test every add is gated by so the sentinel is never
// added to. The gap between them only has to hold one step's price, which
// ZOPT_MAX_STEP_PRICE bounds; rounding it up to a power of two leaves the
// rest of the range for real costs.
#define ZOPT_PRICE_UNREACHABLE INT32_MAX
#define ZOPT_PRICE_UNREACHABLE_THRESHOLD (INT32_MAX - (1 << 16))

// What the price type can carry, and so the largest block the DP can parse
// in one piece: every position may cost ZOPT_MAX_STEP_PRICE, and the sum has
// to stay under the unreachable test. Derived rather than chosen, so the two
// cannot drift apart: it works out at about 341 KiB, five times
// LZFSE_ZOPT_BLOCK_SIZE, the one block size a call now ever uses. Positions
// are int32_t as well, which this is far inside.
#define ZOPT_MAX_BLOCK_SIZE \
  ((uint32_t)(ZOPT_PRICE_UNREACHABLE_THRESHOLD / ZOPT_MAX_STEP_PRICE))

// The fixed block size must stay provably inside the DP price sum's range.
typedef char lzfse_zopt_block_size_fits_price_range[(LZFSE_ZOPT_BLOCK_SIZE <= ZOPT_MAX_BLOCK_SIZE) ? 1 : -1];

// Shortest match the tree proposes; it hashes three bytes. The format itself
// has no floor.
#define ZOPT_MIN_MATCH_LEN 3

// Shortest match the repeat-distance probe proposes. The probe is not
// hash-based, so it can go below ZOPT_MIN_MATCH_LEN.
#define ZOPT_MIN_REPEAT_MATCH_LEN 2

// The shortest match either mechanism can produce; the tuple bound below must
// size against this, not ZOPT_MIN_MATCH_LEN alone.
#define ZOPT_MIN_TUPLE_LEN (ZOPT_MIN_MATCH_LEN < ZOPT_MIN_REPEAT_MATCH_LEN ? ZOPT_MIN_MATCH_LEN : ZOPT_MIN_REPEAT_MATCH_LEN)

// Worst-case tuple count for one run_dp_range call: every match consumes at
// least ZOPT_MIN_TUPLE_LEN bytes, plus one trailing all-literal tuple. Checked
// at runtime against z->max_tuples, not just asserted; an overflow falls back
// to a raw block.
static inline size_t zopt_max_tuples_for(void) {
  return (size_t)LZFSE_ZOPT_BLOCK_SIZE / ZOPT_MIN_TUPLE_LEN + 1;
}

// Tree roots, as log2 of their count; bt_root_bits lowers it for a short
// input. Roots hash three bytes, so past 2^16 they only cost clearing.
#define ZOPT_DEFAULT_HASH_BITS 16
#define ZOPT_MIN_HASH_BITS 10
#define ZOPT_MAX_HASH_BITS 20

// A match at least SKIP_LEN long has the positions inside it, up to KEEP
// bytes before its end, skipped: each takes the match's tail as its only
// candidate and stays out of the tree. On a long repeat every position
// would otherwise walk to the same depth for the same answer.
#define ZOPT_BT_SKIP_LEN 192
#define ZOPT_BT_SKIP_KEEP 32

// One occupied DP bucket-state; see dp_slot below.
typedef struct {
  int32_t cost;
  int32_t last_dist;
  int16_t run_len;      // 0..LZFSE_ENCODE_MAX_L_VALUE (315), so int16 suffices
  int8_t  bucket;       // which L-symbol this slot holds; always >= 1
  int8_t  prev_bucket;  // source bucket of the literal step that wrote it
} lzfse_dp_slot;

typedef char lzfse_dp_slot_must_be_12_bytes[(sizeof(lzfse_dp_slot) == 12) ? 1 : -1];

// Ceiling on tuple_tax. 4096 is already "never emit a match"; a bound at all
// keeps the DP's summed price clear of ZOPT_PRICE_UNREACHABLE.
#define ZOPT_MAX_TUPLE_TAX 4096

typedef struct {
  // Per-call, range-clamped in lzfse_encode_base.c before use.
  int32_t search_depth;
  int32_t iterations;
  // Literal-run states allowed a literal step per position; 0 means
  // ZOPT_MAX_LIVE_BUCKETS.
  int32_t max_live_buckets;
  // Flat surcharge, in the DP's price units, on every match edge; 0
  // reproduces the untaxed parse. Decode throughput follows tuple count, and
  // a small tax also corrects the per-edge model's under-pricing of tuples
  // (shared table headers, wider L/M/D distributions).
  int32_t tuple_tax;
  // Candidate slots per position actually allocated.
  int32_t cand_capacity;
  // Reparse each side of a voluntary split under its own cost model
  // (run_dp_range). Per-call; 0 is off.
  int32_t enable_reparse;
  // Table search passes per block (see lzfse_table_search); 0 is off.
  // Fixed at init, since it decides whether ts_sym is carved.
  int32_t table_search;
  // zopt_max_tuples_for(), stored so bounds checks compare against one value.
  int32_t max_tuples;
  // Sizes split_at; fixed at init.
  int32_t split_max_blocks;
  // Log2 of the tree's root count; fixed at init, since it sizes bt_head.
  int32_t hash_bits;

  // --- Step 1: match candidates, built once per encode call ---
  // Every array below points into the region following this struct, laid out
  // by lzfse_zopt_scratch_size and lzfse_zopt_scratch_init.
  int32_t *cand_len;
  int32_t *cand_dist;
  // The match tree (bt_match.h): two child links per position, and one
  // root per three-byte hash.
  int32_t *bt_son;
  int32_t *bt_head;
  uint16_t *cand_count;

  // --- Step 2: iterative cost-aware DP parse ---
  // Symbol prices in 1/(1 << ZOPT_PRICE_SHIFT) bits, with each symbol's extra
  // bits folded in; literals have none.
  int32_t costq_lit[256];
  int32_t costq_l[LZFSE_ENCODE_L_SYMBOLS];
  int32_t costq_m[LZFSE_ENCODE_M_SYMBOLS];
  int32_t costq_d[LZFSE_ENCODE_D_SYMBOLS];

  // Slot-indexed DP rows: up to dp_nslots occupied bucket-states per position,
  // each carrying its bucket. At most max_live states take a literal step,
  // each writing one bucket at the next position, and matches land only in
  // bucket 0 (dp_cost0/dp_dist0), so a row never overflows. Slots stay sorted
  // ascending by bucket, the order the DP's tie-breaks assume. A slot is 16
  // bytes, so a K=4 row is one cache line.
  int32_t dp_nslots;        // slots carved per position == the level's cap
  uint8_t *dp_nslot;        // [position]: slots actually occupied
  lzfse_dp_slot *dp_slot;   // [position * dp_nslots + s]

  // Length and distance of the match edge that reached [pos]; one per
  // position, since a match always lands in bucket 0.
  int32_t *dp_via_len;
  int32_t *dp_via_dist;

  // Bucket 0 (run length 0) is reached only by match edges, since a literal
  // step always forms a run >= 1. Holding it in two dense arrays keeps the
  // match relaxation's stores contiguous; its run_len is always 0 and its
  // prev_bucket is never read.
  int32_t *dp_cost0;
  int32_t *dp_dist0;


  uint32_t *tup_L;
  uint32_t *tup_M;
  uint32_t *tup_D;
  int32_t n_tuples;

  // Snapshot of the best-scoring iteration: the refinement loop is not
  // monotone, so Step 3 commits this, not the last round.
  uint32_t *best_tup_L;
  uint32_t *best_tup_M;
  uint32_t *best_tup_D;
  int32_t best_n_tuples;

  uint32_t l_occ[LZFSE_ENCODE_L_SYMBOLS];
  uint32_t m_occ[LZFSE_ENCODE_M_SYMBOLS];
  uint32_t d_occ[LZFSE_ENCODE_D_SYMBOLS];
  uint32_t lit_occ[256];

  // Voluntary splitting: byte offset where each winning tuple begins, the
  // committed split points (tuple indices, at most split_max_blocks-1), and
  // histogram scratch for pricing candidate cuts.
  lzfse_offset *tuple_start_pos;
  int32_t *split_at;
  uint32_t split_l_occ_a[LZFSE_ENCODE_L_SYMBOLS];
  uint32_t split_m_occ_a[LZFSE_ENCODE_M_SYMBOLS];
  uint32_t split_d_occ_a[LZFSE_ENCODE_D_SYMBOLS];
  uint32_t split_lit_occ_a[256];
  uint32_t split_l_occ_b[LZFSE_ENCODE_L_SYMBOLS];
  uint32_t split_m_occ_b[LZFSE_ENCODE_M_SYMBOLS];
  uint32_t split_d_occ_b[LZFSE_ENCODE_D_SYMBOLS];
  uint32_t split_lit_occ_b[256];

  // The block's L, M and D symbols, LZFSE_MATCHES_PER_BLOCK each, for the
  // table search; carved only when it is on.
  uint8_t *ts_sym;

  // Backtracking reversal buffers for run_dp_range; in the scratch rather than
  // on the stack because max_tuples is large enough to blow the stack.
  int32_t *rev_len;
  int32_t *rev_dist;
  int32_t *rev_lit_run;
} lzfse_zopt_scratch;

// Region element counts shared by lzfse_zopt_scratch_size and
// lzfse_zopt_scratch_init, so the two cannot disagree.
typedef struct {
  size_t n_pos;      // LZFSE_ZOPT_BLOCK_SIZE, cand_count
  size_t n_dp;
  size_t n_tup;      // max_tuples           , tup_*/best_tup_*/rev_*
  size_t n_tup_plus1;// max_tuples + 1       , tuple_start_pos
  size_t n_cand;     // LZFSE_ZOPT_BLOCK_SIZE*cand_capacity, cand_len/cand_dist
  size_t n_split;    // max(split_max_blocks-1, 1), split_at
  size_t n_son;      // 2 * LZFSE_ZOPT_BLOCK_SIZE, bt_son
  size_t n_head;     // 1 << hash_bits       , bt_head
  size_t n_ts;       // 3 * LZFSE_MATCHES_PER_BLOCK with table_search, else 0
} zopt_region_counts;

static inline zopt_region_counts zopt_compute_region_counts(int32_t cand_capacity, int32_t split_max_blocks, int32_t hash_bits, int32_t table_search) {
  zopt_region_counts c;
  c.n_pos = (size_t)LZFSE_ZOPT_BLOCK_SIZE;
  c.n_dp = (size_t)LZFSE_ZOPT_BLOCK_SIZE + 1;
  c.n_tup = zopt_max_tuples_for();
  c.n_tup_plus1 = c.n_tup + 1;
  c.n_cand = (size_t)LZFSE_ZOPT_BLOCK_SIZE * (size_t)cand_capacity;
  c.n_split = split_max_blocks > 1 ? (size_t)split_max_blocks - 1 : 1;
  c.n_son = 2 * (size_t)LZFSE_ZOPT_BLOCK_SIZE;
  c.n_head = (size_t)1 << hash_bits;
  c.n_ts = table_search > 0 ? 3 * (size_t)LZFSE_MATCHES_PER_BLOCK : 0;
  return c;
}

// Every region starts 8-byte aligned, whatever the previous region's length.
static inline size_t zopt_align_up(size_t x) { return (x + 7u) & ~(size_t)7u; }

// Total bytes for the scratch: the struct plus every region, in the same
// order lzfse_zopt_scratch_init carves them.
static inline size_t lzfse_zopt_scratch_size(int32_t cand_capacity, int32_t split_max_blocks, int32_t hash_bits, int32_t nslots, int32_t table_search) {
  if (cand_capacity < 1) cand_capacity = 1;
  if (cand_capacity > ZOPT_MAX_STORE_LIMIT) cand_capacity = ZOPT_MAX_STORE_LIMIT;
  if (split_max_blocks < 1) split_max_blocks = 1;
  if (hash_bits < ZOPT_MIN_HASH_BITS) hash_bits = ZOPT_MIN_HASH_BITS;
  if (hash_bits > ZOPT_MAX_HASH_BITS) hash_bits = ZOPT_MAX_HASH_BITS;
  zopt_region_counts c = zopt_compute_region_counts(cand_capacity, split_max_blocks, hash_bits, table_search);
  size_t off = zopt_align_up(sizeof(lzfse_zopt_scratch));
  off = zopt_align_up(off + c.n_cand * sizeof(int32_t));                          // cand_len
  off = zopt_align_up(off + c.n_cand * sizeof(int32_t));                          // cand_dist
  off = zopt_align_up(off + c.n_son * sizeof(int32_t));                           // bt_son
  off = zopt_align_up(off + c.n_head * sizeof(int32_t));                          // bt_head
  off = zopt_align_up(off + c.n_pos * sizeof(uint16_t));                          // cand_count
  off = zopt_align_up(off + c.n_dp * (size_t)nslots * sizeof(lzfse_dp_slot));     // dp_slot
  off = zopt_align_up(off + c.n_dp * sizeof(uint8_t));                            // dp_nslot
  off = zopt_align_up(off + c.n_dp * sizeof(int32_t));                           // dp_via_len
  off = zopt_align_up(off + c.n_dp * sizeof(int32_t));                           // dp_via_dist
  off = zopt_align_up(off + c.n_dp * sizeof(int32_t));                           // dp_cost0
  off = zopt_align_up(off + c.n_dp * sizeof(int32_t));                           // dp_dist0
  off = zopt_align_up(off + c.n_tup * sizeof(uint32_t));                         // tup_L
  off = zopt_align_up(off + c.n_tup * sizeof(uint32_t));                         // tup_M
  off = zopt_align_up(off + c.n_tup * sizeof(uint32_t));                         // tup_D
  off = zopt_align_up(off + c.n_tup * sizeof(uint32_t));                         // best_tup_L
  off = zopt_align_up(off + c.n_tup * sizeof(uint32_t));                         // best_tup_M
  off = zopt_align_up(off + c.n_tup * sizeof(uint32_t));                         // best_tup_D
  off = zopt_align_up(off + c.n_tup_plus1 * sizeof(lzfse_offset));               // tuple_start_pos
  off = zopt_align_up(off + c.n_split * sizeof(int32_t));                        // split_at
  off = zopt_align_up(off + c.n_tup * sizeof(int32_t));                          // rev_len
  off = zopt_align_up(off + c.n_tup * sizeof(int32_t));                          // rev_dist
  off = zopt_align_up(off + c.n_tup * sizeof(int32_t));                          // rev_lit_run
  off = zopt_align_up(off + c.n_ts);                                              // ts_sym
  return off;
}

// Carves the regions in the same order and sizes as lzfse_zopt_scratch_size;
// keep the two in step.
static inline void lzfse_zopt_scratch_init(lzfse_zopt_scratch *z, int32_t cand_capacity, int32_t split_max_blocks, int32_t hash_bits, int32_t nslots, int32_t table_search) {
  if (cand_capacity < 1) cand_capacity = 1;
  if (cand_capacity > ZOPT_MAX_STORE_LIMIT) cand_capacity = ZOPT_MAX_STORE_LIMIT;
  if (split_max_blocks < 1) split_max_blocks = 1;
  if (hash_bits < ZOPT_MIN_HASH_BITS) hash_bits = ZOPT_MIN_HASH_BITS;
  if (hash_bits > ZOPT_MAX_HASH_BITS) hash_bits = ZOPT_MAX_HASH_BITS;
  zopt_region_counts c = zopt_compute_region_counts(cand_capacity, split_max_blocks, hash_bits, table_search);
  z->cand_capacity = cand_capacity;
  z->dp_nslots = nslots;
  z->max_tuples = (int32_t)c.n_tup;
  z->split_max_blocks = split_max_blocks;
  z->hash_bits = hash_bits;
  z->table_search = table_search > 0 ? table_search : 0;
  // Per-call defaults, so a caller that sets only some never leaves the
  // rest as whatever the scratch held.
  z->search_depth = ZOPT_DEFAULT_SEARCH_DEPTH;
  z->iterations = ZOPT_DEFAULT_ITERATIONS;
  z->max_live_buckets = ZOPT_MAX_LIVE_BUCKETS;
  z->tuple_tax = 0;
  z->enable_reparse = 0;

  uint8_t *base = (uint8_t *)z;
  size_t off = zopt_align_up(sizeof(lzfse_zopt_scratch));

  size_t region_start;
  region_start = off; z->cand_len = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_cand * sizeof(int32_t));

  region_start = off; z->cand_dist = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_cand * sizeof(int32_t));

  region_start = off; z->bt_son = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_son * sizeof(int32_t));

  region_start = off; z->bt_head = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_head * sizeof(int32_t));

  region_start = off; z->cand_count = (uint16_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_pos * sizeof(uint16_t));

  region_start = off; z->dp_slot = (lzfse_dp_slot *)(base + region_start);
  off = zopt_align_up(region_start + c.n_dp * (size_t)nslots * sizeof(lzfse_dp_slot));

  region_start = off; z->dp_nslot = (uint8_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_dp * sizeof(uint8_t));

  region_start = off; z->dp_via_len = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_dp * sizeof(int32_t));

  region_start = off; z->dp_via_dist = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_dp * sizeof(int32_t));

  region_start = off; z->dp_cost0 = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_dp * sizeof(int32_t));

  region_start = off; z->dp_dist0 = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_dp * sizeof(int32_t));


  region_start = off; z->tup_L = (uint32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup * sizeof(uint32_t));

  region_start = off; z->tup_M = (uint32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup * sizeof(uint32_t));

  region_start = off; z->tup_D = (uint32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup * sizeof(uint32_t));

  region_start = off; z->best_tup_L = (uint32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup * sizeof(uint32_t));

  region_start = off; z->best_tup_M = (uint32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup * sizeof(uint32_t));

  region_start = off; z->best_tup_D = (uint32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup * sizeof(uint32_t));

  region_start = off; z->tuple_start_pos = (lzfse_offset *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup_plus1 * sizeof(lzfse_offset));

  region_start = off; z->split_at = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_split * sizeof(int32_t));

  region_start = off; z->rev_len = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup * sizeof(int32_t));

  region_start = off; z->rev_dist = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup * sizeof(int32_t));

  region_start = off; z->rev_lit_run = (int32_t *)(base + region_start);
  off = zopt_align_up(region_start + c.n_tup * sizeof(int32_t));

  region_start = off; z->ts_sym = c.n_ts ? base + region_start : NULL;
  off = zopt_align_up(region_start + c.n_ts);
  (void)off; // final position unused, kept for symmetry/future regions
}

#endif // LZFSE_ZOPT_H
