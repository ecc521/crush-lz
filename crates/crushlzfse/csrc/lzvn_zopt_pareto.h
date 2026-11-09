// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Per-encode scratch for the Pareto-front multi-state optimal-parse DP
// (lzvn_pareto_run_dp in lzvn_encode_base.c).
//
// A bounded Pareto front per position. LZVN's D==D_prev op-code means two
// paths with the same cost-so-far and different last_dist are not
// interchangeable, so up to k_cap states are kept per position, keyed by
// (last_dist, run_len). run_len is part of the key because a pending run of
// 0-3 literals embeds for free in the next match header and a longer one
// does not. When a front is full the highest-cost slot is replaced if the
// new state is cheaper; the cheapest state is never evicted.
//
// Backtracking: src_slot is the slot at position cursor-via_len whose
// (run_len, last_dist) priced a match-landing state; run_start_pos/slot
// point at the nearest run_len==0 ancestor, so the start of a pending
// literal run is found without a scan.
#ifndef LZVN_ZOPT_PARETO_H
#define LZVN_ZOPT_PARETO_H

#include <stdint.h>
#include "lzvn_zopt.h" // LZVN_ZOPT_BLOCK_SIZE

// Ceiling k_cap is validated against; scratch is always sized to the caller's k_cap.
#ifndef LZVN_PARETO_MAX_K
#define LZVN_PARETO_MAX_K 32
#endif

typedef struct {
  int32_t cost;
  int32_t run_len;
  int32_t last_dist;      // bucket key; 0 only valid for the start state
  int32_t via_len;        // 0 => reached by a literal edge (or is the start state)
  int32_t via_dist;
  int32_t src_slot;       // meaningful iff via_len>0
  int32_t run_start_pos;
  int32_t run_start_slot;
} lzvn_pareto_slot;

typedef struct {
  int32_t k_cap;          // runtime width the arrays below are actually carved for

  int32_t *count;         // [LZVN_ZOPT_BLOCK_SIZE+1]: live states at this position
  int32_t *worst_cost;    // [LZVN_ZOPT_BLOCK_SIZE+1]: worst cost among live states when count==k_cap

  // Row-major [(LZVN_ZOPT_BLOCK_SIZE+1) * k_cap]: slot s of position pos is
  // at pos*k_cap+s. Contiguous AoS packs both states for k_cap=2 into a single
  // 64-byte L1 cache line.
  lzvn_pareto_slot *slots;
} lzvn_pareto_scratch;

// Must carve the same regions, in the same order, as lzvn_pareto_scratch_init.
static inline size_t lzvn_pareto_scratch_size(int32_t k_cap) {
  if (k_cap < 1) k_cap = 1;
  if (k_cap > LZVN_PARETO_MAX_K) k_cap = LZVN_PARETO_MAX_K;
  size_t n_pos = (size_t)LZVN_ZOPT_BLOCK_SIZE + 1;
  size_t n_slot = n_pos * (size_t)k_cap;

  size_t off = lzvn_zopt_align_up(sizeof(lzvn_pareto_scratch));
  off = lzvn_zopt_align_up(off + n_pos * sizeof(int32_t));              // count
  off = lzvn_zopt_align_up(off + n_pos * sizeof(int32_t));              // worst_cost
  off = lzvn_zopt_align_up(off + n_slot * sizeof(lzvn_pareto_slot));    // slots
  return off;
}

// Must walk the same region order and sizes as lzvn_pareto_scratch_size.
static inline void lzvn_pareto_scratch_init(lzvn_pareto_scratch *p, int32_t k_cap) {
  if (k_cap < 1) k_cap = 1;
  if (k_cap > LZVN_PARETO_MAX_K) k_cap = LZVN_PARETO_MAX_K;
  size_t n_pos = (size_t)LZVN_ZOPT_BLOCK_SIZE + 1;
  size_t n_slot = n_pos * (size_t)k_cap;

  p->k_cap = k_cap;

  uint8_t *base = (uint8_t *)p;
  size_t off = lzvn_zopt_align_up(sizeof(lzvn_pareto_scratch));
  size_t region_start;

  region_start = off; p->count = (int32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + n_pos * sizeof(int32_t));

  region_start = off; p->worst_cost = (int32_t *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + n_pos * sizeof(int32_t));

  region_start = off; p->slots = (lzvn_pareto_slot *)(base + region_start);
  off = lzvn_zopt_align_up(region_start + n_slot * sizeof(lzvn_pareto_slot));
  (void)off;
}

#endif // LZVN_ZOPT_PARETO_H
