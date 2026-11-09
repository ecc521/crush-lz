// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// CrushLZFSE: an LZFSE encoder, bit-compatible with Apple's decoder. Levels
// below the default (0) are faster and looser, levels above it denser and
// slower.
//
// Every encode call, whatever the strategy, is bounded to one already-independent
// fixed 64 KiB piece (matching decmpfs's own chunk size) and rejects
// anything larger outright, rather than chunk or stream it: the real caller
// never hands a call more than one such piece. A NULL scratch is allocated
// internally and scratch_size is then ignored; otherwise scratch_size is
// checked against crushlzfse_scratch_size(params) and an undersized buffer
// is rejected rather than overrun. Encoders return the bytes written, or 0
// on a rejected buffer, oversized input or invalid params. Decoders return
// 0 on success and set *out_len, or a negative CRUSHLZFSE_* status.
//
// Buffers are void *, so any object pointer passes without a cast; the bytes
// are read and written as unsigned char whatever the caller's type.
//
// Neither the encoder nor the decoder is thread-safe on a shared scratch;
// give each thread its own.

#ifndef CRUSHLZFSE_H
#define CRUSHLZFSE_H

#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include "lzfse.h" // LZFSE_API

#ifdef __cplusplus
extern "C" {
#endif

#define CRUSHLZFSE_LEVEL_MIN     (-5)
#define CRUSHLZFSE_LEVEL_MAX     11
#define CRUSHLZFSE_LEVEL_DEFAULT 0
// Never a level; returned by crushlzfse_params_for_level for a NULL out.
#define CRUSHLZFSE_LEVEL_INVALID INT_MIN

// Decoder status.
#define CRUSHLZFSE_INVALID          (-1) // not a valid stream
#define CRUSHLZFSE_OUTPUT_TOO_SMALL (-2)

typedef enum {
  CRUSHLZFSE_STRATEGY_LAZY,    // levels 0 to 5
  CRUSHLZFSE_STRATEGY_OPTIMAL, // levels 6 to 11
  CRUSHLZFSE_STRATEGY_FAST     // levels -5 to -1
} crushlzfse_strategy;

typedef struct {
  crushlzfse_strategy strategy;
  union {
    struct {
      int hash_bits;  // log2 of the hash table size
      int hash_width; // candidates per bucket, at most 64
      int lookahead;  // 0 to 2: following positions tried for a better match
    } lazy;
    // min_match is the length the main table hashes; candidates are
    // verified on 4 bytes, so shorter matches still pass on a hash hit. It
    // is 4 to 8, or 4 to 6 when long_table or lazy is set. lazy tries up to
    // two following bytes for a match at least two bytes longer, except
    // after a hit on the last match distance, which is taken as is.
    struct {
      int hash_bits;  // log2 of each hash table's size
      int min_match;  // bytes the main table hashes
      int skip_shift; // over unmatched input the stride grows by one byte
      int max_step;   //   per 2^skip_shift bytes, up to max_step
      int long_table; // 1: a second table hashed on 8 bytes, consulted first
      int lazy;       // 1: look ahead for a longer match before taking one
    } fast;
    struct {
      // Match-tree nodes visited per position. Ratio saturates near 32.
      int search_depth;
      int iterations;        // cost-model refinement passes
      int enable_reparse;    // re-run the parse after block splitting
      int32_t split_max_blocks;
      int32_t hash_bits;     // log2 of the match tree's root count
      int32_t store_limit;   // candidates kept per position, longest first
      int32_t tuple_tax;
      int32_t max_live_buckets;
      // Hill-climb passes over each block's frequency tables, scored by
      // exact payload and header bits; 0 is off.
      int32_t table_search;
    } optimal;
  } p;
} crushlzfse_encode_params;

// Valid ranges for every field above; params outside them are rejected.
typedef struct {
  // level_default is the level encode_buffer uses for CRUSHLZFSE_LEVEL_DEFAULT,
  // reported here so a caller with the library but not the header can ask.
  int level_min, level_max, level_default;
  int search_depth_min, search_depth_max;
  int iterations_min, iterations_max;
  int enable_reparse_min, enable_reparse_max;
  int32_t split_max_blocks_min, split_max_blocks_max;
  int32_t optimal_hash_bits_min, optimal_hash_bits_max;
  int32_t store_limit_min, store_limit_max;
  int32_t tuple_tax_min, tuple_tax_max;
  int32_t max_live_buckets_min, max_live_buckets_max;
  int32_t table_search_min, table_search_max;
  int lazy_hash_bits_min, lazy_hash_bits_max;
  int lazy_hash_width_min, lazy_hash_width_max;
  int lazy_lookahead_min, lazy_lookahead_max;
  int fast_hash_bits_min, fast_hash_bits_max;
  int fast_min_match_min, fast_min_match_max; // max is 6 with long_table or lazy
  int fast_skip_shift_min, fast_skip_shift_max;
  int fast_max_step_min, fast_max_step_max;
  int fast_long_table_min, fast_long_table_max;
  int fast_lazy_min, fast_lazy_max;
} crushlzfse_capabilities;

LZFSE_API crushlzfse_capabilities crushlzfse_get_capabilities(void);

// The settings a level stands for. Returns the level actually used: levels
// outside the range are clamped, not rejected, so a caller asking for "as
// fast as possible" with INT_MIN gets the fastest level rather than an error.
// Returns CRUSHLZFSE_LEVEL_INVALID, which is never a level, only if out is NULL.
LZFSE_API int crushlzfse_params_for_level(int level, crushlzfse_encode_params *out);

// Scratch bytes an encode with these params needs. There is deliberately no
// "big enough for anything" query, because for most of these codecs no
// useful such size exists: the optimal strategies size their tables from
// params the caller chooses. A caller reusing one buffer over several levels
// sizes it for the largest of the params it will actually use. Returns 0
// for a NULL params.
//
// Note this is the params pointer, not the scratch pointer: a NULL *scratch*
// passed to an encode is still valid and allocates internally.
LZFSE_API size_t crushlzfse_scratch_size(const crushlzfse_encode_params *params);

// Output bytes an encode of src_size bytes with these params needs, at
// most. `params` is required and must not be NULL, for consistency with
// crushlzfse_scratch_size and in case a future strategy's overhead differs;
// today every strategy shares the one fixed LZFSE_ZOPT_BLOCK_SIZE block, so
// the bound does not actually vary by strategy. Pass the same params the
// encode call itself will use.
LZFSE_API size_t crushlzfse_encode_bound(size_t src_size, const crushlzfse_encode_params *params);

// One call is one stream, bounded to one already-independent LZFSE_ZOPT_BLOCK_SIZE
// piece (64 KiB, matching decmpfs's own chunk size): a caller with more
// input chunks it and calls once per chunk.
LZFSE_API size_t crushlzfse_encode_buffer(void *dst, size_t dst_size,
                                          const void *src, size_t src_size,
                                          void *scratch, size_t scratch_size, int level);

LZFSE_API size_t crushlzfse_encode_buffer_advanced(void *dst, size_t dst_size,
                                                   const void *src, size_t src_size,
                                                   void *scratch, size_t scratch_size,
                                                   const crushlzfse_encode_params *params);

// Chaining. A caller encoding a file as a run of 64 KiB chunks can pass one
// crushlzfse_stats from each chunk's call to the next, in order: the
// optimal levels (6 to 11) start their parse from the previous chunk's L, M
// and D symbol statistics instead of a greedy guess, which is denser and,
// where it ends the refinement passes sooner, faster. Every level writes the
// statistics, so a chain may mix levels.
//
// Each output is still a complete, independent stream that any LZFSE
// decoder, Apple's included, reads on its own; only the bytes chosen depend
// on the chunks before it in the chain. Start a chain, at each file or
// wherever chunks may be encoded separately, with a zeroed struct.
//
// The contents are opaque, and any contents are safe: bytes this function
// did not write can cost ratio, never validity. The call reads the seed
// before writing, then overwrites stats with this chunk's statistics, or
// with zeros when the chunk ends up as an LZVN, raw or empty stream or the
// call returns 0, so the next chunk runs unseeded. A NULL or zeroed stats
// gives exactly crushlzfse_encode_buffer_advanced's bytes.
#define CRUSHLZFSE_STATS_WORDS 105
typedef struct {
  uint32_t opaque[CRUSHLZFSE_STATS_WORDS];
} crushlzfse_stats;

#if defined(CRUSHLZFSE_DISPATCH_PROOF)
LZFSE_API size_t crushlzfse_encode_buffer_chained(void *dst, size_t dst_size,
                                                  const void *src, size_t src_size,
                                                  void *scratch, size_t scratch_size,
                                                  const crushlzfse_encode_params *params,
                                                  crushlzfse_stats *stats)
__CPROVER_requires(src != NULL || src_size == 0)
__CPROVER_requires(__CPROVER_r_ok(src, src_size))
__CPROVER_requires(dst != NULL || dst_size == 0)
__CPROVER_requires(__CPROVER_w_ok(dst, dst_size))
__CPROVER_requires(src == NULL || dst == NULL || !__CPROVER_same_object(src, dst))
__CPROVER_requires(params != NULL && __CPROVER_r_ok(params, sizeof(*params)))
__CPROVER_requires(scratch == NULL || __CPROVER_w_ok(scratch, scratch_size))
__CPROVER_requires(stats == NULL || __CPROVER_rw_ok(stats, sizeof(*stats)))
__CPROVER_requires(stats == NULL || src == NULL || !__CPROVER_same_object(stats, src))
__CPROVER_requires(stats == NULL || dst == NULL || !__CPROVER_same_object(stats, dst))
__CPROVER_requires(stats == NULL || scratch == NULL || !__CPROVER_same_object(stats, scratch))
__CPROVER_assigns(dst != NULL: __CPROVER_object_upto(dst, dst_size))
__CPROVER_assigns(scratch != NULL: __CPROVER_object_whole(scratch))
__CPROVER_assigns(stats != NULL: __CPROVER_object_whole(stats))
__CPROVER_ensures(__CPROVER_return_value <= dst_size)
__CPROVER_ensures(__CPROVER_return_value == 0 ==> (stats == NULL || stats->opaque[0] == 0));
#else
LZFSE_API size_t crushlzfse_encode_buffer_chained(void *dst, size_t dst_size,
                                                  const void *src, size_t src_size,
                                                  void *scratch, size_t scratch_size,
                                                  const crushlzfse_encode_params *params,
                                                  crushlzfse_stats *stats);
#endif

// Decodes a complete stream. Also accepts the LZVN-in-LZFSE blocks Apple's
// encoder and this one emit for small inputs.
//
// On CRUSHLZFSE_OUTPUT_TOO_SMALL, *out_len is still set: to the number of
// bytes of dst that hold real, correct decoded output before dst ran out of
// room, not left untouched.
// src and dst may occupy disjoint byte ranges of the same allocation. Neither
// range may overlap the other; a non-NULL out_len must occupy a disjoint range.
LZFSE_API int crushlzfse_decode_buffer(void *dst, size_t dst_size,
                                       const void *src, size_t src_size,
                                       size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // CRUSHLZFSE_H
