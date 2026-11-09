// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// CrushLZVN: an LZVN encoder, bit-compatible with Apple's decoder. Same
// conventions as crushlzfse.h: every encode call, Greedy or Optimal, is
// bounded to one already-independent fixed 64 KiB piece (matching decmpfs's
// own chunk size) and rejects anything larger outright rather than chunk or
// stream it. A NULL scratch is allocated internally, encoders return bytes
// written or 0, decoders return 0 or a negative CRUSHLZVN_* status.
//
// Raw LZVN carries no header, so the output is not self-describing; the
// caller has to know it is LZVN. Apple wraps it in an LZFSE stream for
// small inputs, which crushlzfse_encode_buffer does automatically.

#ifndef CRUSHLZVN_H
#define CRUSHLZVN_H

#include <stddef.h>
#include <limits.h>
#include <stdint.h>
#include "lzfse.h" // LZFSE_API

#ifdef __cplusplus
extern "C" {
#endif

#define CRUSHLZVN_LEVEL_MIN     (-5)
#define CRUSHLZVN_LEVEL_MAX     10
#define CRUSHLZVN_LEVEL_DEFAULT 0
// Never a level; returned by crushlzvn_params_for_level for a NULL out.
#define CRUSHLZVN_LEVEL_INVALID INT_MIN

#define CRUSHLZVN_INVALID          (-1)
#define CRUSHLZVN_OUTPUT_TOO_SMALL (-2)

typedef enum {
  CRUSHLZVN_STRATEGY_GREEDY,  // levels -2 to 7 (4 to 7 are one setting)
  CRUSHLZVN_STRATEGY_OPTIMAL, // levels 8 to 10
  CRUSHLZVN_STRATEGY_FAST     // levels -5 to -3

} crushlzvn_strategy;

typedef struct {
  crushlzvn_strategy strategy;
  union {
    struct {
      int32_t hash_bits;  // log2 of the hash table size
      int32_t hash_width; // candidates per bucket
    } greedy;
    struct {
      int32_t search_depth; // match-tree nodes visited per position
      int32_t store_limit; // candidates kept per position
      int32_t hash_bits;
      int32_t pareto_k;    // states kept per position
    } optimal;
    // The LZFSE fast strategy's match search and fields, with the same
    // ranges; see crushlzfse.h.
    struct {
      int hash_bits;  // log2 of each hash table's size
      int min_match;  // bytes the main table hashes
      int skip_shift; // over unmatched input the stride grows by one byte
      int max_step;   //   per 2^skip_shift bytes, up to max_step
      int long_table; // 1: a second table hashed on 8 bytes, consulted first
      int lazy;       // 1: look ahead for a longer match before taking one
    } fast;
  } p;
} crushlzvn_encode_params;

typedef struct {
  // level_default is the level encode_buffer uses for CRUSHLZVN_LEVEL_DEFAULT,
  // reported here so a caller with the library but not the header can ask.
  int level_min, level_max, level_default;
  int32_t greedy_hash_bits_min, greedy_hash_bits_max;
  int32_t greedy_hash_width_min, greedy_hash_width_max;
  int32_t search_depth_min, search_depth_max;
  int32_t store_limit_min, store_limit_max;
  int32_t hash_bits_min, hash_bits_max;
  int32_t pareto_k_min, pareto_k_max;
  int fast_hash_bits_min, fast_hash_bits_max;
  int fast_min_match_min, fast_min_match_max; // max is 6 with long_table or lazy
  int fast_skip_shift_min, fast_skip_shift_max;
  int fast_max_step_min, fast_max_step_max;
  int fast_long_table_min, fast_long_table_max;
  int fast_lazy_min, fast_lazy_max;
} crushlzvn_capabilities;

LZFSE_API crushlzvn_capabilities crushlzvn_get_capabilities(void);

// The settings a level stands for. Returns the level actually used: levels
// outside the range are clamped, not rejected, so a caller asking for "as
// fast as possible" with INT_MIN gets the fastest level rather than an error.
// Returns CRUSHLZVN_LEVEL_INVALID, which is never a level, only if out is NULL.
LZFSE_API int crushlzvn_params_for_level(int level, crushlzvn_encode_params *out);

// Scratch bytes an encode with these params needs. There is deliberately no
// "big enough for anything" query, because for most of these codecs no
// useful such size exists: the optimal strategies size their tables from
// params the caller chooses. A caller reusing one buffer over several levels
// sizes it for the largest of the params it will actually use. Returns 0
// for a NULL params.
//
// Note this is the params pointer, not the scratch pointer: a NULL *scratch*
// passed to an encode is still valid and allocates internally.
LZFSE_API size_t crushlzvn_scratch_size(const crushlzvn_encode_params *params);

// Output bytes an encode of src_size bytes with these params needs, at
// most. `params` is required and must not be NULL, for consistency with
// crushlzvn_scratch_size and in case a future strategy's overhead differs;
// today every strategy shares the one fixed LZVN_ZOPT_BLOCK_SIZE block, so
// the bound does not actually vary by strategy. Pass the same params the
// encode call itself will use.
LZFSE_API size_t crushlzvn_encode_bound(size_t src_size, const crushlzvn_encode_params *params);

// One call is one stream, bounded to one already-independent LZVN_ZOPT_BLOCK_SIZE
// piece (64 KiB, matching decmpfs's own chunk size): a caller with more
// input chunks it and calls once per chunk.
// Both encode entry points below require source and destination to be separate
// allocations (even if their byte ranges would not overlap). If scratch is supplied,
// it must be separate from source and params; its supplied byte range must not
// overlap destination. Destination and scratch may occupy adjacent ranges of
// one allocation (the LZFSE fallback uses this layout). Params must not be
// stored in destination. A NULL scratch is allocated internally.
LZFSE_API size_t crushlzvn_encode_buffer(void *dst, size_t dst_size,
                                         const void *src, size_t src_size,
                                         void *scratch, size_t scratch_size, int level);

#if defined(CRUSHLZFSE_DISPATCH_PROOF) || defined(CRUSHLZVN_DISPATCH_PROOF) || defined(LZVN_PROOF) || defined(LZFSE_PROOF)
#define CRUSHLZVN_PROOF_RANGES_DISJOINT(a, a_size, b, b_size) \
  ((a_size) == 0 || (b_size) == 0 || \
   !__CPROVER_same_object((a), (b)) || \
   (__CPROVER_POINTER_OFFSET(a) <= __CPROVER_POINTER_OFFSET(b) \
      ? (a_size) <= (size_t)(__CPROVER_POINTER_OFFSET(b) - __CPROVER_POINTER_OFFSET(a)) \
      : (b_size) <= (size_t)(__CPROVER_POINTER_OFFSET(a) - __CPROVER_POINTER_OFFSET(b))))
LZFSE_API size_t crushlzvn_encode_buffer_advanced(void *dst, size_t dst_size,
                                                  const void *src, size_t src_size,
                                                  void *scratch, size_t scratch_size,
                                                  const crushlzvn_encode_params *params)
__CPROVER_requires(src != NULL || src_size == 0)
__CPROVER_requires(src == NULL || __CPROVER_r_ok(src, src_size))
__CPROVER_requires(dst != NULL || dst_size == 0)
__CPROVER_requires(dst == NULL || __CPROVER_w_ok(dst, dst_size))
__CPROVER_requires(params != NULL && __CPROVER_r_ok(params, sizeof(*params)))
__CPROVER_requires(scratch == NULL || __CPROVER_w_ok(scratch, scratch_size))
__CPROVER_requires(src == NULL || dst == NULL || !__CPROVER_same_object(src, dst))
__CPROVER_requires(scratch == NULL || src == NULL || !__CPROVER_same_object(scratch, src))
__CPROVER_requires(dst == NULL || !__CPROVER_same_object(params, dst))
__CPROVER_requires(scratch == NULL || !__CPROVER_same_object(params, scratch))
__CPROVER_requires(scratch == NULL || dst == NULL ||
                   CRUSHLZVN_PROOF_RANGES_DISJOINT(scratch, scratch_size, dst, dst_size))
__CPROVER_assigns(dst != NULL: __CPROVER_object_upto(dst, dst_size))
__CPROVER_assigns(scratch != NULL: __CPROVER_object_upto(scratch, scratch_size))
__CPROVER_ensures(__CPROVER_return_value <= dst_size);
#else
LZFSE_API size_t crushlzvn_encode_buffer_advanced(void *dst, size_t dst_size,
                                                  const void *src, size_t src_size,
                                                  void *scratch, size_t scratch_size,
                                                  const crushlzvn_encode_params *params);
#endif

// On CRUSHLZVN_OUTPUT_TOO_SMALL, *out_len is still set: to the number of
// bytes of dst that hold real, correct decoded output before dst ran out of
// room, not left untouched.
LZFSE_API int crushlzvn_decode_buffer(void *dst, size_t dst_size,
                                      const void *src, size_t src_size,
                                      size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // CRUSHLZVN_H
