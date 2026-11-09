// SPDX-License-Identifier: MPL-2.0 AND MIT
// Copyright (c) 2022 Corellium LLC, author Ernesto A. Fernández
// Modifications copyright (c) 2026 Tucker Willenborg
//
// CrushLZBITMAP: an LZBITMAP encoder and decoder for Apple's undocumented
// COMPRESSION_LZBITMAP format (decmpfs types 13 and 14). Derived from
// Corellium's implementation. Same conventions as crushlzfse.h: any input
// size, a NULL scratch is allocated internally, encoders return bytes
// written or 0, decoders return 0 or a negative CRUSHLZBITMAP_* status.
//
// The format chunks the input at 32 KiB; crushlzbitmap_encode_chunk emits
// one chunk of a larger stream so callers can encode chunks in parallel or
// one at a time, the way decmpfs stores them. Levels below the default (0)
// trade ratio for throughput. Level 7 chooses periods by shortest path;
// levels 8–12 retain competing periods in a beam.

#ifndef CRUSHLZBITMAP_H
#define CRUSHLZBITMAP_H

#include <limits.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRUSHLZBITMAP_LEVEL_MIN          (-5)
#define CRUSHLZBITMAP_LEVEL_MAX          12
#define CRUSHLZBITMAP_LEVEL_DEFAULT      0
/* Never a level; returned by crushlzbitmap_params_for_level for a NULL out. */
#define CRUSHLZBITMAP_LEVEL_INVALID      INT_MIN

#define CRUSHLZBITMAP_INVALID          (-1)
#define CRUSHLZBITMAP_OUTPUT_TOO_SMALL (-2)

// Bytes of input per chunk, and the most a compressed chunk can occupy.
#define CRUSHLZBITMAP_CHUNK_SIZE_BITS  15
#define CRUSHLZBITMAP_CHUNK_SIZE       (1 << CRUSHLZBITMAP_CHUNK_SIZE_BITS)
// Tight: the uncompressed-chunk escape never exceeds CHUNK_SIZE bytes plus
// sizeof(struct zbm_chunk_hdr) (6). The extra 4 on top of that (CHUNK_SIZE
// + 10, not + 6) is not slack: crushlzbitmap_encode_chunk() also writes the
// 4-byte stream magic inline before chunk index 0's body, so the same
// dst_size a caller reuses across every chunk call has to cover that
// worst case too. See zbm_bound_exactness_test.c.
#define CRUSHLZBITMAP_MAX_CHUNK_SIZE   0x800A
// The terminating chunk crushlzbitmap_encode_chunk emits past the input.
#define CRUSHLZBITMAP_LAST_CHUNK_SIZE  6

// The largest src_size a single encode call accepts, on either API. Every
// position within one call's source is tracked as uint32_t internally (the
// row-hash table packs a 24-bit position and 8-bit epoch per entry, with a
// 16-bit reach window), so this is a real ceiling, not a suggestion: past
// it those positions wrap and the encoder can read outside the caller's
// buffer. Chosen at 4 GiB minus one chunk rather than widening that
// tracking throughout, since nothing legitimate needs more: a macOS
// resource fork's uncompressed size cannot exceed 4 GiB, and decmpfs
// stores files as independent 32 KiB chunks regardless.
#define CRUSHLZBITMAP_MAX_SRC_SIZE  (((size_t)1 << 32) - 1 - CRUSHLZBITMAP_CHUNK_SIZE)

#define CRUSHLZBITMAP_STRATEGY_DP     2 // the row tier's candidates, period sequence by shortest path
#define CRUSHLZBITMAP_STRATEGY_BEAM   4 // row-seeded beam with period carry and metadata run pricing
#define CRUSHLZBITMAP_STRATEGY_ROW    3 // full-reach buckets probed at every byte window, optional nearby scan, exact bit-cost scoring
#define CRUSHLZBITMAP_STRATEGY_FAST   5 // searches only where the period in force fails, indexes only what it searched

// Bounds every field below is validated against.
#define CRUSHLZBITMAP_MAX_BEAM_WIDTH        64
#define CRUSHLZBITMAP_MAX_ITERATIONS        64
#define CRUSHLZBITMAP_MAX_DP_CANDS          255
#define CRUSHLZBITMAP_MIN_ROW_HASH_BITS     8
#define CRUSHLZBITMAP_MAX_ROW_HASH_BITS     16
#define CRUSHLZBITMAP_MAX_ROW_DEPTH         16
#define CRUSHLZBITMAP_MAX_ROW_SCAN          256
#define CRUSHLZBITMAP_MIN_FAST_HASH_BITS    10
#define CRUSHLZBITMAP_MAX_FAST_HASH_BITS    16
#define CRUSHLZBITMAP_MAX_FAST_WINDOWS      8
#define CRUSHLZBITMAP_MAX_FAST_DIST_CACHE   2
#define CRUSHLZBITMAP_MAX_FAST_ACCEPT_DIFF  7
// The run of searches that sets the skip stays inside one chunk's blocks,
// 2^(CHUNK_SIZE_BITS - 3), so a larger shift would never skip.
#define CRUSHLZBITMAP_MAX_FAST_SKIP_SHIFT   (CRUSHLZBITMAP_CHUNK_SIZE_BITS - 4)

typedef struct {
    int hash_bits;       // log2 of the bucket count, 8 to 16
    int depth;           // entries per bucket, all probed: 1, 2, 4, 8 or 16; hash_bits + log2(depth) <= 18
    int dist_cache_size; // recently used periods to retry, 0 to 8; above 4 only with lookahead
    int accept_diff;     // accept the continuing period at this many literals without searching, 0 to 8
    int scan_window;     // nearest periods scanned exhaustively on a searched block: a multiple of 16, 0 to 256; above 32 only with lookahead
    int lookahead;       // 1 to probe the block after each candidate too, preferring periods that persist
} crushlzbitmap_row_params;

typedef struct {
    crushlzbitmap_row_params row; // candidate sourcing; lookahead must be 1
    int max_candidates; // candidates kept per block for the shortest path, 1 to 255
    int iterations;     // DP passes; later passes reuse the previous top-12 table
} crushlzbitmap_dp_params;

typedef struct {
    crushlzbitmap_row_params row; // candidate sourcing; lookahead must be 1
    int max_candidates;           // recorded candidates per block, 1 to 255
    int beam_width;               // surviving states: 1, 2, 4, 8, 16, 32 or 64
} crushlzbitmap_beam_params;

typedef struct {
    int hash_bits;       // log2 of the table size, 10 to 16
    int windows;         // byte windows looked up per searched block: 1, 2, 4 or 8, spread evenly over the block
    int dist_cache_size; // recently used periods retried on a searched block, 0 to 2
    int accept_diff;     // keep the period in force at this many literals without searching, 0 to 7
    int skip_shift;      // 0 never skips; else after n searches in a row that keep the period, the next n >> skip_shift blocks are not searched; 0 to 11
} crushlzbitmap_fast_params;

typedef struct {
    int strategy; // CRUSHLZBITMAP_STRATEGY_*
    union {
        crushlzbitmap_dp_params dp;
        crushlzbitmap_beam_params beam;
        crushlzbitmap_row_params row;
        crushlzbitmap_fast_params fast;
    } p;
} crushlzbitmap_params;

// Valid ranges for every params field; anything outside them is rejected.
// The DP candidate bounds also apply to beam.max_candidates; beam_width
// must additionally be a power of two.
// level_default is the level encode_buffer uses for
// CRUSHLZBITMAP_LEVEL_DEFAULT, reported here so a caller that has the library
// but not the header can ask for it. row_depth must additionally be a power of
// two, and hash_bits x depth must not exceed 2^18 table entries; scan_window
// must be a multiple of 16. Ranges alone do not capture those, so a params set
// inside every range here can still be rejected. fast_windows must also be a
// power of two.
typedef struct {
  int level_min, level_max, level_default;
  int row_hash_bits_min, row_hash_bits_max;
  int row_depth_min, row_depth_max;
  int row_lookahead_min, row_lookahead_max;
  int row_dist_cache_size_min, row_dist_cache_size_max;
  int row_scan_window_min, row_scan_window_max;
  int row_accept_diff_min, row_accept_diff_max;
  int dp_max_candidates_min, dp_max_candidates_max;
  int dp_iterations_min, dp_iterations_max;
  int beam_width_min, beam_width_max;
  int fast_hash_bits_min, fast_hash_bits_max;
  int fast_windows_min, fast_windows_max;
  int fast_dist_cache_size_min, fast_dist_cache_size_max;
  int fast_accept_diff_min, fast_accept_diff_max;
  int fast_skip_shift_min, fast_skip_shift_max;
} crushlzbitmap_capabilities;

crushlzbitmap_capabilities crushlzbitmap_get_capabilities(void);

// The settings a level stands for. Returns the level actually used: levels
// outside the range are clamped, not rejected. Returns
// CRUSHLZBITMAP_LEVEL_INVALID, which is never a level, only for a NULL out.
int crushlzbitmap_params_for_level(int level, crushlzbitmap_params *params);

// The documented defaults of one strategy. Returns 0, or
// CRUSHLZBITMAP_INVALID for an unknown strategy.
int crushlzbitmap_default_params(int strategy, crushlzbitmap_params *params);

// Alignment a scratch buffer must satisfy. The encoder's row table is read a
// bucket at a time with one 16-byte vector load, and 16 is what keeps a bucket
// from straddling a cache line; a larger alignment measures no faster and
// would put the buffer out of reach of plain malloc. malloc and calloc already
// exceed this, so only a caller carving scratch out of a pool of its own has
// to do anything about it.
#define CRUSHLZBITMAP_SCRATCH_ALIGN 16

// Scratch bytes an encode with these params needs. There is deliberately no
// "big enough for anything" query, because for most of these codecs no
// useful such size exists: the optimal strategies size their tables from
// params the caller chooses. A caller reusing one buffer over several levels
// sizes it for the largest of the params it will actually use. Returns 0 for
// a NULL params, matching the other codecs' scratch_size and this codec's
// own encode_buffer_advanced.
//
// Note this is the params pointer, not the scratch pointer: a NULL *scratch*
// passed to an encode is still valid and allocates internally.
size_t crushlzbitmap_scratch_size(const crushlzbitmap_params *params);

// An output size that always fits any input of src_size bytes.
size_t crushlzbitmap_encode_bound(size_t src_size);

size_t crushlzbitmap_encode_buffer(void *dst, size_t dst_size,
                                   const void *src, size_t src_size,
                                   void *scratch, size_t scratch_size, int level);

// A NULL params means the default level, the same as encode_chunk.
size_t crushlzbitmap_encode_buffer_advanced(void *dst, size_t dst_size,
                                            const void *src, size_t src_size,
                                            void *scratch, size_t scratch_size,
                                            const crushlzbitmap_params *params);

// Emits chunk `index` of the stream for the whole input `src`: the stream
// header when index is 0, and the terminating chunk once index is past the
// input. Concatenating chunks 0..N in order gives exactly what
// crushlzbitmap_encode_buffer would. dst needs CRUSHLZBITMAP_MAX_CHUNK_SIZE
// bytes. A NULL params means the default level.
size_t crushlzbitmap_encode_chunk(void *dst, size_t dst_size,
                                  const void *src, size_t src_size, size_t index,
                                  void *scratch, size_t scratch_size,
                                  const crushlzbitmap_params *params);

// With a NULL dst, walks the chunk headers (each carries its own decoded
// length) and reports the total in *out_len without decoding any chunk
// body. dst_size still bounds the total: it fails CRUSHLZBITMAP_OUTPUT_TOO_SMALL
// once the running total would exceed it, so pass SIZE_MAX for no cap.
//
// On CRUSHLZBITMAP_OUTPUT_TOO_SMALL, *out_len is still set: to the bytes
// decoded from every chunk fully completed before the one that didn't fit
// (up to CRUSHLZBITMAP_CHUNK_SIZE short of the truth, not byte-exact within
// that last chunk), not left untouched.
// The src[0, src_size), dst[0, dst_size), and *out_len storage ranges must
// be pairwise disjoint wherever present. Disjoint ranges may share an
// allocation. With NULL dst, dst_size is only a limit for the length probe.
int crushlzbitmap_decode_buffer(void *dst, size_t dst_size,
                                const void *src, size_t src_size,
                                size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // CRUSHLZBITMAP_H
