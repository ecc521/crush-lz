// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// CrushLZ4: an encoder and decoder for Apple's COMPRESSION_LZ4 (the
// published LZ4 block format inside Apple's bv41/bv4-/bv4$ frame, decmpfs
// types 15 and 16). Same conventions as crushlzfse.h: any input size, a
// NULL scratch is allocated internally, the encoder returns bytes written
// or 0, the decoder returns 0 or a negative CRUSHLZ4_* status. -2 and -1
// trade ratio for speed against the default (0), 1 to 10 the reverse. See
// the crate README for the measured ladder.
//
// The block encoder is upstream LZ4 (github.com/lz4/lz4, vendored unmodified
// under csrc/vendor/lz4, BSD 2-Clause). What is ours is the frame, the
// decoder, the level ladder and the cross-block window. The reasons are
// measured and written up in the crate README: upstream beats a hand-written
// encoder at every point on the curve, and its level 12 parse comes within
// 0.008 points of this format's provable floor.

#ifndef CRUSHLZ4_H
#define CRUSHLZ4_H

#include <limits.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRUSHLZ4_LEVEL_MIN          (-5)
#define CRUSHLZ4_LEVEL_MAX          10
#define CRUSHLZ4_LEVEL_DEFAULT      0
// Never a level; returned by crushlz4_params_for_level for a NULL out.
#define CRUSHLZ4_LEVEL_INVALID      INT_MIN

#define CRUSHLZ4_INVALID          (-1)
#define CRUSHLZ4_OUTPUT_TOO_SMALL (-2)

// Frame layout: blocks of up to CRUSHLZ4_BLOCK_SIZE input bytes, each either
// compressed (magic, decoded size, encoded size, payload) or stored (magic,
// size, bytes), then the end magic. Little-endian throughout.
#define CRUSHLZ4_BLOCK_SIZE       0x10000
#define CRUSHLZ4_MAGIC_COMPRESSED 0x31347662u // "bv41"
#define CRUSHLZ4_MAGIC_STORED     0x2D347662u // "bv4-"
#define CRUSHLZ4_MAGIC_END        0x24347662u // "bv4$"
#define CRUSHLZ4_MIN_MATCH        4
#define CRUSHLZ4_MAX_OFFSET       65535

// The two encoders upstream exposes. They write the same bitstream; only the
// parse differs, so a stream gives no clue which produced it.
//
//   FAST  LZ4_compress_fast. One knob, `acceleration`: higher skips more
//         input per miss, so it runs faster and compresses worse. 1 is
//         upstream's own default.
//   HC    LZ4_compress_HC. `hc_level` 2..9 widen a hash chain; 10..12 run a
//         shortest-path parse instead. 1 is accepted and clamps to 2, which
//         is upstream's floor, so the two are indistinguishable.
#define CRUSHLZ4_MODE_FAST 0
#define CRUSHLZ4_MODE_HC   1

// What a level resolves to. Exactly one of the two fields is read, chosen by
// `mode`; the other is ignored rather than validated, so a params built from
// one level and edited toward the other mode still means what it reads like.
typedef struct {
  int mode;         // CRUSHLZ4_MODE_FAST or CRUSHLZ4_MODE_HC
  int acceleration; // FAST only: >= 1, higher is faster and worse
  int hc_level;     // HC only: 1..12, 1 clamping to 2
} crushlz4_encode_params;

// Valid ranges for every field above; params outside them are rejected.
// level_default is the level crushlz4_encode_buffer uses for
// CRUSHLZ4_LEVEL_DEFAULT, reported here so a caller that has the library but
// not the header can ask for it.
typedef struct {
  int level_min, level_max, level_default;
  int mode_min, mode_max;
  int acceleration_min, acceleration_max;
  int hc_level_min, hc_level_max;
} crushlz4_capabilities;

crushlz4_capabilities crushlz4_get_capabilities(void);

// The settings a level stands for. Returns the level actually used: levels
// outside the range are clamped, not rejected, so a caller asking for "as
// fast as possible" with INT_MIN gets the fastest level rather than an error.
// Returns CRUSHLZ4_LEVEL_INVALID, which is never a level, only if out is NULL.
int crushlz4_params_for_level(int level, crushlz4_encode_params *out);

// Scratch bytes an encode with these params needs. The two modes want very
// different amounts: the FAST levels a 16 KiB hash table, the HC levels a
// 256 KiB chain. Neither varies with input size or with the knob.
//
// There is deliberately no "big enough for anything" query across these
// codecs, because for most of them no useful such size exists: their
// optimal strategies size tables from params the caller chooses. A caller
// reusing one buffer over several levels sizes it for the largest of the
// params it will actually use. Returns 0 for a NULL params.
//
// Note this is the params pointer, not the scratch pointer: a NULL *scratch*
// passed to an encode is still valid and allocates internally.
size_t crushlz4_scratch_size(const crushlz4_encode_params *params);

// An output size that always fits any input of src_size bytes.
size_t crushlz4_encode_bound(size_t src_size);

size_t crushlz4_encode_buffer(void *dst, size_t dst_size,
                              const void *src, size_t src_size,
                              void *scratch, size_t scratch_size, int level);

// The same encode driven by raw params rather than a level. Returns 0 if
// params is NULL or any field is outside crushlz4_get_capabilities(). This
// is what measures the ladder; the levels above are the points on it worth
// naming.
size_t crushlz4_encode_buffer_advanced(void *dst, size_t dst_size,
                                       const void *src, size_t src_size,
                                       void *scratch, size_t scratch_size,
                                       const crushlz4_encode_params *params);

// src and dst must not overlap.
//
// With a NULL dst, validates the stream and reports its decoded size in
// *out_len without writing anything. dst_size still bounds that size: it
// fails CRUSHLZ4_OUTPUT_TOO_SMALL once the decoded total would exceed it,
// so pass SIZE_MAX for no cap.
//
// On CRUSHLZ4_OUTPUT_TOO_SMALL (with a real dst), *out_len is still set: to
// the bytes decoded from every bv41/bv4- block fully completed before the
// one that didn't fit (block granularity, not byte-exact within that last
// block), not left untouched.
int crushlz4_decode_buffer(void *dst, size_t dst_size,
                           const void *src, size_t src_size,
                           size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // CRUSHLZ4_H
