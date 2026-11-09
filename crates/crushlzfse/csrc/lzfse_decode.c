/*
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:  

1.  Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
    in the documentation and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
// Modifications copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0 AND BSD-3-Clause


// LZFSE decode API

#include "lzfse.h"
#include "lzfse_internal.h"

size_t lzfse_decode_scratch_size() { return sizeof(lzfse_decoder_state); }

#ifdef LZFSE_PROOF
//  A zero-length buffer may be NULL; the scratch buffer holds one
//  lzfse_decoder_state, suitably aligned (lzfse_decode_scratch_size()).
#define LZFSE_PROOF_DECODE_BUFFERS(dst, dst_size, src, src_size)               \
  __CPROVER_requires(src_size == 0 || (src != NULL && __CPROVER_r_ok(src, src_size))) \
  __CPROVER_requires(dst_size == 0 || (dst != NULL && __CPROVER_w_ok(dst, dst_size))) \
  __CPROVER_requires(src_size == 0 || dst_size == 0 ||                       \
                     LZFSE_DISJOINT_RANGES(src, src_size, dst, dst_size))
#endif

size_t lzfse_decode_buffer_with_scratch(uint8_t *__restrict dst_buffer,
                         size_t dst_size, const uint8_t *__restrict src_buffer,
                         size_t src_size, void *__restrict scratch_buffer)
#ifdef LZFSE_PROOF
LZFSE_PROOF_DECODE_BUFFERS(dst_buffer, dst_size, src_buffer, src_size)
__CPROVER_requires(__CPROVER_w_ok(scratch_buffer, sizeof(lzfse_decoder_state)) &&
                   LZFSE_OFFSET(scratch_buffer) % _Alignof(lzfse_decoder_state) == 0)
__CPROVER_requires(src_size == 0 || !__CPROVER_same_object(src_buffer, scratch_buffer))
__CPROVER_requires(dst_size == 0 || !__CPROVER_same_object(dst_buffer, scratch_buffer))
__CPROVER_assigns(__CPROVER_object_upto(scratch_buffer, sizeof(lzfse_decoder_state)),
                  lzfse_proof_tables_ok)
__CPROVER_assigns(dst_size != 0: __CPROVER_object_upto(dst_buffer, dst_size))
__CPROVER_ensures(__CPROVER_return_value <= dst_size)
#endif
{
  // No stream fits in zero bytes, and src + 0 is undefined for a NULL src.
  if (src_size == 0)
    return 0;
  // Zero-capacity output stays inside a real object, even for a NULL dst.
  uint8_t empty_dst;
  if (dst_size == 0)
    dst_buffer = &empty_dst;
  lzfse_decoder_state *s = (lzfse_decoder_state *)scratch_buffer;
  // Load-bearing, not just defensive: a block with n_literals=0 but
  // n_matches>0 reads literals[] without writing it first, so skipping this
  // on a reused scratch buffer would leak a prior decode's literal bytes
  // into this one.
  memset(s, 0x00, sizeof(*s));
#ifdef LZFSE_PROOF
  // Zeroed rows are valid rows; this is where the table ghost starts.
  __CPROVER_assert(LZFSE_PROOF_LITERAL_TABLE_OK(&s->compressed_lzfse_block_state, _z) &&
                       LZFSE_PROOF_VALUE_TABLES_OK(&s->compressed_lzfse_block_state, _z),
                   "zeroed decoder tables are valid");
  lzfse_proof_tables_ok = 1;
#endif

  s->src = src_buffer;
  s->src_begin = src_buffer;
  s->src_end = s->src + src_size;
  s->dst = dst_buffer;
  s->dst_begin = dst_buffer;
  s->dst_end = dst_buffer + dst_size;

  int status = lzfse_decode(s);
  if (status == LZFSE_STATUS_DST_FULL)
    return dst_size;
  if (status != LZFSE_STATUS_OK)
    return 0;                           // failed
  return (size_t)(s->dst - dst_buffer); // bytes written
}

size_t lzfse_decode_buffer(uint8_t *__restrict dst_buffer, size_t dst_size,
                           const uint8_t *__restrict src_buffer,
                           size_t src_size, void *__restrict scratch_buffer)
#ifdef LZFSE_PROOF
LZFSE_PROOF_DECODE_BUFFERS(dst_buffer, dst_size, src_buffer, src_size)
__CPROVER_requires(scratch_buffer == NULL ||
                   (__CPROVER_w_ok(scratch_buffer, sizeof(lzfse_decoder_state)) &&
                    LZFSE_OFFSET(scratch_buffer) % _Alignof(lzfse_decoder_state) == 0 &&
                    (src_size == 0 || !__CPROVER_same_object(src_buffer, scratch_buffer)) &&
                    (dst_size == 0 || !__CPROVER_same_object(dst_buffer, scratch_buffer))))
__CPROVER_assigns(lzfse_proof_tables_ok)
__CPROVER_assigns(scratch_buffer != NULL:
                  __CPROVER_object_upto(scratch_buffer, sizeof(lzfse_decoder_state)))
__CPROVER_assigns(dst_size != 0: __CPROVER_object_upto(dst_buffer, dst_size))
__CPROVER_ensures(__CPROVER_return_value <= dst_size)
#endif
{
  int has_malloc = 0;
  size_t ret = 0;

  if (scratch_buffer == NULL) {
    // +1 in case scratch size could be zero
    scratch_buffer = malloc(lzfse_decode_scratch_size() + 1);
    has_malloc = 1;
  }
  if (scratch_buffer == NULL)
    return 0;
  ret = lzfse_decode_buffer_with_scratch(dst_buffer,
                               dst_size, src_buffer,
                               src_size, scratch_buffer);
  if (has_malloc)
    free(scratch_buffer);
  return ret;
}
