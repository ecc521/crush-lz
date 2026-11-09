#!/usr/bin/env python3
"""Shipping LZFSE fast encoder loop under explicit search/emitter contracts."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify
import re


def generate(source):
    start = source.index('LZFSE_INLINE int crushlzfse_encode_base_fast_impl(')
    end = source.index('// One instantiation per hashed length and mode', start)
    body = source[start:end]
    body = body.replace('#endif\n', '', 1)
    asm = '''#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(prime)); // opaque, so it stays in a register
#endif'''
    assert body.count(asm) == 1
    body = body.replace(asm, '')
    stride = '  const lzfse_offset max_stride = max_step > probed ? max_step : probed;'
    assert body.count(stride) == 1
    body = body.replace(stride, stride + r'''
  /*@ assert 1 <= probed <= 2; */
  /*@ assert 1 <= max_stride <= 64; */''', 1)
    match_end = '    rep = (uint32_t)(mpos - mref);'
    assert body.count(match_end) == 1
    body = body.replace(match_end, r'''    /*@ assert ip + 4 <= mpos + len <= s->src_end - 8; */
    rep = (uint32_t)(mpos - mref);''', 1)
    no_match = '    if (len == 0) {'
    assert body.count(no_match) == 1
    body = body.replace(no_match, no_match + '\n      const lzfse_offset before_step = ip;', 1)
    branch_end = '      continue;'
    assert body.count(branch_end) == 1
    body = body.replace(branch_end, r'''      /*@ assert ip > before_step; */
      continue;''', 1)
    loop = '  while (ip < ilimit) {'
    assert body.count(loop) == 1
    body = body.replace(loop, r'''
  /*@ loop invariant \valid(s);
      loop invariant 0 <= s->src_literal <= s->src_end;
      loop invariant 1 <= ip <= s->src_end + 64;
      loop invariant s->src_literal <= ip;
      loop invariant rep <= s->src_literal;
      loop assigns ip, rep, s->src_literal,
                   table[0 .. (1<<hash_bits)-1],
                   ltable[0 .. (1<<hash_bits)-1];
      loop variant s->src_end + 64 - ip;
  */
''' + loop, 1)
    body = body.replace('LZFSE_INLINE int crushlzfse_encode_base_fast_impl(', r'''
/*@ requires \valid(s);
    requires 0 <= s->src_end <= 65536;
    requires 0 <= s->src_literal <= s->src_encode_i;
    requires s->src_encode_i <= s->src_end;
    requires 10 <= hash_bits <= 16;
    requires 4 <= min_match <= (long_table || lazy ? 6 : 8);
    requires 1 <= skip_shift <= 31;
    requires 1 <= max_step <= 64;
    requires long_table == 0 || long_table == 1;
    requires lazy == 0 || lazy == 1;
    requires \valid_read(s->src + (0 .. s->src_end-1));
    requires \valid(table + (0 .. (1<<hash_bits)-1));
    requires !long_table || \valid(ltable + (0 .. (1<<hash_bits)-1));
    requires \separated(s, s->src + (0 .. s->src_end-1),
                        table + (0 .. (1<<hash_bits)-1),
                        ltable + (0 .. (1<<hash_bits)-1));
    assigns s->src_encode_i, s->src_literal,
            table[0 .. (1<<hash_bits)-1],
            ltable[0 .. (1<<hash_bits)-1];
    ensures \result == 0 || \result == -2;
    ensures 0 <= s->src_literal <= s->src_end;
*/
LZFSE_INLINE int crushlzfse_encode_base_fast_impl(''', 1)
    return r'''
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#define LZFSE_INLINE static
#define LZFSE_STATUS_OK 0
#define LZFSE_STATUS_DST_FULL -2
#define CRUSHLZFSE_FAST_PRIME 0xCF1BBCDCB7A56463ULL
typedef int64_t lzfse_offset;

typedef struct {
  const uint8_t *src;
  lzfse_offset src_end;
  lzfse_offset src_literal;
  lzfse_offset src_encode_i;
} lzfse_encoder_state;

/*@ requires 0 <= anchor <= ip < ilimit;
    requires ilimit == src_end-16;
    requires src_end <= 65536;
    requires rep <= anchor;
    requires 4 <= min_match <= (long_table || lazy ? 6 : 8);
    requires 10 <= hash_bits <= 16;
    requires long_table == 0 || long_table == 1;
    requires lazy == 0 || lazy == 1;
    requires \valid_read(src + (0 .. src_end-1));
    requires \valid(table + (0 .. (1<<hash_bits)-1));
    requires !long_table || \valid(ltable + (0 .. (1<<hash_bits)-1));
    requires \valid(mpos_out) && \valid(mref_out);
    assigns table[0 .. (1<<hash_bits)-1],
            ltable[0 .. (1<<hash_bits)-1],*mpos_out,*mref_out;
    ensures \result == 0 ||
      (anchor <= *mpos_out <= ip+1 && 0 <= *mref_out < *mpos_out &&
       1 <= *mpos_out-*mref_out <= 65535 &&
       ip+4 <= *mpos_out+\result <= src_end-8 && \result >= 4);
*/
uint32_t crushlzfse_fast_find(const uint8_t *src,lzfse_offset src_end,
  lzfse_offset ilimit,lzfse_offset ip,lzfse_offset anchor,uint32_t rep,
  int min_match,int hash_bits,uint64_t prime,uint16_t *table,
  uint16_t *ltable,int long_table,int lazy,lzfse_offset *mpos_out,
  lzfse_offset *mref_out);

/*@ requires 0 <= mpos && mpos+4 <= end;
    requires \valid_read(src + (mpos+2 .. mpos+9));
    requires \valid_read(src + (end-2 .. end+6));
    requires \valid_read(src + (end-1 .. end+6));
    requires 4 <= min_match <= 8;
    requires 10 <= hash_bits <= 16;
    requires \valid(table + (0 .. (1<<hash_bits)-1));
    requires !long_table || \valid(ltable + (0 .. (1<<hash_bits)-1));
    assigns table[0 .. (1<<hash_bits)-1],
            ltable[0 .. (1<<hash_bits)-1];
*/
void crushlzfse_fast_index_match(const uint8_t *src,lzfse_offset mpos,
  lzfse_offset end,int min_match,int hash_bits,uint64_t prime,
  uint16_t *table,uint16_t *ltable,int long_table);

/*@ requires 0 <= anchor <= *ip <= s->src_end + 64;
    requires 1 <= probed <= 2;
    requires 1 <= skip_shift <= 31;
    requires probed <= max_stride <= 64;
    requires \valid(s) && \valid(ip);
    assigns *ip, s->src_literal;
    ensures \old(*ip) + probed <= *ip <= \old(*ip) + max_stride;
    ensures \result == 0 || \result == -2;
    ensures \old(s->src_literal) <= s->src_literal <= s->src_end;
    ensures s->src_literal <= *ip;
*/
int crushlzfse_fast_skip(lzfse_encoder_state *s, lzfse_offset anchor, lzfse_offset *ip,
                         int probed, int skip_shift, lzfse_offset max_stride);

/*@ requires 0 <= anchor <= mpos;
    requires len >= 4 && mpos + len <= s->src_end - 8;
    requires 0 <= mpos - (lzfse_offset)rep;
    requires \valid(s);
    assigns s->src_literal;
    ensures \result == 0 || \result == -2;
    ensures \result == 0 ==> s->src_literal == mpos + len;
    ensures 0 <= s->src_literal <= s->src_end;
*/
int crushlzfse_fast_emit(lzfse_encoder_state *s, lzfse_offset anchor, lzfse_offset mpos,
                         uint32_t len, uint32_t rep);
''' + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzfse_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzfse-fast-loop'
    output.mkdir(parents=True, exist_ok=True)
    verify('fast_loop', generate(source), output, ['crushlzfse_encode_base_fast_impl'], 20,
           split=False)
    if args.mutants:
        old = 'if (crushlzfse_fast_skip(s, anchor, &ip, probed, skip_shift, max_stride) != LZFSE_STATUS_OK) goto fail;'
        assert source.count(old) == 1
        generated = generate(source)
        assert generated.count(old) == 1
        verify('fast_no_progress', generated.replace(old, 'ip = before_step;'),
               output, ['crushlzfse_encode_base_fast_impl'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
