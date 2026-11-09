#!/usr/bin/env python3
"""Shipping LZVN fast encoder loop under explicit search/emitter contracts."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


import re

def generate(source):
    start = source.index('LZVN_INLINE size_t lzvn_encode_fast_impl(')
    end = source.index('// One instantiation per hashed length and mode', start)
    body = source[start:end]
    body = re.sub(r'#ifdef LZVN_PROOF\n.*?#endif\n', '', body, flags=re.DOTALL)
    asm = '''#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(prime)); // opaque, so it stays in a register
#endif'''
    assert body.count(asm) == 1
    body = body.replace(asm, '')
    stride = '  const lzvn_offset max_stride = max_step > probed ? max_step : probed;'
    assert body.count(stride) == 1
    body = body.replace(stride, stride + r'''
  /*@ assert 1 <= probed <= 2; */
  /*@ assert 1 <= max_stride <= 64; */''', 1)
    match_end = '    anchor = mpos + len;'
    assert body.count(match_end) == 1
    body = body.replace(match_end, match_end + r'''
    /*@ assert ip + 4 <= anchor <= src_end - 8; */''', 1)
    no_match = '    if (len == 0) {'
    assert body.count(no_match) == 1
    body = body.replace(no_match, no_match + '\n      const lzvn_offset before_step = ip;', 1)
    branch_end = '      continue;'
    assert body.count(branch_end) == 1
    body = body.replace(branch_end, r'''      /*@ assert ip > before_step; */
      continue;''', 1)
    loop = '  while (ip < ilimit) {'
    assert body.count(loop) == 1
    body = body.replace(loop, r'''
  /*@ loop invariant 0 <= anchor <= src_end;
      loop invariant 1 <= ip <= src_end + 64;
      loop invariant anchor <= ip;
      loop invariant rep <= anchor;
      loop invariant \base_addr(q) == \base_addr(dst);
      loop invariant dst <= q <= q1;
      loop assigns q,anchor,ip,rep,dst[0 .. dst_size-1],
                   table[0 .. (1<<hash_bits)-1],
                   ltable[0 .. (1<<hash_bits)-1];
      loop variant src_end + 64 - ip;
  */
''' + loop, 1)
    body = body.replace('LZVN_INLINE size_t lzvn_encode_fast_impl(', r'''
/*@ requires 0 <= src_size <= 65536;
    requires 0 <= dst_size <= PTRDIFF_MAX;
    requires 10 <= hash_bits <= 16;
    requires 4 <= min_match <= (long_table || lazy ? 6 : 8);
    requires 1 <= skip_shift <= 31;
    requires 1 <= max_step <= 64;
    requires long_table == 0 || long_table == 1;
    requires lazy == 0 || lazy == 1;
    requires \valid_read(src + (0 .. src_size-1));
    requires \valid(dst + (0 .. dst_size-1));
    requires \valid(table + (0 .. (1<<hash_bits)-1));
    requires \valid(ltable + (0 .. (1<<hash_bits)-1));
    requires \separated(src + (0 .. src_size-1),
                        dst + (0 .. dst_size-1),
                        table + (0 .. (1<<hash_bits)-1),
                        ltable + (0 .. (1<<hash_bits)-1));
    assigns dst[0 .. dst_size-1],table[0 .. (1<<hash_bits)-1],
            ltable[0 .. (1<<hash_bits)-1];
    ensures \result <= dst_size;
*/
LZVN_INLINE size_t lzvn_encode_fast_impl(''', 1)
    return r'''
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#define LZFSE_INLINE static
#define LZVN_INLINE static
#define LZVN_ENCODE_MIN_DST_SIZE 16
#define LZVN_ZOPT_BLOCK_SIZE 65536
#define CRUSHLZFSE_FAST_PRIME 0xCF1BBCDCB7A56463ULL
typedef int64_t lzvn_offset;
/*@ requires 0 <= anchor <= ip <= 65600;
    requires 1 <= skip_shift <= 31;
    requires 1 <= probed <= 2;
    requires probed <= max_stride <= 64;
    assigns \nothing;
    ensures 1 <= \result <= max_stride;
*/
lzvn_offset lzvn_fast_skip_step(lzvn_offset ip,lzvn_offset anchor,
  int skip_shift,int probed,lzvn_offset max_stride);
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
    requires \valid(ltable + (0 .. (1<<hash_bits)-1));
    requires \valid(mpos_out) && \valid(mref_out);
    assigns table[0 .. (1<<hash_bits)-1],
            ltable[0 .. (1<<hash_bits)-1],*mpos_out,*mref_out;
    ensures \result == 0 ||
      (anchor <= *mpos_out <= ip+1 && 0 <= *mref_out < *mpos_out &&
       1 <= *mpos_out-*mref_out <= 65535 &&
       ip+4 <= *mpos_out+\result <= src_end-8 && \result >= 4);
*/
uint32_t crushlzfse_fast_find(const uint8_t *src,lzvn_offset src_end,
  lzvn_offset ilimit,lzvn_offset ip,lzvn_offset anchor,uint32_t rep,
  int min_match,int hash_bits,uint64_t prime,uint16_t *table,
  uint16_t *ltable,int long_table,int lazy,lzvn_offset *mpos_out,
  lzvn_offset *mref_out);
/*@ requires 0 <= mpos && mpos+4 <= end;
    requires \valid_read(src + (mpos+2 .. mpos+9));
    requires \valid_read(src + (end-2 .. end+6));
    requires \valid_read(src + (end-1 .. end+6));
    requires 4 <= min_match <= 8;
    requires 10 <= hash_bits <= 16;
    requires \valid(table + (0 .. (1<<hash_bits)-1));
    requires \valid(ltable + (0 .. (1<<hash_bits)-1));
    assigns table[0 .. (1<<hash_bits)-1],
            ltable[0 .. (1<<hash_bits)-1];
*/
void crushlzfse_fast_index_match(const uint8_t *src,lzvn_offset mpos,
  lzvn_offset end,int min_match,int hash_bits,uint64_t prime,
  uint16_t *table,uint16_t *ltable,int long_table);
/*@ requires 0 <= L <= 65536 && M >= 3 && 1 <= D <= 65535;
    requires \base_addr(q)==\base_addr(q1);
    requires 0 <= q1-q <= PTRDIFF_MAX;
    requires \valid(q + (0 .. q1-q-1));
    requires \valid_read(p + (0 .. L+7));
    requires \separated(q + (0 .. q1-q-1),p + (0 .. L+7));
    assigns q[0 .. q1-q-1],\result \from q,q1,L,M,D,D_prev,p[0 .. L+7];
    ensures \base_addr(\result)==\base_addr(q);
    ensures q <= \result <= q1;
*/
uint8_t *emit(const uint8_t *p,uint8_t *q,uint8_t *q1,size_t L,
              size_t M,size_t D,size_t D_prev);
/*@ requires 0 <= L <= 65536;
    requires \base_addr(q)==\base_addr(q1);
    requires 0 <= q1-q <= PTRDIFF_MAX;
    requires \valid(q + (0 .. q1-q-1));
    requires \valid_read(p + (0 .. L-1));
    requires \separated(q + (0 .. q1-q-1),p + (0 .. L-1));
    assigns q[0 .. q1-q-1],\result \from q,q1,L,p[0 .. L-1];
    ensures \base_addr(\result)==\base_addr(q);
    ensures q <= \result <= q1;
*/
uint8_t *emit_literal(const uint8_t *p,uint8_t *q,uint8_t *q1,size_t L);
/*@ requires \valid(q + (0 .. 7)); assigns q[0 .. 7]; */
void store8(uint8_t *q,uint64_t value);
''' + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzvn_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzvn-fast-loop'
    output.mkdir(parents=True, exist_ok=True)
    verify('fast_loop', generate(source), output, ['lzvn_encode_fast_impl'], 20,
           split=False)
    if args.mutants:
        old = 'ip += lzvn_fast_skip_step(ip, anchor, skip_shift, probed, max_stride);'
        assert source.count(old) == 1
        generated = generate(source)
        assert generated.count(old) == 1
        verify('fast_no_progress', generated.replace(old, 'ip = before_step;'),
               output, ['lzvn_encode_fast_impl'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
