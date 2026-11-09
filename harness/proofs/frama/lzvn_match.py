#!/usr/bin/env python3
"""Shipping match emitter, with independently checked memcpy-based helpers."""
from pathlib import Path
import re
import argparse
import sys
sys.dont_write_bytecode=True
from wp_common import verify


def generate(source):
    a=source.index('LZVN_INLINE unsigned char *emit(')
    b=source.index('static inline int32_t offset_to_s32',a)
    body=source[a:b]
    body=body.replace('  size_t x;', '''  size_t x;
  unsigned char *const q_base=q;
  const unsigned char *const p_base=p;
  const size_t original_L=L;''',1)
    body=body.replace('  while (L > 15)',r'''
  /*@ loop invariant 0<=L<=original_L;
      loop invariant p==p_base+(original_L-L);
      loop invariant \base_addr(q)==\base_addr(q_base);
      loop invariant 0<=q-q_base<=q1-q_base;
      loop assigns L,x,p,q,q_base[0 .. q1-q_base-1];
      loop variant L;
  */
  while (L > 15)''',1)
    body=body.replace('  while (M > 15)',r'''
  /*@ loop invariant \base_addr(q)==\base_addr(q_base);
      loop invariant 0<q-q_base<=q1-q_base;
      loop assigns M,x,q,q_base[0 .. q1-q_base-1];
      loop variant M;
  */
  while (M > 15)''',1)
    return r'''
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#define LZVN_INLINE static
#define LZVN_ENCODE_MAX_DISTANCE 65535
#define LZVN_EMIT_BYTE(dst,b) (*(dst)++=(b))
/*@ requires \valid(q+(0 .. 1)); assigns q[0 .. 1]; */
void store2(uint8_t *q,uint16_t value);
/*@ requires \valid(q+(0 .. 3)); assigns q[0 .. 3]; */
void store4(uint8_t *q,uint32_t value);
/*@ requires \valid_read(p+(0 .. 3)); assigns \nothing; */
uint32_t load4(const uint8_t *p);
/*@ requires 0<=n<=PTRDIFF_MAX-7;
    requires \valid(dst+(0 .. n+6));
    requires \valid_read(src+(0 .. n+6));
    requires \separated(dst+(0 .. n+6),src+(0 .. n+6));
    assigns dst[0 .. n+6],\result \from dst,src[0 .. n+6],n;
    ensures \result==dst+n;
*/
uint8_t *lzvn_copy64(uint8_t *dst,const uint8_t *src,size_t n);
/*@ requires 0<=L<=PTRDIFF_MAX-8;
    requires M>=3;
    requires 1<=D<=LZVN_ENCODE_MAX_DISTANCE;
    requires \base_addr(q)==\base_addr(q1);
    requires 0<=q1-q<=PTRDIFF_MAX;
    requires \valid(q+(0 .. q1-q-1));
    requires \valid_read(p+(0 .. L+7));
    requires \separated(q+(0 .. q1-q-1),p+(0 .. L+7));
    assigns q[0 .. q1-q-1],\result \from q,q1,L,M,D,D_prev,p[0 .. L+7];
    ensures \base_addr(\result)==\base_addr(q);
    ensures 0<=\result-q<=q1-q;
    ensures \result==q1 || q<\result;
*/
''' + body


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[3]
    source=(root/'crates/crushlzfse/csrc/lzvn_encode_base.c').read_text()
    header=(root/'crates/crushlzfse/csrc/lzvn_encode_base.h').read_text()
    assert re.search(r'#define LZVN_ENCODE_MAX_DISTANCE\s*\\\s*0xffff',header), 'shipping distance limit changed'
    output=root/'harness/build/proofs-frama-lzvn-match'
    output.mkdir(parents=True,exist_ok=True)
    verify('match',generate(source),output,['emit'],1819,split=True)
    if args.mutants:
        a=source.index('LZVN_INLINE unsigned char *emit(')
        b=source.index('static inline int32_t offset_to_s32',a)
        for name,old,new in [
            ('match_no_capacity','if ((size_t)(q1 - q) <= 8)','if (0)'),
            ('match_no_progress','M -= x;','M -= 0;'),
        ]:
            piece=source[a:b]
            assert old in piece
            mutant=source[:a]+piece.replace(old,new)+source[b:]
            verify(name,generate(mutant),output,['emit'],50,False,
                   split=True)


if __name__=='__main__':
    main()
