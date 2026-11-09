#!/usr/bin/env python3
"""Full-domain shipping literal emitter; copy8 is independently checked by CBMC.

The production emitter body is extracted unchanged. Internal store2 uses the
standard two-byte memcpy footprint; its value is never read by the encoder.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source):
    a = source.index('LZVN_INLINE unsigned char *emit_literal(')
    b = source.index('// ===============================================================', a)
    body = source[a:b]
    body = body.replace('  size_t x;', '''  size_t x;
  unsigned char *const q_base=q;
  const unsigned char *const p_base=p;
  const size_t original_L=L;''', 1)
    body = body.replace('  while (L > 15)', r'''
  /*@ loop invariant 0<=L<=original_L;
      loop invariant p==p_base+(original_L-L);
      loop invariant \base_addr(q)==\base_addr(q_base);
      loop invariant 0<=q-q_base<=q1-q_base;
      loop invariant original_L==L || q-q_base>0;
      loop invariant original_L==L ==> q==q_base;
      loop assigns L,x,p,q,q_base[0 .. q1-q_base-1];
      loop variant L;
  */
  while (L > 15)''', 1)
    return r'''
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#define LZVN_INLINE static
#define LZVN_EMIT_BYTE(dst,b) (*(dst)++=(b))
/*@ requires \valid(q+(0 .. 1)); assigns q[0 .. 1]; */
void store2(uint8_t *q,uint16_t value);
/*@ requires \valid(dst+(0 .. n-1));
    requires \valid_read(src+(0 .. n-1));
    requires \separated(dst+(0 .. n-1),src+(0 .. n-1));
    assigns dst[0 .. n-1],\result \from dst,src[0 .. n-1],n;
    ensures \result==dst+n;
*/
uint8_t *lzvn_copy8(uint8_t *dst,const uint8_t *src,size_t n);
/*@ requires 0<=L<=PTRDIFF_MAX;
    requires \base_addr(q)==\base_addr(q1);
    requires 0<=q1-q<=PTRDIFF_MAX;
    requires \valid(q+(0 .. q1-q-1));
    requires \valid_read(p+(0 .. L-1));
    requires \separated(q+(0 .. q1-q-1),p+(0 .. L-1));
    assigns q[0 .. q1-q-1],\result \from q,q1,L,p[0 .. L-1];
    ensures \base_addr(\result)==\base_addr(q);
    ensures 0<=\result-q<=q1-q;
    ensures \result==q1 || (L==0 ? \result==q : q<\result);
*/
''' + body


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[3]
    source=(root/'crates/crushlzfse/csrc/lzvn_encode_base.c').read_text()
    output=root/'harness/build/proofs-frama-lzvn-literal'
    output.mkdir(parents=True,exist_ok=True)
    verify('literal',generate(source),output,['emit_literal'],122,split=True)
    if args.mutants:
        for name,old,new in [
            ('literal_no_capacity','if ((size_t)(q1 - q) <= L + 10)','if (0)'),
            ('literal_no_progress','L -= x;','L -= 0;'),
        ]:
            a=source.index('LZVN_INLINE unsigned char *emit_literal(')
            b=source.index('// ===============================================================',a)
            piece=source[a:b]
            assert piece.count(old)==1
            mutant=source[:a]+piece.replace(old,new)+source[b:]
            verify(name,generate(mutant),output,['emit_literal'],20,False,
                   split=True)


if __name__=='__main__':
    main()
