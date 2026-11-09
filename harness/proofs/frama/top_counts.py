#!/usr/bin/env python3
"""Actual top selector's count effects for fast metadata reservation composition.

Standard memmove values/footprints and independently checked quotient/remainder
arithmetic are dependencies. Counts only become zero or retain their old value;
counts for keys absent from the resulting top table remain unchanged.
Initialized counts and zero reserved-key counts remain caller requirements.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
import top_values
from wp_common import verify


def generate(source):
    g=top_values.generate(source)
    old=r'     ensures (uint8_t)(k&3)==(k&3);'
    new=old+r'''
     ensures (k>>2)==k/4;
     ensures 0<=(k>>2)<=255;
     ensures (uint8_t)(k>>2)==(k>>2);
     ensures 4*(uint8_t)(k>>2)+(uint8_t)(k&3)==k;
    '''
    assert g.count(old)==1;g=g.replace(old,new)
    pos=g.index('static void zbm_find_most_common_bitmaps(');a=g.rfind('/*@',0,pos)
    contract=g[a:pos]
    contract=contract.replace('*/',r'''
     ensures \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[k]<=\old(state->usecnts[k]);
     ensures \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[k]==0 || state->usecnts[k]==\old(state->usecnts[k]);
     ensures \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS && !in_tops(&state->top_bitmaps[0],ZBM_BITMAP_COUNT,k) ==> state->usecnts[k]==\old(state->usecnts[k]);
    */''')
    g=g[:a]+contract+g[pos:]
    pos=g.index('    /*@ predicate top_key(')
    g=g[:pos]+r'''
    /*@ predicate in_tops{L}(struct zbm_bmap *top,integer count,integer key)=
     \exists integer j; 0<=j<count && 4*top[j].bitmap+top[j].period_bytecnt==key;
    */
    '''+g[pos:]
    old=r'     loop invariant \forall integer j; 0<=j<i ==> state->top_bitmaps[j].period_bytecnt<=2;'
    new=old+r'''
     loop invariant \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[k]<=\at(state->usecnts[k],Pre);
     loop invariant \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[k]==0 || state->usecnts[k]==\at(state->usecnts[k],Pre);
     loop invariant \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS && !in_tops(&state->top_bitmaps[0],i,k) ==> state->usecnts[k]==\at(state->usecnts[k],Pre);
    '''
    assert g.count(old)==1;g=g.replace(old,new)
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-top-counts');output.mkdir(parents=True,exist_ok=True)
    functions=['proof_count_key','zbm_find_most_common_bitmaps']
    verify('top_counts',generate(source),output,functions,178,split=True)
    if args.mutants:
        a=source.index('static void zbm_find_most_common_bitmaps(')
        b=source.index('/* Total bytes of the first metadata area',a)
        body=source[a:b]
        variants=[('wrong_cleared_key','state->usecnts[tops[i].bmprot] = 0;',
                   'state->usecnts[tops[i].bmprot ^ 4] = 0;'),
                  ('wrong_top_bitmap','(uint8_t)(tops[i].bmprot >> 2);',
                   '(uint8_t)(tops[i].bmprot >> 3);')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed),output,functions,178,False,split=True)


if __name__=='__main__':
    main()
