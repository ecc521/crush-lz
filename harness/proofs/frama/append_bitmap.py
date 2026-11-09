#!/usr/bin/env python3
"""Actual bitmap append safety and count/period-shape preservation.

Initialized active bitmap/count fields, valid state, period>=8 and remaining
slot capacity are caller prerequisites. Full strategy initialization remains
outside this component. Pair-key arithmetic is proved by zbm_encoder_bmprot.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
from wp_common import verify


def generate(source):
    
    a=source.index('static void zbm_append_new_bitmap(')
    b=source.index('/*\n * The encoder\'s period floor',a)
    prefix=source[:a]
    model=r'''
    /* Exact shipping zbm_bmprot consequence: registered CBMC zbm_encoder_bmprot. */
    /*@ requires \valid_read(bmap);
     requires bmap->period_bytecnt<=2;
     assigns \nothing;
     ensures 0<=\result<ZBM_POSSIBLE_BMPROTS;
     ensures \result==4*bmap->bitmap+bmap->period_bytecnt;
     ensures \result%4==bmap->period_bytecnt;
    */
    int proof_pair_key(struct zbm_bmap *bmap);
    #define zbm_bmprot(p) proof_pair_key(p)
    /*@ requires \valid(state);
     requires 0<=state->bmp_cnt<ZBM_MAX_BITMAP_COUNT;
     requires period>=8;
     requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]<=state->bmp_cnt;
     requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> state->usecnts[q]==0;
     assigns state->bitmaps[state->bmp_cnt],state->periods[state->bmp_cnt],state->bmp_cnt,state->period,state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1];
     ensures state->bmp_cnt==\old(state->bmp_cnt)+1;
     ensures state->period==period;
     ensures \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]<=state->bmp_cnt;
     ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> state->usecnts[q]==0;
    */
    '''
    g=prefix+model+source[a:b]
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-append-bitmap')
    output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_append_new_bitmap']
    verify('append_bitmap',generate(source),output,functions,88,split=True)
    if args.mutants:
        variants=[
            ('bitmap_overrun','new_bmp = &state->bitmaps[state->bmp_cnt];','new_bmp = &state->bitmaps[state->bmp_cnt + 1];'),
            ('reserved_period','new_bmp->period_bytecnt = 2;','new_bmp->period_bytecnt = 3;'),
            ('reserved_count','++state->usecnts[zbm_bmprot(new_bmp)];','++state->usecnts[zbm_bmprot(new_bmp) | 3];'),
        ]
        a=source.index('static void zbm_append_new_bitmap(')
        b=source.index('/*\n * The encoder\'s period floor',a)
        body=source[a:b]
        for name,old,new in variants:
            assert body.count(old)==1, 'mutation site changed'
            bad=source[:a]+body.replace(old,new)+source[b:]
            verify(name,generate(bad),output,functions,88,False,split=True)


if __name__=='__main__':
    main()
