#!/usr/bin/env python3
"""Actual block-commit safety, period shape, counts and run bounds.

Caller prerequisites include initialized fields, a remaining bitmap slot and
separated state/run pointers. Registered pair-key arithmetic supplies the
bounded int32 expression; full strategy callers remain outside scope.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
from wp_common import verify


def generate(source):
    
    a=source.index('static void zbm_commit_block_pbc(')
    b=source.index('static void zbm_commit_block(',a)
    model=r'''
    /* Registered pair-key arithmetic: the same int32 expression and domain. */
    /*@ requires 0<=pbc<=2;
     assigns \nothing;
     ensures 0<=((int)bitmap<<2)<=1020;
     ensures ((int)bitmap<<2 | pbc)==4*bitmap+pbc;
     ensures 0<=((int)bitmap<<2 | pbc)<ZBM_POSSIBLE_BMPROTS;
     ensures ((int)bitmap<<2 | pbc)%4==pbc;
    */
    void proof_pair_parts(uint8_t bitmap,int pbc);
    /*@ requires \valid(state) && \valid(run_bmprot) && \valid(run_len);
     requires \separated(state,run_bmprot,run_len);
     requires 0<=state->bmp_cnt<ZBM_MAX_BITMAP_COUNT;
     requires period>=8;
     requires 0<=period_bytecnt<=2;
     requires 0<=*run_len<=state->bmp_cnt;
     requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]<=state->bmp_cnt;
     requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> state->usecnts[q]==0;
     assigns state->bitmaps[state->bmp_cnt],state->periods[state->bmp_cnt],state->bmp_cnt,state->period,state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1],*run_bmprot,*run_len;
     ensures state->bmp_cnt==\old(state->bmp_cnt)+1;
     ensures state->period==period;
     ensures *run_bmprot==4*bitmap+period_bytecnt;
     ensures 1<=*run_len<=state->bmp_cnt;
     ensures \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]<=state->bmp_cnt;
     ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> state->usecnts[q]==0;
    */
    '''
    body=source[a:b]
    old='    int bmprot = (int)bitmap << 2 | period_bytecnt;'
    assert body.count(old)==1
    body=body.replace(old,'    proof_pair_parts(bitmap,period_bytecnt);\n'+old)
    prefix=source[:a]
    old='static int zbm_period_bytecnt_for(uint16_t period, uint16_t current_period)'
    assert prefix.count(old)==1
    prefix=prefix.replace(old,r'/*@ assigns \nothing; ensures 0<=\result<=2; */ '+old)
    wrappercontract=model[model.index('/*@ requires \\valid(state)'):]
    wrappercontract=wrappercontract.replace(' requires 0<=period_bytecnt<=2;\n','')
    wrappercontract=wrappercontract.replace(' ensures *run_bmprot==4*bitmap+period_bytecnt;', ' ensures 0<=*run_bmprot<ZBM_POSSIBLE_BMPROTS;')
    c=source.index('/* The candidate loop',b)
    g=prefix+model+body+wrappercontract+source[b:c]
    old='static int zbm_nibble_cost_for_run(int r);'
    assert g.count(old)==1
    g=g.replace(old,r'/*@ requires 0<=r<=ZBM_MAX_BITMAP_COUNT; assigns \nothing; ensures 0<=\result<=r; */ '+old)
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-commit-block')
    output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_period_bytecnt_for','zbm_commit_block_pbc','zbm_commit_block']
    verify('commit_block',generate(source),output,functions,104,split=True)
    if args.mutants:
        a=source.index('static void zbm_commit_block_pbc(')
        b=source.index('static void zbm_commit_block(',a)
        body=source[a:b]
        variants=[
            ('bitmap_overrun','&state->bitmaps[state->bmp_cnt];','&state->bitmaps[state->bmp_cnt + 1];'),
            ('run_overrun','++*run_len;','*run_len += 2;'),
        ]
        for name,old,new in variants:
            assert body.count(old)==1, 'mutation site changed'
            bad=source[:a]+body.replace(old,new)+source[b:]
            verify(name,generate(bad),output,functions,104,False,split=True)
        old='return ne * (1 + wide);'
        assert source.count(old)==1
        verify('reserved_period',generate(source.replace(old,'return ne * (2 + wide);')),output,functions,104,False,split=True)


if __name__=='__main__':
    main()
