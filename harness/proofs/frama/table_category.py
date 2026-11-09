#!/usr/bin/env python3
"""Actual selector table's top/explicit category for an arbitrary supported key.

Query affects no stores, so the postcondition lifts to all supported keys.
Pair-key, byte-key and default-selector arithmetic are registered CBMC
prerequisites. Inputs have initialized top/count fields and period counts<=2.
This does not assume that the caller's counts are a bitmap histogram.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
from wp_common import verify


def generate(source):
    a=source.index('static void zbm_build_bmap_num_table(');b=source.index('/* Resolve every block',a)
    prefix=source[:source.index('static int zbm_bmprot(')]
    models=r'''
    /*@ predicate selected_suffix{L}(struct zbm_compress_state *state,integer first,integer query)=
     \exists integer j; first<=j<ZBM_BITMAP_COUNT &&
     state->top_bitmaps[j].bitmap+256*state->top_bitmaps[j].period_bytecnt==query &&
     state->usecnts[4*state->top_bitmaps[j].bitmap+state->top_bitmaps[j].period_bytecnt]==0;
    */
    /* Independently checked registered zbm_encoder_table_defaults arithmetic. */
    /*@ requires key<ZBM_POSSIBLE_BMPROTS; assigns \nothing;
     ensures (uint8_t)(key>>8)==key/256;
     ensures 0<=(uint8_t)(key>>8)<=3;
    */
    void proof_default_key(unsigned key);
    /* Registered zbm_encoder_bmprot and zbm_encoder_key exact arithmetic. */
    /*@ requires \valid_read(bmap); requires bmap->period_bytecnt<=2;
     assigns \nothing;
     ensures 0<=\result<ZBM_POSSIBLE_BMPROTS;
     ensures \result==4*bmap->bitmap+bmap->period_bytecnt;
    */
    int proof_pair_key(struct zbm_bmap *bmap);
    /*@ requires \valid_read(bmap); requires bmap->period_bytecnt<=2;
     assigns \nothing;
     ensures \result==bmap->bitmap+256*bmap->period_bytecnt;
     ensures \result<(3u<<8);
    */
    unsigned proof_bmap_key(const struct zbm_bmap *bmap);
    #define zbm_bmprot(p) proof_pair_key(p)
    #define zbm_bmkey(p) proof_bmap_key(p)
    /*@ requires \valid(state);
     requires query<(3u<<8);
     requires \forall integer j; 0<=j<ZBM_BITMAP_COUNT ==> state->top_bitmaps[j].period_bytecnt<=2;
     assigns state->bmap_num_tbl[0 .. ZBM_POSSIBLE_BMPROTS-1];
     ensures state->bmap_num_tbl[query]<=14;
     ensures (state->bmap_num_tbl[query]>=ZBM_BITMAP_BASE) <==> selected_suffix(state,0,query);
    */
    '''
    body=source[a:b].replace('zbm_build_bmap_num_table(struct zbm_compress_state *state)', 'zbm_build_bmap_num_table(struct zbm_compress_state *state,unsigned query)')
    body=body.replace('    unsigned key;','    (void)query;\n    unsigned key;',1)
    old='    for(key = 0; key < ZBM_POSSIBLE_BMPROTS; ++key)';assert body.count(old)==1
    body=body.replace(old,r'''    /*@ loop invariant 0<=key<=ZBM_POSSIBLE_BMPROTS;
     loop invariant query<key ==> state->bmap_num_tbl[query]==query/256;
     loop assigns key,state->bmap_num_tbl[0 .. ZBM_POSSIBLE_BMPROTS-1];
     loop variant ZBM_POSSIBLE_BMPROTS-key;
     */
    '''+old)
    old=next(line for line in body.splitlines() if line.startswith('        state->bmap_num_tbl[key] ='));assert body.count(old)==1
    body=body.replace(old,'    {\n        proof_default_key(key);\n'+old+'\n    }')
    old='    for(i = ZBM_BITMAP_COUNT - 1; i >= 0; --i)';assert body.count(old)==1
    body=body.replace(old,r'''    /*@ loop invariant -1<=i<ZBM_BITMAP_COUNT;
     loop invariant state->bmap_num_tbl[query]<=14;
     loop invariant (state->bmap_num_tbl[query]>=ZBM_BITMAP_BASE) <==> selected_suffix(state,i+1,query);
     loop assigns i,bmprot,state->bmap_num_tbl[0 .. ZBM_POSSIBLE_BMPROTS-1];
     loop variant i+1;
     */
    '''+old)
    g=prefix+models+body
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-table-category');output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_build_bmap_num_table']
    verify('table_category',generate(source),output,functions,65,split=True)
    if args.mutants:
        a=source.index('static void zbm_build_bmap_num_table(')
        b=source.index('/* Resolve every block',a)
        body=source[a:b]
        variants=[('missing_top_overwrite','if(state->usecnts[bmprot] == 0)','if(0)'),
                  ('wrong_default_category','(uint8_t)(key >> 8);','(uint8_t)(key >> 7);')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed),output,functions,40,False,split=True)


if __name__=='__main__':
    main()
