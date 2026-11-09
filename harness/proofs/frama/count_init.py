#!/usr/bin/env python3
"""Actual row reset and fast count-fold fragments, including reserved-key shape.

Standard memset zero semantics are trusted. Registered count-fold arithmetic
supplies the exact unsigned expression. Fast key counts are an initialized,
bounded caller input; the fast search loops remain outside this component.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
from wp_common import verify


def generate(source):
    
    prefix=source[:source.index('static int zbm_bmprot(')]
    
    a=source.index('static long zbm_decide_chunk_row(')
    b=source.index('    zbm_row_prepare_index(state, chunk_start);',a)
    body=source[source.index('{',a)+1:b]
    models=r'''
    /* Standard memset zeroes every byte of the unsigned count array. */
    /*@ requires value==0;
     requires n==ZBM_POSSIBLE_BMPROTS*sizeof(*d);
     requires \valid(d+(0 .. ZBM_POSSIBLE_BMPROTS-1));
     assigns d[0 .. ZBM_POSSIBLE_BMPROTS-1];
     ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> d[q]==0;
    */
    void proof_zero_counts(zbm_usecnt_t *d,int value,size_t n);
    #define memset(d,v,n) proof_zero_counts(d,v,n)
    /*@ requires \valid(state);
     assigns state->src \from chunk_src;
     assigns state->read,state->period,state->bmp_cnt,state->row_mru,state->row_mru2,state->row_next_diff,state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1];
     ensures state->src==chunk_src;
     ensures state->read==0 && state->period==8 && state->bmp_cnt==0;
     ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]==0;
    */
    static void proof_row_init(struct zbm_compress_state *state,const uint8_t *chunk_src)
    {
    '''
    g=prefix+models+body+'}\n'
    row=g
    a=source.index('static int zbm_build_metadata_fast(')
    x=source.index('    memset(state->usecnts, 0, sizeof(state->usecnts));',a)
    y=source.index('    zbm_find_most_common_bitmaps(state);',x)
    body=source[x:y]
    models=models[:models.index('/*@ requires \\valid(state);')]+r'''
    /* Registered zbm_encoder_count_fold checks this exact unsigned expression. */
    /*@ requires key<(3u<<8);
     assigns \nothing;
     ensures \result==((unsigned)((key&0xffu)<<2) | key>>8);
     ensures \result<ZBM_POSSIBLE_BMPROTS;
     ensures \result%4<=2;
     ensures 0<=(key&0xffu)<=255;
     ensures 0<=((key&0xffu)<<2)<=1020;
     ensures (key>>8)==key/256;
     ensures ((unsigned)((key&0xffu)<<2) | key>>8)==4*(key%256)+key/256;
     ensures ((unsigned)((key&0xffu)<<2) | key>>8)<ZBM_POSSIBLE_BMPROTS;
     ensures ((unsigned)((key&0xffu)<<2) | key>>8)%4<=2;
    */
    unsigned proof_fold_index(unsigned key);
    /*@ requires \valid(state);
     requires 0<=state->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
     requires \forall integer q; 0<=q<(3u<<8) ==> state->key_usecnts[q]<=state->bmp_cnt;
     assigns state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1];
     ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]<=state->bmp_cnt;
     ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> state->usecnts[q]==0;
    */
    static void proof_fast_count_fold(struct zbm_compress_state *state)
    {
     unsigned key;
    '''
    old='    for(key = 0; key < (3u << 8); ++key)'
    assert body.count(old)==1
    body=body.replace(old,r'''    /*@ loop invariant 0<=key<=(3u<<8);
     loop invariant \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]<=state->bmp_cnt;
     loop invariant \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> state->usecnts[q]==0;
     loop assigns key,state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1];
     loop variant (3u<<8)-key;
     */
    '''+old+' {\n        unsigned proof_index=proof_fold_index(key);\n        (void)proof_index;')
    body+='    }\n'
    g=prefix+models+body+'}\n'
    return {'row':(row,['proof_row_init'],32),'fast':(g,['proof_fast_count_fold'],33)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-count-init')
    output.mkdir(parents=True,exist_ok=True)
    def prove(name,text,tag,expected=True):
        g,functions,minimum=generate(text)[name]
        verify(tag,g,output,functions,minimum if expected or name=='fast' else 20,expected,split=True)
    prove('row',source,'row_count_init')
    prove('fast',source,'fast_count_fold')
    if args.mutants:
        a=source.index('static long zbm_decide_chunk_row(')
        b=source.index('    zbm_row_prepare_index(state, chunk_start);',a)
        body=source[a:b]
        old='memset(state->usecnts, 0, sizeof(state->usecnts));'
        assert body.count(old)==1
        bad=source[:a]+body.replace(old,'(void)state;')+source[b:]
        prove('row',bad,'missing_count_reset',False)
        a=source.index('static int zbm_build_metadata_fast(')
        b=source.index('    zbm_find_most_common_bitmaps(state);',a)
        body=source[a:b]
        variants=[
            ('reserved_fold_count','state->usecnts[(key & 0xffu) << 2 | key >> 8]','state->usecnts[((key & 0xffu) << 2 | key >> 8) | 3]'),
            ('key_count_overread','state->key_usecnts[key];','state->key_usecnts[key + 1];'),
        ]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            bad=source[:a]+body.replace(old,new)+source[b:]
            prove('fast',bad,tag,False)


if __name__=='__main__':
    main()
