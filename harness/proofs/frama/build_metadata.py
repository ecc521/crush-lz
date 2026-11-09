#!/usr/bin/env python3
"""Compose the actual ordinary metadata caller from verified helper contracts.

This proves caller safety, cursor accounting and failure handling under explicit
initialized-field and output-domain requirements. Strategy and API callers must
still establish those requirements. No whole-encoder completion is implied.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
import metadata_bounds,trailing_table
from wp_common import verify,DOMAIN


def generate(source):
    prefix=source[:source.index('static int zbm_bmprot(')]
    models=r'''
    /*@ predicate proof_table_ok{L}(uint8_t *tbl)=
     \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS ==> tbl[k]<=14;
     predicate live_counts{L}(zbm_usecnt_t *counts)=
     \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS && k%4==3 ==> counts[k]==0;
    */
    /* Verified top_values.py actual selector contract. */
    /*@ requires \valid(state);
     requires live_counts(&state->usecnts[0]);
     assigns state->top_bitmaps[0 .. ZBM_BITMAP_COUNT-1],state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1];
     ensures \forall integer k; 0<=k<ZBM_BITMAP_COUNT ==> state->top_bitmaps[k].period_bytecnt<=2;
     ensures live_counts(&state->usecnts[0]);
    */
    void zbm_find_most_common_bitmaps(struct zbm_compress_state *state);
    /* Registered query-independent zbm_encoder_number_table consequence. */
    /*@ requires \valid(state);
     requires \forall integer k; 0<=k<ZBM_BITMAP_COUNT ==> state->top_bitmaps[k].period_bytecnt<=2;
     assigns state->bmap_num_tbl[0 .. ZBM_POSSIBLE_BMPROTS-1];
     ensures proof_table_ok(&state->bmap_num_tbl[0]);
    */
    void zbm_build_bmap_num_table(struct zbm_compress_state *state);
    '''
    for name,function in [('period','zbm_write_metadata_1'),('bitmap','zbm_write_metadata_2'),('fused','zbm_write_metadata_12'),('selector','zbm_write_metadata_3')]:
     text,_,_=metadata_bounds.generate(source,name)
     pos=text.index('static int '+function+'(');a=text.rfind('/*@',0,pos)
     end=text.index('\n',pos)
     models+=text[a:pos]+text[pos:end].replace('static int ','int ',1)+';\n'
    text=trailing_table.generate(source)
    pos=text.index('static int zbm_write_trailing_bitmaps(')
    start=text.rfind('/*@',0,pos);end=text.index('\n',pos)
    models+=text[start:pos]+text[pos:end].replace('static int ','int ',1)+';\n'
    a=source.index('static struct uint24 zbm_u32_to_u24(');b=source.index('struct top_bmap',a)
    models+=r'/*@ assigns \nothing; */'+'\n'+source[a:b]
    span=r'''\separated(&state->dest,&state->dest_end,&state->written,&state->bmp_cnt,
     state->bitmaps+(0 .. ZBM_MAX_BITMAP_COUNT-1),state->periods+(0 .. ZBM_MAX_BITMAP_COUNT-1),
     state->usecnts+(0 .. ZBM_POSSIBLE_BMPROTS-1),state->top_bitmaps+(0 .. ZBM_BITMAP_COUNT-1),
     state->bmap_num_tbl+(0 .. ZBM_POSSIBLE_BMPROTS-1),state->bmap_nums+(0 .. ZBM_MAX_BITMAP_COUNT+15),
     state->run_bnd+(0 .. 64),state->run_long+(0 .. 64),
     state->dest+(0 .. state->dest_end-state->dest-1))'''
    contract=r'''
    /*@ requires \valid(state) && \valid(hdr);
     requires \valid(state->dest) || \valid(state->dest-1);
     requires \base_addr(state->dest)==\base_addr(state->dest_end);
     requires 0<=state->dest_end-state->dest<=0x1000000000000;
     requires \valid(state->dest+(0 .. state->dest_end-state->dest-1));
     requires '''+DOMAIN+r''';
     requires '''+span+r''';
     requires \separated(state,hdr);
     requires \separated(hdr,state->dest+(0 .. state->dest_end-state->dest-1));
     requires 0<=state->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
     requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     requires live_counts(&state->usecnts[0]);
     requires state->written<=UINT32_MAX-4*state->bmp_cnt-ZBM_BITMAP_BYTECNT;
     assigns state->dest,state->written,state->dest[0 .. state->dest_end-state->dest-1],
     state->top_bitmaps[0 .. ZBM_BITMAP_COUNT-1],state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1],
     state->bmap_num_tbl[0 .. ZBM_POSSIBLE_BMPROTS-1],state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT+15],
     state->run_bnd[0 .. 64],state->run_long[0 .. 64],hdr->meta_off_1,hdr->meta_off_2,hdr->meta_off_3;
     ensures \result==0 || \result==ZBM_CANT_COMPRESS;
     ensures state->written==\old(state->written)+(state->dest-\old(state->dest));
     ensures 0<=state->dest_end-state->dest;
     ensures 0<=state->dest-\old(state->dest)<=4*state->bmp_cnt+ZBM_BITMAP_BYTECNT;
    */
    '''
    a=source.index('static int zbm_build_metadata(');b=source.index('/*\n * Exact nibble count',a)
    g=prefix+models+contract+source[a:b]
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-build-metadata')
    output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_u32_to_u24','zbm_build_metadata']
    verify('build_metadata',generate(source),output,functions,267,split=True)
    if args.mutants:
        a=source.index('static int zbm_build_metadata(')
        b=source.index('/*\n * Exact nibble count',a)
        body=source[a:b]
        variants=[('missing_bitmap_writer','err = zbm_write_metadata_2(state);','err = 0;'),
                  ('extra_written_byte','    return zbm_write_trailing_bitmaps(state);',
                   '    state->written++;\n    return zbm_write_trailing_bitmaps(state);')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed),output,functions,200,False,split=True)


if __name__=='__main__':
    main()
