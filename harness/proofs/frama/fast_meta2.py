#!/usr/bin/env python3
"""Portable fast metadata-2 writer with an explicit selector-count prefix.

Native vector paths are excluded by CRUSH_SIMD_PORTABLE. The supplied prefix
is a caller requirement for the writer; its analysis-only construction is
verified and composed with the writer in this target. The read-only query
changes no codec stores; its selector result lifts to all active blocks.
Producer histogram consistency remains open. Pair-key arithmetic is the
registered CBMC dependency.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
from wp_common import verify


def generate(source):
    a=source.index('static uint8_t *zbm_fast_nums_meta2(')
    b=source.index('/* Areas 1 and 2',a)
    body=source[a:b]
    prefix=source[:source.index('static int zbm_bmprot(')]
    models=r"""
    /* Registered zbm_encoder_key exact arithmetic. */
    /*@ requires \valid_read(bmap); requires bmap->period_bytecnt<=2;
     assigns \nothing;
     ensures \result==bmap->bitmap+256*bmap->period_bytecnt;
     ensures \result<768;
    */
    unsigned proof_bmap_key(const struct zbm_bmap *bmap);
    #define zbm_bmkey(p) proof_bmap_key(p)
    /*@ requires \valid(state);
     requires 0<=state->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
     requires query<=state->bmp_cnt;
     requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     requires \forall integer q; 0<=q<768 ==> state->bmap_num_tbl[q]<=14;
     requires \valid_read(prefix+(0 .. state->bmp_cnt));
     requires prefix[0]==0;
     requires \forall integer q; 0<=q<=state->bmp_cnt ==> prefix[q]<=q && prefix[q]<=prefix[state->bmp_cnt];
     requires \forall integer q; 0<=q<state->bmp_cnt ==> prefix[q+1]==prefix[q]+(state->bmap_num_tbl[state->bitmaps[q].bitmap+256*state->bitmaps[q].period_bytecnt]<3 ? 1 : 0);
     requires \valid(d2+(0 .. prefix[state->bmp_cnt]));
     requires \separated(state,prefix+(0 .. state->bmp_cnt));
     requires \separated(&state->bmp_cnt,state->bitmaps+(0 .. ZBM_MAX_BITMAP_COUNT-1),state->bmap_num_tbl+(0 .. ZBM_POSSIBLE_BMPROTS-1),state->bmap_nums+(0 .. ZBM_MAX_BITMAP_COUNT+15),prefix+(0 .. state->bmp_cnt),d2+(0 .. prefix[state->bmp_cnt]));
     assigns \result \from d2,state,*state,prefix,prefix[0 .. state->bmp_cnt];
     assigns state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT+15],d2[0 .. prefix[state->bmp_cnt]];
     ensures \base_addr(\result)==\base_addr(d2);
     ensures \result==d2+prefix[state->bmp_cnt];
     ensures query<state->bmp_cnt ==> state->bmap_nums[query]==state->bmap_num_tbl[state->bitmaps[query].bitmap+256*state->bitmaps[query].period_bytecnt];
    */
    """
    old='zbm_fast_nums_meta2(struct zbm_compress_state *state, uint8_t *d2)'
    assert body.count(old)==1
    body=body.replace(old,old[:-1]+',const unsigned *prefix,unsigned query)')
    old='    int i = 0, t;';assert body.count(old)==1
    body=body.replace(old,old+'\n    uint8_t *start=d2;\n    unsigned query_key=query<cnt ? bmaps[query].bitmap+256u*bmaps[query].period_bytecnt : 0;\n    unsigned query_num=tbl[query_key];')
    old='    for(; i < cnt; ++i) {';assert body.count(old)==1
    body=body.replace(old,r"""    /*@ loop invariant 0<=i<=cnt;
     loop invariant d2==start+prefix[i];
     loop invariant \forall integer q; 0<=q<768 ==> tbl[q]<=14;
     loop invariant query<i ==> nums[query]==query_num;
     loop invariant query_num==tbl[query_key];
     loop invariant query<cnt ==> query_key==bmaps[query].bitmap+256*bmaps[query].period_bytecnt;
     loop assigns i,d2,state->bmap_nums[0 .. i-1],start[0 .. prefix[cnt]];
     loop variant cnt-i;
    */
    """+old)
    old='unsigned num = tbl[zbm_bmkey(&bmaps[i])];';assert body.count(old)==1
    body=body.replace(old,r"""unsigned proof_key=zbm_bmkey(&bmaps[i]);
        /*@ assert proof_key<ZBM_POSSIBLE_BMPROTS; */
        unsigned num = tbl[proof_key];
        /*@ assert num<=14; */
        /*@ assert num==tbl[bmaps[i].bitmap+256*bmaps[i].period_bytecnt]; */""")
    old=next(line.strip() for line in body.splitlines() if line.strip().startswith('nums[i] ='));assert body.count(old)==1
    body=body.replace(old,r"""/*@ assert 0<=i<ZBM_MAX_BITMAP_COUNT+16; */
        """+old)
    body=body.replace('        d2[0] = bmaps[i].bitmap;',r"""        /*@ assert nums[i]==tbl[bmaps[i].bitmap+256*bmaps[i].period_bytecnt]; */
        d2[0] = bmaps[i].bitmap;""")
    return prefix+models+body



def generate_prefix(source):
    g=source[:source.index('static int zbm_bmprot(')]+r"""
    /* Registered zbm_encoder_key exact arithmetic. */
    /*@ requires \valid_read(bmap); requires bmap->period_bytecnt<=2;
     assigns \nothing;
     ensures \result==bmap->bitmap+256*bmap->period_bytecnt;
     ensures \result<768;
    */
    unsigned proof_bmap_key(const struct zbm_bmap *bmap);
    /*@ requires \valid_read(state);
     requires 0<=state->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
     requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     requires \valid(prefix+(0 .. state->bmp_cnt));
     requires \separated(state,prefix+(0 .. state->bmp_cnt));
     assigns prefix[0 .. state->bmp_cnt];
     ensures prefix[0]==0;
     ensures \forall integer q; 0<=q<=state->bmp_cnt ==> prefix[q]<=q && prefix[q]<=prefix[state->bmp_cnt];
     ensures \forall integer q; 0<=q<state->bmp_cnt ==> prefix[q+1]==prefix[q]+(state->bmap_num_tbl[state->bitmaps[q].bitmap+256*state->bitmaps[q].period_bytecnt]<3 ? 1 : 0);
    */
    static void proof_fast_prefix(struct zbm_compress_state *state,unsigned *prefix)
    {
     unsigned q;
     prefix[0]=0;
     /*@ loop invariant 0<=q<=state->bmp_cnt;
     loop invariant prefix[0]==0;
     loop invariant \forall integer j; 0<=j<=q ==> prefix[j]<=j && prefix[j]<=prefix[q];
     loop invariant \forall integer j; 0<=j<q ==> prefix[j+1]==prefix[j]+(state->bmap_num_tbl[state->bitmaps[j].bitmap+256*state->bitmaps[j].period_bytecnt]<3 ? 1 : 0);
     loop assigns q,prefix[0 .. state->bmp_cnt];
     loop variant state->bmp_cnt-q;
     */
     for(q=0;q<(unsigned)state->bmp_cnt;++q) {
       unsigned key=proof_bmap_key(&state->bitmaps[q]);
       prefix[q+1]=prefix[q]+(state->bmap_num_tbl[key]<3);
     }
    }
    """
    return g


def generate_local(source):
    g=generate(source)
    pref=generate_prefix(source)
    pref=pref[pref.index('/*@ requires \\valid_read(state);'):]
    g+=pref+r"""
    /*@ requires \valid(state);
     requires 0<=state->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
     requires query<=state->bmp_cnt;
     requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     requires \forall integer q; 0<=q<768 ==> state->bmap_num_tbl[q]<=14;
     requires \valid(d2+(0 .. state->bmp_cnt));
     requires \separated(&state->bmp_cnt,state->bitmaps+(0 .. ZBM_MAX_BITMAP_COUNT-1),state->bmap_num_tbl+(0 .. ZBM_POSSIBLE_BMPROTS-1),state->bmap_nums+(0 .. ZBM_MAX_BITMAP_COUNT+15),d2+(0 .. state->bmp_cnt));
     assigns \result \from state,*state,d2,query;
     assigns state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT+15],d2[0 .. state->bmp_cnt];
     ensures \base_addr(\result)==\base_addr(d2);
     ensures 0<=\result-d2<=state->bmp_cnt;
     ensures query<state->bmp_cnt ==> state->bmap_nums[query]==state->bmap_num_tbl[state->bitmaps[query].bitmap+256*state->bitmaps[query].period_bytecnt];
    */
    static uint8_t *proof_fast_meta2_local(struct zbm_compress_state *state,uint8_t *d2,unsigned query)
    {
     unsigned prefix[ZBM_MAX_BITMAP_COUNT+1];
     proof_fast_prefix(state,prefix);
     return zbm_fast_nums_meta2(state,d2,prefix,query);
    }
    """
    return g


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-fast-meta2');output.mkdir(parents=True,exist_ok=True)
    verify('fast_meta2_local',generate_local(source),output,
           ['zbm_fast_nums_meta2','proof_fast_prefix','proof_fast_meta2_local'],181,split=True)
    functions=['zbm_fast_nums_meta2']
    if args.mutants:
        a=source.index('static uint8_t *zbm_fast_nums_meta2(')
        b=source.index('/* Areas 1 and 2',a)
        body=source[a:b]
        variants=[('extra_destination_advance','d2 += num < ZBM_BITMAP_BASE;','d2 += 1 + (num < ZBM_BITMAP_BASE);'),
                  ('wrong_selector','nums[i] = (uint8_t)num;','nums[i] = (uint8_t)(num + 1);')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed),output,functions,101,False,split=True)


if __name__=='__main__':
    main()
