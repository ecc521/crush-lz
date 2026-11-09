#!/usr/bin/env python3
"""Derive active selector ranges from valid tables in the shipping writers.

These targets retain the arbitrary-table memory safety domain and add a
conditional value contract. Library frame conclusions are derived from
byte_frame.py; standard memcpy/memmove footprint semantics remain trusted.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
import bitmap_metadata, fused_metadata
from wp_common import verify


def generate(source,name):
    assert name in ('bitmap','fused')
    g={'bitmap':bitmap_metadata,'fused':fused_metadata}[name].generate(source)
    # Retain arbitrary-table safety, conditionally derive active selector bounds.
    pos=g.index('static void zbm_build_bmap_nums(') if name=='bitmap' else g.index('static int zbm_write_metadata_12(')
    start=g.rfind('/*@',0,pos)
    logic=r'''/*@ predicate proof_table_ok{L}(uint8_t *tbl)=
     \forall integer k; 0 <= k < ZBM_POSSIBLE_BMPROTS ==> tbl[k]<=14;
    */
    '''
    g=g[:start]+logic+g[start:]
    if name=='bitmap':
     pos=g.index('static void zbm_build_bmap_nums(');start=g.rfind('/*@',0,pos)
     contract=g[start:pos]
     clause=r'''        ensures proof_table_ok(&state->bmap_num_tbl[0]) ==>
             (\forall integer q; 0 <= q < state->bmp_cnt ==> state->bmap_nums[q]<=14);
    '''
     contract=contract.replace('    */',clause+'    */')
     g=g[:start]+contract+g[pos:]
     g=g.replace('        /*@ loop invariant 0 <= i <= cnt;',r'''        /*@ loop invariant 0 <= i <= cnt;
                loop invariant proof_table_ok(&state->bmap_num_tbl[0]) ==>
                 (\forall integer q; 0 <= q < i ==> state->bmap_nums[q]<=14);''',1)
     g=g.replace('            /*@ loop invariant 0 <= i <= state->bmp_cnt;',r'''            /*@ loop invariant 0 <= i <= state->bmp_cnt;
                    loop invariant proof_table_ok(&state->bmap_num_tbl[0]) ==>
                     (\forall integer q; 0 <= q < i ==> state->bmap_nums[q]<=14);''',1)
     function='zbm_write_metadata_2'
     functions=['zbm_build_bmap_nums','proof_build_bitmap_prefix',function,'proof_trial_destination']
    else:
     function='zbm_write_metadata_12'
     functions=['proof_build_period_prefix','zbm_period_bytes_total','zbm_u32_to_u24',function,'proof_trial_destination']
     pos=g.index('static int '+function+'(')
     body=g[pos:]
     body=body.replace('        /*@ loop invariant 0 <= i <= cnt;',r'''        /*@ loop invariant 0 <= i <= cnt;
                loop invariant proof_table_ok(&state->bmap_num_tbl[0]) ==>
                 (\forall integer q; 0 <= q < i ==> state->bmap_nums[q]<=14);''',1)
     g=g[:pos]+body
    pos=g.index('static int '+function+'(');start=g.rfind('/*@',0,pos)
    contract=g[start:pos]
    condition='proof_table_ok(&state->bmap_num_tbl[0])' if name=='bitmap' else r'\result == 1 && proof_table_ok(&state->bmap_num_tbl[0])'
    contract=contract.replace('        ensures state->written',r'        ensures '+condition+r''' ==>
             (\forall integer q; 0 <= q < state->bmp_cnt ==> state->bmap_nums[q]<=14);
            ensures state->written''',1)
    g=g[:start]+contract+g[pos:]
    if name=="fused":
        for helper,macro in [('proof_period_memcpy','memcpy'),('proof_move_bytes','memmove')]:
         pos=g.index('    void '+helper+'(');start=g.rfind('/*@',0,pos)
         end=g.index('\n',g.index('    #define '+macro+'(',pos))+1
         old=g[start:end];contract=old[:old.index('    void '+helper+'(')]
         req=r'''        requires n <= ZBM_MAX_BITMAP_COUNT;
                requires \valid_read(nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));
                requires \valid_read(tbl+(0 .. ZBM_POSSIBLE_BMPROTS-1));
                requires \separated(nums+(0 .. ZBM_MAX_BITMAP_COUNT+15),tbl+(0 .. ZBM_POSSIBLE_BMPROTS-1),d+(0 .. n-1));
        '''
         post=r'''        ensures \forall integer q; 0<=q<=ZBM_MAX_BITMAP_COUNT+15 ==> nums[q]==\old(nums[q]);
                ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> tbl[q]==\old(tbl[q]);
        '''
         contract=contract.replace('        assigns ',req+'        assigns ',1).replace('    */',post+'    */')
         declaration=old[old.index('    void '+helper+'('):old.index('\n',old.index('    void '+helper+'('))]
         declaration=declaration.replace('size_t n);','size_t n,const uint8_t *nums,const uint8_t *tbl);')
         replacement=contract+declaration+'\n    #define '+macro+'(d, src, n) '+helper+'(d, src, n, state->bmap_nums,state->bmap_num_tbl)\n'
         g=g[:start]+replacement+g[end:]
        pos=g.index('static int zbm_write_metadata_12(')
        body=g[pos:]
        old='        /*@ loop invariant 0 <= i <= cnt;'
        assert body.count(old)==1
        body=body.replace(old,old+r'''
                    loop invariant \separated(nums+(0 .. ZBM_MAX_BITMAP_COUNT+15),tbl+(0 .. ZBM_POSSIBLE_BMPROTS-1),d0+(0 .. room-1));
        ''',1)
        # Checked intermediate properties identify and factor the final frame step.
        statement=r'/*@ assert proof_table_ok(&state->bmap_num_tbl[0]) ==> (\forall integer q; 0<=q<cnt ==> state->bmap_nums[q]<=14); */'
        for anchor in ['    len2 = d2 - area2;',
                       '    hdr->meta_off_1 = zbm_u32_to_u24(state->written);',
                       '    hdr->meta_off_2 = zbm_u32_to_u24(state->written + (uint32_t)len1);',
                       '    state->written += (uint32_t)(len1 + len2);',
                       '    state->dest = d0 + len1 + len2;',
                       '    return 1;']:
         assert body.count(anchor)==1
         body=body.replace(anchor,'    '+statement+'\n'+anchor)
        g=g[:pos]+body
    return g,functions


def main():
    import argparse
    import concurrent.futures
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-metadata-selectors')
    output.mkdir(parents=True,exist_ok=True)
    def prove(name,text,expected=True):
        generated,functions=generate(text,name)
        verify(name+'_selectors'+('' if expected else '_invalid_value'),generated,
               output,functions,257 if name=='bitmap' else 238,expected,split=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda name:prove(name,source),['bitmap','fused']))
    if args.mutants:
        def mutation(name):
            function='zbm_write_metadata_2' if name=='bitmap' else 'zbm_write_metadata_12'
            a=source.index('static int '+function+'(')
            b=source.index('/* How many consecutive blocks',a) if name=='bitmap' else source.index('static int zbm_build_metadata(',a)
            body=source[a:b]
            old='nums[i] = (uint8_t)num;'
            assert body.count(old)==1, 'selector store changed'
            body=body.replace(old,old+'\n        nums[i] = 255;')
            prove(name,source[:a]+body+source[b:],False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(mutation,['bitmap','fused']))


if __name__=='__main__':
    main()
