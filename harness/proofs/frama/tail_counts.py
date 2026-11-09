#!/usr/bin/env python3
"""Actual fast tail producer's exact key-count update and retained bitmap prefix.

This strengthens fast_tail's safety/shape contract. Histogram consistency must
still be established by the complete producer loop and its initialization.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
import fast_tail
from wp_common import verify


def generate(source):
    g=fast_tail.generate(source)
    old='     ensures state->bmp_cnt==\\old(state->bmp_cnt)+1;'
    assert g.count(old)==1
    g=g.replace(old,old+r"""
     ensures state->bitmaps[\old(state->bmp_cnt)].period_bytecnt==0;
     ensures \forall integer q; 0<=q<(3<<8) ==> state->key_usecnts[q]==\old(state->key_usecnts[q])+(q==state->bitmaps[\old(state->bmp_cnt)].bitmap ? 1 : 0);
     ensures \forall integer q; 0<=q<\old(state->bmp_cnt) ==> state->bitmaps[q].bitmap==\old(state->bitmaps[q].bitmap) && state->bitmaps[q].period_bytecnt==\old(state->bitmaps[q].period_bytecnt);
    """)
    return g

def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-tail-counts');output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_period_floor_bitmap','zbm_fast_tail_block']
    verify('tail_counts',generate(source),output,functions,240,split=True)
    if args.mutants:
        a=source.index('static void zbm_fast_tail_block(')
        b=source.index("/*\n * Every block's bitmap number",a)
        body=source[a:b]
        variants=[('wrong_count_key','++state->key_usecnts[bm];','++state->key_usecnts[bm ^ 1u];'),
                  ('wrong_tail_period_count','period_bytecnt = 0;','period_bytecnt = 1;')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed),output,functions,230,False,split=True)


if __name__=='__main__':
    main()
