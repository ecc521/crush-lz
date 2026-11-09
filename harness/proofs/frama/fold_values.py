#!/usr/bin/env python3
"""Exact values from the actual fast count-fold fragment.

The injectivity lemma is proved by WP in this same run. Registered count-fold
arithmetic and standard memset semantics remain explicit dependencies.
Initialized key counts bounded by bmp_cnt remain producer prerequisites.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
import count_init
from wp_common import verify


def generate(source):
    g,_,_=count_init.generate(source)['fast']
    pos=g.index('static void proof_fast_count_fold(');a=g.rfind('/*@',0,pos)
    contract=g[a:pos]
    contract=contract.replace('*/',r' ensures \forall integer q; 0<=q<(3<<8) ==> state->usecnts[4*(q%256)+q/256]==state->key_usecnts[q];'+'\n*/')
    g=g[:a]+contract+g[pos:]
    pos=g.index('static void proof_fast_count_fold(');pos=g.rfind('/*@',0,pos)
    g=g[:pos]+r'''
    /* Pure arithmetic fact: verified here, not a codec algorithm replacement. */
    /*@ requires key<(3u<<8); assigns \nothing;
     ensures \forall integer q; 0<=q<key ==> 4*(q%256)+q/256 != 4*(key%256)+key/256;
    */
    static void proof_fold_unique(unsigned key) { (void)key; }
    '''+g[pos:]
    old='     loop invariant \\forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> state->usecnts[q]==0;'
    assert g.count(old)==1
    g=g.replace(old,old+'\n'+r' loop invariant \forall integer q; 0<=q<key ==> state->usecnts[4*(q%256)+q/256]==state->key_usecnts[q];')
    old='        unsigned proof_index=proof_fold_index(key);';assert g.count(old)==1
    g=g.replace(old,'        proof_fold_unique(key);\n'+old)
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-fold-values');output.mkdir(parents=True,exist_ok=True)
    functions=['proof_fold_unique','proof_fast_count_fold']
    verify('fold_values',generate(source),output,functions,39,split=True)
    if args.mutants:
        a=source.index('static int zbm_build_metadata_fast(')
        b=source.index('    zbm_find_most_common_bitmaps(state);',a)
        body=source[a:b]
        old='state->key_usecnts[key];';assert body.count(old)==1
        changed=source[:a]+body.replace(old,'0;')+source[b:]
        verify('discard_key_counts',generate(changed),output,functions,35,False,split=True)


if __name__=='__main__':
    main()
