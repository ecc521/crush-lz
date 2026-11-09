#!/usr/bin/env python3
"""Cursor-growth consequences for actual period, bitmap and fused writers.

The underlying verified source generators retain both output domains and all
capacity paths. The selector writer already has its tighter ceiling bound.
"""
from pathlib import Path
import concurrent.futures
import sys
sys.dont_write_bytecode=True
import period_metadata,metadata_selectors,selector_tight
from wp_common import verify


def generate(source,name):
    if name=='period':
     g=period_metadata.generate(source)
     funcs=['proof_build_period_prefix','zbm_write_metadata_1','proof_trial_destination']
     function='zbm_write_metadata_1';bound='2*state->bmp_cnt';minimum=148
    elif name in ('bitmap','fused'):
     g,funcs=metadata_selectors.generate(source,name)
     function='zbm_write_metadata_2' if name=='bitmap' else 'zbm_write_metadata_12'
     bound='state->bmp_cnt' if name=='bitmap' else '3*state->bmp_cnt'
     minimum=257 if name=='bitmap' else 238
    else:
     g=selector_tight.generate(source)
     funcs=['zbm_write_metadata_3','proof_trial_destination']
     function='zbm_write_metadata_3';bound='(state->bmp_cnt+1)/2';minimum=1351
    if name=='selector':
     return g,funcs,minimum
    pos=g.index('static int '+function+'(');start=g.rfind('/*@',0,pos)
    contract=g[start:pos]
    i=contract.rfind('*/')
    contract=contract[:i]+r' ensures 0<=state->dest-\old(state->dest)<='+bound+';\n'+contract[i:]
    g=g[:start]+contract+g[pos:]
    return g,funcs,{"period":237,"bitmap":263,"fused":242}[name]


def main():
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-metadata-bounds')
    output.mkdir(parents=True,exist_ok=True)
    def prove(name):
        g,functions,minimum=generate(source,name)
        verify(name+'_bound',g,output,functions,minimum,split=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(prove,['period','bitmap','fused']))


if __name__=='__main__':
    main()
