#!/usr/bin/env python3
"""Actual literal writer's recomputing path without caller-provided ghost data.

The verified prefix builder constructs local analysis-only prefix storage.
Its writes do not affect the shipping state, input or output. Original writer
operations are retained, with known_total<0 as the path requirement. Existing
pack/table arithmetic and reviewed native SIMD dependencies remain explicit.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
import literal_writer
from wp_common import verify


def generate(source):
    g=literal_writer.generate(source)
    pos=g.index('static int zbm_emit_literals(');a=g.rfind('/*@',0,pos)
    contract=g[a:pos]
    lines=contract.splitlines(keepends=True)
    lines=[line for line in lines if not ('requires' in line and 'prefix' in line)]
    contract=''.join(lines).replace(',prefix[0 .. state->bmp_cnt]','')
    contract=contract.replace(' assigns state->dest', ' requires known_total<0;\n assigns state->dest',1)
    contract=contract.replace('*/',r' ensures state->written==\old(state->written)+(state->dest-\old(state->dest));'+'\n'+r' ensures 0<=state->dest-\old(state->dest)<=8*state->bmp_cnt;'+'\n*/',1)
    g=g[:a]+contract+g[pos:]
    old='long known_total,const unsigned *prefix)';assert g.count(old)==1
    g=g.replace(old,'long known_total)')
    old='    total = known_total >= 0 ? known_total : zbm_literal_total(bmaps, cnt);';assert g.count(old)==1
    g=g.replace(old,'    unsigned prefix[ZBM_MAX_BITMAP_COUNT+1];\n    proof_literal_prefix(bmaps,cnt,prefix);\n'+old)
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-literal-recompute');output.mkdir(parents=True,exist_ok=True)
    functions=['proof_literal_prefix','zbm_emit_literals','proof_trial_destination']
    verify('literal_recompute',generate(source),output,functions,760,split=True)
    if args.mutants:
        a=source.index('static int zbm_emit_literals(')
        b=source.index('#if defined(ZBM_PROOF) && defined(ZBM_PROOF_SELECTOR_VALUES)',a)
        body=source[a:b]
        variants=[('missing_tail_limit','j < 8 && s != state->src_end','j < 8'),
                  ('extra_written_byte','state->written += (uint32_t)(d - state->dest);',
                   'state->written += (uint32_t)(d - state->dest) + 1;')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed),output,functions,684 if tag=='missing_tail_limit' else 760,False,split=True)


if __name__=='__main__':
    main()
