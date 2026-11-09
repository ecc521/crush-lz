#!/usr/bin/env python3
"""Compose actual trial scoring with metadata safety and buffer-state restoration.

Initialized active fields/count shape remain strategy caller requirements.
The assigns clause lists the actual scratch, metadata and cursor fields.
Standard memset footprint and registered arbitrary-byte pair-key arithmetic are explicit dependencies.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
import build_metadata
from wp_common import verify


def generate(source,helper_source=None):
    # Mutations are confined to score_trial; reuse the unchanged helper proofs.
    g=build_metadata.generate(source if helper_source is None else helper_source)
    pos=g.index('static int zbm_build_metadata(')
    a=g.rfind('/*@',0,pos);b=g.index('\n',pos)
    # Retain the derived declarations, replacing the actual metadata body with its proved contract.
    models=g[:pos]+g[pos:b].replace('static int ','int ',1)+';\n'
    models+=r"""
    /* Arbitrary-byte bound from registered zbm_encoder_bmprot. */
    /*@ requires \valid(bmap); assigns \nothing;
     ensures 0<=\result<ZBM_POSSIBLE_BMPROTS;
    */
    int zbm_bmprot(struct zbm_bmap *bmap);
    /* Standard memset write footprint. */
    /*@ requires n==ZBM_POSSIBLE_BMPROTS;
     requires \valid(d+(0 .. n-1));
     assigns d[0 .. n-1];
    */
    void proof_zero_estimates(uint8_t *d,int value,size_t n);
    #define memset(d,v,n) proof_zero_estimates(d,v,n)
    /*@ requires \valid(state);
     requires 0<=data_bytes<=CRUSHLZBITMAP_MAX_CHUNK_SIZE;
     requires 0<=state->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
     requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     requires live_counts(&state->usecnts[0]);
     assigns state->dest,state->dest_end \from state,state->dest,state->dest_end;
     assigns state->written,
     state->meta_scratch[0 .. ZBM_META_SCRATCH_SIZE-1],
     state->top_bitmaps[0 .. ZBM_BITMAP_COUNT-1],state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1],
     state->bmap_num_tbl[0 .. ZBM_POSSIBLE_BMPROTS-1],state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT+15],
     state->run_bnd[0 .. 64],state->run_long[0 .. 64],state->is_top_estimate[0 .. ZBM_POSSIBLE_BMPROTS-1];
     ensures state->dest==\old(state->dest);
     ensures state->dest_end==\old(state->dest_end);
     ensures state->written==\old(state->written);
     ensures \result<=sizeof(struct zbm_cmp_chunk_hdr)+CRUSHLZBITMAP_MAX_CHUNK_SIZE+ZBM_META_SCRATCH_SIZE;
    */
    """
    a=source.index('static size_t zbm_score_trial(');b=source.index('/*\n * How many of the eight bytes differ',a)
    body=source[a:b]
    old='        for(i = 0; i < ZBM_BITMAP_COUNT; ++i)'
    assert body.count(old)==1
    body=body.replace(old,r"""        /*@ loop invariant 0<=i<=ZBM_BITMAP_COUNT;
     loop assigns i,state->is_top_estimate[0 .. ZBM_POSSIBLE_BMPROTS-1];
     loop variant ZBM_BITMAP_COUNT-i;
     */
    """+old)
    return models+body


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-score-trial')
    output.mkdir(parents=True,exist_ok=True)
    verify('score_trial',generate(source),output,['zbm_score_trial'],111,split=True)
    if args.mutants:
        a=source.index('static size_t zbm_score_trial(')
        b=source.index('/*\n * How many of the eight bytes differ',a)
        body=source[a:b]
        variants=[('scratch_end_overrun','state->dest_end = state->meta_scratch + ZBM_META_SCRATCH_SIZE;',
                  'state->dest_end = state->meta_scratch + ZBM_META_SCRATCH_SIZE + 1;'),
                  ('missing_dest_restore','state->dest = saved_dest;','(void)saved_dest;'),
                  ('missing_written_restore','state->written = saved_written;','(void)saved_written;'),
                  ('clobbered_best_snapshot','    return total;',
                   '    state->best.bmp_cnt = ZBM_MAX_BITMAP_COUNT + 1;\n    return total;')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed,source),output,['zbm_score_trial'],100,False,split=True)


if __name__=='__main__':
    main()
