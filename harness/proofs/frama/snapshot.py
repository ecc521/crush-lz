#!/usr/bin/env python3
"""Spatial safety and scalar-count copying for actual snapshot save/restore.

Standard memcpy footprints are trusted; copied array values are unconstrained.
The caller provides valid objects, separated source fields/snapshot, and an
initialized source bitmap count. Internal state->best snapshots are allowed.
This does not yet prove preservation of active array values or shape.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
from wp_common import verify


def generate(source):
    prefix=source[:source.index('static int zbm_bmprot(')]
    models=''
    for name,typ,count in [('bmaps','struct zbm_bmap','ZBM_MAX_BITMAP_COUNT'),('periods','uint16_t','ZBM_MAX_BITMAP_COUNT'),('counts','zbm_usecnt_t','ZBM_POSSIBLE_BMPROTS')]:
     models+=r"""
    /* Standard memcpy footprint for the exact shipping array extent. */
    /*@ requires n=="""+count+r"""*sizeof(*d);
     requires \valid(d+(0 .. """+count+r"""-1));
     requires \valid_read(s+(0 .. """+count+r"""-1));
     requires \separated(d+(0 .. """+count+r"""-1),s+(0 .. """+count+r"""-1));
     assigns d[0 .. """+count+r"""-1];
    */
    void proof_copy_"""+name+'('+typ+' *d,const '+typ+' *s,size_t n);\n'
    a=source.index('static void zbm_snapshot_save(');b=source.index('/* Scores the chunk',a)
    body=source[a:b]
    for field,name in [('bitmaps','bmaps'),('periods','periods'),('usecnts','counts')]:
     for obj in ['snap','state']:
      old='memcpy('+obj+'->'+field
      assert body.count(old)==1
      body=body.replace(old,'proof_copy_'+name+'('+obj+'->'+field)
    contracts={
    'save':r"""/*@ requires \valid(state) && \valid(snap);
     requires \separated(state->bitmaps+(0 .. ZBM_MAX_BITMAP_COUNT-1),
 state->periods+(0 .. ZBM_MAX_BITMAP_COUNT-1),state->usecnts+(0 .. ZBM_POSSIBLE_BMPROTS-1),
 &state->bmp_cnt,snap);
     assigns *snap;
     ensures snap->bmp_cnt==state->bmp_cnt;
    */
    """,
    'restore':r"""/*@ requires \valid(state) && \valid(snap);
     requires \separated(state->bitmaps+(0 .. ZBM_MAX_BITMAP_COUNT-1),
 state->periods+(0 .. ZBM_MAX_BITMAP_COUNT-1),state->usecnts+(0 .. ZBM_POSSIBLE_BMPROTS-1),
 &state->bmp_cnt,snap);
     assigns state->bitmaps[0 .. ZBM_MAX_BITMAP_COUNT-1],state->periods[0 .. ZBM_MAX_BITMAP_COUNT-1],
     state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1],state->bmp_cnt;
     ensures state->bmp_cnt==snap->bmp_cnt;
    */
    """}
    for name,contract in contracts.items():
     body=body.replace('static void zbm_snapshot_'+name+'(',contract+'static void zbm_snapshot_'+name+'(')
    return prefix+models+body


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-snapshot')
    output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_snapshot_save','zbm_snapshot_restore']
    verify('snapshot',generate(source),output,functions,46,split=True)
    if args.mutants:
        a=source.index('static void zbm_snapshot_save(')
        b=source.index('/* Scores the chunk',a)
        body=source[a:b]
        variants=[('save_count_overwrite','memcpy(snap->usecnts, state->usecnts,',
                  'memcpy(snap->usecnts + 1, state->usecnts,'),
                  ('missing_count_restore','state->bmp_cnt = snap->bmp_cnt;',
                  '(void)snap->bmp_cnt;')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed),output,functions,40,False,split=True)


if __name__=='__main__':
    main()
