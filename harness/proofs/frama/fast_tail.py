#!/usr/bin/env python3
"""Actual fast tail producer safety, progress and active count/bitmap shape.

Caller requirements cover initialized state/key counts, a remaining bitmap slot,
valid source/history geometry, period>=8 and eight writable staging bytes.
Staging may be internal if separated from the fields and source being accessed.
The actual period-floor helper is proved too. Full fast-loop callers remain open.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
from wp_common import verify


def generate(source):
    prefix=source[:source.index('static int zbm_bmprot(')]
    a=source.index('static uint8_t zbm_period_floor_bitmap(');b=source.index('/* Which lanes of a full block',a)
    g=prefix+r'''
    /*@ requires period>=8; requires 1<=size<=8;
     assigns \nothing; ensures \result==bitmap;
    */
    '''+source[a:b]
    a=source.index('static void zbm_fast_tail_block(');b=source.index('/*\n * Every block\'s bitmap number',a)
    contract=r'''
    /*@ requires \valid(state) && \valid(litp);
     requires 0<=state->bmp_cnt<ZBM_MAX_BITMAP_COUNT;
     requires state->read<state->decmp_len<=CRUSHLZBITMAP_CHUNK_SIZE;
     requires state->period>=8;
     requires state->preread+state->read<=UINT32_MAX;
     requires \base_addr(state->src)==\base_addr(state->buf_base);
     requires state->src-state->buf_base==state->preread+state->read;
     requires state->preread+state->decmp_len<=state->buf_len<=0x1000000000000;
     requires \valid_read(state->buf_base+(0 .. state->buf_len-1));
     requires \valid(*litp+(0 .. 7));
     requires \separated(litp,state,state->buf_base+(0 .. state->buf_len-1),*litp+(0 .. 7));
     requires \separated(state,state->buf_base+(0 .. state->buf_len-1));
     requires \separated(&state->src,&state->read,&state->bmp_cnt,&state->period,&state->preread,&state->decmp_len,&state->buf_base,&state->buf_len,
     state->bitmaps+(0 .. ZBM_MAX_BITMAP_COUNT-1),state->key_usecnts+(0 .. (3<<8)-1),
     state->buf_base+(0 .. state->buf_len-1),*litp+(0 .. 7));
     requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     requires \forall integer q; 0<=q<(3<<8) ==> state->key_usecnts[q]<=state->bmp_cnt;
     assigns state->src,*litp \from state,*state,litp,*litp,state->buf_base[0 .. state->buf_len-1];
     assigns state->bitmaps[state->bmp_cnt],state->bmp_cnt,state->read,state->key_usecnts[0 .. (3<<8)-1],(*litp)[0 .. 7];
     ensures state->bmp_cnt==\old(state->bmp_cnt)+1;
     ensures state->read==\old(state->read)+(\old(state->decmp_len-state->read)<8 ? \old(state->decmp_len-state->read) : 8);
     ensures state->src==\old(state->src)+(state->read-\old(state->read));
     ensures 0<=*litp-\old(*litp)<=state->read-\old(state->read);
     ensures \base_addr(*litp)==\old(\base_addr(*litp));
     ensures \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     ensures \forall integer q; 0<=q<(3<<8) ==> state->key_usecnts[q]<=state->bmp_cnt;
    */
    '''
    body=source[a:b]
    old='    for(j = 0; j < n; ++j)'
    assert body.count(old)==2
    first=r'''    /*@ loop invariant 0<=j<=n;
     loop assigns j,bm;
     loop variant n-j;
     */
    '''
    body=body.replace(old,first+old,1)
    second=r'''    uint8_t *start=*litp;
        /*@ loop invariant 0<=j<=n;
     loop invariant 0<=*litp-start<=j;
     loop invariant \base_addr(*litp)==\base_addr(start);
     loop assigns j,*litp,start[0 .. 7];
     loop variant n-j;
     */
    '''
    pos=body.rfind(old);body=body[:pos]+second+body[pos:]
    g+=contract+body
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-fast-tail');output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_period_floor_bitmap','zbm_fast_tail_block']
    verify('fast_tail',generate(source),output,functions,230,split=True)
    if args.mutants:
        a=source.index('static void zbm_fast_tail_block(')
        b=source.index('/*\n * Every block\'s bitmap number',a)
        body=source[a:b]
        variants=[('missing_history_guard','per > pos || src[j] !=','src[j] !='),
                  ('literal_source_overread','*(*litp)++ = src[j];','*(*litp)++ = src[j + 8];')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed),output,functions,190,False,split=True)


if __name__=='__main__':
    main()
