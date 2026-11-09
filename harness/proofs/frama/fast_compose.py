#!/usr/bin/env python3
"""Actual fast reset fragment and tail-loop composition.

The loop derives all calls to the verified fast tail producer, including bitmap
slot, staging, history and progress requirements. Its entry relation between
read and bitmap count still must follow from the bulk fast producer.
The source's &lit call is lifted to &(*litp), preserving the pointer object.
Standard memset zero semantics remain trusted for the reset fragment.
"""
from pathlib import Path
import argparse
import re
import sys
sys.dont_write_bytecode=True
import fast_tail
from wp_common import verify


def generate_init(source):
    prefix=source[:source.index('static int zbm_bmprot(')]
    a=source.index('static int zbm_build_compressed_chunk_fast(')
    x=source.index('    state->read = 0;',a);y=source.index('    zbm_fast_prepare_index(',x)
    body=source[x:y]
    g=prefix+r'''
    /* Standard memset zero semantics on the exact fast key-count array. */
    /*@ requires n==(3<<8)*sizeof(*d); requires value==0;
     requires \valid(d+(0 .. (3<<8)-1));
     assigns d[0 .. (3<<8)-1];
     ensures \forall integer q; 0<=q<(3<<8) ==> d[q]==0;
    */
    void proof_zero_keys(zbm_usecnt_t *d,int value,size_t n);
    #define memset(d,v,n) proof_zero_keys(d,v,n)
    /*@ requires \valid(state);
     assigns state->read,state->period,state->bmp_cnt,state->key_usecnts[0 .. (3<<8)-1];
     ensures state->read==0 && state->period==8 && state->bmp_cnt==0;
     ensures \forall integer q; 0<=q<(3<<8) ==> state->key_usecnts[q]==0;
    */
    static void proof_fast_init(struct zbm_compress_state *state)
    {
    '''+body+'}\n'
    return g


def generate_loop(source):
    g=fast_tail.generate(source)
    pos=g.index('static void zbm_fast_tail_block(');a=g.rfind('/*@',0,pos);b=g.index('\n',pos)
    g=source[:source.index('static int zbm_bmprot(')]+g[a:pos]+g[pos:b].replace('static void ','void ',1)+';\n'
    contract=r'''
    /*@ requires \valid(state);
     requires state->read<=state->decmp_len<=CRUSHLZBITMAP_CHUNK_SIZE;
     requires state->read==state->decmp_len || state->read%8==0;
     requires state->bmp_cnt==(state->read+7)/8;
     requires state->period>=8;
     requires state->preread+state->decmp_len<=UINT32_MAX;
     requires \base_addr(state->src)==\base_addr(state->buf_base);
     requires state->src-state->buf_base==state->preread+state->read;
     requires state->preread+state->decmp_len<=state->buf_len<=0x1000000000000;
     requires \valid_read(state->buf_base+(0 .. state->buf_len-1));
     requires \valid(lit+(0 .. state->decmp_len-state->read+7));
     requires \separated(state,state->buf_base+(0 .. state->buf_len-1));
     requires \separated(&state->src,&state->read,&state->bmp_cnt,&state->period,&state->preread,&state->decmp_len,&state->buf_base,&state->buf_len,
     state->bitmaps+(0 .. ZBM_MAX_BITMAP_COUNT-1),state->key_usecnts+(0 .. (3<<8)-1),
     state->buf_base+(0 .. state->buf_len-1),lit+(0 .. state->decmp_len-state->read+7));
     requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     requires \forall integer q; 0<=q<(3<<8) ==> state->key_usecnts[q]<=state->bmp_cnt;
     assigns state->src \from state,*state,lit;
     assigns state->bitmaps[0 .. ZBM_MAX_BITMAP_COUNT-1],state->bmp_cnt,state->read,state->key_usecnts[0 .. (3<<8)-1],lit[0 .. state->decmp_len-state->read+7];
     ensures state->read==state->decmp_len;
     ensures state->bmp_cnt==(state->decmp_len+7)/8;
     ensures state->src==state->buf_base+state->preread+state->decmp_len;
     ensures \base_addr(\result)==\base_addr(lit);
     ensures 0<=\result-lit<=state->decmp_len-\old(state->read);
     ensures \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     ensures \forall integer q; 0<=q<(3<<8) ==> state->key_usecnts[q]<=state->bmp_cnt;
    */
    static uint8_t *proof_fast_tail_loop(struct zbm_compress_state *state,uint8_t *lit)
    {
     uint32_t initial=state->read;
     uint8_t *start=lit;
     /*@ loop invariant state->read<=state->decmp_len<=CRUSHLZBITMAP_CHUNK_SIZE;
     loop invariant state->read==state->decmp_len || state->read%8==0;
     loop invariant state->bmp_cnt==(state->read+7)/8;
     loop invariant initial<=state->read;
     loop invariant state->src==state->buf_base+state->preread+state->read;
     loop invariant \base_addr(lit)==\base_addr(start);
     loop invariant 0<=lit-start<=state->read-initial;
     loop invariant \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
     loop invariant \forall integer q; 0<=q<(3<<8) ==> state->key_usecnts[q]<=state->bmp_cnt;
     loop assigns lit,state->src,state->read,state->bmp_cnt,state->bitmaps[0 .. ZBM_MAX_BITMAP_COUNT-1],state->key_usecnts[0 .. (3<<8)-1],start[0 .. state->decmp_len-initial+7];
     loop variant state->decmp_len-state->read;
     */
    '''
    a=source.index('static int zbm_build_compressed_chunk_fast(')
    b=source.index('    if((size_t)(lit - lit0)',a)
    body=source[a:b]
    line=next(line for line in body.splitlines() if line.startswith('    while(state->read'))
    a=body.index(line)
    loop=body[a:]
    assert len(loop.strip().splitlines())==2 and loop.strip().endswith('zbm_fast_tail_block(state, &lit);')
    g+=contract+loop+'\n}\n'
    pos=g.index('static uint8_t *proof_fast_tail_loop(');start=g.rfind('/*@',0,pos)
    wrapper=g[start:]
    wrapper=wrapper.replace('static uint8_t *proof_fast_tail_loop(struct zbm_compress_state *state,uint8_t *lit)', 'static void proof_fast_tail_loop(struct zbm_compress_state *state,uint8_t **litp)')
    wrapper=re.sub(r'\blit\b','(*litp)',wrapper)
    wrapper=wrapper.replace('requires \\valid(state);', 'requires \\valid(state) && \\valid(litp);')
    wrapper=wrapper.replace(' assigns state->src \\from state,*state,(*litp);', ' assigns state->src,*litp \\from state,*state,litp,*litp,state->buf_base[0 .. state->buf_len-1];')
    wrapper=wrapper.replace(' ensures \\base_addr(\\result)==\\base_addr((*litp));', ' ensures \\base_addr(*litp)==\\old(\\base_addr(*litp));')
    wrapper=wrapper.replace(' ensures 0<=\\result-(*litp)<=state->decmp_len-\\old(state->read);', ' ensures 0<=*litp-\\old(*litp)<=state->decmp_len-\\old(state->read);')
    old=' requires \\separated(state,state->buf_base+(0 .. state->buf_len-1));'
    wrapper=wrapper.replace(old,old+'\n requires \\separated(litp,state,state->buf_base+(0 .. state->buf_len-1),(*litp)+(0 .. state->decmp_len-state->read+7));')
    g=g[:start]+wrapper
    assert g.startswith(source[:source.index('static int zbm_bmprot(')])
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-fast-compose');output.mkdir(parents=True,exist_ok=True)
    verify('fast_init',generate_init(source),output,['proof_fast_init'],18,split=True)
    verify('tail_loop',generate_loop(source),output,['proof_fast_tail_loop'],109,split=True)
    if args.mutants:
        a=source.index('static int zbm_build_compressed_chunk_fast(')
        b=source.index('/* ------------------------------------------------------------------ */',a)
        body=source[a:b]
        old='memset(state->key_usecnts, 0, sizeof(state->key_usecnts));'
        assert body.count(old)==1
        changed=source[:a]+body.replace(old,'(void)state;')+source[b:]
        verify('missing_key_reset',generate_init(changed),output,['proof_fast_init'],10,False,split=True)
        old='while(state->read < state->decmp_len)'
        assert body.count(old)==1
        changed=source[:a]+body.replace(old,'while(state->read <= state->decmp_len)')+source[b:]
        verify('extra_tail_iteration',generate_loop(changed),output,['proof_fast_tail_loop'],109,False,split=True)


if __name__=='__main__':
    main()
