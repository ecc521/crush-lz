#!/usr/bin/env python3
"""Safety of the actual fixed-size trailing-table bit writers.

Standard memset footprint and registered bit-shift arithmetic are dependencies.
Period-count shape is unnecessary for safety; byte correctness is separate.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
from wp_common import verify,DOMAIN


def generate(source):
    prefix=source[:source.index('static int zbm_bmprot(')]
    a=source.index('static void zbm_write_single_bit(');b=source.index('static void zbm_write_single_bitmap(',a)
    bit=r'''
    /* Bit-precise consequence of zbm_encoder_bit_shift. */
    /*@ requires 0<=val<=1 && 0<=offset<8;
     assigns \nothing;
     ensures 0<=(val<<offset)<=128;
    */
    void proof_bit_shift(int val,int offset);
    /*@ requires \valid(bit);
     requires 0<=bit->offset<8;
     requires 0<=val<=1;
     requires \valid(bit->addr);
     requires \separated(bit,bit->addr);
     assigns bit->addr \from bit->addr,bit->offset;
     assigns bit->offset \from bit->offset;
     assigns *bit->addr \from *bit->addr,bit->offset,val;
     ensures bit->addr==\old(bit->addr)+(\old(bit->offset)==7 ? 1 : 0);
     ensures bit->offset==(\old(bit->offset)+1)%8;
    */
    '''+source[a:b].replace('    *bit->addr |= val << bit->offset;','    proof_bit_shift(val,bit->offset);\n    *bit->addr |= val << bit->offset;')
    c=source.index('static int zbm_write_trailing_bitmaps(',b)
    body=source[b:c]
    body=body.replace('    int i;','    int i;\n    uint8_t *start=bit->addr;\n    int initial=bit->offset;',1)
    for count,extra in [(8,0),(2,8)]:
     old='    for(i = 0; i < '+str(count)+'; ++i)'
     annotation=r'''    /*@ loop invariant 0<=i<='''+str(count)+r''';
     loop invariant bit->addr==start+(initial+'''+str(extra)+r'''+i)/8;
     loop invariant bit->offset==(initial+'''+str(extra)+r'''+i)%8;
     loop assigns i,bit->addr,bit->offset,start[0 .. 2];
     loop variant '''+str(count)+r'''-i;
     */
    '''
     assert body.count(old)==1
     body=body.replace(old,annotation+old)
    bitmap=r'''
    /*@ requires \valid(bit);
     requires 0<=bit->offset<8;
     requires \valid(bit->addr+(0 .. 2));
     requires \separated(bit,bit->addr+(0 .. 2));
     assigns bit->addr \from bit->addr,bit->offset;
     assigns bit->offset \from bit->offset;
     assigns bit->addr[0 .. 2] \from bit->addr[0 .. 2],bit->offset,bmap;
     ensures bit->addr==\old(bit->addr)+(\old(bit->offset)+10)/8;
     ensures bit->offset==(\old(bit->offset)+10)%8;
    */
    '''+body
    models=r'''
    /* Standard memset footprint, all n bytes written. */
    /*@ requires n==ZBM_BITMAP_BYTECNT;
     requires \valid(d+(0 .. n-1));
     assigns d[0 .. n-1];
    */
    void proof_zero_bytes(uint8_t *d,int value,size_t n);
    #define memset(d,v,n) proof_zero_bytes(d,v,n)
    /*@ requires \valid(state);
     requires \valid(state->dest) || \valid(state->dest-1);
     requires \base_addr(state->dest)==\base_addr(state->dest_end);
     requires 0<=state->dest_end-state->dest<=0x1000000000000;
     requires \valid(state->dest+(0 .. state->dest_end-state->dest-1));
     requires '''+DOMAIN+r''';
     requires \separated(&state->dest,&state->dest_end,&state->written,
     state->top_bitmaps+(0 .. ZBM_BITMAP_COUNT-1),state->dest+(0 .. state->dest_end-state->dest-1));
     requires state->written<=UINT32_MAX-ZBM_BITMAP_BYTECNT;
     assigns state->dest,state->written,state->dest[0 .. state->dest_end-state->dest-1] \from state->dest,state->dest_end,state->written,state->top_bitmaps[0 .. ZBM_BITMAP_COUNT-1];
     ensures \result==0 || \result==ZBM_CANT_COMPRESS;
     ensures state->dest==\old(state->dest)+(\result==0 ? ZBM_BITMAP_BYTECNT : 0);
     ensures state->written==\old(state->written)+(\result==0 ? ZBM_BITMAP_BYTECNT : 0);
     ensures \result==0 ==> ZBM_BITMAP_BYTECNT<=\old(state->dest_end-state->dest);
    */
    '''
    d=source.index('static struct uint24 zbm_u32_to_u24(',c)
    body=source[c:d]
    old=next(line for line in body.splitlines() if line.startswith('    for(i = 0; i < ZBM_BITMAP_COUNT'))
    annotation=r'''    /*@ loop invariant 0<=i<=ZBM_BITMAP_COUNT;
     loop invariant bmap.addr==state->dest+(10*i)/8;
     loop invariant bmap.offset==(10*i)%8;
     loop assigns i,bmap,state->dest[0 .. state->dest_end-state->dest-1];
     loop variant ZBM_BITMAP_COUNT-i;
     */
    '''
    assert body.count(old)==1
    body=body.replace(old,annotation+old)
    g=prefix+bit+bitmap+models+body
    return g


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-trailing-table')
    output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_write_single_bit','zbm_write_single_bitmap','zbm_write_trailing_bitmaps']
    verify('trailing_table',generate(source),output,functions,165,split=True)
    if args.mutants:
        a=source.index('static int zbm_write_trailing_bitmaps(')
        b=source.index('static struct uint24 zbm_u32_to_u24(',a)
        body=source[a:b]
        variants=[('short_capacity','< ZBM_BITMAP_BYTECNT','< ZBM_BITMAP_BYTECNT - 1'),
                  ('extra_bitmap','i < ZBM_BITMAP_COUNT','i < ZBM_BITMAP_COUNT + 1')]
        for tag,old,new in variants:
            assert body.count(old)==1,'mutation site changed'
            changed=source[:a]+body.replace(old,new)+source[b:]
            verify(tag,generate(changed),output,functions,165,False,split=True)


if __name__=='__main__':
    main()
