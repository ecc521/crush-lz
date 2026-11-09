#!/usr/bin/env python3
"""Exact literal totals and bitmap-bit budgets for writer composition.

The literal sum is the shipping portable algorithm with a read-only ghost
prefix parameter. Popcount/table semantics import zbm_pack8_correct. Native
SIMD arithmetic remains a reviewed/trusted equivalence assumption; its load
footprints have separate CBMC coverage. This does not prove the literal writer
or the whole encoder.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode=True


def generate(source):
    s=source
    a=s.index('static long zbm_literal_total(');b=s.index('/*\n * Writes every committed block',a)
    terms=['(j>'+str(k)+' ? ((bm>>'+str(k)+')&1) : 0)' for k in range(8)]
    models='/*@ logic integer consumed(integer bm,integer j) = '+' + '.join(terms)+';\n logic integer pc(integer bm)=consumed(bm,8); */\n'
    models+=r'''
    /* Existing CBMC zbm_pack8_correct establishes table consumption equals the
       eight bitmap bit sum and lies in 0..8, for all 256 bitmap values. */
    /*@ assigns \nothing; ensures 0 <= \result <= 8; ensures \result==pc(bm); */
    uint8_t proof_popcount(uint8_t bm);
    #define zbm_popcount8(bm) proof_popcount(bm)
    /*@ requires \valid_read(bmaps+(0 .. cnt-1));
     requires 0 <= cnt <= ZBM_MAX_BITMAP_COUNT;
     requires \valid(prefix+(0 .. cnt));
     requires \separated(bmaps+(0 .. cnt-1),prefix+(0 .. cnt));
     assigns prefix[0 .. cnt];
     ensures prefix[0]==0;
     ensures \forall integer q; 0 <= q < cnt ==> prefix[q+1]==prefix[q]+pc(bmaps[q].bitmap);
     ensures \forall integer q; 0 <= q <= cnt ==> 0 <= prefix[q] <= 8*q;
     ensures \forall integer q; 0 <= q <= cnt ==> prefix[q]<=prefix[cnt];
    */
    static void proof_literal_prefix(const struct zbm_bmap *bmaps,int cnt,unsigned *prefix)
    {
     int i;prefix[0]=0;
     /*@ loop invariant 0 <= i <= cnt;
     loop invariant prefix[0]==0;
     loop invariant \forall integer q; 0 <= q < i ==> prefix[q+1]==prefix[q]+pc(bmaps[q].bitmap);
     loop invariant \forall integer q; 0 <= q <= i ==> 0 <= prefix[q] <= 8*q;
     loop invariant \forall integer q; 0 <= q <= i ==> prefix[q]<=prefix[i];
     loop assigns i,prefix[0 .. cnt];
     loop variant cnt-i;
     */
     for(i=0;i<cnt;++i) prefix[i+1]=prefix[i]+zbm_popcount8(bmaps[i].bitmap);
    }
    /*@ requires 0 <= j < 8;
     assigns \nothing;
     ensures consumed(bm,j+1)==consumed(bm,j)+((bm>>j)&1);
     ensures 0 <= consumed(bm,j) <= consumed(bm,j+1) <= pc(bm) <= 8;
    */
    static void proof_literal_bit_step(uint8_t bm,int j)
    {
    '''
    for j in range(8):
     models+=f' if(j=={j}) {{ /*@ assert consumed(bm,j+1)==consumed(bm,j)+((bm>>j)&1); */ }}\n'
    models+='}\n'
    models+=r'''
    /*@ requires 0 <= cnt <= ZBM_MAX_BITMAP_COUNT;
     requires \valid_read(bmaps+(0 .. cnt-1));
     requires \valid_read(prefix+(0 .. cnt));
     requires prefix[0]==0;
     requires \forall integer q; 0 <= q < cnt ==> prefix[q+1]==prefix[q]+pc(bmaps[q].bitmap);
     requires \forall integer q; 0 <= q <= cnt ==> 0 <= prefix[q] <= 8*q;
     assigns \nothing;
     ensures \result==prefix[cnt];
     ensures 0 <= \result <= 8*cnt;
    */
    '''
    body=s[a:b].replace('zbm_literal_total(const struct zbm_bmap *bmaps, int cnt)', 'zbm_literal_total(const struct zbm_bmap *bmaps, int cnt,const unsigned *prefix)')
    assert body.count('    for(; i < cnt; ++i)')==1, 'literal sum tail loop changed'
    assert body.count('total += zbm_popcount8(bmaps[i].bitmap);')==1, 'literal sum changed'
    body=body.replace('    for(; i < cnt; ++i)',r'''    /*@ loop invariant 0 <= i <= cnt;
     loop invariant total==prefix[i];
     loop assigns i,total;
     loop variant cnt-i;
     */
        for(; i < cnt; ++i)''')
    return s[:a]+models+body


def main():
    import argparse
    import concurrent.futures
    from wp_common import verify, witness
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-literal-totals')
    output.mkdir(parents=True,exist_ok=True)
    functions=['proof_literal_prefix','proof_literal_bit_step','zbm_literal_total']
    runtime=r'''#include <assert.h>
#include <stdio.h>
#include "libzbitmap.c"
static struct zbm_bmap bmaps[ZBM_MAX_BITMAP_COUNT];
int main(void) {
 unsigned checks=0;
 for(int cnt=0;cnt<=ZBM_MAX_BITMAP_COUNT;++cnt) for(int mode=0;mode<4;++mode) {
  long expected=0;
  for(int i=0;i<cnt;++i) {
   unsigned bm=mode==0?0:mode==1?255:mode==2?(unsigned)i&255:((unsigned)i*17)^((unsigned)i>>3);
   bmaps[i].bitmap=(uint8_t)bm; bmaps[i].period_bytecnt=(uint8_t)(i%3);
   for(int j=0;j<8;++j) expected+=((bmaps[i].bitmap>>j)&1);
  }
  assert(zbm_literal_total(bmaps,cnt)==expected);++checks;
 }
 printf("literal total independent oracle: %u checks passed\n",checks);
}
'''
    witness(output,runtime)
    witness(output,runtime,native=True)
    generated=generate(source)
    verify('literal_totals',generated,output,functions,60)
    if args.mutants:
        variants=[
            ('extra_prefix_literal','prefix[i+1]=prefix[i]+zbm_popcount8(bmaps[i].bitmap);',
             'prefix[i+1]=prefix[i]+zbm_popcount8(bmaps[i].bitmap)+1;'),
            ('wrong_sum','total += zbm_popcount8(bmaps[i].bitmap);','total += zbm_popcount8(bmaps[i].bitmap)+1;'),
            ('wrong_bit_budget','ensures consumed(bm,j+1)==consumed(bm,j)+((bm>>j)&1);',
             'ensures consumed(bm,j+1)==consumed(bm,j)+((bm>>j)&1)+1;'),
        ]
        def mutation(item):
            name,old,new=item
            assert generated.count(old)==1,'mutation site changed'
            verify(name,generated.replace(old,new),output,functions,60,False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(mutation,variants))


if __name__=='__main__':
    main()
