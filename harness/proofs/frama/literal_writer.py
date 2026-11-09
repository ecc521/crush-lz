#!/usr/bin/env python3
"""Actual literal-writer safety, including tight output and partial tails.

Read-only ghost prefix parameters import literal_totals. Row count/footprint
models import literal_row plus registered zbm_pack8_correct. Native intrinsic
semantics remain reviewed/trusted. This is a component proof; strategy and
public callers still must establish its buffer, bitmap/count and separation
preconditions. No byte-correctness or whole encoder proof is claimed.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode=True


def generate(source):
    from literal_totals import generate as generate_totals
    from wp_common import SPAN,protect_span
    s=source
    a=s.index('static int zbm_emit_literals(');b=s.index('#if defined(ZBM_PROOF) && defined(ZBM_PROOF_SELECTOR_VALUES)',a)
    models=r'''
    /* Geometry/count properties derive from checked row_geometry and
       zbm_pack8_correct; keep the large static initializer out of writer VCs. */
    /*@ requires 0 <= room <= 0x1000000000000;
     requires \valid(dest+(0 .. room-1));
     requires \separated(&zbm_pack_row[0]+(0 .. 255),dest+(0 .. room-1));
     assigns \result \from bm,dest,room;
     ensures \valid_read(\result+(0 .. 15));
     ensures \result[8]==pc(bm);
     ensures 0 <= \result[8] <= 8;
     ensures \separated(\result+(0 .. 15),dest+(0 .. room-1));
    */
    const uint8_t *proof_row(uint8_t bm,uint8_t *dest,ptrdiff_t room);
    /* Eight-byte footprint established by zbm_pack8_correct; native SIMD
       semantics/footprints reviewed in crush_simd.h. */
    /*@ requires \valid(d+(0 .. 7)); requires \valid_read(src+(0 .. 7));
     requires \valid_read(row+(0 .. 15));
     requires \separated(d+(0 .. 7),src+(0 .. 7));
     requires \separated(d+(0 .. 7),row+(0 .. 15));
     assigns d[0 .. 7];
    */
    void proof_pack(uint8_t *d,const uint8_t *src,const uint8_t *row);
    #define zbm_pack8(d,s,r) proof_pack(d,s,r)
    /* Verified literal_totals shipping portable scanner consequence. */
    /*@ requires 0 <= cnt <= ZBM_MAX_BITMAP_COUNT;
     requires \valid_read(bmaps+(0 .. cnt-1));
     requires \valid_read(prefix+(0 .. cnt));
     requires prefix[0]==0;
     requires \forall integer q; 0 <= q < cnt ==> prefix[q+1]==prefix[q]+pc(bmaps[q].bitmap);
     requires \forall integer q; 0 <= q <= cnt ==> 0 <= prefix[q] <= 8*q;
     assigns \nothing;
     ensures \result==prefix[cnt];
    */
    long proof_total(const struct zbm_bmap *bmaps,int cnt,const unsigned *prefix);
    #define zbm_literal_total(b,c) proof_total(b,c,prefix)
    /*@ requires \valid(state);
     requires 0 <= state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
     requires \base_addr(chunk_src)==\base_addr(state->src_end);
     requires 0 <= state->src_end-chunk_src <= 8*state->bmp_cnt;
     requires state->bmp_cnt==0 || 8*(state->bmp_cnt-1)<state->src_end-chunk_src;
     requires \valid_read(chunk_src+(0 .. state->src_end-chunk_src-1));
     requires \valid_read(chunk_src) || \valid_read(chunk_src-1);
     requires \valid(state->dest) || \valid(state->dest-1);
     requires \base_addr(state->dest)==\base_addr(state->dest_end);
     requires 0 <= state->dest_end-state->dest <= 0x1000000000000;
     requires \valid(state->dest+(0 .. state->dest_end-state->dest-1));
     requires \separated(state, state->dest + (0 .. state->dest_end - state->dest - 1));
     requires \separated(&zbm_pack_row[0]+(0 .. 255),state->dest+(0 .. state->dest_end-state->dest-1));
     requires \separated(state,chunk_src+(0 .. state->src_end-chunk_src-1));
     requires \separated(state->dest+(0 .. state->dest_end-state->dest-1),chunk_src+(0 .. state->src_end-chunk_src-1));
     requires \valid_read(prefix+(0 .. state->bmp_cnt));
     requires \separated(prefix+(0 .. state->bmp_cnt),state,state->dest+(0 .. state->dest_end-state->dest-1),chunk_src+(0 .. state->src_end-chunk_src-1));
     requires prefix[0]==0;
     requires \forall integer q; 0 <= q < state->bmp_cnt ==> prefix[q+1]==prefix[q]+pc(state->bitmaps[q].bitmap);
     requires \forall integer q; 0 <= q <= state->bmp_cnt ==> 0 <= prefix[q] <= 8*q && prefix[q]<=prefix[state->bmp_cnt];
     requires known_total<0 || known_total==prefix[state->bmp_cnt];
     requires state->written<=UINT32_MAX-8*state->bmp_cnt;
     assigns state->dest,state->written,state->src,state->read,state->dest[0 .. state->dest_end-state->dest-1] \from state->dest,state->dest_end,state->written,state->src,state->src_end,state->read,state->bmp_cnt,state->bitmaps[0 .. ZBM_MAX_BITMAP_COUNT-1],chunk_src[0 .. state->src_end-chunk_src-1],known_total,prefix[0 .. state->bmp_cnt];
     ensures \result==0 || \result==ZBM_CANT_COMPRESS;
     ensures \result==0 ==> 0 <= state->dest-\old(state->dest)<=\old(state->dest_end-state->dest);
     ensures \result==0 ==> state->src==state->src_end;
     ensures \result==0 ==> state->read==state->src_end-chunk_src;
     ensures \result!=0 ==> state->dest==\old(state->dest) && state->written==\old(state->written) && state->src==\old(state->src) && state->read==\old(state->read);
    */
    '''
    assert s[a:b].count('for(; i + 1 < cnt; ++i)')==1, 'bulk literal loop changed'
    assert s[a:b].count('for(; i < cnt; ++i)')==1, 'exact literal loop changed'
    assert s[a:b].count('zbm_pack_row[bmaps[i].bitmap]')==1, 'pack row lookup changed'
    body=s[a:b].replace('long known_total)', 'long known_total,const unsigned *prefix)')
    body=body.replace('zbm_pack_row[bmaps[i].bitmap]', 'proof_row(bmaps[i].bitmap,state->dest,room)')
    common=r'''loop invariant 0 <= i <= cnt;
     loop invariant \base_addr(d)==\base_addr(state->dest);
     loop invariant 0 <= d-state->dest <= prefix[i];
     loop invariant 0 <= s-chunk_src <= state->src_end-chunk_src;
     loop invariant \base_addr(s)==\base_addr(chunk_src);
     loop invariant \forall integer q; 0 <= q < cnt ==> prefix[q+1]==prefix[q]+pc(bmaps[q].bitmap);
     loop invariant \forall integer q; 0 <= q <= cnt ==> 0 <= prefix[q] <= 8*q && prefix[q]<=prefix[cnt];
    '''
    body=body.replace('        for(; i + 1 < cnt; ++i)',r'''        /*@ '''+common+r'''
     loop invariant s==chunk_src+8*i;
     loop assigns i,d,s,state->dest[0 .. room-1];
     loop variant cnt-i;
     */
            for(; i + 1 < cnt; ++i)''')
    body=body.replace('    for(; i < cnt; ++i)',r'''    /*@ '''+common+r'''
     loop invariant i<cnt ? s==chunk_src+8*i : s==state->src_end;
     loop assigns i,j,d,s,state->dest[0 .. room-1];
     loop variant cnt-i;
     */
        for(; i < cnt; ++i)''')
    # Insert the loop contract at the invariant loop start, not at a
    # condition that the unsafe mutation intentionally changes.
    assert body.count('        for(j = 0;')==1
    body=body.replace('        for(j = 0;',r'''        /*@ loop invariant 0 <= j <= 8;
 loop invariant s==chunk_src+8*i+j;
 loop invariant \base_addr(d)==\base_addr(state->dest);
 loop invariant 0 <= d-state->dest <= prefix[i]+consumed(bm,j);
 loop invariant 0 <= s-chunk_src <= state->src_end-chunk_src;
 loop invariant prefix[i+1]==prefix[i]+pc(bm);
 loop assigns j,d,s,state->dest[0 .. room-1];
 loop variant 8-j;
 */
        for(j = 0;''')
    old='            if(bm >> j & 1)\n                *d++ = *s;'
    assert body.count(old)==1
    body=body.replace(old,r'''        {
            proof_literal_bit_step(bm,j);
            if(bm >> j & 1)
                *d++ = *s;
        }''')
    # Preserve source/read and cursor fields as well as the shared metadata span.
    span=SPAN.replace('&state->dest,','&state->src, &state->src_end, &state->read, &state->dest,')
    g=protect_span(generate_totals(s)+models+body,s,span=span)
    return g


def main():
    import argparse
    import concurrent.futures
    from wp_common import verify, witness
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-literal-writer')
    output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_emit_literals','proof_trial_destination']
    runtime=r'''#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "libzbitmap.c"
static struct zbm_compress_state state;
static uint8_t expected[CRUSHLZBITMAP_CHUNK_SIZE];
int main(void) {
 unsigned cases=0;
 for(int cnt=0;cnt<=ZBM_MAX_BITMAP_COUNT;++cnt) for(int mode=0;mode<4;++mode)
 for(int partial=0;partial<2;++partial) {
  int tail=partial ? 1+cnt%8 : 8;
  int size=cnt==0?0:8*(cnt-1)+tail;
  uint8_t *src=malloc((size_t)(size?size:1));assert(src);
  for(int i=0;i<size;++i) src[i]=(uint8_t)(i*13+mode*29);
  int total=0,actual=0;
  for(int i=0;i<cnt;++i) {
   unsigned bm=mode==0?0:mode==1?255:mode==2?(unsigned)i&255:((unsigned)i*17)^((unsigned)i>>3);
   state.bitmaps[i].bitmap=(uint8_t)bm;
   state.bitmaps[i].period_bytecnt=(uint8_t)(i%3);
   for(int j=0;j<8;++j) if((state.bitmaps[i].bitmap>>j)&1) {
    ++total;
    if(8*i+j<size) expected[actual++]=src[8*i+j];
   }
  }
  for(int capacity=0;capacity<3;++capacity) {
   int room=capacity==0?total+8:capacity==1?total:total-1;
   if(room<0) continue;
   for(int known=0;known<2;++known) for(int internal=0;internal<2;++internal) {
    if(internal && room+16>ZBM_META_SCRATCH_SIZE) continue;
    uint8_t *storage=internal?state.meta_scratch:malloc((size_t)room+16);
    assert(storage);memset(storage,0xee,(size_t)room+16);
    state.bmp_cnt=cnt;state.src=src;state.src_end=src+size;state.read=23;
    state.dest=storage+8;state.dest_end=state.dest+room;state.written=17;
    int status=zbm_emit_literals(&state,src,known?total:-1);
    if(room<total) {
     assert(status==ZBM_CANT_COMPRESS);assert(state.dest==storage+8);
     assert(state.src==src && state.read==23 && state.written==17);
     for(int i=0;i<room+16;++i) assert(storage[i]==0xee);
    } else {
     assert(status==0);assert(state.dest==storage+8+actual);
     assert(state.written==(unsigned)(17+actual));
     assert(state.src==src+size && state.read==(unsigned)size);
     assert(memcmp(storage+8,expected,(size_t)actual)==0);
    }
    for(int i=0;i<8;++i) assert(storage[i]==0xee && storage[8+room+i]==0xee);
    if(!internal) free(storage);
    ++cases;
   }
  }
  free(src);
 }
 printf("literal writer independent oracle: %u cases passed\n",cases);
}
'''
    witness(output,runtime)
    witness(output,runtime,native=True)
    verify('literal_writer',generate(source),output,functions,135)
    if args.mutants:
        variants=[
            ('missing_bulk_padding','if(total + 8 <= room)', 'if(total <= room)'),
            ('missing_source_end','j < 8 && s != state->src_end','j < 8'),
            ('missing_size_rejection','if(total > room)', 'if(total > room+1)'),
        ]
        def mutation(item):
            name,old,new=item
            a=source.index('static int zbm_emit_literals(')
            b=source.index('#if defined(ZBM_PROOF) && defined(ZBM_PROOF_SELECTOR_VALUES)',a)
            body=source[a:b]
            assert body.count(old)==1, 'mutation site changed'
            verify(name,generate(source[:a]+body.replace(old,new)+source[b:]),output,functions,130,False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(mutation,variants))


if __name__=='__main__':
    main()
