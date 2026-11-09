#!/usr/bin/env python3
"""Selector vector/scalar budget lemmas for exact-capacity composition.

These read-only ghost lemmas connect independently verified CBMC bit helpers
and WP canonical maps/prefix budgets. They do not prove the shipping writer
or the whole encoder. All imported models are specified consequences of
registered helper proofs; standard Typed memory model and strict goal checks.
"""
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True

LEMMAS = r'''
/* Verified CBMC word-index and exact arbitrary-bit window consequences. */
/*@ requires 0 <= index < ZBM_MAX_BITMAP_COUNT;
 assigns \nothing;
 ensures \result == index/64;
 ensures 0 <= \result < ZBM_MAX_BITMAP_COUNT/64;
 ensures (index & 63)==index%64;
*/
int proof_word_index(int index);
/*@ requires shift < 64;
 assigns \nothing;
 ensures \forall integer k; 0 <= k < 16 ==> ((\result >> k)&1)==
  (shift+k<64 ? (word >> (shift+k))&1 : (next >> (shift+k-64))&1);
*/
uint16_t proof_window(uint64_t word,uint64_t next,unsigned shift);
/*@ logic integer flag{L}(uint64_t *array,integer q) = (array[q/64] >> (q%64))&1; */
/*@ requires \valid_read(marked+(0 .. ZBM_MAX_BITMAP_COUNT/64));
 requires 16 <= cnt <= ZBM_MAX_BITMAP_COUNT;
 requires 0 <= i <= cnt-16;
 requires i <= q < i+16;
 assigns \nothing;
 ensures \result==0 ==> flag(marked,q)==0;
*/
static uint16_t proof_zero_window(const uint64_t *marked,int cnt,int i,int q)
{
 (void)q;
 int kk=proof_word_index(i), shift=i&63;
 uint16_t bits=proof_window(marked[kk],marked[kk+1],(unsigned)shift);
 /*@ assert 0 <= q-i < 16; */
 /*@ assert q==64*kk+shift+(q-i); */
 /*@ assert shift+q-i<64 ==> q/64==kk; */
 /*@ assert shift+q-i<64 ==> q%64==shift+q-i; */
 /*@ assert shift+q-i>=64 ==> q/64==kk+1; */
 /*@ assert shift+q-i>=64 ==> q%64==shift+q-i-64; */
 /*@ assert ((bits >> (q-i))&1)==flag(marked,q); */
 return bits;
}


/*@ requires \valid_read(st);
 requires 16 <= st->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
 requires \valid_read(first+(0 .. st->bmp_cnt-1));
 requires \valid_read(last+(0 .. st->bmp_cnt-1));
 requires \valid_read(boundary+(0 .. ZBM_MAX_BITMAP_COUNT/64));
 requires \valid_read(marked+(0 .. ZBM_MAX_BITMAP_COUNT/64));
 requires 0 <= i <= st->bmp_cnt-16;
 requires i <= q < i+16;
 requires bits==0 ==> (\forall integer k; i <= k < i+16 ==> flag(marked,k)==0);
 requires 0 <= first[q] <= q <= last[q] < st->bmp_cnt;
 requires \forall integer j; first[q] <= j <= last[q] ==> st->bmap_nums[j]==st->bmap_nums[q];
 requires \forall integer j; 0 <= j < st->bmp_cnt ==> flag(boundary,j)==
  (j==st->bmp_cnt-1 || st->bmap_nums[j]!=st->bmap_nums[j+1] ? 1 : 0);
 requires \forall integer w,k; 0 <= w <= st->bmp_cnt-4 && w <= k <= w+3 &&
  flag(boundary,w)==0 && flag(boundary,w+1)==0 && flag(boundary,w+2)==0 ==> flag(marked,k)==1;
 assigns \nothing;
 ensures bits==0 ==> last[q]-first[q]<3;
*/
static void proof_short_member(struct zbm_compress_state *st,const int *first,const int *last,
 const uint64_t *boundary,const uint64_t *marked,int i,int q,uint16_t bits)
{
 if(bits==0 && last[q]-first[q]>=3) {
  int w=q-3>first[q]?q-3:first[q];
  /*@ assert 0 <= w <= st->bmp_cnt-4; */
  /*@ assert w <= q <= w+3; */
  /*@ assert first[q] <= w && w+3 <= last[q]; */
  /*@ assert flag(boundary,w)==0; */
  /*@ assert flag(boundary,w+1)==0; */
  /*@ assert flag(boundary,w+2)==0; */
  /*@ assert flag(marked,q)==1; */
  /*@ assert flag(marked,q)==0; */
  /*@ assert \false; */
 }
}

/*@ requires 16 <= cnt <= ZBM_MAX_BITMAP_COUNT;
 requires 0 <= i <= cnt-16;
 requires \valid_read(first+(0 .. cnt-1));
 requires \valid_read(last+(0 .. cnt-1));
 requires \valid_read(prefix+(0 .. cnt));
 requires \forall integer q; 0 <= q < cnt ==> 0 <= first[q] <= q <= last[q] < cnt;
 requires \forall integer q,j; 0 <= q < cnt && first[q] <= j <= last[q] ==> first[j]==first[q] && last[j]==last[q];
 requires \forall integer q; i <= q < i+16 ==> last[q]-first[q]<3;
 requires \forall integer q; 0 <= q < cnt && last[q]-first[q]<3 ==> prefix[q+1]==prefix[q]+1;
 assigns \nothing;
 ensures prefix[i+16]==prefix[i]+16;
 ensures i+16==cnt || first[i+16]==i+16 || last[i+16]-first[i+16]<3;
*/
static void proof_vector_budget(int cnt,int i,const int *first,const int *last,const unsigned *prefix)
{
 int k;
 /*@ loop invariant 0 <= k <= 16;
 loop invariant prefix[i+k]==prefix[i]+k;
 loop assigns k;
 loop variant 16-k;
 */
 for(k=0;k<16;++k) {
  /*@ assert prefix[i+k+1]==prefix[i+k]+1; */
 }
 int e=i+16;
 if(e<cnt && first[e]!=e && last[e]-first[e]>=3) {
  /*@ assert first[e] <= e-1 <= last[e]; */
  /*@ assert first[e-1]==first[e] && last[e-1]==last[e]; */
  /*@ assert last[e-1]-first[e-1]<3; */
  /*@ assert \false; */
 }
}
/*@ requires \valid_read(st);
 requires 1 <= st->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
 requires \valid_read(first+(0 .. st->bmp_cnt-1));
 requires \valid_read(last+(0 .. st->bmp_cnt-1));
 requires \valid_read(boundary+(0 .. ZBM_MAX_BITMAP_COUNT/64));
 requires 0 <= idx <= found < st->bmp_cnt;
 requires 0 <= first[idx] <= idx <= last[idx] < st->bmp_cnt;
 requires \forall integer j; first[idx] <= j <= last[idx] ==> st->bmap_nums[j]==st->bmap_nums[idx];
 requires last[idx]==st->bmp_cnt-1 || st->bmap_nums[last[idx]+1]!=st->bmap_nums[idx];
 requires \forall integer j; 0 <= j < st->bmp_cnt ==> flag(boundary,j)==
  (j==st->bmp_cnt-1 || st->bmap_nums[j]!=st->bmap_nums[j+1] ? 1 : 0);
 requires flag(boundary,found)==1;
 requires \forall integer j; idx <= j < found ==> flag(boundary,j)==0;
 assigns \nothing;
 ensures found==last[idx];
*/
static void proof_search_end(struct zbm_compress_state *st,const int *first,const int *last,
 const uint64_t *boundary,int idx,int found)
{
 if(found<last[idx]) {
  /*@ assert st->bmap_nums[found]==st->bmap_nums[idx]; */
  /*@ assert st->bmap_nums[found+1]==st->bmap_nums[idx]; */
  /*@ assert flag(boundary,found)==0; */
  /*@ assert \false; */
 }
 if(found>last[idx]) {
  /*@ assert flag(boundary,last[idx])==1; */
  /*@ assert flag(boundary,last[idx])==0; */
  /*@ assert \false; */
 }
}

/*@ logic integer cost(integer r) = r<4 ? r : 3+(r-4)/15; */
/*@ requires 1 <= cnt <= ZBM_MAX_BITMAP_COUNT;
 requires 0 <= i < cnt;
 requires \valid_read(first+(0 .. cnt-1));
 requires \valid_read(last+(0 .. cnt-1));
 requires \valid_read(prefix+(0 .. cnt));
 requires \forall integer q; 0 <= q < cnt ==> 0 <= first[q] <= q <= last[q] < cnt;
 requires \forall integer q,j; 0 <= q < cnt && first[q] <= j <= last[q] ==> first[j]==first[q] && last[j]==last[q];
 requires \forall integer q; 0 <= q < cnt-1 && last[q]==q ==> first[q+1]==q+1;
 requires first[i]==i || last[i]-first[i]<3;
 requires prefix[last[i]+1]-prefix[i]==
  (last[i]-first[i]<3 ? last[i]-i+1 : first[i]==i ? cost(last[i]-first[i]+1) : 0);
 assigns \nothing;
 ensures prefix[last[i]+1]-prefix[i]==cost(last[i]-i+1);
 ensures last[i]==cnt-1 || first[last[i]+1]==last[i]+1;
*/
static void proof_scalar_budget(int cnt,int i,const int *first,const int *last,const unsigned *prefix)
{
 int e=last[i],r=e-i+1;
 if(r<4) {
  /*@ assert last[i]-first[i]<3; */
  /*@ assert prefix[e+1]-prefix[i]==r; */
 } else {
  /*@ assert last[i]-first[i]>=3; */
  /*@ assert first[i]==i; */
  /*@ assert prefix[e+1]-prefix[i]==cost(r); */
 }
 /*@ assert last[e]==e; */
 if(e<cnt-1) { /*@ assert first[e+1]==e+1; */ }
}
'''


def generate(source, lemmas=LEMMAS):
    end=source.index('static int zbm_write_metadata_3(')
    prefix=source[:end]
    old='static int zbm_nibble_cost_for_run(int r);'
    assert prefix.count(old)==1
    prefix=prefix.replace(old, r'/*@ requires 0 <= r <= ZBM_MAX_BITMAP_COUNT; assigns \nothing; ensures 0 <= \result <= r; */ '+old)
    # The queried window's result is independent of the query. This is needed
    # to export its pointwise postcondition to all sixteen positions for the
    # same actual mask. Other lemmas are void/read-only and need no lifting.
    body=lemmas[lemmas.index('static uint16_t proof_zero_window('):]
    body=body[body.index('{')+1:body.index('return bits;')]
    body=re.sub(r'/\*@.*?\*/','',body,flags=re.S)
    body=body.replace('(void)q;','')
    assert re.search(r'\bq\b',body) is None, 'window query changed runtime result'
    return prefix+lemmas


def main():
    import argparse
    import concurrent.futures
    from wp_common import verify, witness
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-selector-steps')
    output.mkdir(parents=True,exist_ok=True)
    functions=['proof_zero_window','proof_short_member','proof_vector_budget',
               'proof_search_end','proof_scalar_budget']
    runtime=r'''#include <assert.h>
#include <stdio.h>
#include "libzbitmap.c"
static struct zbm_compress_state state;
static int first[ZBM_MAX_BITMAP_COUNT], last[ZBM_MAX_BITMAP_COUNT];
static unsigned prefix[ZBM_MAX_BITMAP_COUNT+1];
int main(void) {
 unsigned checks=0;
 for(int cnt=0;cnt<=ZBM_MAX_BITMAP_COUNT;++cnt) for(int mode=0;mode<4;++mode) {
  state.bmp_cnt=cnt;
  for(int i=0;i<cnt;++i) state.bmap_nums[i]=(uint8_t)(mode==0?14:mode==1?i%15:mode==2?(i/19)%15:((i*17/43)%15));
  prefix[0]=0;
  for(int i=0;i<cnt;) {
   int e=i;while(e+1<cnt && state.bmap_nums[e+1]==state.bmap_nums[i]) ++e;
   unsigned r=(unsigned)(e-i+1),cost=r<4?r:3+(r-4)/15;
   for(int q=i;q<=e;++q) {
    first[q]=i;last[q]=e;
    prefix[q+1]=prefix[q]+(r<4?1:q==i?cost:0);
   }
   i=e+1;
  }
  zbm_build_run_boundaries(&state);
  zbm_build_long_runs_arrays(&state.run_bnd,&state.run_long,cnt);
  for(int i=0;i<cnt;i+=7) {
   int e=zbm_find_run_end(&state.run_bnd,i,cnt);assert(e==last[i]);
   if(first[i]==i || last[i]-first[i]<3)
    assert(prefix[e+1]-prefix[i]==(unsigned)zbm_nibble_cost_for_run(e-i+1));
   if(i+16<=cnt) {
    int k=zbm_selector_word_index(i);assert(k==i/64 && (i&63)==i%64);
    uint16_t mask=zbm_long_run_window(state.run_long[k],state.run_long[k+1],(unsigned)(i&63));
    if(mask==0) {
     for(int q=i;q<i+16;++q) {
      assert(((state.run_long[q/64]>>(q%64))&1)==0);
      assert(last[q]-first[q]<3);
     }
     assert(prefix[i+16]==prefix[i]+16);
     assert(i+16==cnt || first[i+16]==i+16 || last[i+16]-first[i+16]<3);
    }
   }
   ++checks;
  }
 }
 printf("selector step independent oracle: %u checks passed\n",checks);
}
'''
    witness(output,runtime)
    witness(output,runtime,native=True)
    verify('selector_steps',generate(source),output,functions,87)
    if args.mutants:
        variants=[
            ('wrong_word_shift','shift=i&63','shift=i&31'),
            ('missed_member_window','q-3>first[q]?q-3:first[q]', 'q-4>first[q]?q-4:first[q]'),
            ('skipped_prefix_step','for(k=0;k<16;++k)', 'for(k=0;k<16;k+=2)'),
            ('wrong_boundary_conclusion','ensures found==last[idx];', 'ensures found==last[idx]+1;'),
            ('wrong_scalar_budget','ensures prefix[last[i]+1]-prefix[i]==cost(last[i]-i+1);', 'ensures prefix[last[i]+1]-prefix[i]==cost(last[i]-i+1)+1;'),
        ]
        def mutation(item):
            name,old,new=item
            assert LEMMAS.count(old)==1, 'mutation site changed'
            verify(name,generate(source,LEMMAS.replace(old,new)),output,functions,87,False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(mutation,variants))


if __name__=='__main__':
    main()
