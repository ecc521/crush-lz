#!/usr/bin/env python3
"""Verified canonical run maps and selector budgets for tight-capacity work.

These are read-only-query proofs of ghost bookkeeping, not a proof of the
shipping tight-capacity writer or the whole encoder. Queries occur only in
contracts/annotations and void casts, so the proved pointwise postconditions
apply to every valid query for the same computed arrays.
"""
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True

MODELS = r'''
/* Registered CBMC run_values plus num==nums[idx] gives this complete run
   contract; initial block equality is supplied by the caller. */
/*@ requires \valid_read(st);
 requires 1 <= st->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
 requires 0 <= idx < st->bmp_cnt;
 requires num == st->bmap_nums[idx];
 requires \valid(next);
 requires \separated(st,next);
 assigns *next;
 ensures 1 <= \result <= st->bmp_cnt-idx;
 ensures \forall integer q; idx <= q < idx+\result ==> st->bmap_nums[q]==num;
 ensures idx+\result == st->bmp_cnt || (*next == st->bmap_nums[idx+\result] && *next != num);
*/
int proof_run(struct zbm_compress_state *st, int idx, int num, int *next);
/*@ requires 1 <= r <= ZBM_MAX_BITMAP_COUNT;
 assigns \nothing;
 ensures 1 <= \result <= r;
 ensures \result == (r < 4 ? r : 3+(r-4)/15);
*/
int proof_cost(int r);
/*@ logic integer cost(integer r) = r < 4 ? r : 3+(r-4)/15; */

'''

MAP = r'''
/*@ requires \valid_read(st);
 requires 0 <= st->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
 requires 0 <= q < (st->bmp_cnt==0 ? 1 : st->bmp_cnt);
 requires 0 <= v < (st->bmp_cnt==0 ? 1 : st->bmp_cnt);
 requires \valid(first+(0 .. st->bmp_cnt-1));
 requires \valid(last+(0 .. st->bmp_cnt-1));
 requires \separated(st,first+(0 .. st->bmp_cnt-1),last+(0 .. st->bmp_cnt-1));
 assigns first[0 .. st->bmp_cnt-1],last[0 .. st->bmp_cnt-1];
 ensures  0 <= q < st->bmp_cnt ==> 0 <= first[q] <= q <= last[q] < st->bmp_cnt;
 ensures  0 <= q < st->bmp_cnt && first[q] <= v <= last[q] ==> st->bmap_nums[v]==st->bmap_nums[q];
 ensures  0 <= q < st->bmp_cnt ==> first[q]==0 || st->bmap_nums[first[q]-1]!=st->bmap_nums[q];
 ensures  0 <= q < st->bmp_cnt ==> last[q]==st->bmp_cnt-1 || st->bmap_nums[last[q]+1]!=st->bmap_nums[q];
 ensures  0 <= q < st->bmp_cnt && first[q] <= v <= last[q] ==> first[v]==first[q] && last[v]==last[q];
 ensures  0 <= q < st->bmp_cnt-1 && last[q]==q ==> first[q+1]==q+1;
*/
static void proof_canonical_map(struct zbm_compress_state *st,int *first,int *last,int q,int v)
{
 (void)q;(void)v;
 int cnt=st->bmp_cnt,i=0;
 /*@ loop invariant 0 <= i <= cnt;
 loop invariant  0 <= q < i ==> 0 <= first[q] <= q <= last[q] < i;
 loop invariant  0 <= q < i && first[q] <= v <= last[q] ==> st->bmap_nums[v]==st->bmap_nums[q];
 loop invariant  0 <= q < i ==> first[q]==0 || st->bmap_nums[first[q]-1]!=st->bmap_nums[q];
 loop invariant  0 <= q < i ==> last[q]==cnt-1 || st->bmap_nums[last[q]+1]!=st->bmap_nums[q];
 loop invariant  0 <= q < i && first[q] <= v <= last[q] ==> first[v]==first[q] && last[v]==last[q];
 loop invariant  0 <= q < i-1 && last[q]==q ==> first[q+1]==q+1;
 loop invariant i==0 || last[i-1]==i-1;
 loop invariant i==0 || i==cnt || st->bmap_nums[i-1]!=st->bmap_nums[i];
 loop assigns i,first[0 .. cnt-1],last[0 .. cnt-1];
 loop variant cnt-i;
 */
 while(i<cnt) {
  int num=st->bmap_nums[i],next=num;
  int r=proof_run(st,i,num,&next),e=i+r;
  int j=0;
  /*@ loop invariant 0 <= j <= r;
  loop invariant j==0 || last[i+j-1]==e-1;
  loop invariant i <= q < i+j ==> first[q]==i && last[q]==e-1;
  loop invariant i <= v < i+j ==> first[v]==i && last[v]==e-1;
  loop invariant i <= q+1 < i+j ==> first[q+1]==i && last[q+1]==e-1;
  loop invariant  0 <= q < i ==> 0 <= first[q] <= q <= last[q] < i;
  loop invariant  0 <= q < i && first[q] <= v <= last[q] ==> st->bmap_nums[v]==st->bmap_nums[q];
  loop invariant  0 <= q < i ==> first[q]==0 || st->bmap_nums[first[q]-1]!=st->bmap_nums[q];
  loop invariant  0 <= q < i ==> last[q]==cnt-1 || st->bmap_nums[last[q]+1]!=st->bmap_nums[q];
  loop invariant  0 <= q < i && first[q] <= v <= last[q] ==> first[v]==first[q] && last[v]==last[q];
  loop invariant  0 <= q < i-1 && last[q]==q ==> first[q+1]==q+1;
  loop invariant i==0 || last[i-1]==i-1;
  loop assigns j,first[i .. e-1],last[i .. e-1];
  loop variant r-j;
  */
  while(j<r) {first[i+j]=i;last[i+j]=e-1;++j;}
  i=e;
 }
}
'''

BUDGET = r'''
/*@ requires 0 <= cnt <= ZBM_MAX_BITMAP_COUNT;
 requires 0 <= q < (cnt==0 ? 1 : cnt);
 requires 0 <= p <= cnt;
 requires \valid_read(first+(0 .. cnt-1));
 requires \valid_read(last+(0 .. cnt-1));
 requires \valid(prefix+(0 .. cnt));
 requires \separated(prefix+(0 .. cnt),first+(0 .. cnt-1),last+(0 .. cnt-1));
 requires \forall integer q; 0 <= q < cnt ==> 0 <= first[q] <= q <= last[q] < cnt;
 requires \forall integer q,j; 0 <= q < cnt && first[q] <= j <= last[q] ==> first[j]==first[q] && last[j]==last[q];
 requires \forall integer q; 0 <= q < cnt-1 && last[q]==q ==> first[q+1]==q+1;
 assigns prefix[0 .. cnt];
 ensures prefix[0]==0;
 ensures 0 <= prefix[p] <= prefix[cnt] <= cnt;
 ensures 0 <= q < cnt ==> prefix[q+1]-prefix[q] ==
   (last[q]-first[q]<3 ? 1 : first[q]==q ? cost(last[q]-first[q]+1) : 0);
 ensures 0 <= q < cnt ==> prefix[last[q]+1]-prefix[q] ==
   (last[q]-first[q]<3 ? last[q]-q+1 : first[q]==q ? cost(last[q]-first[q]+1) : 0);
*/
static void proof_canonical_budget(int cnt,const int *first,const int *last,unsigned *prefix,int q,int p)
{
 (void)q;(void)p;
 int i=0;prefix[0]=0;
 /*@ loop invariant 0 <= i <= cnt;
 loop invariant i==cnt || first[i]==i;
 loop invariant prefix[0]==0;
 loop invariant 0 <= prefix[i] <= i;
 loop invariant p <= i ==> 0 <= prefix[p] <= prefix[i];
 loop invariant 0 <= q < i ==> last[q]<i;
 loop invariant 0 <= q < i ==> prefix[q+1]-prefix[q] ==
   (last[q]-first[q]<3 ? 1 : first[q]==q ? cost(last[q]-first[q]+1) : 0);
 loop invariant 0 <= q < i ==> prefix[last[q]+1]-prefix[q] ==
   (last[q]-first[q]<3 ? last[q]-q+1 : first[q]==q ? cost(last[q]-first[q]+1) : 0);
 loop assigns i,prefix[0 .. cnt];
 loop variant cnt-i;
 */
 while(i<cnt) {
  int r=last[i]-i+1,c=proof_cost(r),e=i+r;
  unsigned before=prefix[i];int j=0;
  /*@ assert \forall integer k; i <= k < e ==> first[k]==i && last[k]==e-1; */
  /*@ loop invariant 0 <= j <= r;
  loop invariant prefix[i]==before;
  loop invariant 0 <= before <= i;
  loop invariant prefix[i+j]==before+(r<4 ? j : j==0 ? 0 : c);
  loop invariant p <= i ==> 0 <= prefix[p] <= before;
  loop invariant i < q <= i+j ==> prefix[q]==before+(r<4 ? q-i : c);
  loop invariant i < q+1 <= i+j ==> prefix[q+1]==before+(r<4 ? q+1-i : c);
  loop invariant i < last[q]+1 <= i+j ==> prefix[last[q]+1]==before+(r<4 ? last[q]+1-i : c);
  loop invariant i < p <= i+j ==> prefix[p]==before+(r<4 ? p-i : c);
  loop invariant 0 <= q < i ==> prefix[q+1]-prefix[q] ==
    (last[q]-first[q]<3 ? 1 : first[q]==q ? cost(last[q]-first[q]+1) : 0);
  loop invariant 0 <= q < i ==> prefix[last[q]+1]-prefix[q] ==
    (last[q]-first[q]<3 ? last[q]-q+1 : first[q]==q ? cost(last[q]-first[q]+1) : 0);
  loop assigns j,prefix[i+1 .. e];
  loop variant r-j;
  */
  while(j<r) {prefix[i+j+1]=before+(r<4 ? j+1 : c);++j;}
  /*@ assert last[e-1]==e-1; */
  if(e<cnt) { /*@ assert first[e]==e; */ }
  i=e;
 }
}
'''


def query_independence(body, function, names):
    # Remove only ACSL annotations, then inspect the actual C implementation.
    c = re.sub(r'/\*@.*?\*/', '', body, flags=re.S)
    c = c[c.index(function):]
    c = c[c.index('{'):]
    for name in names:
        c = c.replace('(void)' + name + ';', '')
        assert re.search(r'\b' + name + r'\b', c) is None, 'query influences C implementation'


def generate(source):
    query_independence(MAP, 'proof_canonical_map', ['q', 'v'])
    query_independence(BUDGET, 'proof_canonical_budget', ['q', 'p'])
    start = source.index('/* Exact byte count zbm_write_metadata_3()')
    return source[:start] + MODELS + MAP + BUDGET


def main():
    import argparse
    import concurrent.futures
    from wp_common import verify, witness
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    source = Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    generated = generate(source)
    output = Path('harness/build/proofs-frama-selector-budget')
    output.mkdir(parents=True, exist_ok=True)
    functions = ['proof_canonical_map', 'proof_canonical_budget']
    runtime = '#include <stdio.h>\n#include \"libzbitmap.c\"\n' + MODELS + MAP + BUDGET + r'''

int proof_run(struct zbm_compress_state *st,int idx,int num,int *next) { return zbm_run_length(st,idx,num,next); }
int proof_cost(int r) { return zbm_nibble_cost_for_run(r); }
static struct zbm_compress_state st;
static unsigned prefix[4097];
static int first[4096],last[4096],expected_first[4096],expected_last[4096];
int main(void) {
 unsigned cases=0;
 for(int cnt=0;cnt<=4096;++cnt) for(int mode=0;mode<4;++mode) {
  st.bmp_cnt=cnt;
  for(int i=0;i<cnt;++i) st.bmap_nums[i]=(uint8_t)(mode==0?14:mode==1?i%15:mode==2?(i/19)%15:(i*17/43)%15);
  for(int i=0;i<cnt;++i) expected_first[i]=i>0 && st.bmap_nums[i]==st.bmap_nums[i-1]?expected_first[i-1]:i;
  for(int i=cnt-1;i>=0;--i) expected_last[i]=i+1<cnt && st.bmap_nums[i]==st.bmap_nums[i+1]?expected_last[i+1]:i;
  proof_canonical_map(&st,first,last,cnt?cnt-1:0,cnt/2);
  proof_canonical_budget(cnt,first,last,prefix,cnt?cnt-1:0,cnt);
  unsigned total=0;
  assert(prefix[0]==0);
  for(int i=0;i<cnt;++i) {
   assert(first[i]==expected_first[i] && last[i]==expected_last[i]);
   int run=expected_last[i]-expected_first[i]+1;
   total+=run<4?1:expected_first[i]==i?3+(run-4)/15:0;
   assert(prefix[i+1]==total && prefix[i]<=prefix[i+1] && total<=(unsigned)cnt);
   int tail=run<4?expected_last[i]-i+1:expected_first[i]==i?3+(run-4)/15:0;
   assert(prefix[last[i]+1]-prefix[i]==(unsigned)tail);
  }
  assert(zbm_metadata_3_bytes(&st)==(ptrdiff_t)((total+1)/2));
  ++cases;
 }
 printf("canonical map/budget/scanner oracle: %u cases passed\n",cases);
}
'''
    witness(output, runtime)
    witness(output, runtime, native=True)

    verify('selector_budget', generated, output, functions, 155)
    if args.mutants:
        variants = [
            ('bad_run_endpoint', 'last[i+j]=e-1;', 'last[i+j]=e;'),
            ('extra_prefix_cost', 'before+(r<4 ? j+1 : c);', 'before+(r<4 ? j+2 : c+1);'),
        ]
        def mutation(item):
            name, old, new = item
            assert generated.count(old) == 1, 'mutation site changed'
            verify(name, generated.replace(old,new), output, functions, 155, False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(mutation, variants))


if __name__ == '__main__':
    main()
