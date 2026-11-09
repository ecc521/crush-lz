#!/usr/bin/env python3
"""The literal selector preflight scanner equals the verified prefix budget.

Ghost parameters provide the canonical maps/budget proved in selector_budget.
Endpoint uniqueness is verified here; the scanner algorithm is unchanged.
This is not the optimized writer or whole encoder safety proof.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
from selector_budget import MODELS


def generate(source):
    s=source
    a=s.index('static ptrdiff_t zbm_metadata_3_bytes(')
    b=s.index('/* Four equal blocks require three consecutive equality edges.',a)
    helpers=MODELS+r'''
    /*@ requires \valid_read(st);
     requires 0 <= idx < st->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
     assigns \nothing;
     ensures \result == st->bmap_nums[idx];
    */
    int proof_number(struct zbm_compress_state *st,int idx);
    #define zbm_bmap_num_for_index(st,i) proof_number(st,i)
    #define zbm_run_length(st,i,n,next) proof_run(st,i,n,next)
    #define zbm_nibble_cost_for_run(r) proof_cost(r)

    /* Endpoint uniqueness from the complete scanner and canonical-map contracts. */
    /*@ requires \valid_read(st);
     requires 0 <= idx <= mapped < st->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
     requires 1 <= r <= st->bmp_cnt-idx;
     requires \forall integer j; idx <= j <= mapped ==> st->bmap_nums[j]==st->bmap_nums[idx];
     requires mapped==st->bmp_cnt-1 || st->bmap_nums[mapped+1]!=st->bmap_nums[idx];
     requires \forall integer j; idx <= j < idx+r ==> st->bmap_nums[j]==st->bmap_nums[idx];
     requires idx+r==st->bmp_cnt || st->bmap_nums[idx+r]!=st->bmap_nums[idx];
     assigns \nothing;
     ensures idx+r==mapped+1;
    */
    static void proof_end_agrees(struct zbm_compress_state *st,int idx,int mapped,int r)
    {
     if(idx+r<=mapped) {
      /*@ assert st->bmap_nums[idx+r]==st->bmap_nums[idx]; */
      /*@ assert st->bmap_nums[idx+r]!=st->bmap_nums[idx]; */
      /*@ assert \false; */
     }
     if(idx+r>mapped+1) {
      /*@ assert st->bmap_nums[mapped+1]==st->bmap_nums[idx]; */
      /*@ assert st->bmap_nums[mapped+1]!=st->bmap_nums[idx]; */
      /*@ assert \false; */
     }
    }

    /* The arrays are verified bookkeeping, not assumed prefix equations. Their
       universal properties follow from selector_budget's independent queries. */
    /*@ requires \valid_read(state);
     requires 0 <= state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
     requires \valid_read(first+(0 .. state->bmp_cnt-1));
     requires \valid_read(last+(0 .. state->bmp_cnt-1));
     requires \valid_read(prefix+(0 .. state->bmp_cnt));
     requires \separated(state,first+(0 .. state->bmp_cnt-1),last+(0 .. state->bmp_cnt-1),prefix+(0 .. state->bmp_cnt));
     requires \forall integer q; 0 <= q < state->bmp_cnt ==> 0 <= first[q] <= q <= last[q] < state->bmp_cnt;
     requires \forall integer q,j; 0 <= q < state->bmp_cnt && first[q] <= j <= last[q] ==> state->bmap_nums[j]==state->bmap_nums[q];
     requires \forall integer q; 0 <= q < state->bmp_cnt ==> last[q]==state->bmp_cnt-1 || state->bmap_nums[last[q]+1]!=state->bmap_nums[q];
     requires \forall integer q,j; 0 <= q < state->bmp_cnt && first[q] <= j <= last[q] ==> first[j]==first[q] && last[j]==last[q];
     requires \forall integer q; 0 <= q < state->bmp_cnt-1 && last[q]==q ==> first[q+1]==q+1;
     requires prefix[0]==0;
     requires \forall integer q; 0 <= q <= state->bmp_cnt ==> 0 <= prefix[q] <= prefix[state->bmp_cnt] <= state->bmp_cnt;
     requires \forall integer q; 0 <= q < state->bmp_cnt ==> prefix[last[q]+1]-prefix[q] ==
       (last[q]-first[q]<3 ? last[q]-q+1 : first[q]==q ? cost(last[q]-first[q]+1) : 0);
     assigns \nothing;
     ensures \result==(prefix[state->bmp_cnt]+1)/2;
     ensures 0 <= \result <= (state->bmp_cnt+1)/2;
    */
    '''
    body=s[a:b]
    assert body.count('for(i = 0; i < state->bmp_cnt; i += repeat)') == 1
    assert body.count('repeat = zbm_run_length(state, i, num, &next);') == 1
    body=body.replace('zbm_metadata_3_bytes(struct zbm_compress_state *state)', 'zbm_metadata_3_bytes(struct zbm_compress_state *state,const int *first,const int *last,const unsigned *prefix)')
    body=body.replace('    for(i = 0; i < state->bmp_cnt; i += repeat)',r'''    /*@ loop invariant 0 <= i <= state->bmp_cnt;
     loop invariant nibbles==prefix[i];
     loop invariant 0 <= nibbles <= state->bmp_cnt;
     loop invariant i==state->bmp_cnt || first[i]==i;
     loop invariant i==state->bmp_cnt || num==state->bmap_nums[i];
     loop assigns i,repeat,num,nibbles;
     loop variant state->bmp_cnt-i;
    */
        for(i = 0; i < state->bmp_cnt; i += repeat)''')
    body=body.replace('        repeat = zbm_run_length(state, i, num, &next);',r'''        repeat = zbm_run_length(state, i, num, &next);
        proof_end_agrees(state,i,last[i],repeat);
            /*@ assert last[i+repeat-1]==i+repeat-1; */
            if(i+repeat<state->bmp_cnt) {
                /*@ assert first[i+repeat]==i+repeat; */
            }
            /*@ assert i+repeat==last[i]+1; */''')
    return s[:a]+helpers+body


def main():
    import argparse
    import concurrent.futures
    from wp_common import verify
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-selector-preflight')
    output.mkdir(parents=True,exist_ok=True)
    functions=['proof_end_agrees','zbm_metadata_3_bytes']

    def prove(name,text,expected=True):
        verify(name,generate(text),output,functions,65,expected)

    prove('selector_preflight',source)
    if args.mutants:
        variants=[
            ('extra_run_cost','nibbles += zbm_nibble_cost_for_run(repeat);',
             'nibbles += zbm_nibble_cost_for_run(repeat) + 1;'),
            ('wrong_next_selector','        num = next;', '        num = 255;'),
        ]
        def mutation(item):
            name,old,new=item
            # Restrict the mutation to the actual scanner, excluding callers.
            a=source.index('static ptrdiff_t zbm_metadata_3_bytes(')
            b=source.index('/* Four equal blocks require',a)
            body=source[a:b]
            assert body.count(old)==1, 'mutation site changed'
            prove(name,source[:a]+body.replace(old,new)+source[b:],False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(mutation,variants))


if __name__=='__main__':
    main()
