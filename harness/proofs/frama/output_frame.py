#!/usr/bin/env python3
"""A query-independent frame theorem for bounded encoder output effects.

The abstract havoc declaration permits ANY changes inside *out and the output
interval, and no other changes. The lemma derives preservation of protected
bytes/words from separation and the ordinary ACSL assigns semantics. This is
not a claim that a codec helper has the write frame; registered helper proofs
must establish each actual helper's frame before this theorem is used.
"""
from pathlib import Path
import re
import sys
sys.dont_write_bytecode=True

MODEL = r'''
/* Abstract all possible updates within the helper's declared write frame.
   This model adds no postconditions or memory effects outside that frame. */
/*@ requires \valid(out);
 requires 0 <= n <= ZBM_MAX_BITMAP_COUNT;
 requires \valid(d+(0 .. n-1));
 requires \separated(out,d+(0 .. n-1));
 assigns *out,d[0 .. n-1] \from *out,d[0 .. n-1];
*/
void proof_havoc(struct zbm_nybl_out *out,uint8_t *d,int n);
/*@ requires \valid(out);
 requires 0 <= n <= ZBM_MAX_BITMAP_COUNT;
 requires \valid(d+(0 .. n-1));
 requires \valid_read(nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));
 requires \valid_read(bnd+(0 .. ZBM_MAX_BITMAP_COUNT/64));
 requires \valid_read(lng+(0 .. ZBM_MAX_BITMAP_COUNT/64));
 requires 0 <= q <= ZBM_MAX_BITMAP_COUNT+15;
 requires 0 <= k <= ZBM_MAX_BITMAP_COUNT/64;
 requires \separated(out,d+(0 .. n-1),nums+(0 .. ZBM_MAX_BITMAP_COUNT+15),bnd+(0 .. ZBM_MAX_BITMAP_COUNT/64),lng+(0 .. ZBM_MAX_BITMAP_COUNT/64));
 assigns *out,d[0 .. n-1] \from *out,d[0 .. n-1];
 ensures nums[q]==\old(nums[q]);
 ensures bnd[k]==\old(bnd[k]);
 ensures lng[k]==\old(lng[k]);
*/
static void proof_output_frame(struct zbm_nybl_out *out,uint8_t *d,int n,
 const uint8_t *nums,const uint64_t *bnd,const uint64_t *lng,int q,int k)
{
 (void)q;(void)k;
 proof_havoc(out,d,n);
}

/* Any memory effects allowed by the actual long-builder's write frame. */
/*@ requires \valid(marked); assigns (*marked)[0 .. ZBM_MAX_BITMAP_COUNT/64]; */
void proof_havoc_words(uint64_t (*marked)[ZBM_MAX_BITMAP_COUNT/64+1]);
/*@ requires \valid_read(boundary);
 requires \valid(marked);
 requires \valid_read(nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));
 requires 0 <= q <= ZBM_MAX_BITMAP_COUNT+15;
 requires \separated(boundary,marked,nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));
 requires 0 <= k <= ZBM_MAX_BITMAP_COUNT/64;
 assigns (*marked)[0 .. ZBM_MAX_BITMAP_COUNT/64];
 ensures (*boundary)[k]==\old((*boundary)[k]);
 ensures nums[q]==\old(nums[q]);
*/
static void proof_word_frame(const uint64_t (*boundary)[ZBM_MAX_BITMAP_COUNT/64+1],
 uint64_t (*marked)[ZBM_MAX_BITMAP_COUNT/64+1],const uint8_t *nums,int q,int k)
{
 (void)q;(void)k;proof_havoc_words(marked);
}
'''


def generate(source,model=MODEL):
    end=source.index('static int zbm_write_metadata_3(')
    prefix=source[:end]
    old='static int zbm_nibble_cost_for_run(int r);'
    assert prefix.count(old)==1
    prefix=prefix.replace(old,r'/*@ requires 0 <= r <= ZBM_MAX_BITMAP_COUNT; assigns \nothing; ensures 0 <= \result <= r; */ '+old)
    body=model[model.index('static void proof_output_frame'):]
    body=body[body.index('{'):body.index('}\n')+1]
    body=re.sub(r'/\*@.*?\*/','',body,flags=re.S)
    body=body.replace('(void)q;','').replace('(void)k;','')
    assert not re.search(r'\b(?:q|k)\b',body), 'frame effects depend on query'
    word=model[model.index('static void proof_word_frame'):]
    word=word[word.index('{'):word.index('}\n')+1].replace('(void)k;','').replace('(void)q;','')
    assert not re.search(r'\b(?:q|k)\b',word), 'word frame effects depend on query'
    return prefix+model


def main():
    import argparse
    import concurrent.futures
    from wp_common import verify
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-output-frame')
    output.mkdir(parents=True,exist_ok=True)
    functions=['proof_output_frame','proof_word_frame']
    verify('output_frame',generate(source),output,functions,14)
    if args.mutants:
        old=r'requires \separated(out,d+(0 .. n-1),nums+(0 .. ZBM_MAX_BITMAP_COUNT+15),bnd+(0 .. ZBM_MAX_BITMAP_COUNT/64),lng+(0 .. ZBM_MAX_BITMAP_COUNT/64));'
        new=r'requires \separated(out,d+(0 .. n-1),bnd+(0 .. ZBM_MAX_BITMAP_COUNT/64),lng+(0 .. ZBM_MAX_BITMAP_COUNT/64)); requires \separated(out,nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));'
        variants=[('output_may_alias_nums',old,new),
                  ('extra_output_byte','proof_havoc(out,d,n);','proof_havoc(out,d,n+1);'),
                  ('marked_may_alias_boundary',r'requires \separated(boundary,marked,nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));',r'requires \separated(boundary,nums+(0 .. ZBM_MAX_BITMAP_COUNT+15)); requires \separated(marked,nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));')]
        def mutation(item):
            name,old,new=item
            assert MODEL.count(old)==1, 'mutation site changed'
            verify(name,generate(source,MODEL.replace(old,new)),output,functions,14,False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(mutation,variants))


if __name__=='__main__':
    main()
