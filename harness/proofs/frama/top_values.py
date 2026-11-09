#!/usr/bin/env python3
"""Top-table output shape under initialized, valid use-count prerequisites.

The actual selector algorithm is retained. Standard memmove value semantics
and registered CBMC key arithmetic are explicit dependencies. Strategy callers
must still establish initialized counts and zero reserved-key use counts.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
from wp_common import verify


def generate(source):
    s=source
    a=s.index('static void zbm_find_most_common_bitmaps(')
    b=s.index('/* Total bytes of the first metadata area',a)
    body=s[a:b]
    models=r'''
    /*@ predicate top_key(integer k)= -1<=k<ZBM_POSSIBLE_BMPROTS && (k<0 || k%4<=2);
     predicate live_counts{L}(zbm_usecnt_t *counts)=
      \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS && k%4==3 ==> counts[k]==0;
    */
    /* Pure key selection fact: its body is verified by this harness. */
    /*@ requires 0<=k<ZBM_POSSIBLE_BMPROTS;
     requires \valid_read(counts+(0 .. ZBM_POSSIBLE_BMPROTS-1));
     requires live_counts(counts);
     requires counts[k]!=0;
     assigns \nothing;
     ensures top_key(k);
    */
    static void proof_count_key(const zbm_usecnt_t *counts,int k)
    { (void)counts;(void)k; }
    /* Registered CBMC zbm_encoder_top_bits, query only scalar arithmetic. */
    /*@ requires 0<=k<ZBM_POSSIBLE_BMPROTS;
     assigns \nothing;
     ensures (k&3)==k%4;
     ensures 0<=(k&3)<=3;
     ensures (uint8_t)(k&3)==(k&3);
    */
    void proof_low_bits(int k);
    /* Standard memmove on whole top entries: overlap is allowed and values come
       from the pre-call source. No codec helper algorithm is substituted. */
    /*@ requires n%sizeof(*d)==0;
     requires n<=ZBM_BITMAP_COUNT*sizeof(*d);
     requires \valid(d+(0 .. n/sizeof(*d)-1));
     requires \valid_read(src+(0 .. n/sizeof(*d)-1));
     assigns d[0 .. n/sizeof(*d)-1] \from src[0 .. n/sizeof(*d)-1];
     ensures \forall integer k; 0<=k<n/sizeof(*d) ==> d[k].bmprot==\old(src[k].bmprot) && d[k].usecnt==\old(src[k].usecnt);
    */
    void proof_top_move(struct top_bmap *d,const struct top_bmap *src,size_t n);
    /* Query-independent shift consequence of top_shift's 16/16 proof.
       Original d/src/n expressions are evaluated and their relationship checked. */
    /*@ requires \valid(tops+(0 .. ZBM_BITMAP_COUNT-1));
     requires 0<=i<ZBM_BITMAP_COUNT;
     requires d==&tops[i+1] && src==&tops[i];
     requires n==(size_t)(ZBM_BITMAP_COUNT-i-1)*sizeof(tops[i]);
     requires \forall integer j; 0<=j<ZBM_BITMAP_COUNT ==> top_key(tops[j].bmprot);
     assigns tops[i+1 .. ZBM_BITMAP_COUNT-1];
     ensures \forall integer j; 0<=j<ZBM_BITMAP_COUNT ==> top_key(tops[j].bmprot);
    */
    void proof_top_shift(struct top_bmap *d,const struct top_bmap *src,size_t n,struct top_bmap *tops,int i);
    #define memmove(d,s,n) proof_top_shift(d,s,n,tops,i)
    /*@ requires \valid(state);
     requires live_counts(&state->usecnts[0]);
     assigns state->top_bitmaps[0 .. ZBM_BITMAP_COUNT-1],state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1];
     ensures \forall integer k; 0<=k<ZBM_BITMAP_COUNT ==> state->top_bitmaps[k].period_bytecnt<=2;
     ensures live_counts(&state->usecnts[0]);
    */
    '''
    old='    for(i = 0; i < ZBM_BITMAP_COUNT; ++i)'
    assert body.count(old)==2
    body=body.replace(old,r'''    /*@ loop invariant 0<=i<=ZBM_BITMAP_COUNT;
     loop invariant \forall integer j; 0<=j<i ==> top_key(tops[j].bmprot) && tops[j].usecnt==0;
     loop assigns i,tops[0 .. ZBM_BITMAP_COUNT-1];
     loop variant ZBM_BITMAP_COUNT-i;
     */
    '''+old,1)
    old='    for(bmprot = 0; bmprot < ZBM_POSSIBLE_BMPROTS; ++bmprot)'
    assert body.count(old)==1
    body=body.replace(old,r'''    /*@ loop invariant 0<=bmprot<=ZBM_POSSIBLE_BMPROTS;
     loop invariant \forall integer j; 0<=j<ZBM_BITMAP_COUNT ==> top_key(tops[j].bmprot);
     loop invariant live_counts(&state->usecnts[0]);
     loop invariant \separated(state,tops+(0 .. ZBM_BITMAP_COUNT-1));
     loop assigns bmprot,i,tops[0 .. ZBM_BITMAP_COUNT-1];
     loop variant ZBM_POSSIBLE_BMPROTS-bmprot;
     */
    '''+old)
    old='        for(i = 0; tops[i].usecnt >= usecnt; ++i)'
    assert body.count(old)==1
    body=body.replace(old,r'''        /*@ loop invariant 0<=i<ZBM_BITMAP_COUNT;
     loop invariant tops[ZBM_BITMAP_COUNT-1].usecnt<usecnt;
     loop assigns i;
     loop variant ZBM_BITMAP_COUNT-i;
     */
    '''+old)
    old='    for(i = 0; i < ZBM_BITMAP_COUNT; ++i)'
    pos=body.rfind(old)
    body=body[:pos]+r'''    /*@ loop invariant 0<=i<=ZBM_BITMAP_COUNT;
     loop invariant \forall integer j; 0<=j<ZBM_BITMAP_COUNT ==> top_key(tops[j].bmprot);
     loop invariant \forall integer j; 0<=j<i ==> state->top_bitmaps[j].period_bytecnt<=2;
     loop invariant live_counts(&state->usecnts[0]);
     loop assigns i,state->top_bitmaps[0 .. ZBM_BITMAP_COUNT-1],state->usecnts[0 .. ZBM_POSSIBLE_BMPROTS-1];
     loop variant ZBM_BITMAP_COUNT-i;
     */
    '''+body[pos:]
    old='        /* tops[] is sorted descending'
    assert body.count(old)==1
    body=body.replace(old,r'        proof_count_key(state->usecnts,bmprot);'+'\n'+old)
    old='        tops[i].bmprot = bmprot'
    assert body.count(old)==1
    body=body.replace(old,r"""        /*@ assert \forall integer j; 0<=j<ZBM_BITMAP_COUNT ==> top_key(tops[j].bmprot); */
    """+old)
    old='        state->top_bitmaps[i].period_bytecnt = (uint8_t)(tops[i].bmprot & 3);'
    assert body.count(old)==1
    body=body.replace(old,'        proof_low_bits(tops[i].bmprot);\n'+old)
    prefix=s[:a]
    old='static int zbm_nibble_cost_for_run(int r);'
    assert prefix.count(old)==1
    prefix=prefix.replace(old,r'/*@ requires 0<=r<=ZBM_MAX_BITMAP_COUNT; assigns \nothing; ensures 0<=\result<=r; */ '+old)
    g=prefix+models+body
    return g

SHIFT = r'''
/*@ requires \valid(tops+(0 .. ZBM_BITMAP_COUNT-1));
 requires 0<=i<ZBM_BITMAP_COUNT;
 requires 0<=q<ZBM_BITMAP_COUNT;
 requires \forall integer j; 0<=j<ZBM_BITMAP_COUNT ==> top_key(tops[j].bmprot);
 assigns tops[i+1 .. ZBM_BITMAP_COUNT-1];
 ensures top_key(tops[q].bmprot);
*/
static void proof_shift(struct top_bmap *tops,int i,int q)
{
 (void)q;
 /*@ assert ((size_t)(ZBM_BITMAP_COUNT-i-1)*sizeof(tops[i]))/sizeof(tops[i])==ZBM_BITMAP_COUNT-i-1; */
 memmove(&tops[i+1],&tops[i],(size_t)(ZBM_BITMAP_COUNT-i-1)*sizeof(tops[i]));
 /*@ assert q<=i ==> tops[q].bmprot==\at(tops[q].bmprot,Pre); */
 /*@ assert q>i ==> tops[q].bmprot==\at(tops[q-1].bmprot,Pre); */

}
'''


def generate_shift(source):
    g=generate(source)
    g=g[:g.index(r'/*@ requires \valid(state);')]
    a=g.index('/* Query-independent shift consequence')
    b=g.index('#define memmove',a)
    b=g.index('\n',b)
    g=g[:a]+'#define memmove(d,s,n) proof_top_move(d,s,n,q-i-1)'+g[b:]
    old='void proof_top_move(struct top_bmap *d,const struct top_bmap *src,size_t n);'
    assert g.count(old)==1
    g=g.replace(old,'void proof_top_move(struct top_bmap *d,const struct top_bmap *src,size_t n,int query);')
    old=r' ensures \forall integer k; 0<=k<n/sizeof(*d) ==> d[k].bmprot==\old(src[k].bmprot) && d[k].usecnt==\old(src[k].usecnt);'
    assert g.count(old)==1
    # A queried instance of the same standard memmove semantics; query affects
    # neither the footprint nor the bytes copied. Its arbitrary value permits
    # lifting the verified wrapper result to every protected top-table entry.
    g=g.replace(old,old+r'''
 ensures 0<=query<n/sizeof(*d) ==> d[query].bmprot==\old(src[query].bmprot);
''')
    original='memmove(&tops[i + 1], &tops[i], (size_t)(ZBM_BITMAP_COUNT - i - 1) * sizeof(tops[i]));'
    assert source.count(original)==1, 'shipping shift expression changed'
    return g+SHIFT


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-top-values')
    output.mkdir(parents=True,exist_ok=True)
    verify('top_shift',generate_shift(source),output,['proof_shift'],16,split=True)
    functions=['proof_count_key','zbm_find_most_common_bitmaps']
    verify('top_values',generate(source),output,functions,166,split=True)
    if args.mutants:
        old='state->top_bitmaps[i].period_bytecnt = (uint8_t)(tops[i].bmprot & 3);'
        assert source.count(old)==1
        bad=source.replace(old,old+' state->top_bitmaps[i].period_bytecnt = 3;')
        verify('reserved_period_count',generate(bad),output,functions,166,False,split=True)
        old='tops[i].bmprot = bmprot;'
        assert source.count(old)==1
        bad=source.replace(old,'tops[i].bmprot = bmprot | 3;')
        verify('reserved_selected_key',generate(bad),output,functions,166,False,split=True)


if __name__=='__main__':
    main()
