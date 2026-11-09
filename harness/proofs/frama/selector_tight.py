#!/usr/bin/env python3
"""Shipping selector-writer safety for all capacities, including exact preflight.

Canonical maps and budgets, scanner equality, step and frame consequences come
from the registered CBMC and Frama-C components. Ghost bookkeeping preserves
the shipping algorithm. Strategy and public API callers remain outside scope.
"""
from pathlib import Path
import re
import sys
sys.dont_write_bytecode=True
import selector_wide, selector_budget, selector_steps
from wp_common import verify, witness


def generate(source):
    g=selector_wide.generate(source)
    # Lift verified query-independent bookkeeping to universal contracts.
    maptext=selector_budget.MAP[:selector_budget.MAP.index('static void proof_canonical_map')]
    maptext=re.sub(r' requires 0 <= [qv] < \(st->bmp_cnt==0 \? 1 : st->bmp_cnt\);\n','',maptext)
    maptext=maptext.replace('ensures  0 <= q','ensures \\forall integer q,v; 0 <= q')
    maptext+='void proof_map(struct zbm_compress_state *st,int *first,int *last);\n'
    budgettext=selector_budget.BUDGET[:selector_budget.BUDGET.index('static void proof_canonical_budget')]
    budgettext=re.sub(r' requires 0 <= q < \(cnt==0 \? 1 : cnt\);\n','',budgettext)
    budgettext=budgettext.replace(' requires 0 <= p <= cnt;\n','')
    budgettext=budgettext.replace('ensures 0 <= prefix[p]', 'ensures \\forall integer p; 0 <= p <= cnt ==> 0 <= prefix[p]')
    budgettext=budgettext.replace('ensures 0 <= q < cnt', 'ensures \\forall integer q; 0 <= q < cnt')
    budgettext+='void proof_budget(int cnt,const int *first,const int *last,unsigned *prefix);\n'
    logic=r'''/*@ logic integer cost(integer r)=r<4?r:3+(r-4)/15;
     logic integer flag{L}(uint64_t *array,integer q)=(array[q/64]>>(q%64))&1;
    */
    '''
    start=g.index('    /* Models import consequences')
    g=g[:start]+logic+maptext+budgettext+g[start:]
    g=g.replace('ensures \\result == index/64;', 'ensures \\result == index/64;\n ensures (index & 63)==index%64;')
    # Exact boundaries are registered CBMC boundary_values consequences.
    g=g.replace('     ensures state->bmp_cnt == 0 ||',r'''     ensures \forall integer q; 0 <= q < state->bmp_cnt ==> flag(state->run_bnd,q)==
           (q==state->bmp_cnt-1 || state->bmap_nums[q]!=state->bmap_nums[q+1] ? 1 : 0);
         ensures state->bmp_cnt == 0 ||''')
    g=g.replace('     ensures (*marked)[(cnt+63)/64] == 0;',r'''     ensures (*marked)[(cnt+63)/64] == 0;
         ensures \forall integer w,k; 0 <= w <= cnt-4 && w <= k <= w+3 &&
           flag(&(*boundary)[0],w)==0 && flag(&(*boundary)[0],w+1)==0 && flag(&(*boundary)[0],w+2)==0 ==> flag(&(*marked)[0],k)==1;''')
    # Size scanner contract already verified against canonical prefix bookkeeping.
    a=g.index('    /*@ requires \\valid_read(state);',g.index('uint64_t proof_pack'))
    b=g.index('    /*@ requires \\valid(out);',a)
    from selector_preflight import generate as preflight
    pf=preflight(source)
    x=pf.index('    /* The arrays are verified bookkeeping')
    x=pf.index('    /*@',x);y=pf.index('static ptrdiff_t zbm_metadata_3_bytes',x)
    sizecontract=pf[x:y].replace('    ', '')
    g=g[:a]+sizecontract+'ptrdiff_t proof_size(struct zbm_compress_state *state,const int *first,const int *last,const unsigned *prefix);\n#define zbm_metadata_3_bytes(s) proof_size(s,first,last,prefix)\n'+g[b:]
    # Import pure endpoint and step lemmas; their bodies are verified selector_steps.
    start=g.index("    /* Models import consequences")
    lemmas=selector_steps.LEMMAS
    for name,ret in [('proof_short_member','void'),('proof_vector_budget','void'),('proof_search_end','void'),('proof_scalar_budget','void')]:
     pos=lemmas.index('static '+ret+' '+name+'(');cstart=lemmas.rfind('/*@',0,pos);bend=lemmas.index('\n{',pos)
     decl=lemmas[cstart:bend].replace('static '+ret+' ',ret+' ')+';\n'
     g=g[:start]+decl+g[start:];start+=len(decl)
    # Word/next evaluation retained; zero-mask universal consequence of proof_zero_window.
    a=g.index('    /*@ requires shift < 64; assigns \\nothing; */')
    b=g.index('    /*@ requires \\valid_read(nums',a)
    g=g[:a]+r'''/*@ requires shift < 64;
     requires 16 <= cnt <= ZBM_MAX_BITMAP_COUNT;
     requires 0 <= i <= cnt-16;
     requires \valid_read(marked+(0 .. ZBM_MAX_BITMAP_COUNT/64));
     requires word==marked[i/64] && next==marked[i/64+1] && shift==i%64;
     assigns \nothing;
     ensures \result==0 ==> (\forall integer q; i <= q < i+16 ==> flag(marked,q)==0);
    */
    uint16_t proof_mask(uint64_t word,uint64_t next,unsigned shift,const uint64_t *marked,int cnt,int i);
    #define zbm_long_run_window(w,n,s) proof_mask(w,n,s,lng,cnt,i)
    '''+g[b:]
    g=g.replace('(state->bmp_cnt+1)/2 <= state->dest_end-state->dest', '0 <= state->dest_end-state->dest')
    g=g.replace('     ensures \\result == 0;', '     ensures \\result == 0 || \\result == ZBM_CANT_COMPRESS;')
    g=g.replace('    int proof_emitted=0;', '''    int proof_emitted=0;
        int first[ZBM_MAX_BITMAP_COUNT],last[ZBM_MAX_BITMAP_COUNT];
        unsigned prefix[ZBM_MAX_BITMAP_COUNT+1];
        proof_map(state,first,last);
        proof_budget(state->bmp_cnt,first,last,prefix);''')
    # Replace wide bound with exact prefix invariant and preserve semantic maps.
    g=g.replace('     loop invariant 0 <= proof_emitted <= i;',r'''     loop invariant proof_emitted==prefix[i];
         loop invariant 0 <= proof_emitted <= prefix[cnt] <= cnt;
         loop invariant i==cnt || first[i]==i || last[i]-first[i]<3;
         loop invariant \forall integer q; 0 <= q < cnt ==> 0 <= first[q] <= q <= last[q] < cnt;
         loop invariant \forall integer q,j; 0 <= q < cnt && first[q] <= j <= last[q] ==> nums[j]==nums[q] && first[j]==first[q] && last[j]==last[q];
         loop invariant \forall integer q; 0 <= q < cnt ==> last[q]==cnt-1 || nums[last[q]+1]!=nums[q];
         loop invariant \forall integer q; 0 <= q < cnt-1 && last[q]==q ==> first[q+1]==q+1;
         loop invariant \forall integer q; 0 <= q < cnt && last[q]-first[q]<3 ==> prefix[q+1]==prefix[q]+1;
         loop invariant \forall integer q; 0 <= q < cnt ==> prefix[last[q]+1]-prefix[q]==(last[q]-first[q]<3 ? last[q]-q+1 : first[q]==q ? cost(last[q]-first[q]+1) : 0);
         loop invariant \forall integer q; 0 <= q < cnt ==> flag(state->run_bnd,q)==(q==cnt-1 || nums[q]!=nums[q+1] ? 1 : 0);
         loop invariant \forall integer w,k; 0 <= w <= cnt-4 && w <= k <= w+3 && flag(state->run_bnd,w)==0 && flag(state->run_bnd,w+1)==0 && flag(state->run_bnd,w+2)==0 ==> flag(lng,k)==1;''')
    g=g.replace('     loop invariant 0 <= out.addr-state->dest <= (cnt+1)/2;', '     loop invariant 0 <= out.addr-state->dest <= (prefix[cnt]+1)/2;')
    # Materialize the short-member theorem for each vector position (read-only).
    g=g.replace('                uint64_t pk =',r'''                int q;
                    /*@ loop invariant i <= q <= i+16;
                     loop invariant \forall integer j; i <= j < q ==> last[j]-first[j]<3;
                     loop assigns q;
                     loop variant i+16-q;
                    */
                    for(q=i;q<i+16;++q) proof_short_member(state,first,last,state->run_bnd,lng,i,q,0);
                    proof_vector_budget(cnt,i,first,last,prefix);
                    uint64_t pk =''')
    g=g.replace('            to_write = nums[i];','''            proof_search_end(state,first,last,state->run_bnd,i,e);
                proof_scalar_budget(cnt,i,first,last,prefix);
                to_write = nums[i];''')
    # Search helper's full registered boundary selection contract.
    g=g.replace('     ensures idx <= \\result < cnt;',r'''     ensures idx <= \result < cnt;
         ensures flag(&(*boundary)[0],\result)==1;
         ensures \forall integer q; idx <= q < \result ==> flag(&(*boundary)[0],q)==0;''')

    g=g.replace('     loop invariant proof_emitted==prefix[i];',r"""     loop invariant proof_emitted==prefix[i];
         loop invariant \separated(first+(0 .. cnt-1),last+(0 .. cnt-1),prefix+(0 .. cnt),nums+(0 .. cnt-1),state->dest+(0 .. state->dest_end-state->dest-1));
         loop invariant \separated(state->run_bnd+(0 .. 64),state->run_long+(0 .. 64),state->dest+(0 .. state->dest_end-state->dest-1));""")
    g=g.replace('            to_write = nums[i];',r"""            /*@ assert prefix[e+1]==prefix[i]+cost(e-i+1); */
                to_write = nums[i];""")
    g=g.replace('                proof_emitted += 16;',r"""                /*@ assert prefix[i+16]==prefix[i]+16; */
                    proof_emitted += 16;""")

    g=g.replace('flag(state->run_bnd,','flag(&state->run_bnd[0],')

    # The separately checked word-frame theorem applies to the long-builder's
    # actual marked-only frame under its already required array separation.
    g=g.replace('     ensures (*marked)[(cnt+63)/64] == 0;',r'''     ensures (*marked)[(cnt+63)/64] == 0;
     ensures \forall integer k; 0 <= k <= ZBM_MAX_BITMAP_COUNT/64 ==> (*boundary)[k]==\old((*boundary)[k]);''')
    # These explicit j bounds are redundant with the canonical geometry invariant;
    # they retain its full meaning while simplifying memory-frame instantiation.
    old=r'loop invariant \forall integer q,j; 0 <= q < cnt && first[q] <= j <= last[q] ==> nums[j]==nums[q] && first[j]==first[q] && last[j]==last[q];'
    new=r'''loop invariant \forall integer q,j; 0 <= q < cnt && 0 <= j < cnt && first[q] <= j <= last[q] ==> first[j]==first[q] && last[j]==last[q];
     loop invariant \forall integer q,j; 0 <= q < cnt && 0 <= j < cnt && first[q] <= j <= last[q] ==> nums[j]==nums[q];'''
    assert g.count(old)==1
    g=g.replace(old,new)

    # Mixed word/byte frame consequence: long-builder preserves nums as well
    # as boundary words. Actual helper frame is marked-only, array regions disjoint.
    pos=g.index('    void proof_long(');begin=g.rfind('/*@',0,pos);end=g.index('\n',g.index('#define zbm_build_long_runs_arrays',pos))+1
    old=g[begin:end];new=old.replace('     assigns (*marked)',r'''     requires \valid_read(nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));
     requires \separated(boundary,marked,nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));
         assigns (*marked)''')
    new=new.replace('     ensures (*marked)[(cnt+63)/64] == 0;',r'''     ensures (*marked)[(cnt+63)/64] == 0;
     ensures \forall integer q; 0 <= q <= ZBM_MAX_BITMAP_COUNT+15 ==> nums[q]==\old(nums[q]);''')
    new=new.replace('int cnt);','int cnt,const uint8_t *nums);').replace('proof_long(b,l,c)','proof_long(b,l,c,state->bmap_nums)')
    g=g[:begin]+new+g[end:]

    # The checked output_frame theorem quantifies over ANY helper write effects
    # within the declared destination interval and *out; query-independent nums
    # and word queries lift its result universally. These are derived frame facts.
    for name,macro,params,macroargs,m in [
     ('proof_vector','zbm_write_16_nibbles','uint64_t packed','o,p','8'),
     ('proof_nibbles','zbm_write_nibbles','uint64_t pat, int k','o,p,k','(out->n+k>=16 ? 8 : 0)'),
     ('proof_nibble','zbm_write_nibble','uint8_t val','o,v','(out->n==15 ? 8 : 0)'),
     ('proof_repeat','zbm_write_repetition_count','int repeat','o,r','(out->n+2+(repeat-4)/15+1)/2'),
    ]:
     pos=g.index('    void '+name+'(');begin=g.rfind('/*@',0,pos);end=g.index('\n',g.index('#define '+macro+'(',pos))+1
     old=g[begin:end];decl=old[:old.index('    void '+name+'(')]
     addition=r""" requires \valid_read(nums+(0 .. ZBM_MAX_BITMAP_COUNT+15));
     requires \valid_read(bnd+(0 .. ZBM_MAX_BITMAP_COUNT/64));
     requires \valid_read(lng+(0 .. ZBM_MAX_BITMAP_COUNT/64));
     requires 0 <= """+m+' <= ZBM_MAX_BITMAP_COUNT;\n'
     addition+=r""" requires \separated(out,nums+(0 .. ZBM_MAX_BITMAP_COUNT+15),bnd+(0 .. ZBM_MAX_BITMAP_COUNT/64),lng+(0 .. ZBM_MAX_BITMAP_COUNT/64),out->addr+(0 .. """+m+r"""-1));
     ensures \forall integer q; 0 <= q <= ZBM_MAX_BITMAP_COUNT+15 ==> nums[q]==\old(nums[q]);
     ensures \forall integer k; 0 <= k <= ZBM_MAX_BITMAP_COUNT/64 ==> bnd[k]==\old(bnd[k]) && lng[k]==\old(lng[k]);
    """
     cut=addition.index(' ensures')
     req=addition[:cut]; post=addition[cut:]
     decl=decl.replace('assigns ',req+' assigns ',1).replace('    */',post+'    */')
     new=decl+'void '+name+'(struct zbm_nybl_out *out,'+params+',const uint8_t *nums,const uint64_t *bnd,const uint64_t *lng);\n'
     new+='#define '+macro+'('+macroargs+') '+name+'('+macroargs.replace('o,','o,')+',state->bmap_nums,state->run_bnd,state->run_long)\n'
     g=g[:begin]+new+g[end:]

    g=g.replace("proves only the wide-capacity component of the actual selector writer.","proves both capacity paths of the actual selector writer.")
    pos=g.index('static int zbm_write_metadata_3(');start=g.rfind('/*@',0,pos)
    contract=g[start:pos]
    old=r'     ensures \result == 0 || \result == ZBM_CANT_COMPRESS;'
    assert contract.count(old)==1
    contract=contract.replace(old,old+r'''
     ensures state->written==\old(state->written)+(state->dest-\old(state->dest));
     ensures 0<=state->dest_end-state->dest;
     ensures \result!=0 ==> state->dest==\old(state->dest) && state->written==\old(state->written);
     ensures \forall integer q; 0<=q<state->bmp_cnt ==> state->bmap_nums[q]==\at(state->bmap_nums[q],Pre);
    ''')
    g=g[:start]+contract+g[pos:]
    old='     loop invariant proof_emitted==prefix[i];'
    assert g.count(old)==1
    g=g.replace(old,old+r'''
     loop invariant \forall integer q; 0<=q<cnt ==> nums[q]==\at(state->bmap_nums[q],Pre);
    ''')
    return g

RUNTIME = r'''#include <assert.h>
#include <stdio.h>
#include "libzbitmap.c"
static struct zbm_compress_state state;
static uint8_t dst[ZBM_MAX_BITMAP_COUNT/2+32], expected[ZBM_MAX_BITMAP_COUNT/2+32];
static uint8_t nums[ZBM_MAX_BITMAP_COUNT], nibbles[ZBM_MAX_BITMAP_COUNT+1];
static int oracle(int cnt) {
 int n=0;
 for(int i=0;i<cnt;) {
  int j=i+1; while(j<cnt && nums[j]==nums[i]) ++j;
  int r=j-i;
  if(r<4) { for(int k=0;k<r;++k) nibbles[n++]=nums[i]; }
  else { nibbles[n++]=nums[i]; nibbles[n++]=15; r-=4;
   while(r>=15) { nibbles[n++]=15; r-=15; }
   nibbles[n++]=(uint8_t)r;
  }
  i=j;
 }
 memset(expected,0,sizeof(expected));
 for(int k=0;k<n;++k) expected[k/2]|=(uint8_t)(nibbles[k]<<(4*(k%2)));
 return (n+1)/2;
}
int main(void) {
 unsigned checks=0;
 for(int cnt=0;cnt<=ZBM_MAX_BITMAP_COUNT;++cnt) for(int mode=0;mode<4;++mode) {
  for(int i=0;i<cnt;++i) nums[i]=(uint8_t)(mode==0?14:mode==1?i%15:mode==2?(i/19)%15:((i*17/43)%15));
  int exact=oracle(cnt), wide=(cnt+1)/2;
  for(int variant=0;variant<6;++variant) {
   int kind=variant%3;
   int room=kind==0?wide:kind==1?exact:exact-1;
   if(room<0) continue;
   memset(&state,0,sizeof(state)); memcpy(state.bmap_nums,nums,(size_t)cnt);
   uint8_t *output=variant<3?dst:state.meta_scratch;
   state.bmp_cnt=cnt; state.dest=output+8; state.dest_end=state.dest+room; state.written=17;
   memset(output,0xee,sizeof(dst));
   int status=zbm_write_metadata_3(&state);
   if(room<exact) { assert(status==ZBM_CANT_COMPRESS); assert(state.dest==output+8); assert(state.written==17); }
   else { assert(status==0); assert(state.dest==output+8+exact); assert(state.written==(unsigned)(17+exact));
    assert(memcmp(output+8,expected,(size_t)exact)==0); }
   assert(memcmp(state.bmap_nums,nums,(size_t)cnt)==0);
   for(int i=0;i<8;++i) assert(output[i]==0xee);
   for(size_t i=(size_t)(8+room);i<sizeof(dst);++i) assert(output[i]==0xee);
   ++checks;
  }
 }
 printf("selector writer independent oracle: %u checks passed\n",checks);
}
'''


def main():
    import argparse
    import concurrent.futures
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    parser.add_argument('--proof-only',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-selector-tight')
    output.mkdir(parents=True,exist_ok=True)
    functions=['zbm_write_metadata_3','proof_trial_destination']
    if not args.proof_only:
        witness(output,RUNTIME)
        witness(output,RUNTIME,native=True)
    verify('selector_tight',generate(source),output,functions,1351,split=True)
    if args.mutants:
        variants=[
            ('vector_overrun','if(i + 16 <= cnt &&','if(i + 16 <= cnt + 16 &&'),
            ('extra_final_byte','end = zbm_nybl_finish(&out);','end = zbm_nybl_finish(&out);\n    *end++ = 0;'),
            ('missing_tight_rejection','zbm_metadata_3_bytes(state) > state->dest_end - state->dest)','zbm_metadata_3_bytes(state) < 0)'),
        ]
        def mutation(item):
            name,old,new=item
            assert source.count(old)==1, 'mutation site changed'
            verify(name,generate(source.replace(old,new)),output,functions,1349,False,split=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(mutation,variants))


if __name__=='__main__':
    main()
