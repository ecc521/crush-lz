#!/usr/bin/env python3
"""Actual selector-writer safety with the one-nibble-per-block reservation.

This is a component proof, NOT a proof of the tighter-capacity path or the
whole encoder. Helper models import the registered CBMC contracts; the
writer algorithm is literal shipping source with ghost budget bookkeeping.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode = True


def generate(source):
    s=source
    a=s.index('static int zbm_write_metadata_3(')
    b=s.index('/* This function does not perform boundary checks',a)
    models=r'''
    /* Models import consequences of registered CBMC helper proofs. This target
       proves only the wide-capacity component of the actual selector writer. */
    /*@ requires 1 <= repeat <= 3;
     requires number <= 14;
     assigns \nothing;

     ensures (\result >> (4*repeat)) == 0;
    */
    uint64_t proof_pattern(int repeat, unsigned number);
    #define zbm_short_run_pattern(r,n) proof_pattern(r,n)
    /*@ requires 0 <= index < ZBM_MAX_BITMAP_COUNT;
     assigns \nothing;
     ensures 0 <= \result < ZBM_MAX_BITMAP_COUNT/64;
     ensures \result == index/64;
    */
    int proof_word_index(int index);
    #define zbm_selector_word_index(i) proof_word_index(i)
    /*@ requires \valid(state);
     requires 0 <= state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
     assigns state->bmap_nums[0  ..  ZBM_MAX_BITMAP_COUNT+15], state->run_bnd[0  ..  ZBM_MAX_BITMAP_COUNT/64];
     ensures \forall integer q; 0 <= q < state->bmp_cnt ==> state->bmap_nums[q] == \old(state->bmap_nums[q]);
     ensures state->bmp_cnt == 0 || (state->run_bnd[(state->bmp_cnt-1)/64] & (1ULL << ((state->bmp_cnt-1)%64))) != 0;
    */
    void proof_boundaries(struct zbm_compress_state *state);
    #define zbm_build_run_boundaries(st) proof_boundaries(st)
    /*@ requires \valid_read(boundary);
     requires \valid(marked);
     requires 0 <= cnt <= ZBM_MAX_BITMAP_COUNT;
     requires \separated(boundary, marked);
     assigns (*marked)[0  ..  ZBM_MAX_BITMAP_COUNT/64];
     ensures (*marked)[(cnt+63)/64] == 0;
    */
    void proof_long(const uint64_t (*boundary)[ZBM_MAX_BITMAP_COUNT/64+1], uint64_t (*marked)[ZBM_MAX_BITMAP_COUNT/64+1], int cnt);
    #define zbm_build_long_runs_arrays(b,l,c) proof_long(b,l,c)
    /*@ requires \valid_read(boundary);
     requires 1 <= cnt <= ZBM_MAX_BITMAP_COUNT;
     requires 0 <= idx < cnt;
     requires ((*boundary)[(cnt-1)/64] & (1ULL << ((cnt-1)%64))) != 0;
     assigns \nothing;
     ensures idx <= \result < cnt;
    */
    int proof_end(const uint64_t (*boundary)[ZBM_MAX_BITMAP_COUNT/64+1], int idx, int cnt);
    #define zbm_find_run_end(b,i,c) proof_end(b,i,c)
    /*@ requires shift < 64; assigns \nothing; */
    uint16_t proof_window(uint64_t word, uint64_t next, unsigned shift);
    #define zbm_long_run_window(w,n,s) proof_window(w,n,s)
    /*@ requires \valid_read(nums+(0 .. 15)); assigns \nothing; */
    uint64_t proof_pack(const uint8_t *nums);
    #define zbm_pack_nibbles16(n) proof_pack(n)
    /*@ requires \valid_read(state);
     requires 0 <= state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
     assigns \nothing;
     ensures 0 <= \result <= (state->bmp_cnt+1)/2;
    */
    ptrdiff_t proof_size(struct zbm_compress_state *state);
    #define zbm_metadata_3_bytes(s) proof_size(s)
    /*@ requires \valid(out);
     requires 0 <= out->n < 16;
     requires (out->acc >> (4*out->n)) == 0;
     requires \valid(out->addr+(0 .. 7));
     requires \separated(out, out->addr+(0 .. 7));
     assigns out->addr, out->acc, out->addr[0 .. 7] \from out->addr, out->acc, out->n, packed;
     ensures out->addr == \old(out->addr)+8;
     ensures (out->acc >> (4*out->n)) == 0;
    */
    void proof_vector(struct zbm_nybl_out *out, uint64_t packed);
    #define zbm_write_16_nibbles(o,p) proof_vector(o,p)
    /*@ requires \valid(out);
     requires 0 <= out->n < 16;
     requires (out->acc >> (4*out->n)) == 0;
     requires 1 <= k <= 4;
     requires (pat >> (4*k)) == 0;
     requires \valid(out->addr) || \valid(out->addr-1);
     requires out->n+k < 16 || \valid(out->addr+(0 .. 7));
     requires \separated(out, out->addr+(0 .. (out->n+k >= 16 ? 7 : -1)));
     assigns *out, out->addr[0 .. (out->n+k >= 16 ? 7 : -1)];
     ensures out->n == (\old(out->n)+k)%16;
     ensures out->addr == \old(out->addr)+(\old(out->n)+k >= 16 ? 8 : 0);
     ensures (out->acc >> (4*out->n)) == 0;
    */
    void proof_nibbles(struct zbm_nybl_out *out, uint64_t pat, int k);
    #define zbm_write_nibbles(o,p,k) proof_nibbles(o,p,k)
    /*@ requires \valid(out);
     requires 0 <= out->n < 16;
     requires (out->acc >> (4*out->n)) == 0;
     requires val < 16;
     requires \valid(out->addr) || \valid(out->addr-1);
     requires out->n != 15 || \valid(out->addr+(0 .. 7));
     requires \separated(out, out->addr+(0 .. (out->n == 15 ? 7 : -1)));
     assigns *out, out->addr[0 .. (out->n == 15 ? 7 : -1)];
     ensures out->n == (\old(out->n)+1)%16;
     ensures out->addr == \old(out->addr)+(\old(out->n)==15 ? 8 : 0);
     ensures (out->acc >> (4*out->n)) == 0;
    */
    void proof_nibble(struct zbm_nybl_out *out, uint8_t val);
    #define zbm_write_nibble(o,v) proof_nibble(o,v)
    /*@ requires \valid(out);
     requires 0 <= out->n < 16;
     requires (out->acc >> (4*out->n)) == 0;
     requires 4 <= repeat <= ZBM_MAX_BITMAP_COUNT;
     requires \valid(out->addr+(0 .. (out->n+2+(repeat-4)/15+1)/2-1));
     requires \separated(out, out->addr+(0 .. (out->n+2+(repeat-4)/15+1)/2-1));
     assigns *out, out->addr[0 .. (out->n+2+(repeat-4)/15+1)/2-1];
     ensures out->n == (\old(out->n)+2+(repeat-4)/15)%16;
     ensures out->addr == \old(out->addr)+8*((\old(out->n)+2+(repeat-4)/15)/16);
     ensures (out->acc >> (4*out->n)) == 0;
    */
    void proof_repeat(struct zbm_nybl_out *out, int repeat);
    #define zbm_write_repetition_count(o,r) proof_repeat(o,r)
    /*@ requires \valid_read(out);
     requires 0 <= out->n < 16;
     requires (out->acc >> (4*out->n)) == 0;
     requires \valid(out->addr+(0 .. (out->n+1)/2-1));
     requires \separated(out, out->addr+(0 .. (out->n+1)/2-1));
     assigns out->addr[0 .. (out->n+1)/2-1], \result \from out->addr, out->acc, out->n;
     ensures \result == out->addr+(out->n+1)/2;
    */
    uint8_t *proof_finish(struct zbm_nybl_out *out);
    #define zbm_nybl_finish(o) proof_finish(o)
    /*@ requires \valid(state);
     requires 0 <= state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
     requires (state->bmp_cnt+1)/2 <= state->dest_end-state->dest <= 0x1000000000000;
     requires \base_addr(state->dest)==\base_addr(state->dest_end);
     requires \valid(state->dest) || \valid(state->dest-1);
     requires \valid(state->dest+(0 .. state->dest_end-state->dest-1));
     requires \separated(state,state->dest+(0 .. state->dest_end-state->dest-1));
     requires \forall integer q; 0 <= q < state->bmp_cnt ==> state->bmap_nums[q] <= 14;
     requires state->written <= UINT32_MAX-(state->bmp_cnt+1)/2;
     assigns state->dest, state->written, state->dest[0 .. state->dest_end-state->dest-1],
     state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT+15], state->run_bnd[0 .. 64], state->run_long[0 .. 64] \from state->dest, state->dest_end, state->written, state->bmp_cnt, state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT+15], state->run_bnd[0 .. 64], state->run_long[0 .. 64];
     ensures \result == 0;
     ensures \base_addr(state->dest)==\base_addr(\old(state->dest));
     ensures 0 <= state->dest-\old(state->dest) <= (state->bmp_cnt+1)/2;
    */
    '''
    body=s[a:b]
    assert body.count('while(i < cnt)') == 1, 'selector loop changed'
    assert body.count('zbm_write_16_nibbles(&out, pk)') == 1
    assert body.count('zbm_write_nibbles(&out, zbm_short_run_pattern') == 1
    body=body.replace('    uint8_t *end;', '    uint8_t *end;\n    int proof_emitted=0;')
    body=body.replace('        while(i < cnt)',r'''        /*@ loop invariant 0 <= i <= cnt;
     loop invariant 0 <= proof_emitted <= i;
     loop invariant 0 <= out.n < 16;
     loop invariant (out.acc >> (4*out.n)) == 0;
     loop invariant \base_addr(out.addr)==\base_addr(state->dest);
     loop invariant 0 <= out.addr-state->dest <= (cnt+1)/2;
     loop invariant 2*(out.addr-state->dest)+out.n==proof_emitted;
     loop invariant \forall integer q; 0 <= q < cnt ==> nums[q] <= 14;
     loop invariant cnt == 0 || (state->run_bnd[(cnt-1)/64] & (1ULL << ((cnt-1)%64))) != 0;
     loop assigns i, proof_emitted, out, state->dest[0 .. state->dest_end-state->dest-1];
     loop variant cnt-i;
    */
            while(i < cnt)''')
    body=body.replace('                i += 16;', '                proof_emitted += 16;\n                i += 16;')
    body=body.replace('            if(repeat <= 3) {','            if(repeat <= 3) {\n                proof_emitted += repeat;')
    body=body.replace('            } else {\n                zbm_write_nibble', '            } else {\n                proof_emitted += 3+(repeat-4)/15;\n                zbm_write_nibble')
    body=body.replace('            const int kk =', '            /*@ assert i < ZBM_MAX_BITMAP_COUNT; */\n            const int kk =')
    body=body.replace('                uint64_t pk =', '                /*@ assert i+16 <= ZBM_MAX_BITMAP_COUNT; */\n                uint64_t pk =')
    # Keep exact shipping source through the writer, adding contracts/models only.
    prefix=s[:a].replace('static int zbm_nibble_cost_for_run(int r);',r'''/*@ requires 0 <= r <= ZBM_MAX_BITMAP_COUNT;
     assigns \nothing;
     ensures 0 <= \result <= r;
     ensures r < 4 ? \result == r : \result == 3+(r-4)/15;
    */
    static int zbm_nibble_cost_for_run(int r);''')
    body=body.replace('            int to_write, repeat, e;',r'''            /*@ assert 0 <= kk < ZBM_MAX_BITMAP_COUNT/64; */
                int to_write, repeat, e;''')
    from wp_common import SPAN, protect_span
    selector_span=SPAN.replace('state->dest + (0 ..', 'state->run_bnd + (0 .. ZBM_MAX_BITMAP_COUNT/64),\n        state->run_long + (0 .. ZBM_MAX_BITMAP_COUNT/64),\n        state->dest + (0 ..')
    # Use the exact spelling protect_span locates, then cover both domains.
    models=models.replace(r'\separated(state,state->dest+(0 .. state->dest_end-state->dest-1))',r'\separated(state, state->dest + (0 .. state->dest_end - state->dest - 1))')
    return protect_span(prefix+models+body,s,span=selector_span)


def main():
    import argparse
    import concurrent.futures
    from wp_common import verify, witness
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    source = Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output = Path('harness/build/proofs-frama-selector-wide')
    output.mkdir(parents=True, exist_ok=True)

    def prove(name, text, expected=True):
        verify(name, generate(text), output,
               ['zbm_write_metadata_3', 'proof_trial_destination'], 150, expected)

    runtime = r'''#include <assert.h>
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
    witness(output, runtime)
    witness(output, runtime, native=True)

    prove('selector_wide', source)
    if args.mutants:
        variants = [
            ('vector_overrun', 'if(i + 16 <= cnt &&', 'if(i + 16 <= cnt + 16 &&'),
            ('extra_final_byte', 'end = zbm_nybl_finish(&out);',
             'end = zbm_nybl_finish(&out);\n    *end++ = 0;'),
        ]
        def mutation(item):
            name, old, new = item
            assert source.count(old) == 1, 'mutation site changed'
            prove(name, source.replace(old, new), False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(mutation, variants))


if __name__ == '__main__':
    main()
