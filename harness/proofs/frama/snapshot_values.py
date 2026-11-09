#!/usr/bin/env python3
"""Snapshot active values and count shape from standard memcpy value semantics.

The original copy arguments are evaluated unchanged. An extra read-only active
count restricts bitmap/period value guarantees to initialized fields; it never
changes the copy footprint. All use counts are initialized caller inputs.
Spatial-only snapshot coverage remains separate and less restrictive.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
import snapshot,score_trial
from wp_common import verify

def generate(source):
 g=snapshot.generate(source)
 for name in ['bmaps','periods','counts']:
  pos=g.index('void proof_copy_'+name+'(');a=g.rfind('/*@',0,pos)
  contract=g[a:pos]
  if name=='counts':
   value=r'ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> d[q]==\old(s[q]);'
  else:
   contract=contract.replace(' assigns ', ' requires 0<=active<=ZBM_MAX_BITMAP_COUNT;\n assigns ',1)
   if name=='bmaps':
    value=r'ensures \forall integer q; 0<=q<active ==> d[q].bitmap==\old(s[q].bitmap) && d[q].period_bytecnt==\old(s[q].period_bytecnt);'
   else:
    value=r'ensures \forall integer q; 0<=q<active ==> d[q]==\old(s[q]);'
   declaration=g[pos:g.index('\n',pos)]
   g=g.replace(declaration,declaration.replace('size_t n);','size_t n,int active);'))
  contract=contract.replace('*/',value+'\n*/',1)
  g=g[:a]+contract+g[pos:]
 for function,src,dst in [('save','state','snap'),('restore','snap','state')]:
  pos=g.index('static void zbm_snapshot_'+function+'(');a=g.rfind('/*@',0,pos)
  contract=g[a:pos]
  contract=contract.replace(' assigns ',r''' requires 0<='''+src+r'''->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
 requires \forall integer q; 0<=q<'''+src+r'''->bmp_cnt ==> '''+src+r'''->bitmaps[q].period_bytecnt<=2;
 requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> '''+src+r'''->usecnts[q]<='''+src+r'''->bmp_cnt;
 requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> '''+src+r'''->usecnts[q]==0;
 assigns ''',1)
  post=r''' ensures 0<='''+dst+r'''->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
 ensures \forall integer q; 0<=q<'''+dst+r'''->bmp_cnt ==> '''+dst+r'''->bitmaps[q].period_bytecnt<=2;
 ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> '''+dst+r'''->usecnts[q]<='''+dst+r'''->bmp_cnt;
 ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> '''+dst+r'''->usecnts[q]==0;
 ensures \forall integer q; 0<=q<'''+dst+r'''->bmp_cnt ==> '''+dst+r'''->bitmaps[q].bitmap==\old('''+src+r'''->bitmaps[q].bitmap) && '''+dst+r'''->bitmaps[q].period_bytecnt==\old('''+src+r'''->bitmaps[q].period_bytecnt) && '''+dst+r'''->periods[q]==\old('''+src+r'''->periods[q]);
 ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> '''+dst+r'''->usecnts[q]==\old('''+src+r'''->usecnts[q]);
'''
  contract=contract.replace('*/',post+'*/',1)
  g=g[:a]+contract+g[pos:]
  pos=g.index('static void zbm_snapshot_'+function+'(')
  end=g.index('\n}',pos)
  body=g[pos:end]
  for field,name in [('bitmaps','bmaps'),('periods','periods')]:
   lines=body.splitlines(keepends=True)
   matches=[i for i,line in enumerate(lines) if line.lstrip().startswith('proof_copy_'+name+'(')]
   assert len(matches)==1,'copy site changed'
   i=matches[0];line=lines[i];assert line.rstrip().endswith(');')
   newline='\n' if line.endswith('\n') else ''
   lines[i]=line.rstrip()[:-2]+', '+src+'->bmp_cnt);'+newline
   body=''.join(lines)
  g=g[:pos]+body+g[end:]
 return g



def generate_internal(source):
 assert 'zbm_snapshot_save(state, &state->best);' in source
 assert 'zbm_snapshot_restore(state, &state->best);' in source
 return generate(source)+r'''
/*@ requires \valid(state);
 requires 0<=state->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
 requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
 requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]<=state->bmp_cnt;
 requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> state->usecnts[q]==0;
 assigns *state;
 ensures state->bmp_cnt==\old(state->bmp_cnt);
 ensures \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].bitmap==\old(state->bitmaps[q].bitmap) && state->bitmaps[q].period_bytecnt==\old(state->bitmaps[q].period_bytecnt) && state->periods[q]==\old(state->periods[q]);
 ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]==\old(state->usecnts[q]);
*/
static void proof_internal_snapshot(struct zbm_compress_state *state)
{
 zbm_snapshot_save(state, &state->best);
 zbm_snapshot_restore(state, &state->best);
}
'''


def generate_trial(source):
 g=generate(source)
 s=score_trial.generate(source)
 a=s.index('/* Arbitrary-byte bound from registered zbm_encoder_bmprot.')
 s=s[a:]
 pos=s.index('static size_t zbm_score_trial(');a=s.rfind('/*@',0,pos);b=s.index('\n',pos)
 g+=r'/*@ predicate live_counts{L}(zbm_usecnt_t *counts)= \forall integer k; 0<=k<ZBM_POSSIBLE_BMPROTS && k%4==3 ==> counts[k]==0; */'+'\n'+s[a:pos]+s[pos:b].replace('static size_t ','size_t ',1)+';\n'
 g+=r'''
 /*@ requires \valid(state);
  requires 0<=data_bytes<=CRUSHLZBITMAP_MAX_CHUNK_SIZE;
  requires 0<=state->bmp_cnt<=ZBM_MAX_BITMAP_COUNT;
  requires \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].period_bytecnt<=2;
  requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]<=state->bmp_cnt;
  requires \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS && q%4==3 ==> state->usecnts[q]==0;
  assigns *state;
  ensures state->bmp_cnt==\old(state->bmp_cnt);
  ensures \forall integer q; 0<=q<state->bmp_cnt ==> state->bitmaps[q].bitmap==\old(state->bitmaps[q].bitmap) && state->bitmaps[q].period_bytecnt==\old(state->bitmaps[q].period_bytecnt) && state->periods[q]==\old(state->periods[q]);
  ensures \forall integer q; 0<=q<ZBM_POSSIBLE_BMPROTS ==> state->usecnts[q]==\old(state->usecnts[q]);
  ensures state->dest==\old(state->dest) && state->dest_end==\old(state->dest_end) && state->written==\old(state->written);
 */
 static size_t proof_internal_trial_restore(struct zbm_compress_state *state,long data_bytes)
 {
  size_t total;
  zbm_snapshot_save(state, &state->best);
  total=zbm_score_trial(state, data_bytes);
  zbm_snapshot_restore(state, &state->best);
  return total;
 }
 '''
 return g

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--mutants',action='store_true')
 args=parser.parse_args()
 source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
 output=Path('harness/build/proofs-frama-snapshot-values');output.mkdir(parents=True,exist_ok=True)
 functions=['zbm_snapshot_save','zbm_snapshot_restore']
 verify('snapshot_values',generate(source),output,functions,76,split=True)
 verify('snapshot_internal',generate_internal(source),output,functions+['proof_internal_snapshot'],107,split=True)
 verify('trial_restore',generate_trial(source),output,functions+['proof_internal_trial_restore'],141,split=True)
 if args.mutants:
  a=source.index('static void zbm_snapshot_save(');b=source.index('/* Scores the chunk',a)
  body=source[a:b]
  variants=[('shifted_count_source','memcpy(snap->usecnts, state->usecnts,','memcpy(snap->usecnts, state->usecnts + 1,'),
   ('shifted_period_source','memcpy(state->periods, snap->periods,','memcpy(state->periods, snap->periods + 1,'),
   ('corrupt_restored_shape','    state->bmp_cnt = snap->bmp_cnt;','    state->bmp_cnt = snap->bmp_cnt;\n    state->bitmaps[0].period_bytecnt = 3;')]
  for tag,old,new in variants:
   assert body.count(old)==1,'mutation site changed'
   changed=source[:a]+body.replace(old,new)+source[b:]
   verify(tag,generate(changed),output,functions,76,False,split=True)

if __name__=='__main__':
 main()
