#!/usr/bin/env python3
"""Shipping greedy loop and width dispatch, composed with the checked step."""
from pathlib import Path
import argparse
import re
import sys
sys.dont_write_bytecode=True
from wp_common import verify

STATE=r'''
/*@ predicate match_ok(lzvn_encoder_state *s)=
      (s->pending.M==0 && s->pending.m_end==0) ||
      (0<=s->pending.m_begin<=s->src_current &&
       0<=s->pending.m_end<=s->src_end &&
       3<=s->pending.M && 1<=s->pending.D<=65535 &&
       s->pending.m_end-s->pending.m_begin==s->pending.M &&
       s->src_literal<=s->pending.m_begin &&
       s->src_begin<=s->pending.m_begin-s->pending.D);
    predicate state_ok(lzvn_encoder_state *s)=
      s->src_begin<=s->src_literal<=s->src_end && match_ok(s) &&
      (s->d_prev==0 || (1<=s->d_prev<=65535 && s->d_prev<=s->src_current-s->src_begin)) &&
      \base_addr(s->dst)==\base_addr(s->dst_end) &&
      0<=s->dst_end-s->dst<=PTRDIFF_MAX &&
      \valid(s->dst+(0 .. s->dst_end-s->dst-1));
*/
'''

def contract(step=False):
    return r'''
/*@ requires \valid(state);
    requires 10<=hash_bits<=16 && 1<=hash_width<=64;
    requires 8<=state->src_end<=4294967295;
    requires state->src_begin==0 && 0<=state->src_current<=state->src_current_end<=state->src_end-8;
    requires state_ok(state);
    requires \valid_read(state->src+(0 .. state->src_end-1));
    requires \valid(hist_pos+(0 .. (1<<hash_bits)*hash_width-1));
    requires \valid(hist_value+(0 .. (1<<hash_bits)*hash_width-1));
    requires \valid(hist_cursor+(0 .. (1<<hash_bits)-1));
    requires \separated(state,state->src+(0 .. state->src_end-1),
      state->dst+(0 .. state->dst_end-state->dst-1),
      hist_pos+(0 .. (1<<hash_bits)*hash_width-1),
      hist_value+(0 .. (1<<hash_bits)*hash_width-1),
      hist_cursor+(0 .. (1<<hash_bits)-1));
''' + (r'''
    requires state->src_current<state->src_current_end;
    requires state->src_begin<=sentinel_pos<=state->src_end-4;
''' if step else '') + r'''
    assigns state->dst,state->src_literal,state->pending,state->d_prev,
''' + ('' if step else '      state->src_current,\n') + r'''
      state->dst[0 .. state->dst_end-state->dst-1],
      hist_pos[0 .. (1<<hash_bits)*hash_width-1],
      hist_value[0 .. (1<<hash_bits)*hash_width-1],hist_cursor[0 .. (1<<hash_bits)-1]
      \from state,state->src,state->src_begin,state->src_end,state->src_current,state->src_current_end,
        state->src_literal,state->dst,state->dst_end,state->pending,state->d_prev,
        state->src[0 .. state->src_end-1],hist_pos[0 .. (1<<hash_bits)*hash_width-1],
        hist_value[0 .. (1<<hash_bits)*hash_width-1],hist_cursor[0 .. (1<<hash_bits)-1];
    ensures state_ok(state);
    ensures \base_addr(state->dst)==\base_addr(\old(state->dst));
    ensures \old(state->dst)<=state->dst<=state->dst_end;
    ensures \old(state->src_literal)<=state->src_literal<=state->src_end;
''' + ('    ensures \\result==0 || \\result==1;\n' if step else
     '    ensures \\old(state->src_current)<=state->src_current<=state->src_current_end;\n') + '*/\n'

LOOP=r'''
  /*@ loop invariant state_ok(state);
      loop invariant \at(state->src_current,Pre)<=state->src_current<=state->src_current_end;
      loop invariant \at(state->src_literal,Pre)<=state->src_literal;
      loop invariant \base_addr(state->dst)==\base_addr(\at(state->dst,Pre));
      loop invariant \at(state->dst,Pre)<=state->dst;
      loop assigns state->src_current,state->src_literal,state->dst,state->pending,state->d_prev,
        \at(state->dst,Pre)[0 .. state->dst_end-\at(state->dst,Pre)-1],
        hist_pos[0 .. (1<<hash_bits)*hash_width-1],
        hist_value[0 .. (1<<hash_bits)*hash_width-1],hist_cursor[0 .. (1<<hash_bits)-1];
      loop variant state->src_current_end-state->src_current;
  */
'''

def audit_cbmc_frame(source):
    """Keep the native loop's ACSL frame and separation domain tied to CBMC."""
    for name in ('lzvn_greedy_wide_step', 'lzvn_encode_greedy_wide'):
        start=source.index('int '+name+'(') if name.endswith('_step') else source.index('void '+name+'(')
        body=source[start:source.index('\n{',start)]
        frame=body[body.index('LZVN_ASSIGNS('):body.index('LZVN_ENSURES(')]
        for field in ('state->dst','state->src_literal','state->pending','state->d_prev'):
            assert field in frame, f'{name}: CBMC frame lost {field}'
        if not name.endswith('_step'):
            assert 'state->src_current' in frame, f'{name}: CBMC frame lost src_current'
        for table in ('hist_pos','hist_value','hist_cursor'):
            assert '__CPROVER_object_upto('+table+',' in frame, f'{name}: CBMC frame lost {table}'
        assert '__CPROVER_object_upto(state->dst,' in frame, f'{name}: CBMC output frame missing'
        assert body.count('LZVN_REQUIRES(LZVN_PROOF_RANGES_DISJOINT(')==6, \
            f'{name}: CBMC table/output separation differs from ACSL'
        for expression in ('state, state->src', 'state, state->dst',
                           'state, hist_pos', 'state, hist_value', 'state, hist_cursor',
                           'state->src, hist_pos', 'state->src, hist_value',
                           'state->src, hist_cursor', 'state->src, state->dst'):
            assert expression in body, f'{name}: CBMC separation lost {expression}'
    for acsl in (contract(True),contract()):
        for field in ('state->dst','state->src_literal','state->pending','state->d_prev',
                      'hist_pos[0 ..','hist_value[0 ..','hist_cursor[0 ..',
                      'state->dst[0 ..'):
            assert field in acsl, f'ACSL frame lost {field}'
        assert '\\separated(state,state->src+' in acsl, 'ACSL separation missing'

def generate(source,header):
    types=header[header.index('typedef struct {'):header.index('} lzvn_encoder_state;')+len('} lzvn_encoder_state;')]
    a=source.index('LZFSE_INLINE void lzvn_encode_greedy_wide_hw(')
    b=source.index('void lzvn_encode_greedy_init_table(',a)
    body=source[a:b]
    # Drop CBMC annotations/shortcut only, retaining the actual loop and cases.
    body=re.sub(r'#ifdef LZVN_PROOF\n.*?#endif\n','',body,flags=re.S)
    body=re.sub(r'#if defined\(LZVN_PROOF\).*?#endif\n','',body,flags=re.S)
    body=body.replace('  for (; state->src_current',LOOP+'  for (; state->src_current',1)
    a=body.index('#define LZVN_GREEDY_WIDE_INSTANCE(HW)')
    b=body.index('#undef LZVN_GREEDY_WIDE_INSTANCE',a)+len('#undef LZVN_GREEDY_WIDE_INSTANCE')
    macro=body[a:b]
    widths=re.findall(r'^LZVN_GREEDY_WIDE_INSTANCE\((\d+)\)',macro,re.M)
    assert widths==['1','2','4','8','16','32','64']
    signature=macro[macro.index('  static void'):macro.index('LZVN_GREEDY_WIDE_INSTANCE(1)')]
    signature=signature.replace('\\\n','\n').replace('##HW','HW')
    wrappers='\n'.join(contract().replace('hash_width',w)+signature.replace('HW',w) for w in widths)
    body=body[:a]+wrappers+body[b:]
    body=contract()+body
    body=body.replace('void lzvn_encode_greedy_wide(lzvn_encoder_state',contract()+'void lzvn_encode_greedy_wide(lzvn_encoder_state',1)
    return '#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\ntypedef int64_t lzvn_offset;\n#define LZFSE_INLINE static\n#define LZVN_ENCODE_MAX_DISTANCE 65535\n'+types+STATE+r'''
/*@ requires \valid_read(p+(0 .. 3)); assigns \nothing; */
uint32_t load4(const uint8_t *p);
''' + contract(True)+'''
int lzvn_greedy_wide_step(lzvn_encoder_state *state,int32_t hash_bits,int32_t hash_width,
  int32_t *hist_pos,uint32_t *hist_value,uint16_t *hist_cursor,lzvn_offset sentinel_pos,uint32_t sentinel_val);
''' + body

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output')
    parser.add_argument('--mutants',action='store_true')
    parser.add_argument('--audit-only',action='store_true')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[3]
    source=(root/'crates/crushlzfse/csrc/lzvn_encode_base.c').read_text()
    header=(root/'crates/crushlzfse/csrc/lzvn_encode_base.h').read_text()
    audit_cbmc_frame(source)
    if args.audit_only:
        # A dropped table writer must make the cross-tool audit fail.
        mutant=source.replace('__CPROVER_object_upto(hist_cursor,',
                              '__CPROVER_object_upto(hist_curs0r,',1)
        try:
            audit_cbmc_frame(mutant)
        except AssertionError:
            print('CBMC/ACSL greedy frame audit passed; dropped-writer mutant rejected')
            return
        raise AssertionError('dropped-writer mutant survived frame audit')
    output=Path(args.output or root/'harness/build/proofs-frama-lzvn-greedy-loop')
    output.mkdir(parents=True,exist_ok=True)
    verify('greedy_loop',generate(source,header),output,['lzvn_encode_greedy_wide_hw','lzvn_encode_greedy_wide']+[f'lzvn_encode_greedy_wide_hw{w}' for w in [1,2,4,8,16,32,64]],100,split=True)
    if args.mutants:
        old='state->src_current++)'
        assert source.count(old)==1
        verify('missing_progress',generate(source.replace(old,'state->src_current += 0)'),header),output,['lzvn_encode_greedy_wide_hw'],10,False,split=True)

if __name__=='__main__': main()
