#!/usr/bin/env python3
"""Native 64-bit literal loops, composed with exact FSE primitive contracts.

The shipping table-validity predicate is an explicit caller obligation. Table
producer composition is tracked separately; this target never invents entries.
n_literals is any count up to 40000: the loops step by four and may write up
to three literals past it, inside the copy margin.
"""
from pathlib import Path
import argparse
import re
import sys
sys.dont_write_bytecode=True
from wp_common import verify

MODELS=r'''
/*@ predicate input_valid(fse_in_stream *in)=
      0<=in->accum_nbits<64 && (in->accum >> in->accum_nbits)==0;
    predicate literal_table_valid(int32_t *t)=
      \forall integer k; 0<=k<1024 ==>
        0<=(t[k] & 255)<=10 &&
        0<=(t[k] >> 16) &&
        (t[k] >> 16)+((1<<(t[k] & 255))-1)<1024;
*/
/*@ requires \valid(in) && \valid(buf);
    requires -7<=bits<=0;
    requires \base_addr(*buf)==\base_addr(start);
    requires 0<=*buf-start<=PTRDIFF_MAX;
    requires \valid_read(start+(0 .. *buf-start-1));
    requires \separated(in,buf,start+(0 .. *buf-start-1));
    requires \base_addr(in)!=\base_addr(buf) && \base_addr(in)!=\base_addr(start) &&
      \base_addr(buf)!=\base_addr(start);
    assigns *in,*buf \from bits,in,buf,start[0 .. *buf-start-1];
    ensures \result==0 || \result==-1;
    ensures \base_addr(*buf)==\base_addr(\old(*buf));
    ensures start<=*buf<=\old(*buf);
    ensures 0<=\old(*buf)-*buf<=8;
    ensures \result==0 ==> \old(*buf)-*buf==(bits!=0 ? 8 : 7);
    ensures \result==0 ==> input_valid(in);
*/
int proof_fse_init(fse_in_stream *in,int bits,const uint8_t **buf,const uint8_t *start);
/*@ requires \valid(in) && \valid(buf) && \valid(next);
    requires input_valid(in);
    requires \base_addr(*buf)==\base_addr(start);
    requires 0<=*buf-start<=PTRDIFF_MAX;
    requires \valid_read(start-8+(0 .. *buf-start+7));
    requires \separated(in,buf,next,start-8+(0 .. *buf-start+7));
    requires \base_addr(in)!=\base_addr(buf) && \base_addr(in)!=\base_addr(start) &&
      \base_addr(buf)!=\base_addr(start) && \base_addr(next)!=\base_addr(in) &&
      \base_addr(next)!=\base_addr(buf) && \base_addr(next)!=\base_addr(start);
    assigns *in,*buf,*next \from in,buf,next,(start-8)[0 .. *buf-start+7];
    ensures \result==0 || \result==-1;
    ensures \base_addr(*buf)==\base_addr(\old(*buf));
    ensures 0<=\old(*buf)-*buf<=8;
    ensures \result==0 ==> start<=*buf && input_valid(in) && 56<=in->accum_nbits<=63;
    ensures \old(*buf)-start>=8 ==> \result==0;
*/
int proof_fse_flush_next(fse_in_stream *in,const uint8_t **buf,const uint8_t *start,uint64_t *next);
/*@ requires \valid(in) && \valid(buf);
    requires input_valid(in);
    requires \valid_read(*buf-8+(0 .. 7));
    requires \separated(in,buf,*buf-8+(0 .. 7));
    requires \base_addr(in)!=\base_addr(buf) && \base_addr(in)!=\base_addr(*buf) &&
      \base_addr(buf)!=\base_addr(*buf);
    assigns *in,*buf \from in,buf,(*buf-8)[0 .. 7];
    ensures input_valid(in) && 56<=in->accum_nbits<=63;
    ensures \base_addr(*buf)==\base_addr(\old(*buf));
    ensures 0<=\old(*buf)-*buf<=8;
*/
void proof_fse_flush_unchecked(fse_in_stream *in,const uint8_t **buf);
/*@ requires \valid(state) && *state<1024 && \valid(in);
    requires input_valid(in) && in->accum_nbits>=10;
    requires \valid_read(table+(0 .. 1023));
    requires literal_table_valid(table);
    requires \separated(state,in,table+(0 .. 1023));
    requires \base_addr(state)!=\base_addr(in) && \base_addr(state)!=\base_addr(table) &&
      \base_addr(in)!=\base_addr(table);
    assigns *state,*in,\result \from state,in,table[0 .. 1023];
    ensures *state<1024 && input_valid(in);
    ensures 0<=\old(in->accum_nbits)-in->accum_nbits<=10;
*/
uint8_t proof_fse_decode(uint32_t *state,const int32_t *table,fse_in_stream *in);
/*@ requires \valid_read(p+(0 .. 7)); assigns \nothing; */
uint64_t proof_load8(const uint8_t *p);
/*@ requires \valid(p+(0 .. 3)); assigns p[0 .. 3]; */
void proof_store4(uint8_t *p,uint32_t w);
/*@ requires \valid(p+(0 .. n-1)); assigns p[0 .. n-1]; */
void proof_memset(uint8_t *p,int value,size_t n);
'''

CONTRACT=r'''
/*@ requires \valid(s) && \valid(bs) && \valid_read(header1);
    requires \base_addr(s->src_begin)==\base_addr(s->src)==\base_addr(s->src_end);
    requires 16<=s->src-s->src_begin<=s->src_end-s->src_begin<=PTRDIFF_MAX;
    requires \valid_read(s->src_begin+(0 .. s->src_end-s->src_begin-1));
    requires header1->n_literal_payload_bytes<=s->src_end-s->src;
    requires header1->n_literals<=40000;
    requires -7<=header1->literal_bits<=0;
    requires \forall integer i; 0<=i<4 ==> header1->literal_state[i]<1024;
    requires literal_table_valid(&bs->literal_decoder[0]);
    requires \separated(&s->src,&s->src_begin,&s->src_end,header1,&bs->current_literal,
      bs->literals+(0 .. 40000+LZFSE_DECODE_COPY_MARGIN-1),bs->literal_decoder+(0 .. 1023),
      s->src_begin+(0 .. s->src_end-s->src_begin-1));
    assigns s->src,bs->current_literal,bs->literals[0 .. 40000+LZFSE_DECODE_COPY_MARGIN-1]
      \from s,header1,bs,s->src,s->src_begin,s->src_end,header1->n_literal_payload_bytes,
        header1->n_literals,header1->literal_bits,header1->literal_state[0 .. 3],
        bs->literal_decoder[0 .. 1023],s->src_begin[0 .. s->src_end-s->src_begin-1];
    ensures \result==0 || \result==-1;
    ensures s->src==\old(s->src)+header1->n_literal_payload_bytes;
    ensures \result==0 ==> bs->current_literal==&bs->literals[0];
*/
'''

def loop(bulk):
    return r'''
    /*@ loop invariant \base_addr(lp)==\base_addr(&bs->literals[0]);
        loop invariant 0<=lp-&bs->literals[0]<=header1->n_literals+3;
        loop invariant (lp-&bs->literals[0])%4==0;
        loop invariant \base_addr(buf)==\base_addr(buf_start);
        loop invariant buf_start<=buf<=buf_initial;
        loop invariant 0<=buf_initial-buf<=2*(lp-&bs->literals[0]);
        loop invariant \valid_read(s->src_begin+(0 .. s->src_end-s->src_begin-1));
        loop invariant input_valid(&in);
        loop invariant state0<1024 && state1<1024 && state2<1024 && state3<1024;
        loop invariant literal_table_valid(ltab);
''' + (r'''
        loop invariant lp<=lp_safe+3;
''' if bulk else '') + r'''
        loop assigns lp,buf,in,next,state0,state1,state2,state3,
          bs->literals[0 .. 40000+LZFSE_DECODE_COPY_MARGIN-1];
        loop variant lp_end-lp;
    */
'''

def native_types(internal,fse):
    joined=internal.replace('\\\n',' ')
    names=['LZFSE_ENCODE_L_SYMBOLS','LZFSE_ENCODE_M_SYMBOLS','LZFSE_ENCODE_D_SYMBOLS',
           'LZFSE_ENCODE_LITERAL_SYMBOLS','LZFSE_ENCODE_L_STATES','LZFSE_ENCODE_M_STATES',
           'LZFSE_ENCODE_D_STATES','LZFSE_ENCODE_LITERAL_STATES','LZFSE_LITERALS_PER_BLOCK',
           'LZFSE_MATCHES_PER_BLOCK','LZFSE_L_DECODER_OFFSET','LZFSE_M_DECODER_OFFSET','LZFSE_D_DECODER_OFFSET']
    defs=[]
    for name in names:
        matches=re.findall(r'^#define '+name+r'\s+(.*)$',joined,re.M)
        assert matches,name
        defs.append('#define '+name+' '+matches[-1])
    defs.append(re.findall(r'^#define FSE_DECODER_TABLE_SLACK\s+.*$',fse,re.M)[-1])
    types=['typedef int32_t fse_bit_count;']
    for text,names in [(fse,['fse_in_stream64','fse_value_decoder_entry']),
                       (internal,['lzfse_compressed_block_decoder_state','uncompressed_block_decoder_state',
                                  'lzvn_compressed_block_decoder_state','lzfse_decoder_state',
                                  'lzfse_compressed_block_header_v1'])]:
        for name in names:
            end=text.index('} '+name+';')+len('} '+name+';')
            begin=text.rfind('typedef struct {',0,end)
            types.append(text[begin:end])
            if name=='fse_in_stream64': types.append('typedef fse_in_stream64 fse_in_stream;')
    return '\n'.join(defs+types)+'\n#define FSE_IOSTREAM_64 1\n'


def generate(source,internal,fse,arm=False):
    a=source.index('static LZFSE_HOT_ATTR int\nLZFSE_HOT(lzfse_decode_literals)')
    b=source.index('static LZFSE_HOT_ATTR __attribute__((noinline)) int',a)
    body=source[a:b]
    body=re.sub(r'#ifdef LZFSE_PROOF\n.*?#endif\n','',body,flags=re.S)
    body=body.replace('  uint8_t *lp = bs->literals;','  const uint8_t *const buf_initial=buf;\n  uint8_t *lp = bs->literals;',1)
    body=body.replace('    for (; lp < lp_safe;',loop(True)+'    for (; lp < lp_safe;',1)
    body=body.replace('  for (; lp < lp_end;',loop(False)+'  for (; lp < lp_end;',1)
    for old,new in [('fse_in_init','proof_fse_init'),('fse_in_flush_next','proof_fse_flush_next'),
                    ('fse_in_flush64_unchecked','proof_fse_flush_unchecked'),('fse_decode_u32','proof_fse_decode'),
                    ('load8','proof_load8'),('store4','proof_store4'),('memset','proof_memset')]:
        body=re.sub(r'\b'+old+r'\b',new,body)
    return '#define LZFSE_DECODE_COPY_MARGIN '+('64' if arm else '32')+'\n#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\n'+native_types(internal,fse)+MODELS+'''\n#undef FSE_LOOKAHEAD_REFILL
#define FSE_LOOKAHEAD_REFILL '''+('1' if arm else '0')+'''
#define LZFSE_HOT(x) proof_##x
#define LZFSE_HOT_ATTR
'''+CONTRACT+body

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--arm',action='store_true')
    parser.add_argument('--mutants',action='store_true')
    parser.add_argument('--output')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[3]
    source=(root/'crates/crushlzfse/csrc/lzfse_decode_hot.h').read_text()
    internal=(root/'crates/crushlzfse/csrc/lzfse_internal.h').read_text()
    fse=(root/'crates/crushlzfse/csrc/lzfse_fse.h').read_text()
    output=Path(args.output or root/'harness/build/proofs-frama-lzfse-literals-native')
    output.mkdir(parents=True,exist_ok=True)
    generated=generate(source,internal,fse,args.arm)
    verify('literals_native',generated,output,['proof_lzfse_decode_literals'],100,split=True,include_dirs=['crates/crushlzfse/csrc'])
    if args.mutants:
        variants={
            'unclamped_bulk':('if (safe_bytes > literal_bytes)',
                              'if (safe_bytes > literal_bytes + LZFSE_DECODE_COPY_MARGIN)'),
            'excess_bulk_groups':('size_t safe_groups = (size_t)(buf - buf_start) / 8;',
                                  'size_t safe_groups = (size_t)(buf - buf_start) / 4;'),
        }
        for name,(old,new) in variants.items():
            assert generated.count(old)==1, (name,'source changed')
            verify(name,generated.replace(old,new),output,['proof_lzfse_decode_literals'],
                   100,expected=False,split=True,include_dirs=['crates/crushlzfse/csrc'])

if __name__=='__main__': main()
