#!/usr/bin/env python3
"""Native 32-bit literal loop (FSE_IOSTREAM_64 == 0), composed with the
registered 32-bit FSE primitive contracts from crates/crushlzfse/csrc/lzfse_fse.h.

The shipping configuration is modelled explicitly: fse_in_stream32 with a
32-bit accumulator (accum_nbits in [0, 32)), the checked 32-bit init and
refill, and COPY_MARGIN 64 (non-x86_64). The table-validity predicate is an
explicit caller obligation, as in lzfse_literals_native.py.
"""
from pathlib import Path
import argparse
import re
import sys
sys.dont_write_bytecode = True
from wp_common import verify
from lzfse_literals_native import CONTRACT

MODELS = r'''
/*@ predicate input_valid(fse_in_stream *in)=
      0<=in->accum_nbits<32 && (in->accum >> in->accum_nbits)==0;
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
    assigns *in,*buf \from bits,in,buf,start[0 .. *buf-start-1];
    ensures \result==0 || \result==-1;
    ensures \base_addr(*buf)==\base_addr(\old(*buf));
    ensures start<=*buf<=\old(*buf);
    ensures \result==0 ==> \old(*buf)-*buf==(bits!=0 ? 4 : 3);
    ensures \result==0 ==> input_valid(in) &&
      (bits!=0 ==> in->accum_nbits==bits+32) &&
      (bits==0 ==> in->accum_nbits==24);
*/
int proof_fse_init(fse_in_stream *in,int bits,const uint8_t **buf,const uint8_t *start);
/*@ requires \valid(in) && \valid(buf);
    requires input_valid(in);
    requires \base_addr(*buf)==\base_addr(start);
    requires 0<=*buf-start<=PTRDIFF_MAX;
    requires \valid_read(start+(0 .. *buf-start-1));
    requires \separated(in,buf,start+(0 .. *buf-start-1));
    assigns *in,*buf \from in,buf,start[0 .. *buf-start-1];
    ensures \result==0 || \result==-1;
    ensures \base_addr(*buf)==\base_addr(\old(*buf));
    ensures start<=*buf<=\old(*buf);
    ensures \result==0 ==> input_valid(in) && 24<=in->accum_nbits;
    ensures \result==-1 ==> *buf==\old(*buf) && in->accum==\old(in->accum) &&
      in->accum_nbits==\old(in->accum_nbits);
*/
int proof_fse_flush32(fse_in_stream *in,const uint8_t **buf,const uint8_t *start);
/*@ requires \valid(state) && *state<1024 && \valid(in);
    requires input_valid(in) && in->accum_nbits>=10;
    requires \valid_read(table+(0 .. 1023));
    requires literal_table_valid(table);
    requires \separated(state,in,table+(0 .. 1023));
    assigns *state,*in,\result \from state,in,table[0 .. 1023];
    ensures *state<1024 && input_valid(in);
    ensures 0<=\old(in->accum_nbits)-in->accum_nbits<=10;
*/
uint8_t proof_fse_decode(uint32_t *state,const int32_t *table,fse_in_stream *in);
/*@ requires \valid_read(p+(0 .. 7)); assigns \nothing; */
uint64_t proof_load8(const uint8_t *p);
/*@ requires \valid(p+(0 .. n-1)); assigns p[0 .. n-1]; */
void proof_memset(uint8_t *p,int value,size_t n);
'''


def loop():
    return r'''
    /*@ loop invariant \base_addr(lp)==\base_addr(&bs->literals[0]);
        loop invariant 0<=lp-&bs->literals[0]<=header1->n_literals+3;
        loop invariant (lp-&bs->literals[0])%4==0;
        loop invariant \base_addr(buf)==\base_addr(buf_start);
        loop invariant buf_start<=buf<=buf_initial;
        loop invariant \valid_read(s->src_begin+(0 .. s->src_end-s->src_begin-1));
        loop invariant input_valid(&in);
        loop invariant state0<1024 && state1<1024 && state2<1024 && state3<1024;
        loop invariant literal_table_valid(ltab);
        loop assigns lp,buf,in,state0,state1,state2,state3,
          bs->literals[0 .. 40000+LZFSE_DECODE_COPY_MARGIN-1];
        loop variant lp_end-lp;
    */
'''


def native_types(internal, fse):
    joined = internal.replace('\\\n', ' ')
    names = ['LZFSE_ENCODE_L_SYMBOLS', 'LZFSE_ENCODE_M_SYMBOLS', 'LZFSE_ENCODE_D_SYMBOLS',
             'LZFSE_ENCODE_LITERAL_SYMBOLS', 'LZFSE_ENCODE_L_STATES', 'LZFSE_ENCODE_M_STATES',
             'LZFSE_ENCODE_D_STATES', 'LZFSE_ENCODE_LITERAL_STATES', 'LZFSE_LITERALS_PER_BLOCK',
             'LZFSE_MATCHES_PER_BLOCK', 'LZFSE_L_DECODER_OFFSET', 'LZFSE_M_DECODER_OFFSET',
             'LZFSE_D_DECODER_OFFSET']
    defs = []
    for name in names:
        matches = re.findall(r'^#define ' + name + r'\s+(.*)$', joined, re.M)
        assert matches, name
        defs.append('#define ' + name + ' ' + matches[-1])
    defs.append(re.findall(r'^#define FSE_DECODER_TABLE_SLACK\s+.*$', fse, re.M)[-1])
    types = ['typedef int32_t fse_bit_count;']
    for text, names in [(fse, ['fse_in_stream32', 'fse_value_decoder_entry']),
                        (internal, ['lzfse_compressed_block_decoder_state', 'uncompressed_block_decoder_state',
                                    'lzvn_compressed_block_decoder_state', 'lzfse_decoder_state',
                                    'lzfse_compressed_block_header_v1'])]:
        for name in names:
            end = text.index('} ' + name + ';') + len('} ' + name + ';')
            begin = text.rfind('typedef struct {', 0, end)
            types.append(text[begin:end])
            if name == 'fse_in_stream32':
                types.append('typedef fse_in_stream32 fse_in_stream;')
    return '\n'.join(defs + types) + '\n#define FSE_IOSTREAM_64 0\n'


def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def generate(source, internal, fse):
    a = source.index('static LZFSE_HOT_ATTR int\nLZFSE_HOT(lzfse_decode_literals)')
    b = source.index('static LZFSE_HOT_ATTR __attribute__((noinline)) int', a)
    body = source[a:b]
    body = re.sub(r'#ifdef LZFSE_PROOF\n.*?#endif\n', '', body, flags=re.S)
    body = replace_once(body, '  uint8_t *lp = bs->literals;',
                        '  const uint8_t *const buf_initial=buf;\n  uint8_t *lp = bs->literals;')
    body = replace_once(body, '  for (; lp < lp_end;', loop() + '  for (; lp < lp_end;')
    for old, new in [('fse_in_init', 'proof_fse_init'), ('fse_in_flush', 'proof_fse_flush32'),
                     ('fse_decode_u32', 'proof_fse_decode'), ('load8', 'proof_load8'),
                     ('memset', 'proof_memset')]:
        body = re.sub(r'\b' + old + r'\b', new, body)
    return ('#define LZFSE_DECODE_COPY_MARGIN 64\n#include <stdint.h>\n#include <stddef.h>\n'
            '#include <limits.h>\n' + native_types(internal, fse) + MODELS +
            '\n#define FSE_LOOKAHEAD_REFILL 0\n#define LZFSE_HOT(x) proof_##x\n#define LZFSE_HOT_ATTR\n' +
            CONTRACT + body)


def failed_goals(log):
    return {line.strip() for line in log.read_text().splitlines() if '[Failed]' in line}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    parser.add_argument('--output')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzfse_decode_hot.h').read_text()
    internal = (root / 'crates/crushlzfse/csrc/lzfse_internal.h').read_text()
    fse = (root / 'crates/crushlzfse/csrc/lzfse_fse.h').read_text()
    output = Path(args.output or root / 'harness/build/proofs-frama-lzfse-literals-native32')
    output.mkdir(parents=True, exist_ok=True)
    generated = generate(source, internal, fse)
    baseline_error = None
    try:
        verify('literals_native32', generated, output, ['proof_lzfse_decode_literals'], 100,
               split=True, include_dirs=['crates/crushlzfse/csrc'])
    except AssertionError as error:
        baseline_error = error
    baseline = failed_goals(output / 'literals_native32.log')
    if args.mutants:
        variants = {
            'drop_refill_before_lp2':
                ('    if (proof_fse_flush32(&in, &buf, buf_start) != 0)\n'
                 '      return -1; // [25, 23] bits\n    lp[2] = ',
                 '    lp[2] = '),
            'drop_refill_before_lp0':
                ('    if (proof_fse_flush32(&in, &buf, buf_start) != 0)\n'
                 '      return -1; // [25, 23] bits\n    lp[0] = ',
                 '    lp[0] = '),
            'tail_overrun_margin':
                ('  uint8_t *const lp_end = lp + header1->n_literals;',
                 '  uint8_t *const lp_end = lp + header1->n_literals + LZFSE_DECODE_COPY_MARGIN;'),
        }
        for name, (old, new) in variants.items():
            assert generated.count(old) == 1, (name, 'source changed')
            verify(name, generated.replace(old, new), output, ['proof_lzfse_decode_literals'],
                   100, expected=False, split=True, include_dirs=['crates/crushlzfse/csrc'])
            new_failures = failed_goals(output / (name + '.log')) - baseline
            assert new_failures, (name, 'no failing goal beyond the baseline')
            print(name, 'new failing goals:', sorted(new_failures), flush=True)
    if baseline_error is not None:
        print('baseline: NOT fully proved; failing goals:', sorted(baseline), flush=True)
        raise baseline_error


if __name__ == '__main__':
    main()
