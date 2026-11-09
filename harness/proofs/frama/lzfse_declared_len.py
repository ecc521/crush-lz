#!/usr/bin/env python3
"""Shipping stream-length parser; header unpack/check are separate boundaries."""
from pathlib import Path
import argparse
import re
import sys
sys.dont_write_bytecode=True
from wp_common import verify

CONTRACT=r'''
/*@ requires \base_addr(src)==\base_addr(src_end);
    requires 0<=src_end-src<=PTRDIFF_MAX;
    requires \valid_read(src+(0 .. src_end-src-1));
    requires \valid(out_len);
    requires \separated(out_len,src+(0 .. src_end-src-1));
    assigns *out_len \from src[0 .. src_end-src-1];
    ensures \result==0 || \result==-1;
*/
'''
LOOP=r'''
    /*@ loop invariant \base_addr(src)==\base_addr(src_initial);
        loop invariant 0<=src-src_initial<=src_end-src_initial;
        loop invariant \valid_read(src+(0 .. src_end-src-1));
        loop assigns src,total,*out_len;
        loop variant src_end-src;
    */
'''

def generate(source,internal):
    types=[]
    for name in ['uncompressed_block_header','lzfse_compressed_block_header_v1',
                 'lzfse_compressed_block_header_v2','lzvn_compressed_block_header']:
        end=internal.index(name+';')+len(name+';')
        start=internal.rfind('typedef struct {',0,end)
        types.append(internal[start:end])
    constants='\n'.join(line for line in internal.splitlines() if line.startswith('#define LZFSE_') and
                      ('_BLOCK_MAGIC ' in line or re.match(r'#define LZFSE_ENCODE_\w+_SYMBOLS ',line)))
    body=source[source.index('int lzfse_declared_len('):]
    body=re.sub(r'#ifdef LZFSE_PROOF\n.*?#endif\n','',body,flags=re.S)
    body=body.replace('  size_t total = 0;','  size_t total = 0;\n  const uint8_t *const src_initial=src;',1)
    body=body.replace('  for (;;)',LOOP+'  for (;;)',1)
    # The packed header cast changes the pointer type, not its address. WP's
    # byte/struct cast model is incomplete, so keep that boundary byte-based.
    # The packed size is a ghost argument equal to the native size helper
    # result; the available byte count is the native unpacker's new argument.
    old='const lzfse_compressed_block_header_v2 *header2 =\n            (const lzfse_compressed_block_header_v2 *)src;'
    assert body.count(old)==1
    body=body.replace(old,'const uint8_t *header2 = src;')
    old='lzfse_decode_v1(&header1, header2,\n                            (size_t)(src_end - src))'
    assert body.count(old)==1
    body=body.replace(old,'proof_decode_v1(&header1, header2, header_size, (size_t)(src_end - src))')
    return '#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\n'+constants+'\n'+'\n'.join(types)+r'''
/*@ requires \valid_read(p+(0 .. 3)); assigns \nothing; */
uint32_t load4(const uint8_t *p);
/*@ requires \valid_read(p+(0 .. 31));
    assigns \nothing;
    ensures 0<=\result<=4294967295;
*/
uint32_t lzfse_decode_v2_header_size(const uint8_t *p);
/*@ requires \valid(out);
    requires available>=32;
    requires \valid_read(in+(0 .. available-1));
    requires \separated(out,in+(0 .. 31));
    assigns *out;
    ensures \result==0 || \result==-1;
    ensures \result==0 ==> 32<=header_size<=sizeof(lzfse_compressed_block_header_v2) &&
      header_size<=available;
*/
int proof_decode_v1(lzfse_compressed_block_header_v1 *out,const uint8_t *in,
                    size_t header_size,size_t available);
/*@ requires \valid_read(header); assigns \nothing; */
int lzfse_check_block_header_v1(const lzfse_compressed_block_header_v1 *header);
/* Standard memcpy footprint specialized to the native v1 header call. The
 * copied values are unrestricted: this is strictly a spatial proof. */
/*@ requires n==sizeof(*out);
    requires \valid(out);
    requires \valid_read(src+(0 .. n-1));
    requires \separated(out,src+(0 .. n-1));
    assigns *out;
*/
void proof_header_memcpy(lzfse_compressed_block_header_v1 *out,const uint8_t *src,size_t n);
#define memcpy proof_header_memcpy
''' + CONTRACT+body

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output')
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[3]
    source=(root/'crates/crushlzfse/csrc/lzfse_decode_base.c').read_text()
    internal=(root/'crates/crushlzfse/csrc/lzfse_internal.h').read_text()
    output=Path(args.output or root/'harness/build/proofs-frama-lzfse-declared-len')
    output.mkdir(parents=True,exist_ok=True)
    verify('declared_len',generate(source,internal),output,['lzfse_declared_len'],50,split=True)
    if args.mutants:
        for name,old,new in [
            ('missing_magic_bound','if ((size_t)(src_end - src) < 4)','if (0)'),
            ('missing_payload_bound','if ((size_t)(src_end - src) < n_raw_bytes)','if (0)'),
            ('missing_progress','src += sizeof(uncompressed_block_header);','src += 0;'),
        ]:
            a=source.index('int lzfse_declared_len(')
            piece=source[a:]
            assert piece.count(old)==1
            verify(name,generate(source[:a]+piece.replace(old,new),internal),output,['lzfse_declared_len'],10,False,split=True)

if __name__=='__main__': main()
