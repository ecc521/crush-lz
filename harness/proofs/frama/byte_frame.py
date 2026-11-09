#!/usr/bin/env python3
"""Query-independent protection of a byte across arbitrary bounded byte writes.

Standard library footprint models must establish the actual destination-only
write frame before using this theorem; output contents remain unconstrained.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
import output_frame
from wp_common import verify
MODEL=r'''
/* All byte writes permitted by a standard memcpy/memmove write frame. */
/*@ requires 0<=n<=ZBM_MAX_BITMAP_COUNT;
 requires \valid(d+(0..n-1));
 assigns d[0..n-1];
*/
void proof_havoc_bytes(uint8_t *d,int n);
/*@ requires 0<=n<=ZBM_MAX_BITMAP_COUNT;
 requires \valid(d+(0..n-1));
 requires \valid_read(value);
 requires \separated(value,d+(0..n-1));
 assigns d[0..n-1];
 ensures *value==\old(*value);
*/
static void proof_byte_frame(uint8_t *d,int n,const uint8_t *value)
{
 proof_havoc_bytes(d,n);
}
'''


def generate(source, model=MODEL):
    body=model[model.index('{\n'):]
    assert 'value' not in body, 'effect depends on protected query'
    return output_frame.generate(source,output_frame.MODEL+model)


def main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-byte-frame')
    output.mkdir(parents=True,exist_ok=True)
    verify('byte_frame',generate(source),output,['proof_byte_frame'],5)
    if args.mutants:
        old=r'requires \separated(value,d+(0..n-1));'
        assert MODEL.count(old)==1
        verify('byte_frame_alias',generate(source,MODEL.replace(old,'')),output,['proof_byte_frame'],5,False)


if __name__=='__main__':
    main()
