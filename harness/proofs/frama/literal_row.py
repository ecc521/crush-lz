#!/usr/bin/env python3
"""Literal pack-row geometry and count propagation for writer composition.

The generic table precondition states the byte-8 count relation proved for
our actual static table by zbm_pack8_correct. This theorem establishes the
sixteen-byte row footprint and output separation for the original row lookup.
It does not establish encoder callers or prove native intrinsic semantics.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode=True

MODEL = '/*@ logic integer pc(integer bm) = ((bm>>0)&1) + ((bm>>1)&1) + ((bm>>2)&1) + ((bm>>3)&1) + ((bm>>4)&1) + ((bm>>5)&1) + ((bm>>6)&1) + ((bm>>7)&1); */\n'+r'''
/* Pointer geometry for the exact table row expression used by the writer.
   The actual static table's count relation comes from zbm_pack8_correct. */
/*@ requires \valid_read(rows+(0 .. 255));
 requires 0 <= room <= 0x1000000000000;
 requires \valid(dest+(0 .. room-1));
 requires \separated(rows+(0 .. 255),dest+(0 .. room-1));
 requires \forall integer q; 0 <= q <= 255 ==> rows[q][8]==pc(q);
 assigns \result \from rows,bm;
 ensures \result==&rows[bm][0];
 ensures \valid_read(\result+(0 .. 15));
 ensures \result[8]==pc(bm);
 ensures \separated(\result+(0 .. 15),dest+(0 .. room-1));
*/
static const uint8_t *proof_row_geometry(const uint8_t (*rows)[16],uint8_t bm,uint8_t *dest,ptrdiff_t room)
{
 return rows[bm];
}
'''


def generate(source,model=MODEL):
    end=source.index('static long zbm_literal_total(')
    return source[:end]+model


def main():
    import argparse
    import concurrent.futures
    from wp_common import verify
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants',action='store_true')
    args=parser.parse_args()
    source=Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output=Path('harness/build/proofs-frama-literal-row')
    output.mkdir(parents=True,exist_ok=True)
    functions=['proof_row_geometry']
    verify('literal_row',generate(source),output,functions,5)
    if args.mutants:
        variants=[('wrong_row_start','return rows[bm];','return rows[bm]+1;'),
          ('overlapping_output',r'requires \separated(rows+(0 .. 255),dest+(0 .. room-1));','')]
        def mutation(item):
            name,old,new=item
            assert MODEL.count(old)==1,'mutation site changed'
            verify(name,generate(source,MODEL.replace(old,new)),output,functions,5,False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(mutation,variants))


if __name__=='__main__':
    main()
