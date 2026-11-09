#!/usr/bin/env python3
"""Verify the shipping LZ4 framing loop, with upstream LZ4 excluded.

The loop and final terminator are extracted verbatim from encode(). Allocation,
scratch carving and the public wrappers are separate CBMC obligations. The
upstream contracts describe its documented buffer and state footprints.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source):
    prefix = source[:source.index('/* ---- encoder -----')]
    # CBMC-only dependency declarations are preprocessed away. The state
    # alignment helper is unused here; its arithmetic has a CBMC lemma.
    prefix = prefix.replace('static void put_le32(uint8_t *p, uint32_t v)', r'''
/*@ requires \valid(p+(0 .. 3));
    assigns p[0 .. 3];
*/
static void put_le32(uint8_t *p, uint32_t v)''')
    a = source.index('    while (pos < src_size)', source.index('static int encode('))
    b = source.index('\ndone:', a)
    body = source[a:b]
    assert body.endswith("\n#endif\n")
    body = body[:-len("\n#endif\n")]
    # Lift the excluded library boundaries to unsigned-byte pointer models.
    # The shipping char*/void* conversions preserve the same byte addresses;
    # WP's typed model otherwise rejects C's legal signed/unsigned-char aliases.
    body = body.replace('LZ4_compress_HC_extStateHC(', 'proof_lz4_hc(')
    body = body.replace('LZ4_compress_fast_extState(', 'proof_lz4_fast(')
    body = body.replace('(const char *)(src + pos)', '(src + pos)')
    body = body.replace('(char *)(hdr + 12)', '(hdr + 12)')
    body = body.replace('memmove(hdr + 8, src + pos, block)',
                        'proof_memmove(hdr + 8, src + pos, block)')
    # The annotations already in C compile away under Frama-C. Add the
    # inductive pointer and progress facts immediately before the same loop.
    body = body.replace('    while (pos < src_size)', r'''
    /*@ loop invariant 0<=pos<=src_size;
        loop invariant \base_addr(out)==\base_addr(dest);
        loop invariant 0<=out-dest<=dest_size;
        loop invariant rc==0;
        loop assigns pos,out,rc,dest[0 .. dest_size-1],
            mem[0 .. state_bytes-1];
        loop variant src_size-pos;
    */
    while (pos < src_size)''', 1)
    return prefix + r'''
/*@ requires \valid(state+(0 .. sizeof(LZ4_stream_t)-1));
    requires 0<inputSize<=CRUSHLZ4_BLOCK_SIZE;
    requires 0<capacity;
    requires 1<=acceleration<=CLZ4_ACCEL_MAX;
    requires \valid_read(src+(0 .. inputSize-1));
    requires \valid(dst+(0 .. capacity-1));
    requires \separated(state+(0 .. sizeof(LZ4_stream_t)-1),
                          src+(0 .. inputSize-1),dst+(0 .. capacity-1));
    assigns state[0 .. sizeof(LZ4_stream_t)-1],dst[0 .. capacity-1];
    ensures 0<=\result<=capacity;
*/
int proof_lz4_fast(uint8_t *state,const uint8_t *src,uint8_t *dst,
                               int inputSize,int capacity,int acceleration);

/*@ requires \valid(state+(0 .. sizeof(LZ4_streamHC_t)-1));
    requires 0<inputSize<=CRUSHLZ4_BLOCK_SIZE;
    requires 0<capacity;
    requires 1<=level<=LZ4HC_CLEVEL_MAX;
    requires \valid_read(src+(0 .. inputSize-1));
    requires \valid(dst+(0 .. capacity-1));
    requires \separated(state+(0 .. sizeof(LZ4_streamHC_t)-1),
                          src+(0 .. inputSize-1),dst+(0 .. capacity-1));
    assigns state[0 .. sizeof(LZ4_streamHC_t)-1],dst[0 .. capacity-1];
    ensures 0<=\result<=capacity;
*/
int proof_lz4_hc(uint8_t *state,const uint8_t *src,uint8_t *dst,
                              int inputSize,int capacity,int level);

/*@ requires \valid(dst+(0 .. count-1));
    requires \valid_read(src+(0 .. count-1));
    assigns dst[0 .. count-1], \result \from dst,src[0 .. count-1];
    ensures \result==dst;
*/
uint8_t *proof_memmove(uint8_t *dst,const uint8_t *src,size_t count);

/*@ requires \valid(row);
    requires row->mode==CRUSHLZ4_MODE_FAST || row->mode==CRUSHLZ4_MODE_HC;
    requires row->mode==CRUSHLZ4_MODE_FAST ==> 1<=row->param<=CLZ4_ACCEL_MAX;
    requires row->mode==CRUSHLZ4_MODE_HC ==> 1<=row->param<=LZ4HC_CLEVEL_MAX;
    requires 0<=src_size<=PTRDIFF_MAX;
    requires 0<=dest_size<=PTRDIFF_MAX;
    requires \valid_read(src+(0 .. src_size-1));
    requires \valid(dest+(0 .. dest_size-1));
    requires \valid(out_len);
    requires state_bytes == (row->mode==CRUSHLZ4_MODE_HC ? sizeof(LZ4_streamHC_t) : sizeof(LZ4_stream_t));
    requires \valid(mem+(0 .. state_bytes-1));
    requires \separated(row,out_len,src+(0 .. src_size-1),
                          dest+(0 .. dest_size-1),mem+(0 .. state_bytes-1));
    assigns *out_len,dest[0 .. dest_size-1],mem[0 .. state_bytes-1];
    ensures \result==0 || \result==CLZ4_RANGE;
    ensures \result==0 ==> *out_len<=dest_size;
*/
static int proof_frame_loop(uint8_t *dest,size_t dest_size,
                            const uint8_t *src,size_t src_size,size_t *out_len,
                            uint8_t *mem,size_t state_bytes,const struct clz4_level_row *row)
{
    uint8_t *out=dest;
    uint8_t *const out_end=out+dest_size;
    size_t pos=0;
    int rc=0;
''' + body + r'''
done:
    return rc;
}
'''


def main():
    args = argparse.ArgumentParser()
    args.add_argument('--mutants', action='store_true')
    args = args.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlz4/csrc/crushlz4.c').read_text()
    output = root / 'harness/build/proofs-frama-lz4-frame'
    output.mkdir(parents=True, exist_ok=True)
    functions = ['put_le32', 'proof_frame_loop']
    verify('lz4_frame', generate(source), output, functions, 700,
           split=True, include_dirs=('crates/crushlz4/csrc',))
    if args.mutants:
        for name, old, new in [
            ('no_capacity', 'if ((size_t)(out_end - hdr) < 8 + block)', 'if (0)'),
            ('no_progress', 'pos += block;', 'pos += 0;'),
            ('header_overrun', 'p[3] = (uint8_t)(v >> 24);', 'p[4] = (uint8_t)(v >> 24);'),
        ]:
            assert source.count(old) == 1
            verify(name, generate(source.replace(old, new)), output, functions,
                   20, False, split=True, include_dirs=('crates/crushlz4/csrc',))


if __name__ == '__main__':
    main()
