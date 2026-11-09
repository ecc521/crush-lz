#!/usr/bin/env python3
"""Verify the shipping LZBITMAP framing loop.

The loop is extracted verbatim from zbm_compress_generic(). Allocation,
scratch carving, parameter validation, and public wrappers are separate CBMC
obligations. The verified contract for zbm_compress_single_chunk describes
the per-chunk progress and memory footprints.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source):
    # Cut prefix before the vector SIMD helpers; includes struct zbm_compress_state
    end = source.index('static int zbm_bmprot(')
    prefix = source[:end]

    models = r'''
/*@ requires \valid(state);
    requires state->dest_left >= ZBM_MAGIC_SZ;
    assigns state->dest \from state->dest, state->dest_left;
    assigns state->dest_left \from state->dest_left;
    assigns state->prewritten \from state->prewritten;
    assigns state->dest[0 .. ZBM_MAGIC_SZ - 1] \from state->dest;
    ensures state->dest == \old(state->dest) + ZBM_MAGIC_SZ;
    ensures \base_addr(state->dest) == \base_addr(\old(state->dest));
    ensures state->dest_left == \old(state->dest_left) - ZBM_MAGIC_SZ;
    ensures state->prewritten == \old(state->prewritten) + ZBM_MAGIC_SZ;
    ensures \result == 0;
*/
int proof_zbm_write_magic(struct zbm_compress_state *state);

/*@ requires \valid(state);
    requires 0 <= state->src_left;
    requires 0 <= state->dest_left;
    requires \valid(state->dest + (0 .. state->dest_left - 1));
    requires \valid_read(state->src + (0 .. (state->src_left < CRUSHLZBITMAP_CHUNK_SIZE ? state->src_left : CRUSHLZBITMAP_CHUNK_SIZE) - 1));
    assigns state->src \from state->src, state->src_left;
    assigns state->dest \from state->dest, state->dest_left;
    assigns state->read \from state->src_left;
    assigns state->written \from state->src_left, state->dest_left;
    assigns state->decmp_len \from state->src_left;
    assigns state->dest[0 .. state->dest_left - 1] \from state->src[0 .. (state->src_left < CRUSHLZBITMAP_CHUNK_SIZE ? state->src_left : CRUSHLZBITMAP_CHUNK_SIZE) - 1];
    ensures \result == 0 || \result == ZBM_RANGE || \result < 0;
    ensures \result == 0 ==> (
        state->decmp_len == (\old(state->src_left) < CRUSHLZBITMAP_CHUNK_SIZE ? \old(state->src_left) : CRUSHLZBITMAP_CHUNK_SIZE) &&
        state->read == state->decmp_len &&
        sizeof(struct zbm_chunk_hdr) <= state->written <= state->dest_left &&
        state->dest == \old(state->dest) + state->written &&
        \base_addr(state->dest) == \base_addr(\old(state->dest)) &&
        state->src == \old(state->src) + state->read &&
        \base_addr(state->src) == \base_addr(\old(state->src))
    );
*/
int proof_zbm_compress_single_chunk(struct zbm_compress_state *state, int (*build_chunk)(struct zbm_compress_state *));

/*@ requires \valid(state);
    requires 0 <= src_size <= CRUSHLZBITMAP_MAX_SRC_SIZE;
    requires 0 <= dest_size <= PTRDIFF_MAX;
    requires dest_size >= ZBM_MAGIC_SZ;
    requires \valid_read(src + (0 .. src_size - 1));
    requires \valid(dest + (0 .. dest_size - 1));
    requires \valid(out_len);
    requires \separated(state, out_len, src + (0 .. src_size - 1), dest + (0 .. dest_size - 1));
    assigns *out_len, *state, dest[0 .. dest_size - 1];
    ensures \result == 0 || \result == ZBM_RANGE || \result < 0;
    ensures \result == 0 ==> *out_len <= dest_size;
*/
static int proof_zbm_frame(struct zbm_compress_state *state, uint8_t *dest, size_t dest_size,
                           const uint8_t *src, size_t src_size, size_t *out_len,
                           int (*build_chunk)(struct zbm_compress_state *))
{
    int err = 0;

    state->src = src;
    state->src_left = src_size;
    state->dest = dest;
    state->dest_left = dest_size;
    state->preread = 0;
    state->prewritten = 0;
    state->buf_base = src;
    state->buf_len = src_size;

    err = proof_zbm_write_magic(state);
    if(err)
        return err;

    /*@ loop invariant 0 <= state->src_left <= src_size;
        loop invariant state->preread + state->src_left == src_size;
        loop invariant ZBM_MAGIC_SZ <= state->prewritten <= dest_size;
        loop invariant state->dest_left == dest_size - state->prewritten;
        loop invariant \base_addr(state->dest) == \base_addr(dest);
        loop invariant \base_addr(state->src) == \base_addr(src);
        loop invariant state->dest == dest + state->prewritten;
        loop invariant state->src == src + state->preread;
        loop assigns state->src, state->dest, state->src_left, state->dest_left,
                     state->preread, state->prewritten, state->read, state->written,
                     state->decmp_len, err,
                     dest[0 .. dest_size - 1];
        loop variant state->src_left;
    */
    do {
        err = proof_zbm_compress_single_chunk(state, build_chunk);
        if(err)
            return err;
        state->src_left -= state->read;
        state->dest_left -= state->written;
        state->preread += state->decmp_len;
        state->prewritten += state->written;
    } while(state->read != 0);

    *out_len = state->prewritten;
    return 0;
}
'''
    return prefix + models


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output = root / 'harness/build/proofs-frama-zbm-frame'
    output.mkdir(parents=True, exist_ok=True)

    functions = ['proof_zbm_frame']
    verify('zbm_frame', generate(source), output, functions, 50,
           split=True, include_dirs=('crates/lzbitmap/csrc',))

    if args.mutants:
        for name, old, new in [
            ('no_progress', 'state->src_left -= state->read;', 'state->src_left -= 0;'),
            ('no_prewritten', 'state->prewritten += state->written;', 'state->prewritten += 0;'),
            ('wrong_out_len', '*out_len = state->prewritten;', '*out_len = state->prewritten + 1;'),
        ]:
            bad = generate(source).replace(old, new)
            assert bad != generate(source)
            verify(name, bad, output, functions, 10, False,
                   split=True, include_dirs=('crates/lzbitmap/csrc',))


if __name__ == '__main__':
    main()
