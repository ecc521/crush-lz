#!/usr/bin/env python3
"""WP proof of the shipping period writer; no alternate writer algorithm.

The read-only prefix bookkeeping is separately verified. The typed memcpy
contract models the C library's fixed two-byte footprint, not output bytes.
"""
from pathlib import Path
import sys
sys.dont_write_bytecode = True


def generate(source):
    from wp_common import protect_span
    s = source
    start = s.index('static int zbm_write_metadata_1(struct zbm_compress_state *state)')
    end = s.index('static int zbm_write_metadata_2', start)
    helpers=r'''
    /*@ requires \valid_read(st);
        requires 0 <= count <= ZBM_MAX_BITMAP_COUNT;
        requires \valid(prefix + (0 .. count));
        requires \separated(st, prefix + (0 .. count));
        requires \forall integer q; 0 <= q < count ==> st->bitmaps[q].period_bytecnt <= 2;
        assigns prefix[0 .. count];
        ensures prefix[0] == 0;
        ensures \forall integer q; 0 <= q < count ==> prefix[q+1] == prefix[q] + st->bitmaps[q].period_bytecnt;
        ensures \forall integer q; 0 <= q <= count ==> 0 <= prefix[q] <= 2 * q;
        ensures \forall integer j; 0 <= j <= count ==> prefix[j] <= prefix[count];
    */
    static void proof_build_period_prefix(struct zbm_compress_state *st, unsigned *prefix, int count)
    {
        int q;
        prefix[0] = 0;
        /*@ loop invariant 0 <= q <= count;
            loop invariant prefix[0] == 0;
            loop invariant \forall integer j; 0 <= j < q ==> prefix[j+1] == prefix[j] + st->bitmaps[j].period_bytecnt;
            loop invariant \forall integer j; 0 <= j <= q ==> 0 <= prefix[j] <= 2 * j;
            loop invariant \forall integer j; 0 <= j <= q ==> prefix[j] <= prefix[q];
            loop assigns q, prefix[0 .. count];
            loop variant count - q;
        */
        for(q = 0; q < count; ++q) {
            /*@ assert prefix[q] <= 2 * q; */
            prefix[q+1] = prefix[q] + st->bitmaps[q].period_bytecnt;
        }
    }
    
    /*@ requires n == 2;
        requires \valid(d + (0 .. 1));
        requires \valid_read(src);
        requires \separated(d + (0 .. 1), src);
        assigns d[0 .. 1] \from src[0];
    */
    void proof_period_memcpy(uint8_t *d, const uint16_t *src, size_t n);
    #define memcpy(d, src, n) proof_period_memcpy(d, src, n)
    
    /*@ requires \valid(state);
        requires \valid(state->dest) || \valid(state->dest - 1);
        requires 0 <= state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
        requires 0 <= state->dest_end - state->dest <= 0x1000000000000;
        requires \base_addr(state->dest) == \base_addr(state->dest_end);
        requires \valid(state->dest + (0 .. state->dest_end - state->dest - 1));
        requires \separated(state, state->dest + (0 .. state->dest_end - state->dest - 1));
        requires \forall integer q; 0 <= q < state->bmp_cnt ==> state->bitmaps[q].period_bytecnt <= 2;
        requires state->written <= UINT32_MAX - 2 * state->bmp_cnt;
        assigns state->dest, state->written, state->dest[0 .. state->dest_end - state->dest - 1];
        ensures state->written == \old(state->written) + (state->dest - \old(state->dest));
        ensures \base_addr(state->dest) == \base_addr(state->dest_end);
        ensures 0 <= state->dest_end - state->dest;
        ensures \result == 0 || \result == -1024;
        ensures \result == 0 ==> \base_addr(state->dest) == \base_addr(\old(state->dest));
        ensures \result == 0 ==> 0 <= state->dest - \old(state->dest) <= \old(state->dest_end - state->dest);
        ensures \result != 0 ==> state->dest == \old(state->dest) && state->written == \old(state->written);
    */
    '''
    body=s[start:end]
    assert body.count('for(i = 0; i < state->bmp_cnt; ++i)') == 3, 'writer loops changed; review annotations'
    assert body.count('memcpy(') == 1, 'memcpy footprint changed; review model'
    body=body.replace('    int i;\n','    int i;\n    unsigned proof_prefix[ZBM_MAX_BITMAP_COUNT + 1];\n    proof_build_period_prefix(state, proof_prefix, state->bmp_cnt);\n',1)
    relation=r'\forall integer q; 0 <= q < state->bmp_cnt ==> proof_prefix[q+1] == proof_prefix[q] + state->bitmaps[q].period_bytecnt;'
    body=body.replace('        for(i = 0; i < state->bmp_cnt; ++i) {\n            uint16_t p',r'''        /*@ loop invariant 0 <= i <= state->bmp_cnt;
                loop invariant 0 <= d - state->dest <= 2 * i;
                loop assigns i, d, state->dest[0 .. room - 1];
                loop variant state->bmp_cnt - i;
            */
            for(i = 0; i < state->bmp_cnt; ++i) {
                uint16_t p''')
    body=body.replace('        for(i = 0; i < state->bmp_cnt; ++i)\n            exact +=',r'''        /*@ loop invariant 0 <= i <= state->bmp_cnt;
                loop invariant exact == proof_prefix[i];
                loop assigns i, exact;
                loop variant state->bmp_cnt - i;
            */
            for(i = 0; i < state->bmp_cnt; ++i)
                exact +=''')
    body=body.replace('        for(i = 0; i < state->bmp_cnt; ++i) {\n            bmap',r'''        /*@ loop invariant 0 <= i <= state->bmp_cnt;
                loop invariant d == state->dest + proof_prefix[i];
                loop invariant 0 <= d - state->dest <= exact;
                loop invariant '''+relation+r'''
                loop assigns i, d, bmap, period, state->dest[0 .. room - 1];
                loop variant state->bmp_cnt - i;
            */
            for(i = 0; i < state->bmp_cnt; ++i) {
                bmap''')
    body = body.replace('loop invariant 0 <= d - state->dest <= 2 * i;', r'loop invariant 0 <= d - state->dest <= 2 * i;' + '\n            ' + r'loop invariant \base_addr(d) == \base_addr(state->dest);')
    return protect_span(s[:start]+helpers+body, source)


def main():
    import sys
    sys.dont_write_bytecode = True
    import argparse
    import concurrent.futures
    import subprocess
    from wp_common import verify

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    source = Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output = Path('harness/build/proofs-frama-period')
    output.mkdir(parents=True, exist_ok=True)

    def prove(name, text, expected):
        generated = generate(text)
        # Verify that every shipping loop was annotated and the helper was kept.
        assert generated.count('loop invariant') == 14
        verify(name, generated, output,
               ['proof_build_period_prefix', 'zbm_write_metadata_1', 'proof_trial_destination'],
               130, expected)

    # Concrete executions of the unmodified C file witness satisfiable empty,
    # tight, short and speculative-store contracts, including 4096 blocks.
    witness = output / 'witness.c'
    witness.write_text(r'''#include <assert.h>
#include "libzbitmap.c"
static struct zbm_compress_state st;
static uint8_t output[2 * ZBM_MAX_BITMAP_COUNT + 4];
static void check(int count, int pbc, int room, int expected) {
    memset(&st, 0, sizeof(st));
    memset(output, 0xee, sizeof(output));
    st.bmp_cnt = count; st.dest = output; st.dest_end = output + room;
    for(int i = 0; i < count; ++i) {
        st.bitmaps[i].period_bytecnt = pbc; st.periods[i] = 0x1234;
    }
    int rc = zbm_write_metadata_1(&st);
    assert(rc == expected);
    assert(st.dest == output + (rc == 0 ? count * pbc : 0));
    assert(st.written == (rc == 0 ? (unsigned)(count * pbc) : 0));
    for(unsigned i = room; i < sizeof(output); ++i) assert(output[i] == 0xee);
}
int main(void) {
    check(0, 0, 0, 0); check(1, 2, 2, 0);
    check(1, 2, 1, ZBM_CANT_COMPRESS);
    check(3, 0, 2, 0); check(3, 1, 3, 0); check(3, 2, 8, 0);
    check(ZBM_MAX_BITMAP_COUNT, 2, 2 * ZBM_MAX_BITMAP_COUNT, 0);
    check(ZBM_MAX_BITMAP_COUNT, 2, 2 * ZBM_MAX_BITMAP_COUNT + 2, 0);
    return 0;
}
''')
    subprocess.run(['gcc', '-std=c11', '-O0', '-g0', '-DCRUSH_SIMD_PORTABLE',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-Icrates/lzbitmap/csrc', str(witness), '-o', str(output / 'witness')],
                   check=True)
    subprocess.run([str(output / 'witness')], check=True)
    print('eight executions of the unmodified writer passed with ASan/UBSan', flush=True)

    prove('period_metadata', source, True)
    if args.mutants:
        # Also check the sharper safe bound; this does not edit shipping code.
        prove('bulk_exact_bound', source.replace(
            'if(2 * state->bmp_cnt + 2 <= room)',
            'if(2 * state->bmp_cnt <= room)'), True)
        changes = [
            ('bulk_short', 'if(2 * state->bmp_cnt + 2 <= room)',
             'if(2 * state->bmp_cnt - 1 <= room)'),
            ('tight_capacity', 'if(exact > room)\n            return ZBM_CANT_COMPRESS;',
             'if(exact > room + 1)\n            return ZBM_CANT_COMPRESS;'),
            ('tight_extra_store', '*d++ = (uint8_t)(period >> 8);',
             '*d++ = (uint8_t)(period >> 8); *d++ = 0;'),
        ]
        start = source.index('static int zbm_write_metadata_1(')
        end = source.index('static int zbm_write_metadata_2', start)
        body = source[start:end]
        def mutant(change):
            name, before, after = change
            assert body.count(before) == 1
            prove(name, source[:start] + body.replace(before, after) + source[end:], False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(mutant, changes))


if __name__ == '__main__':
    main()
