#!/usr/bin/env python3
"""WP bitmap-metadata safety, using the verified CBMC bitmap-key contract."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
def generate(source):
    from wp_common import protect_span
    import re
    start=source.index('static int zbm_write_metadata_2(')
    end=source.index('/* How many consecutive blocks', start)
    key_model=r'''
    /* Contract consequence of the registered CBMC zbm_encoder_key proof:
       exact key = bitmap | period_bytecnt << 8; uint8 bitmap and pbc<=2. */
    /*@ requires \valid_read(bmap);
        requires bmap->period_bytecnt <= 2;
        assigns \nothing;
        ensures \result <= 767;
    */
    unsigned proof_bitmap_key(const struct zbm_bmap *bmap);
    #define zbm_bmkey(bmap) proof_bitmap_key(bmap)
    '''
    bs=source.index('static void zbm_build_bmap_nums(')
    # put model immediately before builder, and annotate actual builder
    prefix=source[:bs]+key_model+source[bs:start]
    bs=prefix.index('static void zbm_build_bmap_nums(')
    prefix=prefix[:bs]+r'''
    /*@ requires \valid(state);
        requires 0 <= state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
        requires \forall integer q; 0 <= q < state->bmp_cnt ==> state->bitmaps[q].period_bytecnt <= 2;
        assigns state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT + 15];
    */
    '''+prefix[bs:]
    prefix=prefix.replace('    for(i = 0; i < cnt; ++i)\n        ZBM_LOOP_ASSIGNS(i, state->bmap_nums)', r'''
        /*@ loop invariant 0 <= i <= cnt;
            loop assigns i, state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT + 15];
            loop variant cnt - i;
        */
        for(i = 0; i < cnt; ++i)
            ZBM_LOOP_ASSIGNS(i, state->bmap_nums)''')
    helper=r'''
    /*@ requires \valid_read(st);
        requires 0 <= count <= ZBM_MAX_BITMAP_COUNT;
        requires \valid(prefix + (0 .. count));
        requires \separated(st, prefix + (0 .. count));
        assigns prefix[0 .. count];
        ensures prefix[0] == 0;
        ensures \forall integer q; 0 <= q < count ==> prefix[q+1] == prefix[q] + (st->bmap_nums[q] < ZBM_BITMAP_BASE ? 1 : 0);
        ensures \forall integer q; 0 <= q <= count ==> 0 <= prefix[q] <= q;
        ensures \forall integer j; 0 <= j <= count ==> prefix[j] <= prefix[count];
    */
    static void proof_build_bitmap_prefix(struct zbm_compress_state *st, unsigned *prefix, int count)
    {
        int q;
        prefix[0] = 0;
        /*@ loop invariant 0 <= q <= count;
            loop invariant prefix[0] == 0;
            loop invariant \forall integer j; 0 <= j < q ==> prefix[j+1] == prefix[j] + (st->bmap_nums[j] < ZBM_BITMAP_BASE ? 1 : 0);
            loop invariant \forall integer j; 0 <= j <= q ==> 0 <= prefix[j] <= j;
            loop invariant \forall integer j; 0 <= j <= q ==> prefix[j] <= prefix[q];
            loop assigns q, prefix[0 .. count];
            loop variant count - q;
        */
        for(q = 0; q < count; ++q)
            prefix[q+1] = prefix[q] + (st->bmap_nums[q] < ZBM_BITMAP_BASE);
    }

    /*@ requires \valid(state);
        requires \valid(state->dest) || \valid(state->dest - 1);
        requires 0 <= state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
        requires 0 <= state->dest_end - state->dest <= 0x1000000000000;
        requires \base_addr(state->dest) == \base_addr(state->dest_end);
        requires \valid(state->dest + (0 .. state->dest_end - state->dest - 1));
        requires \separated(state, state->dest + (0 .. state->dest_end - state->dest - 1));
        requires \forall integer q; 0 <= q < state->bmp_cnt ==> state->bitmaps[q].period_bytecnt <= 2;
        requires state->written <= UINT32_MAX - state->bmp_cnt;
        assigns state->dest, state->written, state->dest[0 .. state->dest_end - state->dest - 1], state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT + 15];
        ensures state->written == \old(state->written) + (state->dest - \old(state->dest));
        ensures \base_addr(state->dest) == \base_addr(state->dest_end);
        ensures 0 <= state->dest_end - state->dest;
        ensures \result == 0 || \result == -1024;
        ensures \result == 0 ==> \base_addr(state->dest) == \base_addr(\old(state->dest));
        ensures \result == 0 ==> 0 <= state->dest - \old(state->dest) <= \old(state->dest_end - state->dest);
        ensures \result != 0 ==> state->dest == \old(state->dest) && state->written == \old(state->written);
    */
    '''
    body=source[start:end]
    assert len(re.findall(r'\b(?:for|while)\s*\(', body)) == 3, 'bitmap writer loops changed'
    body=body.replace('    int i;\n','    int i;\n    unsigned proof_prefix[ZBM_MAX_BITMAP_COUNT + 1];\n',1)
    body=body.replace('        for(i = 0; i < state->bmp_cnt; ++i) {\n            unsigned num',r'''
            /*@ loop invariant 0 <= i <= state->bmp_cnt;
                loop invariant \base_addr(d) == \base_addr(state->dest);
                loop invariant 0 <= d - state->dest <= i;
                loop assigns i, d, state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT + 15], state->dest[0 .. room - 1];
                loop variant state->bmp_cnt - i;
            */
            for(i = 0; i < state->bmp_cnt; ++i) {
                unsigned num''')
    body=body.replace('        zbm_build_bmap_nums(state);','        zbm_build_bmap_nums(state);\n        proof_build_bitmap_prefix(state, proof_prefix, state->bmp_cnt);')
    body=body.replace('        for(i = 0; i < state->bmp_cnt; ++i)\n            exact +=',r'''
            /*@ loop invariant 0 <= i <= state->bmp_cnt;
                loop invariant exact == proof_prefix[i];
                loop assigns i, exact;
                loop variant state->bmp_cnt - i;
            */
            for(i = 0; i < state->bmp_cnt; ++i)
                exact +=''')
    body=body.replace('        for(i = 0; i < state->bmp_cnt; ++i) {\n            if(state->bmap_nums',r'''
            /*@ loop invariant 0 <= i <= state->bmp_cnt;
                loop invariant d == state->dest + proof_prefix[i];
                loop invariant 0 <= d - state->dest <= exact;
                loop invariant \forall integer q; 0 <= q < state->bmp_cnt ==> proof_prefix[q+1] == proof_prefix[q] + (state->bmap_nums[q] < ZBM_BITMAP_BASE ? 1 : 0);
                loop assigns i, d, state->dest[0 .. room - 1];
                loop variant state->bmp_cnt - i;
            */
            for(i = 0; i < state->bmp_cnt; ++i) {
                if(state->bmap_nums''')
    # WP pointer validity alone may permit access to a neighboring state field.
    # Check the actual table and selector-array index expressions separately.
    num = re.search(r'unsigned num = tbl\[(.*)\];', body)
    assert num is not None
    body = body.replace(num.group(0),
        'unsigned proof_key = ' + num.group(1) + ';\n' +
        r'            /*@ assert proof_key < ZBM_POSSIBLE_BMPROTS; */' + '\n' +
        '            unsigned num = tbl[proof_key];', 1)
    store = re.search(r'nums\[(.*)\] = \(uint8_t\)num;', body)
    assert store is not None
    body = body.replace(store.group(0),
        'unsigned proof_index = ' + store.group(1) + ';\n' +
        r'            /*@ assert proof_index < ZBM_MAX_BITMAP_COUNT + 16; */' + '\n' +
        '            nums[proof_index] = (uint8_t)num;', 1)
    assert body.count('loop invariant') == 9
    return protect_span(prefix+helper+body, source)


def main():
    import argparse
    import concurrent.futures
    import sys
    sys.dont_write_bytecode = True
    from wp_common import verify, witness

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    source = Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output = Path('harness/build/proofs-frama-bitmap')
    output.mkdir(parents=True, exist_ok=True)

    def prove(name, text, expected=True):
        generated = generate(text)
        assert generated.count('loop invariant') == 15
        verify(name, generated, output,
               ['zbm_build_bmap_nums', 'proof_build_bitmap_prefix', 'zbm_write_metadata_2', 'proof_trial_destination'],
               150, expected)

    witness(output, r'''#include <assert.h>
#include "libzbitmap.c"
static struct zbm_compress_state st;
static uint8_t output[ZBM_MAX_BITMAP_COUNT + 4];
static void check(int count, int num, int room, int expected) {
    memset(&st, 0, sizeof(st)); memset(output, 0xee, sizeof(output));
    memset(st.bmap_num_tbl, num, sizeof(st.bmap_num_tbl));
    st.bmp_cnt = count; st.dest = output; st.dest_end = output + room;
    for(int i = 0; i < count; ++i) {
        st.bitmaps[i].bitmap = 255; st.bitmaps[i].period_bytecnt = 2;
    }
    int rc = zbm_write_metadata_2(&st);
    int written = rc == 0 && num < ZBM_BITMAP_BASE ? count : 0;
    assert(rc == expected); assert(st.dest == output + written);
    assert(st.written == (unsigned)written);
    for(int i = 0; i < count; ++i) assert(st.bmap_nums[i] == num);
    for(unsigned i = room; i < sizeof(output); ++i) assert(output[i] == 0xee);
}
int main(void) {
    check(0, 0, 0, 0); check(1, 0, 1, 0);
    check(1, 0, 0, ZBM_CANT_COMPRESS); check(1, 255, 0, 0);
    check(3, 3, 0, 0); check(3, 2, 3, 0); check(3, 2, 4, 0);
    check(ZBM_MAX_BITMAP_COUNT, 0, ZBM_MAX_BITMAP_COUNT, 0);
    check(ZBM_MAX_BITMAP_COUNT, 0, ZBM_MAX_BITMAP_COUNT + 1, 0);
    return 0;
}
''')
    print('nine executions of the unmodified bitmap writer passed with ASan/UBSan', flush=True)
    prove('bitmap_metadata', source)
    if args.mutants:
        start = source.index('static int zbm_write_metadata_2(')
        end = source.index('/* How many consecutive blocks', start)
        body = source[start:end]
        assert body.count('if(state->bmp_cnt + 1 <= room)') == 1
        prove('bitmap_bulk_exact_bound', source[:start] + body.replace(
            'if(state->bmp_cnt + 1 <= room)', 'if(state->bmp_cnt <= room)') + source[end:])
        changes = [
            ('bulk_short', 'if(state->bmp_cnt + 1 <= room)', 'if(state->bmp_cnt - 1 <= room)'),
            ('tight_capacity', 'if(exact > room)', 'if(exact > room + 1)'),
            ('tight_extra_store', '*d++ = state->bitmaps[i].bitmap;', '*d++ = state->bitmaps[i].bitmap; *d++ = 0;'),
            ('selector_array', 'nums[i] = (uint8_t)num;', 'nums[i + ZBM_MAX_BITMAP_COUNT] = (uint8_t)num;'),
            ('selector_table', 'tbl[zbm_bmkey(&bmaps[i])]', 'tbl[zbm_bmkey(&bmaps[i]) + ZBM_POSSIBLE_BMPROTS]'),
        ]
        def mutant(change):
            name, before, after = change
            assert body.count(before) == 1
            prove(name, source[:start] + body.replace(before, after) + source[end:], False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(mutant, changes))


if __name__ == '__main__':
    main()
