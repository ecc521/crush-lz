#!/usr/bin/env python3
"""WP safety of fused period/bitmap writing and its exact scalar size."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
def generate(source):
    import re
    from period_metadata import generate as period_generate
    from wp_common import protect_span
    pg=period_generate(source)
    helper=pg[pg.index('    /*@ requires \\valid_read(st);'):pg.index('    /*@ requires n == 2;')]
    ps=source.index('static ptrdiff_t zbm_period_bytes_total(')
    fs=source.index('static int zbm_write_metadata_12(')
    fe=source.index('static int zbm_build_metadata(', fs)
    contract=r'''
    /*@ requires \valid_read(bmaps + (0 .. cnt - 1));
        requires 0 <= cnt <= ZBM_MAX_BITMAP_COUNT;
        requires \valid_read(proof_prefix + (0 .. cnt));
        requires proof_prefix[0] == 0;
        requires \forall integer q; 0 <= q < cnt ==> proof_prefix[q+1] == proof_prefix[q] + bmaps[q].period_bytecnt;
        requires \forall integer q; 0 <= q <= cnt ==> 0 <= proof_prefix[q] <= 2 * q;
        assigns \nothing;
        ensures \result == proof_prefix[cnt];
        ensures 0 <= \result <= 2 * cnt;
    */
    '''
    period=source[ps:fs]
    period=period.replace('const struct zbm_bmap *bmaps, int cnt)', 'const struct zbm_bmap *bmaps, int cnt, const unsigned *proof_prefix)',1)
    period=period.replace('    for(; i < cnt; ++i)', r'''
        /*@ loop invariant 0 <= i <= cnt;
            loop invariant total == proof_prefix[i];
            loop invariant 0 <= total <= 2 * i;
            loop assigns i, total;
            loop variant cnt - i;
        */
        for(; i < cnt; ++i)''')
    models=r'''
    /* Consequence of CBMC exact key proof, including arithmetic-form assertion. */
    /*@ requires \valid_read(bmap);
        requires bmap->period_bytecnt <= 2;
        assigns \nothing;
        ensures \result == bmap->bitmap + 256 * bmap->period_bytecnt;
        ensures (\result >> 8) == bmap->period_bytecnt;
        ensures (\result & 255) == bmap->bitmap;
    */
    unsigned proof_bitmap_key(const struct zbm_bmap *bmap);
    #define zbm_bmkey(bmap) proof_bitmap_key(bmap)

    /*@ requires n == 2;
        requires \valid(d + (0 .. 1));
        requires \valid_read(src);
        requires \separated(d + (0 .. 1), src);
        assigns d[0 .. 1] \from src[0];
    */
    void proof_period_memcpy(uint8_t *d, const uint16_t *src, size_t n);
    #define memcpy(d, src, n) proof_period_memcpy(d, src, n)

    /*@ requires \valid(d + (0 .. n - 1));
        requires \valid_read(src + (0 .. n - 1));
        assigns d[0 .. n - 1];
    */
    void proof_move_bytes(uint8_t *d, const uint8_t *src, size_t n);
    #define memmove(d, src, n) proof_move_bytes(d, src, n)

    /*@ requires \valid(state) && \valid(hdr);
        requires \valid(state->dest) || \valid(state->dest - 1);
        requires 0 <= state->bmp_cnt <= ZBM_MAX_BITMAP_COUNT;
        requires 0 <= state->dest_end - state->dest <= 0x1000000000000;
        requires \base_addr(state->dest) == \base_addr(state->dest_end);
        requires \valid(state->dest + (0 .. state->dest_end - state->dest - 1));
        requires \separated(state, hdr, state->dest + (0 .. state->dest_end - state->dest - 1));
        requires \forall integer q; 0 <= q < state->bmp_cnt ==> state->bitmaps[q].period_bytecnt <= 2;
        requires state->written <= UINT32_MAX - 3 * state->bmp_cnt;
        assigns state->dest, state->written, state->dest[0 .. state->dest_end - state->dest - 1], state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT + 15], hdr->meta_off_1, hdr->meta_off_2;
        ensures state->written == \old(state->written) + (state->dest - \old(state->dest));
        ensures \base_addr(state->dest) == \base_addr(state->dest_end);
        ensures 0 <= state->dest_end - state->dest;
        ensures \result == 0 || \result == 1;
        ensures \result == 1 ==> \base_addr(state->dest) == \base_addr(\old(state->dest));
        ensures \result == 1 ==> 0 <= state->dest - \old(state->dest) <= \old(state->dest_end - state->dest);
        ensures \result == 0 ==> state->dest == \old(state->dest) && state->written == \old(state->written);
    */
    '''
    # Prove actual header conversion too, with its simple frame contract.
    u24=source.index('static struct uint24 zbm_u32_to_u24(')
    prefix=source[:u24]+r'/*@ assigns \nothing; */'+'\n'+source[u24:ps]
    body=source[fs:fe]
    assert len(re.findall(r'\b(?:for|while)\s*\(', body)) == 1, 'fused writer loops changed'
    body=body.replace('    int i;\n', '    int i;\n    unsigned proof_prefix[ZBM_MAX_BITMAP_COUNT + 1];\n    proof_build_period_prefix(state, proof_prefix, cnt);\n',1)
    body=body.replace('len1 = zbm_period_bytes_total(bmaps, cnt);', 'len1 = zbm_period_bytes_total(bmaps, cnt, proof_prefix);')
    index = re.search(r'unsigned num = tbl\[(.*)\];', body)
    assert index is not None
    body = body.replace(index.group(0),
        'unsigned proof_key_index = ' + index.group(1) + ';\n' +
        r'        /*@ assert proof_key_index < ZBM_POSSIBLE_BMPROTS; */' + '\n' +
        '        unsigned num = tbl[proof_key_index];', 1)
    store = re.search(r'nums\[(.*)\] = \(uint8_t\)num;', body)
    assert store is not None
    body = body.replace(store.group(0),
        'unsigned proof_num_index = ' + store.group(1) + ';\n' +
        r'        /*@ assert proof_num_index < ZBM_MAX_BITMAP_COUNT + 16; */' + '\n' +
        '        nums[proof_num_index] = (uint8_t)num;', 1)
    body=body.replace('    for(i = 0; i < cnt; ++i) {',r'''
        /*@ loop invariant 0 <= i <= cnt;
            loop invariant d1 == d0 + proof_prefix[i];
            loop invariant 0 <= d1 - d0 <= len1;
            loop invariant \base_addr(d2) == \base_addr(area2);
            loop invariant 0 <= d2 - area2 <= i;
            loop invariant \forall integer q; 0 <= q < cnt ==> proof_prefix[q+1] == proof_prefix[q] + state->bitmaps[q].period_bytecnt;
            loop assigns i, d1, d2, state->bmap_nums[0 .. ZBM_MAX_BITMAP_COUNT + 15], d0[0 .. room - 1];
            loop variant cnt - i;
        */
        for(i = 0; i < cnt; ++i) {''')
    body = body.replace('loop invariant \\forall integer q; 0 <= q < cnt ==> proof_prefix[q+1] == proof_prefix[q] + state->bitmaps[q].period_bytecnt;', r'''loop invariant \forall integer q; 0 <= q < cnt ==> proof_prefix[q+1] == proof_prefix[q] + \at(state->bitmaps[q].period_bytecnt, Pre);
            loop invariant \forall integer q; 0 <= q < cnt ==> state->bitmaps[q].period_bytecnt == \at(state->bitmaps[q].period_bytecnt, Pre);''')
    # Keep this unrelated forward declaration backed by its actual body, so
    # Frama-C never invents an implicit frame while processing the source slice.
    cost_start = source.index('static int zbm_nibble_cost_for_run(int r)\nZBM_REQUIRES')
    cost_end = source.index('static int zbm_nibble_extend_delta(int len)', cost_start)
    cost = source[cost_start:cost_end]
    return protect_span(prefix+helper+contract+period+models+body+cost, source, header=True)


def main():
    import argparse
    import concurrent.futures
    from wp_common import verify, witness

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    source = Path('crates/lzbitmap/csrc/libzbitmap.c').read_text()
    output = Path('harness/build/proofs-frama-fused')
    output.mkdir(parents=True, exist_ok=True)

    def prove(name, text, expected=True):
        generated = generate(text)
        assert generated.count('loop invariant') == 15
        verify(name, generated, output,
               ['zbm_u32_to_u24', 'proof_build_period_prefix', 'zbm_period_bytes_total',
                'zbm_write_metadata_12', 'proof_trial_destination'], 150, expected)

    cases = r'''#include <assert.h>
#include "libzbitmap.c"
static struct zbm_compress_state st;
static uint8_t output[ZBM_META_SCRATCH_SIZE];
static void check(int count, int pbc, int num, int room, int internal) {
    struct zbm_cmp_chunk_hdr hdr;
    memset(&st, 0, sizeof(st)); memset(&hdr, 0xee, sizeof(hdr));
    uint8_t *target = internal ? st.meta_scratch : output;
    memset(target, 0xee, ZBM_META_SCRATCH_SIZE);
    memset(st.bmap_num_tbl, num, sizeof(st.bmap_num_tbl));
    st.bmp_cnt = count; st.dest = target; st.dest_end = target + room;
    for(int i = 0; i < count; ++i) {
        st.bitmaps[i].bitmap = 255; st.bitmaps[i].period_bytecnt = pbc;
        st.periods[i] = 0x1234;
    }
    int expected = count * pbc + count + 3 <= room;
    int written = expected ? count * (pbc + (num < ZBM_BITMAP_BASE)) : 0;
    int rc = zbm_write_metadata_12(&st, &hdr);
    assert(rc == expected); assert(st.dest == target + written);
    assert(st.written == (unsigned)written);
    if(expected) for(int i = 0; i < count; ++i) assert(st.bmap_nums[i] == num);
    for(unsigned i = room; i < ZBM_META_SCRATCH_SIZE; ++i) assert(target[i] == 0xee);
    if(!expected) for(unsigned i = 0; i < (unsigned)room; ++i) assert(target[i] == 0xee);
}
int main(void) {
    for(int internal = 0; internal <= 1; ++internal) {
        check(0, 0, 0, 0, internal); check(0, 0, 0, 3, internal);
        check(1, 2, 0, 6, internal); check(1, 2, 0, 5, internal);
        check(3, 0, 255, 6, internal); check(3, 1, 2, 9, internal);
        check(ZBM_MAX_BITMAP_COUNT, 2, 0, 3 * ZBM_MAX_BITMAP_COUNT + 3, internal);
    }
    return 0;
}
'''
    witness(output, cases)
    witness(output, cases, native=True)
    print('14 portable and 14 native fused-writer executions passed with ASan/UBSan', flush=True)
    prove('fused_metadata', source)
    if args.mutants:
        start = source.index('static int zbm_write_metadata_12(')
        end = source.index('static int zbm_build_metadata(', start)
        body = source[start:end]
        changes = [
            ('capacity_short', 'if(len1 + cnt + 3 > room)', 'if(len1 + cnt - 1 > room)'),
            ('period_advance', 'd1 += key >> 8;', 'd1 += (key >> 8) + 1;'),
            ('bitmap_extra_store', 'd2[0] = (uint8_t)key;', 'd2[0] = (uint8_t)key; d2[2] = 0;'),
            ('move_source', '(size_t)len2);', '(size_t)len2 + 2);'),
            ('selector_table', 'unsigned num = tbl[key];', 'unsigned num = tbl[key + ZBM_POSSIBLE_BMPROTS];'),
        ]
        def mutant(change):
            name, before, after = change
            assert body.count(before) == 1
            prove(name, source[:start] + body.replace(before, after) + source[end:], False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(mutant, changes))


if __name__ == '__main__':
    main()
