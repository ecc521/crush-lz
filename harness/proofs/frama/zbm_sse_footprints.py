#!/usr/bin/env python3
"""Prove shipping x86 SSE LZBITMAP wrapper pointer footprints.

The SSE wrapper bodies come from crush_simd.h. Load/store widths are explicit
trusted intrinsic contracts; no instruction-value semantics are assumed.
"""
from pathlib import Path
import argparse
import sys

sys.dont_write_bytecode = True
from wp_common import verify
from zbm_neon_footprints import extract_function, NOCBMC


MODEL = r'''
#include <stdint.h>''' + NOCBMC + r'''
typedef struct { uint8_t lane[16]; } __m128i;
typedef __m128i zbm_sel_t;

/*@ requires \valid_read((const uint8_t *)p + (0 .. 7));
    assigns \nothing; */
__m128i _mm_loadl_epi64(const __m128i *p);
/*@ requires \valid_read((const uint8_t *)p + (0 .. 15));
    assigns \nothing; */
__m128i _mm_loadu_si128(const __m128i *p);
/*@ requires \valid((uint8_t *)p + (0 .. 7));
    assigns ((uint8_t *)p)[0 .. 7]; */
void _mm_storel_epi64(__m128i *p, __m128i v);
/*@ requires \valid((uint8_t *)p + (0 .. 15));
    assigns ((uint8_t *)p)[0 .. 15]; */
void _mm_storeu_si128(__m128i *p, __m128i v);
/*@ assigns \nothing; */
__m128i _mm_unpacklo_epi64(__m128i a, __m128i b);
/*@ assigns \nothing; */
__m128i _mm_shuffle_epi8(__m128i table, __m128i indices);
/*@ assigns \nothing; */
__m128i _mm_cmpeq_epi8(__m128i a, __m128i b);
/*@ assigns \nothing; */
int _mm_movemask_epi8(__m128i v);
/*@ assigns \nothing; */
__m128i _mm_or_si128(__m128i a, __m128i b);
/*@ assigns \nothing; */
__m128i _mm_and_si128(__m128i a, __m128i b);
/*@ assigns \nothing; */
__m128i _mm_srli_epi16(__m128i v, int n);
/*@ assigns \nothing; */
__m128i _mm_set1_epi16(int n);
/*@ assigns \nothing; */
__m128i _mm_packus_epi16(__m128i a, __m128i b);
/*@ assigns \nothing; */
long long _mm_cvtsi128_si64(__m128i v);
'''


def contract(name):
    if name == 'zbm_sel_load':
        return r'''/*@ requires \valid_read(row + (0 .. 7));
    assigns \nothing; */
'''
    if name in ('zbm_blend8_sel', 'zbm_blend8_row'):
        row = ('    requires \\valid_read(row + (0 .. 7));\n'
               if name == 'zbm_blend8_row' else '')
        return (r'''/*@ requires \valid(dst + (0 .. 7));
    requires \valid_read(base + (0 .. 7));
    requires \valid_read(lits + (0 .. 7));
''' + row + r'''    assigns dst[0 .. 7]; */
''')
    if name == 'zbm_pack8':
        return r'''/*@ requires \valid(d + (0 .. 7));
    requires \valid_read(s + (0 .. 7));
    requires \valid_read(row + (0 .. 7));
    assigns d[0 .. 7]; */
'''
    if name == 'zbm_eq16_mask':
        return r'''/*@ requires \valid_read(a + (0 .. 15));
    requires \valid_read(b + (0 .. 15));
    assigns \nothing; */
'''
    if name == 'zbm_pack_nibbles16':
        return r'''/*@ requires \valid_read(p + (0 .. 15));
    assigns \nothing; */
'''
    width = int(name.removeprefix('zbm_cpy'))
    return (f'/*@ requires \\valid(d + (0 .. {width - 1}));\n'
            f'    requires \\valid_read(s + (0 .. {width - 1}));\n'
            f'    assigns d[0 .. {width - 1}]; */\n')


NAMES = ('zbm_sel_load', 'zbm_blend8_sel', 'zbm_blend8_row',
         'zbm_pack8', 'zbm_cpy8', 'zbm_cpy16', 'zbm_cpy32',
         'zbm_eq16_mask', 'zbm_pack_nibbles16')


def generate(header, mutant=None):
    sse = header.split('#elif defined(__SSE4_1__) && defined(__POPCNT__)', 1)[1]
    sse = sse.split('#endif // defined(CRUSH_SIMD_PORTABLE)', 1)[0]
    types = {'zbm_sel_load': 'zbm_sel_t', 'zbm_eq16_mask': 'uint16_t',
             'zbm_pack_nibbles16': 'uint64_t'}
    bodies = {name: extract_function(sse, name, types.get(name, 'void'))
              for name in NAMES}
    if mutant == 'copy32_overwrite':
        old = '(void *)(d + 16)'
        assert bodies['zbm_cpy32'].count(old) == 1
        bodies['zbm_cpy32'] = bodies['zbm_cpy32'].replace(old, '(void *)(d + 17)')
    elif mutant is not None:
        raise ValueError(mutant)
    return MODEL + '\n'.join(contract(name) + bodies[name] for name in NAMES) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    parser.add_argument('--output')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    header = (root / 'crates/lzbitmap/csrc/crush_simd.h').read_text()
    output = Path(args.output or root / 'harness/build/proofs-frama-zbm-sse-footprints')
    output.mkdir(parents=True, exist_ok=True)
    verify('sse_footprints', generate(header), output, list(NAMES), 20, split=True)
    if args.mutants:
        verify('copy32_overwrite', generate(header, 'copy32_overwrite'),
               output, list(NAMES), 20, expected=False, split=True)


if __name__ == '__main__':
    main()
