#!/usr/bin/env python3
"""Prove shipping ARM NEON decoder wrapper footprints.

The wrapper bodies are extracted from crush_simd.h. The byte widths
of ARM NEON load/store intrinsics are explicit trusted architecture contracts;
this target proves that the shipping wrapper calls stay within those widths.
It does not verify the compiler's intrinsic implementation.
"""
from pathlib import Path
import argparse
import sys

sys.dont_write_bytecode = True
from wp_common import verify


NOCBMC = r'''
/* crush_simd.h's CBMC contracts (harness/proofs/simd) are not ACSL. */
#define ZBM_REQUIRES(x)
#define ZBM_ASSIGNS(...)
#define ZBM_BLEND8_CONTRACT
#define ZBM_BLEND8_ROW_CONTRACT
#define ZBM_SEL_LOAD_CONTRACT
#define ZBM_CPY_CONTRACT(n)
'''

MODEL = r'''
#include <stdint.h>''' + NOCBMC + r'''
typedef struct { uint8_t lane[8]; } uint8x8_t;
typedef struct { uint8_t lane[16]; } uint8x16_t;
typedef struct { uint16_t lane[8]; } uint16x8_t;
typedef struct { uint64_t lane[1]; } uint64x1_t;
typedef uint8x8_t zbm_sel_t;

/* ARM NEON LD1 and ST1 touch exactly the selected vector width. */
/*@ requires \valid_read(p + (0 .. 7)); assigns \nothing; */
uint8x8_t vld1_u8(const uint8_t *p);
/*@ requires \valid_read(p + (0 .. 15)); assigns \nothing; */
uint8x16_t vld1q_u8(const uint8_t *p);
/*@ requires \valid(p + (0 .. 7)); assigns p[0 .. 7]; */
void vst1_u8(uint8_t *p, uint8x8_t v);
/*@ requires \valid(p + (0 .. 15)); assigns p[0 .. 15]; */
void vst1q_u8(uint8_t *p, uint8x16_t v);
/*@ assigns \nothing; */
uint8x16_t vcombine_u8(uint8x8_t lo, uint8x8_t hi);
/*@ assigns \nothing; */
uint8x8_t vqtbl1_u8(uint8x16_t table, uint8x8_t indices);
/*@ assigns \nothing; */
uint8x8_t vtbl1_u8(uint8x8_t table, uint8x8_t indices);
/*@ assigns \nothing; */
uint8x16_t vandq_u8(uint8x16_t a, uint8x16_t b);
/*@ assigns \nothing; */
uint8x16_t vceqq_u8(uint8x16_t a, uint8x16_t b);
/*@ assigns \nothing; */
uint8x8_t vget_low_u8(uint8x16_t v);
/*@ assigns \nothing; */
uint8x8_t vget_high_u8(uint8x16_t v);
/*@ assigns \nothing; */
uint8_t vaddv_u8(uint8x8_t v);
/*@ assigns \nothing; */
uint16x8_t vreinterpretq_u16_u8(uint8x16_t v);
/*@ assigns \nothing; */
uint16x8_t vshrq_n_u16(uint16x8_t v, int n);
/*@ assigns \nothing; */
uint16x8_t vorrq_u16(uint16x8_t a, uint16x8_t b);
/*@ assigns \nothing; */
uint8x8_t vmovn_u16(uint16x8_t v);
/*@ assigns \nothing; */
uint64x1_t vreinterpret_u64_u8(uint8x8_t v);
/*@ assigns \nothing; */
uint64_t vget_lane_u64(uint64x1_t v, int lane);
'''

BLEND = r'''
/*@ requires \valid(dst + (0 .. 7));
    requires \valid_read(base + (0 .. 7));
    requires \valid_read(lits + (0 .. 7));
    assigns dst[0 .. 7]; */
'''
ROW = r'''
/*@ requires \valid(dst + (0 .. 7));
    requires \valid_read(base + (0 .. 7));
    requires \valid_read(lits + (0 .. 7));
    requires \valid_read(row + (0 .. 7));
    assigns dst[0 .. 7]; */
'''


def extract_function(source, name, return_type='void'):
    marker = 'static inline ' + return_type + ' ' + name + '('
    assert source.count(marker) == 1, name
    start = source.index(marker)
    opening = source.index('{', start)
    depth = 0
    for end in range(opening, len(source)):
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
            if depth == 0:
                return source[start:end + 1]
    raise AssertionError(name)


def generate(header, mutant=None):
    neon = header.split('#elif defined(__ARM_NEON)', 1)[1].split(
        '#elif defined(__SSE4_1__) && defined(__POPCNT__)', 1)[0]
    sel_load = extract_function(neon, 'zbm_sel_load', 'zbm_sel_t')
    blend = extract_function(neon, 'zbm_blend8_sel')
    row = extract_function(neon, 'zbm_blend8_row')
    copies = {n: extract_function(neon, n) for n in
              ('zbm_pack8', 'zbm_cpy8', 'zbm_cpy16', 'zbm_cpy32')}
    eq16 = extract_function(neon, 'zbm_eq16_mask', 'uint16_t')
    pack_nibbles = extract_function(neon, 'zbm_pack_nibbles16', 'uint64_t')
    if mutant == 'row_overread':
        old = 'vld1_u8(row)'
        assert row.count(old) == 1
        row = row.replace(old, 'vld1_u8(row + 1)')
    elif mutant == 'blend_overread':
        old = 'vld1_u8(lits)'
        assert blend.count(old) == 1
        blend = blend.replace(old, 'vld1_u8(lits + 1)')
    elif mutant == 'copy8_overwrite':
        old = 'vst1_u8(d, vld1_u8(s));'
        assert copies['zbm_cpy8'].count(old) == 1
        copies['zbm_cpy8'] = copies['zbm_cpy8'].replace(old, 'vst1_u8(d + 1, vld1_u8(s));')
    elif mutant == 'copy32_overwrite':
        old = 'vst1q_u8(d + 16, vld1q_u8(s + 16));'
        assert copies['zbm_cpy32'].count(old) == 1
        copies['zbm_cpy32'] = copies['zbm_cpy32'].replace(old, 'vst1q_u8(d + 17, vld1q_u8(s + 16));')
    elif mutant == 'eq16_overread':
        old = 'vld1q_u8(a)'
        assert eq16.count(old) == 1
        eq16 = eq16.replace(old, 'vld1q_u8(a + 1)')
    elif mutant is not None:
        raise ValueError(mutant)

    parts = [MODEL, r'''/*@ requires \valid_read(row + (0 .. 7));
    assigns \nothing; */
''', sel_load, BLEND, blend, ROW, row, r'''/*@ requires \valid(d + (0 .. 7));
    requires \valid_read(s + (0 .. 7));
    requires \valid_read(row + (0 .. 7));
    assigns d[0 .. 7]; */
''', copies['zbm_pack8']]
    for n, width in (('zbm_cpy8', 8), ('zbm_cpy16', 16), ('zbm_cpy32', 32)):
        last = width - 1
        parts.append(f'''/*@ requires \\valid(d + (0 .. {last}));
    requires \\valid_read(s + (0 .. {last}));
    assigns d[0 .. {last}]; */\n''')
        parts.append(copies[n])
    parts.extend((r'''/*@ requires \valid_read(a + (0 .. 15));
    requires \valid_read(b + (0 .. 15));
    assigns \nothing; */
''', eq16, r'''/*@ requires \valid_read(p + (0 .. 15));
    assigns \nothing; */
''', pack_nibbles))
    return '\n'.join(parts) + '\n'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    parser.add_argument('--output')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    header = (root / 'crates/lzbitmap/csrc/crush_simd.h').read_text()
    output = Path(args.output or root / 'harness/build/proofs-frama-zbm-neon-footprints')
    output.mkdir(parents=True, exist_ok=True)
    functions = ['zbm_sel_load', 'zbm_blend8_sel',
                 'zbm_blend8_row', 'zbm_pack8', 'zbm_cpy8', 'zbm_cpy16', 'zbm_cpy32',
                 'zbm_eq16_mask', 'zbm_pack_nibbles16']
    # WP's typed model asks for separation of the private, read-only static
    # weight table from caller objects. Its address never escapes the helper.
    table_warning = (r"(?s)Warning: \n  Memory model hypotheses for function "
                     r"'zbm_eq16_mask':\n  /\*\@.*?"
                     r"__inline static uint16_t zbm_eq16_mask\(uint8_t const \*a, "
                     r"uint8_t const \*b\);\n")
    verify('neon_footprints', generate(header), output, functions, 20,
           split=True, allowed_warnings=(table_warning,))
    if args.mutants:
        for name in ('row_overread', 'blend_overread', 'copy8_overwrite',
                     'copy32_overwrite', 'eq16_overread'):
            verify(name, generate(header, name), output, functions, 20,
                   expected=False, split=True,
                   allowed_warnings=(table_warning,))


if __name__ == '__main__':
    main()
