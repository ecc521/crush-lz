#!/usr/bin/env python3
"""Prove the shipping LMD literal-budget shortcut and loop termination."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source, header, mutant=None):
    marker = '    if (__builtin_expect(lit_budget > 0, 1)) {'
    begin = source.index(marker, source.index('LZFSE_HOT(lzfse_decode_lmd)'))
    end = source.index('#endif', begin)
    branch = source[begin:end]
    assert branch.count('lit_budget--;') == 1
    assert branch.count('if ((size_t)L >= (size_t)(lit_end - lit))') == 1
    assert branch.count('lit_budget = (lit_end - (lit + L) - 1) / LZFSE_DECODE_L_MAX_VALUE;') == 1
    assert '#define LZFSE_DECODE_L_MAX_VALUE 315' in header
    if mutant == 'no_decrement':
        branch = branch.replace('lit_budget--;', 'lit_budget -= 0;')
    elif mutant == 'wrong_divisor':
        branch = branch.replace('/ LZFSE_DECODE_L_MAX_VALUE;', '/ (LZFSE_DECODE_L_MAX_VALUE - 1);')
    elif mutant == 'no_check':
        branch = branch.replace('if ((size_t)L >= (size_t)(lit_end - lit))',
                                'if (0)')
    elif mutant is not None:
        raise ValueError(mutant)
    branch = branch.replace('return LZFSE_STATUS_ERROR;', 'return -1;')
    return r'''
#include <stddef.h>
#include <stdint.h>
#define LZFSE_DECODE_L_MAX_VALUE 315
/*@ requires 0 <= n_literals <= 40000;
    requires 0 <= count <= 10000;
    requires \valid_read(literals + (0 .. n_literals));
    requires \valid_read(lengths + (0 .. count-1));
    requires \separated(literals + (0 .. n_literals), lengths + (0 .. count-1));
    requires \forall integer k; 0 <= k < count ==>
        lengths[k] <= LZFSE_DECODE_L_MAX_VALUE;
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
int proof_lmd_budget(const uint8_t *literals, size_t n_literals,
                     const uint16_t *lengths, size_t count) {
    const uint8_t *lit = literals;
    const uint8_t *const lit_end = literals + n_literals + 1;
    ptrdiff_t lit_budget = 0;
    /*@ loop invariant 0 <= i <= count;
        loop invariant 0 <= lit - literals <= n_literals;
        loop invariant 0 <= lit_budget;
        loop invariant lit_budget * LZFSE_DECODE_L_MAX_VALUE <=
            lit_end - lit - 1;
        loop assigns i, lit, lit_budget;
        loop variant count - i;
    */
    for (size_t i = 0; i < count; i++) {
        ptrdiff_t L = lengths[i];
        /*@ assert 0 <= L <= LZFSE_DECODE_L_MAX_VALUE; */
''' + branch + r'''
        /*@ assert L <= n_literals - (lit - literals); */
        lit += L;
    }
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root/'crates/crushlzfse/csrc/lzfse_decode_hot.h').read_text()
    header = (root/'crates/crushlzfse/csrc/lzfse_internal.h').read_text()
    output = root/'harness/build/proofs-frama-lzfse-lmd-budget'
    output.mkdir(parents=True, exist_ok=True)
    verify('budget', generate(source, header), output, ['proof_lmd_budget'], 20,
           split=True)
    if args.mutants:
        for name in ('no_decrement', 'wrong_divisor', 'no_check'):
            verify(name, generate(source, header, name), output,
                   ['proof_lmd_budget'], 20, expected=False, split=True)


if __name__ == '__main__':
    main()
