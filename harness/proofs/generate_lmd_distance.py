#!/usr/bin/env python3
"""Prove the shipping LMD distance check equal to the form Frama-C proves."""
from pathlib import Path
import argparse
import hashlib
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / 'frama'))
from lzfse_lmd_native import D_CHECK_SHIPPING, D_CHECK_PROVED


def condition(check):
    assert check.startswith('if (') and check.endswith(')')
    return check[4:-1].replace('(dst - dst_begin)', 'span')


def generate(source):
    assert source.count(D_CHECK_SHIPPING) == 1
    return '/* producer-sha256: ' + hashlib.sha256(source.encode()).hexdigest() + ' */\n' + r'''
#include "proof.h"
#include <stdint.h>
#include <stddef.h>
int32_t nondet_i32(void);
ptrdiff_t nondet_ptrdiff(void);
void harness(void)
{
    int32_t D = nondet_i32();
    ptrdiff_t span = nondet_ptrdiff(), L = nondet_ptrdiff();
    __CPROVER_assume(span >= 0 && L >= 0 && span <= PTRDIFF_MAX - L);
    int shipping = ''' + condition(D_CHECK_SHIPPING) + r''';
    int proved = ''' + condition(D_CHECK_PROVED) + r''';
    __CPROVER_assert(shipping == proved, "shipping distance check equals the proved form");
    PROOF_REACHABLE(D == -1 && shipping, "initial D rejected");
    PROOF_REACHABLE(D == 0, "zero distance");
    PROOF_REACHABLE(!shipping && D == span + L, "farthest distance accepted");
    PROOF_REACHABLE(span > ((ptrdiff_t)1 << 40) && !shipping, "span beyond 32 bits");
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    path = root / 'harness/proofs/lzfse_lmd_distance_check.c'
    text = generate((root / 'crates/crushlzfse/csrc/lzfse_decode_hot.h').read_text())
    if args.check:
        assert path.read_text() == text, 'regenerate LMD distance-check lemma'
    else:
        path.write_text(text)


if __name__ == '__main__':
    main()
