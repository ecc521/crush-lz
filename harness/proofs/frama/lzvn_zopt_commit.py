#!/usr/bin/env python3
"""Shipping lzvn_zopt_commit tuple commit and buffer bounds proof."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source, mutant=None):
    start = source.index('{\n  if (dst_size < 8)\n    return 0;\n  unsigned char *q = dst;')
    end = source.index('\n}\n\n// Entry point for the optimal levels', start)
    fn_body = source[start:end + 2]

    loop_target = '  for (int32_t t = 0; t < z->n_tuples; t++) {'
    assert loop_target in fn_body
    loop_replacement = r'''  /*@ loop invariant 0 <= t <= z->n_tuples;
      loop invariant \base_addr(q) == \base_addr(dst);
      loop invariant \base_addr(q1) == \base_addr(dst);
      loop invariant q1 == dst + dst_size - 8;
      loop invariant dst <= q <= q1;
      loop invariant start_pos <= cursor <= start_pos + t * 65536;
      loop assigns t, q, d_prev, cursor, dst[0 .. dst_size - 1];
      loop variant z->n_tuples - t;
  */
  for (int32_t t = 0; t < z->n_tuples; t++) {'''
    fn_body = fn_body.replace(loop_target, loop_replacement)

    if mutant == 'no_min_dst':
        fn_body = fn_body.replace('if (dst_size < 8)\n    return 0;', '/* dropped dst_size check */', 1)
    elif mutant == 'corrupt_store':
        fn_body = fn_body.replace('store8(q, 0x06);', 'store8(q + 1, 0x06);', 1)
    elif mutant == 'oversized_eos':
        fn_body = fn_body.replace('q += 8;', 'q += 16;', 1)

    acsl_contract = r'''
/*@ requires \valid_read(z);
    requires 0 <= z->n_tuples <= z->max_tuples <= 10000;
    requires \valid_read(z->tup_L + (0 .. z->n_tuples - 1));
    requires \valid_read(z->tup_M + (0 .. z->n_tuples - 1));
    requires \valid_read(z->tup_D + (0 .. z->n_tuples - 1));
    requires 0 <= dst_size <= PTRDIFF_MAX;
    requires \valid(dst + (0 .. dst_size - 1));
    requires 0 <= start_pos <= 65536;
    requires \valid_read(src + (start_pos .. start_pos + z->n_tuples * 65536 + 8));
    requires \separated(dst + (0 .. dst_size - 1), src + (start_pos .. start_pos + z->n_tuples * 65536 + 8));
    requires \separated(dst + (0 .. dst_size - 1), z);
    requires \separated(dst + (0 .. dst_size - 1), z->tup_L + (0 .. z->n_tuples - 1));
    requires \separated(dst + (0 .. dst_size - 1), z->tup_M + (0 .. z->n_tuples - 1));
    requires \separated(dst + (0 .. dst_size - 1), z->tup_D + (0 .. z->n_tuples - 1));
    requires (\forall integer t; 0 <= t < z->n_tuples ==>
                (z->tup_L[t] <= 32768 && z->tup_M[t] <= 32768));
    requires (\forall integer t; 0 <= t < z->n_tuples ==>
                (z->tup_M[t] > 0 ==> (z->tup_M[t] >= 3 && 1 <= z->tup_D[t] <= 65535)));
    assigns dst[0 .. dst_size - 1];
    ensures 0 <= \result <= dst_size;
*/
size_t lzvn_zopt_commit(const unsigned char *src, unsigned char *dst,
                        size_t dst_size, const lzvn_zopt_scratch *z,
                        int32_t start_pos) '''
    body = acsl_contract + fn_body

    header = r'''
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

typedef struct {
  int32_t max_tuples;
  int32_t n_tuples;
  uint32_t *tup_L;
  uint32_t *tup_M;
  uint32_t *tup_D;
} lzvn_zopt_scratch;

/*@ requires \valid(q + (0 .. 7));
    assigns q[0 .. 7];
*/
void store8(uint8_t *q, uint64_t v);

/*@ requires 0 <= L <= PTRDIFF_MAX;
    requires \base_addr(q) == \base_addr(q1);
    requires 0 <= q1 - q <= PTRDIFF_MAX;
    requires \valid(q + (0 .. q1 - q - 1));
    requires \valid_read(p + (0 .. L - 1));
    requires \separated(q + (0 .. q1 - q - 1), p + (0 .. L - 1));
    assigns q[0 .. q1 - q - 1], \result \from q, q1, L, p[0 .. L - 1];
    ensures \base_addr(\result) == \base_addr(q);
    ensures 0 <= \result - q <= q1 - q;
    ensures \result == q1 || (L == 0 ? \result == q : q < \result);
*/
unsigned char *emit_literal(const unsigned char *p, unsigned char *q, unsigned char *q1, size_t L);

/*@ requires 0 <= L <= PTRDIFF_MAX - 8;
    requires M >= 3;
    requires 1 <= D <= 65535;
    requires \base_addr(q) == \base_addr(q1);
    requires 0 <= q1 - q <= PTRDIFF_MAX;
    requires \valid(q + (0 .. q1 - q - 1));
    requires \valid_read(p + (0 .. L + 7));
    requires \separated(q + (0 .. q1 - q - 1), p + (0 .. L + 7));
    assigns q[0 .. q1 - q - 1], \result \from q, q1, L, M, D, D_prev, p[0 .. L + 7];
    ensures \base_addr(\result) == \base_addr(q);
    ensures 0 <= \result - q <= q1 - q;
    ensures \result == q1 || q < \result;
*/
unsigned char *emit(const unsigned char *p, unsigned char *q,
                    unsigned char *q1, size_t L, size_t M,
                    size_t D, size_t D_prev);
'''
    return header + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzvn_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzvn-zopt-commit'
    output.mkdir(parents=True, exist_ok=True)
    verify('lzvn_zopt_commit', generate(source), output, ['lzvn_zopt_commit'], 10, split=True)

    if args.mutants:
        verify('lzvn_zopt_commit_no_min_dst',
               generate(source, mutant='no_min_dst'),
               output, ['lzvn_zopt_commit'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzvn_zopt_commit_corrupt_store',
               generate(source, mutant='corrupt_store'),
               output, ['lzvn_zopt_commit'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzvn_zopt_commit_oversized_eos',
               generate(source, mutant='oversized_eos'),
               output, ['lzvn_zopt_commit'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
