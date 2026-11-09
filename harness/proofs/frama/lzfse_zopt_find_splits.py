#!/usr/bin/env python3
"""Shipping lzfse_zopt_find_splits block split search proof."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source, mutant=None):
    start = source.index('{\n  int32_t *split_at = z->split_at;\n  *n_splits = 0;')
    end = source.index('\n}\n\n#if defined(LZFSE_BASE_PROOF)\nstatic __attribute__((noinline)) int lzfse_zopt_commit', start)
    fn_body = source[start:end + 2]

    loop1_target = '    for (int32_t t = 0; t < z->best_n_tuples; t++) {'
    assert loop1_target in fn_body
    loop1_replacement = r'''    /*@ loop invariant 0 <= t <= z->best_n_tuples;
        loop invariant 0 <= z->tuple_start_pos[t] <= (lzfse_offset)t * 10000000000LL;
        loop assigns t, z->tuple_start_pos[1 .. z->best_n_tuples];
        loop variant z->best_n_tuples - t;
    */
    for (int32_t t = 0; t < z->best_n_tuples; t++) {'''
    fn_body = fn_body.replace(loop1_target, loop1_replacement)

    loop2_target = '    for (int32_t i = 1; i < *n_splits; i++) {'
    assert loop2_target in fn_body
    loop2_replacement = r'''    /*@ loop invariant 1 <= i;
        loop invariant (*n_splits <= 0) || (1 <= i <= *n_splits);
        loop invariant 0 <= *n_splits < z->split_max_blocks;
        loop invariant *n_splits == \at(*n_splits, LoopEntry);
        loop invariant z->split_max_blocks == \at(z->split_max_blocks, Pre);
        loop invariant split_at == z->split_at;
        loop invariant \valid(split_at + (0 .. z->split_max_blocks - 1));
        loop invariant \separated(split_at + (0 .. z->split_max_blocks - 1), n_splits);
        loop invariant \separated(split_at + (0 .. z->split_max_blocks - 1), z);
        loop assigns i, split_at[0 .. \at(z->split_max_blocks, Pre) - 1];
        loop variant *n_splits - i;
    */
    for (int32_t i = 1; i < *n_splits; i++) {'''
    fn_body = fn_body.replace(loop2_target, loop2_replacement)

    inner_target = '      while (j >= 0 && split_at[j] > v) { split_at[j + 1] = split_at[j]; j--; }'
    assert inner_target in fn_body
    inner_replacement = r'''      /*@ loop invariant -1 <= j < i;
          loop invariant 0 <= *n_splits < z->split_max_blocks;
          loop invariant 1 <= i < *n_splits;
          loop invariant *n_splits == \at(*n_splits, LoopEntry);
          loop invariant z->split_max_blocks == \at(z->split_max_blocks, Pre);
          loop invariant split_at == z->split_at;
          loop invariant \valid(split_at + (0 .. z->split_max_blocks - 1));
          loop invariant \separated(split_at + (0 .. z->split_max_blocks - 1), n_splits);
          loop invariant \separated(split_at + (0 .. z->split_max_blocks - 1), z);
          loop assigns j, split_at[0 .. \at(z->split_max_blocks, Pre) - 1];
          loop variant j + 1;
      */
      while (j >= 0 && split_at[j] > v) { split_at[j + 1] = split_at[j]; j--; }'''
    fn_body = fn_body.replace(inner_target, inner_replacement)

    if mutant == 'oob_start_pos':
        fn_body = fn_body.replace('z->tuple_start_pos[t + 1] =',
                                  'z->tuple_start_pos[t + 2] =', 1)
    elif mutant == 'no_zero_splits':
        fn_body = fn_body.replace('*n_splits = 0;',
                                  '/* deleted */', 1)
    elif mutant == 'underflow_sort':
        fn_body = fn_body.replace('while (j >= 0 && split_at[j] > v)',
                                  'while (j >= -1 && split_at[j] > v)', 1)

    acsl_contract = r'''
/*@ requires \valid(s);
    requires \valid(z);
    requires \valid(n_splits);
    requires 1 <= z->split_max_blocks <= 64;
    requires 0 <= z->best_n_tuples <= 65536;
    requires \valid(z->tuple_start_pos + (0 .. z->best_n_tuples));
    requires \valid_read(z->best_tup_L + (0 .. z->best_n_tuples - 1));
    requires \valid_read(z->best_tup_M + (0 .. z->best_n_tuples - 1));
    requires \valid(z->split_at + (0 .. z->split_max_blocks - 1));
    requires \separated(z->tuple_start_pos + (0 .. z->best_n_tuples),
                        z->split_at + (0 .. z->split_max_blocks - 1),
                        z->best_tup_L + (0 .. z->best_n_tuples - 1),
                        z->best_tup_M + (0 .. z->best_n_tuples - 1),
                        n_splits, s, z);
    assigns *n_splits,
            z->tuple_start_pos[0 .. z->best_n_tuples],
            z->split_at[0 .. z->split_max_blocks - 1];
    ensures 0 <= *n_splits < (z->split_max_blocks > 1 && z->best_n_tuples > 1 ? z->split_max_blocks : 2);
*/
void lzfse_zopt_find_splits(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                            int32_t *n_splits) '''
    body = acsl_contract + fn_body

    header = r'''
#include <stdint.h>
#include <stddef.h>

typedef int64_t lzfse_offset;

typedef struct {
  uint8_t *src;
  lzfse_offset src_end;
} lzfse_encoder_state;

typedef struct {
  int32_t split_max_blocks;
  int32_t best_n_tuples;
  uint32_t *best_tup_L;
  uint32_t *best_tup_M;
  uint32_t *best_tup_D;
  lzfse_offset *tuple_start_pos;
  int32_t *split_at;
} lzfse_zopt_scratch;

/*@ requires \valid(s) && \valid(z);
    requires max_blocks >= 1;
    requires \valid(out + (0 .. max_blocks - 1));
    requires \valid(n_out);
    requires 0 <= *n_out < max_blocks;
    requires \separated(out + (0 .. max_blocks - 1), z, s, n_out);
    assigns out[0 .. max_blocks - 1], *n_out;
    ensures \old(*n_out) <= *n_out < max_blocks;
*/
void split_recurse(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                   int32_t lo, int32_t hi, int32_t max_blocks,
                   int32_t *out, int32_t *n_out);
'''
    return header + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzfse_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzfse-zopt-find-splits'
    output.mkdir(parents=True, exist_ok=True)
    verify('lzfse_zopt_find_splits', generate(source), output, ['lzfse_zopt_find_splits'], 10, split=True)

    if args.mutants:
        verify('lzfse_zopt_find_splits_oob_start_pos',
               generate(source, mutant='oob_start_pos'),
               output, ['lzfse_zopt_find_splits'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzfse_zopt_find_splits_no_zero_splits',
               generate(source, mutant='no_zero_splits'),
               output, ['lzfse_zopt_find_splits'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzfse_zopt_find_splits_underflow_sort',
               generate(source, mutant='underflow_sort'),
               output, ['lzfse_zopt_find_splits'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
