#!/usr/bin/env python3
"""Full-index memory safety of the shipping LZVN Pareto row insertion."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source):
    start = source.index('static int32_t lzvn_pareto_insert(')
    end = source.index('// Repeat-match ends already measured', start)
    body = source[start:end]
    row = '  lzvn_pareto_slot *slots = p->slots + (size_t)pos * (size_t)k_cap;'
    assert body.count(row) == 1
    body = body.replace(row, row + r'''
  /*@ assert \valid(slots + (0 .. k_cap-1)); */''', 1)
    body = body.replace('  for (int32_t s = 0; s < cnt; s++) {', r'''
  /*@ loop invariant 0 <= s <= cnt;
      loop assigns s, slots[0 .. k_cap-1], p->worst_cost[pos];
      loop variant cnt - s;
  */
  for (int32_t s = 0; s < cnt; s++) {''', 1)
    body = body.replace('for (int32_t w = 1; w < k_cap; w++)', r'''/*@ loop invariant 1 <= w <= k_cap;
              loop assigns w,wc;
              loop variant k_cap-w;
          */
          for (int32_t w = 1; w < k_cap; w++)''')
    body = body.replace('  for (int32_t s = 1; s < cnt; s++) {', r'''
  /*@ loop invariant 1 <= s <= cnt;
      loop invariant 0 <= worst < cnt;
      loop assigns s,worst,worst_cost;
      loop variant cnt-s;
  */
  for (int32_t s = 1; s < cnt; s++) {''', 1)
    body = body.replace('static int32_t lzvn_pareto_insert(', r'''
/*@ requires \valid(p);
    requires 1 <= p->k_cap <= 32;
    requires 0 <= pos <= 65536;
    requires \valid(p->count + (0 .. 65536));
    requires \valid(p->worst_cost + (0 .. 65536));
    requires \valid(p->slots + (0 .. (65537 * p->k_cap - 1)));
    requires 0 <= p->count[pos] <= p->k_cap;
    assigns p->count[pos],p->worst_cost[pos],
            p->slots[pos*p->k_cap .. (pos+1)*p->k_cap-1];
*/
static int32_t lzvn_pareto_insert(''', 1)
    return r'''
#include <stdint.h>
#include <stddef.h>
typedef struct {
  int32_t cost,run_len,last_dist,via_len,via_dist,src_slot,run_start_pos,run_start_slot;
} lzvn_pareto_slot;
typedef struct {
  int32_t k_cap;
  int32_t *count;
  int32_t *worst_cost;
  lzvn_pareto_slot *slots;
} lzvn_pareto_scratch;
''' + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzvn_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzvn-pareto-insert'
    output.mkdir(parents=True, exist_ok=True)
    verify('pareto_insert', generate(source), output,
           ['lzvn_pareto_insert'], 20, split=True)
    if args.mutants:
        old = 'p->slots + (size_t)pos * (size_t)k_cap;'
        generated = generate(source)
        assert generated.count(old) == 1
        verify('pareto_row_shift', generated.replace(old,
               'p->slots + (size_t)pos * (size_t)k_cap + 1;'),
               output, ['lzvn_pareto_insert'], 20, False,
               split=True, timeout=3, parallelism=2)


if __name__ == '__main__':
    main()
