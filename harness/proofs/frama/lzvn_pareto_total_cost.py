#!/usr/bin/env python3
"""Shipping lzvn_pareto_total_cost minimum cost search and bounds proof."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source, mutant=None):
    start = source.index('{\n  int32_t cnt = p->count[end_pos];')
    end = source.index('\n}\n\n/*! Commits the tuple sequence', start)
    fn_body = source[start:end + 2]

    loop_target = '  for (int32_t s = 0; s < cnt; s++)\n    if (s_end[s].cost < best)\n      best = s_end[s].cost;'
    assert loop_target in fn_body
    loop_replacement = r'''  /*@ loop invariant 0 <= s <= cnt;
      loop invariant s_end == p->slots + end_pos * p->k_cap;
      loop invariant s == 0 ==> best == 2147483647;
      loop invariant (s > 0 && (\forall integer i; 0 <= i < cnt ==> 0 <= p->slots[end_pos * p->k_cap + i].cost <= 1000000))
                     ==> 0 <= best <= 1000000;
      loop invariant (\forall integer i; 0 <= i < s ==> best <= p->slots[end_pos * p->k_cap + i].cost);
      loop assigns s, best;
      loop variant cnt - s;
  */
  for (int32_t s = 0; s < cnt; s++)
    if (s_end[s].cost < best)
      best = s_end[s].cost;'''
    fn_body = fn_body.replace(loop_target, loop_replacement)

    if mutant == 'early_stop':
        fn_body = fn_body.replace('for (int32_t s = 0; s < cnt; s++)',
                                  'for (int32_t s = 0; s < cnt - 1; s++)', 1)
    elif mutant == 'oob_count':
        fn_body = fn_body.replace('int32_t cnt = p->count[end_pos];',
                                  'int32_t cnt = p->count[end_pos] + 1;', 1)
    elif mutant == 'inverted_check':
        fn_body = fn_body.replace('if (s_end[s].cost < best)',
                                  'if (s_end[s].cost > best)', 1)

    acsl_contract = r'''
/*@ requires \valid(p);
    requires 1 <= p->k_cap <= 32;
    requires 0 <= end_pos <= 65536;
    requires \valid(p->count + (0 .. 65536));
    requires \valid(p->slots + (0 .. (65537 * p->k_cap - 1)));
    requires 0 <= p->count[end_pos] <= p->k_cap;
    assigns \nothing;
    ensures p->count[end_pos] == 0 ==> \result == 2147483647;
    ensures (\forall integer i; 0 <= i < p->count[end_pos] ==> \result <= p->slots[end_pos * p->k_cap + i].cost);
    ensures (p->count[end_pos] > 0 && (\forall integer i; 0 <= i < p->count[end_pos] ==> 0 <= p->slots[end_pos * p->k_cap + i].cost <= 1000000))
            ==> (0 <= \result <= 1000000);
*/
int32_t lzvn_pareto_total_cost(lzvn_pareto_scratch *p, int32_t end_pos) '''
    body = acsl_contract + fn_body

    header = r'''
#include <stdint.h>
#include <stddef.h>

#define INT32_MAX 2147483647

typedef struct {
  int32_t cost;
  int32_t run_len;
  int32_t last_dist;
  int32_t via_len;
  int32_t via_dist;
  int32_t src_slot;
  int32_t run_start_pos;
  int32_t run_start_slot;
} lzvn_pareto_slot;

typedef struct {
  int32_t k_cap;
  int32_t *count;
  int32_t *worst_cost;
  lzvn_pareto_slot *slots;
} lzvn_pareto_scratch;
'''
    return header + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzvn_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzvn-pareto-total-cost'
    output.mkdir(parents=True, exist_ok=True)
    verify('lzvn_pareto_total_cost', generate(source), output, ['lzvn_pareto_total_cost'], 10, split=True)

    if args.mutants:
        verify('lzvn_pareto_total_cost_early_stop',
               generate(source, mutant='early_stop'),
               output, ['lzvn_pareto_total_cost'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzvn_pareto_total_cost_oob_count',
               generate(source, mutant='oob_count'),
               output, ['lzvn_pareto_total_cost'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzvn_pareto_total_cost_inverted_check',
               generate(source, mutant='inverted_check'),
               output, ['lzvn_pareto_total_cost'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
