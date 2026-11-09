#!/usr/bin/env python3
"""Shipping lzvn_pareto_run_dp dispatch and tuple bounds proof."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(mutant=None):
    header = r'''
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

typedef int32_t lzvn_offset;

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

typedef struct {
  int32_t max_tuples;
  int32_t n_tuples;
  uint32_t *tup_L;
  uint32_t *tup_M;
  uint32_t *tup_D;
  int32_t *rev_len;
  int32_t *rev_dist;
  int32_t *rev_lit_run;
} lzvn_zopt_scratch;
'''

    callee_contracts = r'''
/*@ requires \valid(z);
    requires \valid(p);
    requires p->k_cap == 2;
    requires 0 <= start_pos <= end_pos <= 65536;
    requires 0 <= src_end <= PTRDIFF_MAX;
    requires end_pos <= src_end;
    requires \valid_read(src + (0 .. src_end - 1));
    requires z->max_tuples > 0;
    requires \valid(z->tup_M + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_L + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_D + (0 .. z->max_tuples - 1));
    requires \separated(p, p->count + (0 .. end_pos), p->worst_cost + (0 .. end_pos),
                        p->slots + (0 .. ((end_pos + 1) * p->k_cap - 1)),
                        z, z->tup_M + (0 .. z->max_tuples - 1),
                        z->tup_L + (0 .. z->max_tuples - 1),
                        z->tup_D + (0 .. z->max_tuples - 1));
    assigns z->n_tuples,
            p->count[0 .. end_pos],
            p->worst_cost[0 .. end_pos],
            p->slots[0 .. ((end_pos + 1) * p->k_cap - 1)],
            z->tup_M[0 .. z->max_tuples - 1],
            z->tup_L[0 .. z->max_tuples - 1],
            z->tup_D[0 .. z->max_tuples - 1];
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> (0 <= z->n_tuples <= z->max_tuples);
    ensures \result == 1 ==> (z->n_tuples == 0 || z->tup_L[z->n_tuples - 1] <= 65536);
*/
int lzvn_pareto_run_dp_k2(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                          const unsigned char *src, lzvn_offset src_end,
                          int32_t start_pos, int32_t end_pos);

/*@ requires \valid(z);
    requires \valid(p);
    requires p->k_cap == 4;
    requires 0 <= start_pos <= end_pos <= 65536;
    requires 0 <= src_end <= PTRDIFF_MAX;
    requires end_pos <= src_end;
    requires \valid_read(src + (0 .. src_end - 1));
    requires z->max_tuples > 0;
    requires \valid(z->tup_M + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_L + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_D + (0 .. z->max_tuples - 1));
    requires \separated(p, p->count + (0 .. end_pos), p->worst_cost + (0 .. end_pos),
                        p->slots + (0 .. ((end_pos + 1) * p->k_cap - 1)),
                        z, z->tup_M + (0 .. z->max_tuples - 1),
                        z->tup_L + (0 .. z->max_tuples - 1),
                        z->tup_D + (0 .. z->max_tuples - 1));
    assigns z->n_tuples,
            p->count[0 .. end_pos],
            p->worst_cost[0 .. end_pos],
            p->slots[0 .. ((end_pos + 1) * p->k_cap - 1)],
            z->tup_M[0 .. z->max_tuples - 1],
            z->tup_L[0 .. z->max_tuples - 1],
            z->tup_D[0 .. z->max_tuples - 1];
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> (0 <= z->n_tuples <= z->max_tuples);
    ensures \result == 1 ==> (z->n_tuples == 0 || z->tup_L[z->n_tuples - 1] <= 65536);
*/
int lzvn_pareto_run_dp_k4(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                          const unsigned char *src, lzvn_offset src_end,
                          int32_t start_pos, int32_t end_pos);

/*@ requires \valid(z);
    requires \valid(p);
    requires p->k_cap == 6;
    requires 0 <= start_pos <= end_pos <= 65536;
    requires 0 <= src_end <= PTRDIFF_MAX;
    requires end_pos <= src_end;
    requires \valid_read(src + (0 .. src_end - 1));
    requires z->max_tuples > 0;
    requires \valid(z->tup_M + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_L + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_D + (0 .. z->max_tuples - 1));
    requires \separated(p, p->count + (0 .. end_pos), p->worst_cost + (0 .. end_pos),
                        p->slots + (0 .. ((end_pos + 1) * p->k_cap - 1)),
                        z, z->tup_M + (0 .. z->max_tuples - 1),
                        z->tup_L + (0 .. z->max_tuples - 1),
                        z->tup_D + (0 .. z->max_tuples - 1));
    assigns z->n_tuples,
            p->count[0 .. end_pos],
            p->worst_cost[0 .. end_pos],
            p->slots[0 .. ((end_pos + 1) * p->k_cap - 1)],
            z->tup_M[0 .. z->max_tuples - 1],
            z->tup_L[0 .. z->max_tuples - 1],
            z->tup_D[0 .. z->max_tuples - 1];
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> (0 <= z->n_tuples <= z->max_tuples);
    ensures \result == 1 ==> (z->n_tuples == 0 || z->tup_L[z->n_tuples - 1] <= 65536);
*/
int lzvn_pareto_run_dp_k6(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                          const unsigned char *src, lzvn_offset src_end,
                          int32_t start_pos, int32_t end_pos);

/*@ requires \valid(z);
    requires \valid(p);
    requires 1 <= p->k_cap <= 32;
    requires 0 <= start_pos <= end_pos <= 65536;
    requires 0 <= src_end <= PTRDIFF_MAX;
    requires end_pos <= src_end;
    requires \valid_read(src + (0 .. src_end - 1));
    requires z->max_tuples > 0;
    requires \valid(z->tup_M + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_L + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_D + (0 .. z->max_tuples - 1));
    requires \separated(p, p->count + (0 .. end_pos), p->worst_cost + (0 .. end_pos),
                        p->slots + (0 .. ((end_pos + 1) * p->k_cap - 1)),
                        z, z->tup_M + (0 .. z->max_tuples - 1),
                        z->tup_L + (0 .. z->max_tuples - 1),
                        z->tup_D + (0 .. z->max_tuples - 1));
    assigns z->n_tuples,
            p->count[0 .. end_pos],
            p->worst_cost[0 .. end_pos],
            p->slots[0 .. ((end_pos + 1) * p->k_cap - 1)],
            z->tup_M[0 .. z->max_tuples - 1],
            z->tup_L[0 .. z->max_tuples - 1],
            z->tup_D[0 .. z->max_tuples - 1];
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> (0 <= z->n_tuples <= z->max_tuples);
    ensures \result == 1 ==> (z->n_tuples == 0 || z->tup_L[z->n_tuples - 1] <= 65536);
*/
int lzvn_pareto_run_dp_generic(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                               const unsigned char *src, lzvn_offset src_end,
                               int32_t start_pos, int32_t end_pos);
'''

    dp_contract = r'''
/*@ requires \valid(z);
    requires \valid(p);
    requires 1 <= p->k_cap <= 32;
    requires 0 <= start_pos <= end_pos <= 65536;
    requires 0 <= src_end <= PTRDIFF_MAX;
    requires end_pos <= src_end;
    requires \valid_read(src + (0 .. src_end - 1));
    requires z->max_tuples > 0;
    requires \valid(z->tup_M + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_L + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_D + (0 .. z->max_tuples - 1));
    requires \separated(p, p->count + (0 .. end_pos), p->worst_cost + (0 .. end_pos),
                        p->slots + (0 .. ((end_pos + 1) * p->k_cap - 1)),
                        z, z->tup_M + (0 .. z->max_tuples - 1),
                        z->tup_L + (0 .. z->max_tuples - 1),
                        z->tup_D + (0 .. z->max_tuples - 1));
    assigns z->n_tuples,
            p->count[0 .. end_pos],
            p->worst_cost[0 .. end_pos],
            p->slots[0 .. ((end_pos + 1) * p->k_cap - 1)],
            z->tup_M[0 .. z->max_tuples - 1],
            z->tup_L[0 .. z->max_tuples - 1],
            z->tup_D[0 .. z->max_tuples - 1];
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> (0 <= z->n_tuples <= z->max_tuples);
    ensures \result == 1 ==> (z->n_tuples == 0 || z->tup_L[z->n_tuples - 1] <= 65536);
*/
'''

    if mutant == 'bad_return':
        dp_body = r'''
int lzvn_pareto_run_dp(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                       const unsigned char *src,
                       lzvn_offset src_end, int32_t start_pos,
                       int32_t end_pos)
{
  int res;
  switch (p->k_cap) {
  case 2: res = 2; break;
  case 4: res = lzvn_pareto_run_dp_k4(z, p, src, src_end, start_pos, end_pos); break;
  case 6: res = lzvn_pareto_run_dp_k6(z, p, src, src_end, start_pos, end_pos); break;
  default: res = lzvn_pareto_run_dp_generic(z, p, src, src_end, start_pos, end_pos); break;
  }
  return res;
}
'''
    elif mutant == 'corrupt_tuples':
        dp_body = r'''
int lzvn_pareto_run_dp(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                       const unsigned char *src,
                       lzvn_offset src_end, int32_t start_pos,
                       int32_t end_pos)
{
  int res;
  switch (p->k_cap) {
  case 2: res = lzvn_pareto_run_dp_k2(z, p, src, src_end, start_pos, end_pos); break;
  case 4: res = lzvn_pareto_run_dp_k4(z, p, src, src_end, start_pos, end_pos); break;
  case 6: res = lzvn_pareto_run_dp_k6(z, p, src, src_end, start_pos, end_pos); break;
  default: res = lzvn_pareto_run_dp_generic(z, p, src, src_end, start_pos, end_pos); break;
  }
  if (res == 1) {
    z->n_tuples = z->max_tuples + 1;
  }
  return res;
}
'''
    elif mutant == 'wrong_k_guard':
        dp_body = r'''
int lzvn_pareto_run_dp(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                       const unsigned char *src,
                       lzvn_offset src_end, int32_t start_pos,
                       int32_t end_pos)
{
  /* Dispatches to k2 without checking p->k_cap == 2 */
  return lzvn_pareto_run_dp_k2(z, p, src, src_end, start_pos, end_pos);
}
'''
    else:
        dp_body = r'''
int lzvn_pareto_run_dp(lzvn_zopt_scratch *z, lzvn_pareto_scratch *p,
                       const unsigned char *src,
                       lzvn_offset src_end, int32_t start_pos,
                       int32_t end_pos)
{
  int res;
  switch (p->k_cap) {
  case 2: res = lzvn_pareto_run_dp_k2(z, p, src, src_end, start_pos, end_pos); break;
  case 4: res = lzvn_pareto_run_dp_k4(z, p, src, src_end, start_pos, end_pos); break;
  case 6: res = lzvn_pareto_run_dp_k6(z, p, src, src_end, start_pos, end_pos); break;
  default: res = lzvn_pareto_run_dp_generic(z, p, src, src_end, start_pos, end_pos); break;
  }
  return res;
}
'''

    return header + callee_contracts + dp_contract + dp_body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = root / 'harness/build/proofs-frama-lzvn-pareto-run-dp'
    output.mkdir(parents=True, exist_ok=True)
    verify('lzvn_pareto_run_dp', generate(), output, ['lzvn_pareto_run_dp'], 10, split=True)

    if args.mutants:
        verify('lzvn_pareto_run_dp_bad_return',
               generate(mutant='bad_return'),
               output, ['lzvn_pareto_run_dp'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzvn_pareto_run_dp_corrupt_tuples',
               generate(mutant='corrupt_tuples'),
               output, ['lzvn_pareto_run_dp'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzvn_pareto_run_dp_wrong_k_guard',
               generate(mutant='wrong_k_guard'),
               output, ['lzvn_pareto_run_dp'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
