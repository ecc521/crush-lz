#!/usr/bin/env python3
"""Shipping lzfse run_dp_range dispatch, termination, and tuple bounds proof."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(mutant=None):
    header = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef int64_t lzfse_offset;

typedef struct {
  const unsigned char *src;
  lzfse_offset src_end;
  lzfse_offset src_literal;
} lzfse_encoder_state;

typedef struct {
  int32_t max_tuples;
  int32_t n_tuples;
  int32_t best_n_tuples;
  int32_t iterations;
  uint32_t *tup_L;
  uint32_t *tup_M;
  uint32_t *tup_D;
  uint32_t *best_tup_L;
  uint32_t *best_tup_M;
  uint32_t *best_tup_D;
  int32_t *rev_len;
  int32_t *rev_dist;
  int32_t *rev_lit_run;
} lzfse_zopt_scratch;
'''

    step_contract = r'''
/*@ requires \valid(s);
    requires \valid(z);
    requires 0 <= start_pos <= end_pos <= 65536;
    requires \separated(s, z);
    requires 0 < z->max_tuples <= 10000;
    requires \valid(z->best_tup_L + (0 .. z->max_tuples - 1));
    requires \valid(z->best_tup_M + (0 .. z->max_tuples - 1));
    requires \valid(z->best_tup_D + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_L + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_M + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_D + (0 .. z->max_tuples - 1));
    requires \valid(z->rev_len + (0 .. z->max_tuples - 1));
    requires \valid(z->rev_dist + (0 .. z->max_tuples - 1));
    requires \valid(z->rev_lit_run + (0 .. z->max_tuples - 1));
    requires \separated(z,
                        z->best_tup_L + (0 .. z->max_tuples - 1),
                        z->best_tup_M + (0 .. z->max_tuples - 1),
                        z->best_tup_D + (0 .. z->max_tuples - 1),
                        z->tup_L + (0 .. z->max_tuples - 1),
                        z->tup_M + (0 .. z->max_tuples - 1),
                        z->tup_D + (0 .. z->max_tuples - 1),
                        z->rev_len + (0 .. z->max_tuples - 1),
                        z->rev_dist + (0 .. z->max_tuples - 1),
                        z->rev_lit_run + (0 .. z->max_tuples - 1));
    assigns z->n_tuples, z->best_n_tuples,
            z->best_tup_L[0 .. z->max_tuples - 1],
            z->best_tup_M[0 .. z->max_tuples - 1],
            z->best_tup_D[0 .. z->max_tuples - 1],
            z->tup_L[0 .. z->max_tuples - 1],
            z->tup_M[0 .. z->max_tuples - 1],
            z->tup_D[0 .. z->max_tuples - 1],
            z->rev_len[0 .. z->max_tuples - 1],
            z->rev_dist[0 .. z->max_tuples - 1],
            z->rev_lit_run[0 .. z->max_tuples - 1];
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> (0 <= z->best_n_tuples <= z->max_tuples);
    ensures \result == 1 ==> (0 <= z->n_tuples <= z->max_tuples);
*/
'''

    if mutant == 'corrupt_step_tuples':
        step_body = r'''
int run_dp_step(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                lzfse_offset start_pos, lzfse_offset end_pos)
{
  int tuple_overflow = 0;
  int32_t *rev_len = z->rev_len;
  int32_t *rev_dist = z->rev_dist;
  int32_t *rev_lit_run = z->rev_lit_run;
  int32_t nrev = 0;
  int32_t pending_lit = 0;
  lzfse_offset pos = end_pos;
  int32_t max_t = z->max_tuples;

  /*@ loop invariant start_pos <= pos <= end_pos;
      loop invariant 0 <= nrev <= max_t;
      loop invariant 0 <= pending_lit <= end_pos - pos;
      loop invariant max_t == \at(z->max_tuples, Pre);
      loop invariant rev_len == \at(z->rev_len, Pre);
      loop invariant rev_dist == \at(z->rev_dist, Pre);
      loop invariant rev_lit_run == \at(z->rev_lit_run, Pre);
      loop invariant \valid(rev_len + (0 .. max_t - 1));
      loop invariant \valid(rev_dist + (0 .. max_t - 1));
      loop invariant \valid(rev_lit_run + (0 .. max_t - 1));
      loop assigns pos, nrev, pending_lit, tuple_overflow,
                   rev_len[0 .. max_t - 1],
                   rev_dist[0 .. max_t - 1],
                   rev_lit_run[0 .. max_t - 1];
      loop variant pos - start_pos;
  */
  while (pos > start_pos) {
    if (pos > start_pos + 1) {
      if (nrev >= max_t) { tuple_overflow = 1; break; }
      rev_len[nrev] = 2;
      rev_dist[nrev] = 1;
      rev_lit_run[nrev] = pending_lit;
      nrev++;
      pending_lit = 0;
      pos -= 2;
    } else {
      pending_lit++;
      pos--;
    }
  }

  z->n_tuples = 0;
  if (!tuple_overflow) {
    uint32_t running_L = (uint32_t)pending_lit;
    uint32_t *tup_L = z->tup_L;
    uint32_t *tup_M = z->tup_M;
    uint32_t *tup_D = z->tup_D;

    /*@ loop invariant -1 <= r < nrev;
        loop invariant 0 <= z->n_tuples <= max_t;
        loop invariant max_t == \at(z->max_tuples, Pre);
        loop invariant tup_L == \at(z->tup_L, Pre);
        loop invariant tup_M == \at(z->tup_M, Pre);
        loop invariant tup_D == \at(z->tup_D, Pre);
        loop invariant rev_len == \at(z->rev_len, Pre);
        loop invariant rev_dist == \at(z->rev_dist, Pre);
        loop invariant rev_lit_run == \at(z->rev_lit_run, Pre);
        loop invariant \valid(tup_L + (0 .. max_t - 1));
        loop invariant \valid(tup_M + (0 .. max_t - 1));
        loop invariant \valid(tup_D + (0 .. max_t - 1));
        loop invariant \valid(rev_len + (0 .. max_t - 1));
        loop invariant \valid(rev_dist + (0 .. max_t - 1));
        loop invariant \valid(rev_lit_run + (0 .. max_t - 1));
        loop assigns r, running_L, z->n_tuples, tuple_overflow,
                     tup_L[0 .. max_t - 1],
                     tup_M[0 .. max_t - 1],
                     tup_D[0 .. max_t - 1];
        loop variant r + 1;
    */
    for (int32_t r = nrev - 1; r >= 0 && !tuple_overflow; r--) {
      if (z->n_tuples >= max_t) { tuple_overflow = 1; break; }
      tup_L[z->n_tuples] = running_L;
      tup_M[z->n_tuples] = (uint32_t)rev_len[r];
      tup_D[z->n_tuples] = (uint32_t)rev_dist[r];
      z->n_tuples++;
      running_L = (uint32_t)rev_lit_run[r];
    }
    if (!tuple_overflow && (running_L > 0 || z->n_tuples == 0)) {
      if (z->n_tuples >= max_t) {
        tuple_overflow = 1;
      } else {
        tup_L[z->n_tuples] = running_L;
        tup_M[z->n_tuples] = 0;
        tup_D[z->n_tuples] = 0;
        z->n_tuples++;
      }
    }
  }

  if (tuple_overflow) return 0;

  uint32_t *best_tup_L = z->best_tup_L;
  uint32_t *best_tup_M = z->best_tup_M;
  uint32_t *best_tup_D = z->best_tup_D;
  uint32_t *tup_L = z->tup_L;
  uint32_t *tup_M = z->tup_M;
  uint32_t *tup_D = z->tup_D;
  int32_t n = z->n_tuples;

  /*@ loop invariant 0 <= t <= n;
      loop invariant n == \at(z->n_tuples, LoopEntry);
      loop invariant max_t == \at(z->max_tuples, Pre);
      loop invariant best_tup_L == \at(z->best_tup_L, Pre);
      loop invariant best_tup_M == \at(z->best_tup_M, Pre);
      loop invariant best_tup_D == \at(z->best_tup_D, Pre);
      loop invariant tup_L == \at(z->tup_L, Pre);
      loop invariant tup_M == \at(z->tup_M, Pre);
      loop invariant tup_D == \at(z->tup_D, Pre);
      loop invariant \valid(best_tup_L + (0 .. max_t - 1));
      loop invariant \valid(best_tup_M + (0 .. max_t - 1));
      loop invariant \valid(best_tup_D + (0 .. max_t - 1));
      loop invariant \valid(tup_L + (0 .. max_t - 1));
      loop invariant \valid(tup_M + (0 .. max_t - 1));
      loop invariant \valid(tup_D + (0 .. max_t - 1));
      loop assigns t,
                   best_tup_L[0 .. max_t - 1],
                   best_tup_M[0 .. max_t - 1],
                   best_tup_D[0 .. max_t - 1];
      loop variant n - t;
  */
  for (int32_t t = 0; t < n; t++) {
    best_tup_L[t] = tup_L[t];
    best_tup_M[t] = tup_M[t];
    best_tup_D[t] = tup_D[t];
  }
  z->best_n_tuples = max_t + 1;

  return 1;
}
'''
    else:
        step_body = r'''
int run_dp_step(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                lzfse_offset start_pos, lzfse_offset end_pos)
{
  int tuple_overflow = 0;
  int32_t *rev_len = z->rev_len;
  int32_t *rev_dist = z->rev_dist;
  int32_t *rev_lit_run = z->rev_lit_run;
  int32_t nrev = 0;
  int32_t pending_lit = 0;
  lzfse_offset pos = end_pos;
  int32_t max_t = z->max_tuples;

  /*@ loop invariant start_pos <= pos <= end_pos;
      loop invariant 0 <= nrev <= max_t;
      loop invariant 0 <= pending_lit <= end_pos - pos;
      loop invariant max_t == \at(z->max_tuples, Pre);
      loop invariant rev_len == \at(z->rev_len, Pre);
      loop invariant rev_dist == \at(z->rev_dist, Pre);
      loop invariant rev_lit_run == \at(z->rev_lit_run, Pre);
      loop invariant \valid(rev_len + (0 .. max_t - 1));
      loop invariant \valid(rev_dist + (0 .. max_t - 1));
      loop invariant \valid(rev_lit_run + (0 .. max_t - 1));
      loop assigns pos, nrev, pending_lit, tuple_overflow,
                   rev_len[0 .. max_t - 1],
                   rev_dist[0 .. max_t - 1],
                   rev_lit_run[0 .. max_t - 1];
      loop variant pos - start_pos;
  */
  while (pos > start_pos) {
    if (pos > start_pos + 1) {
      if (nrev >= max_t) { tuple_overflow = 1; break; }
      rev_len[nrev] = 2;
      rev_dist[nrev] = 1;
      rev_lit_run[nrev] = pending_lit;
      nrev++;
      pending_lit = 0;
      pos -= 2;
    } else {
      pending_lit++;
      pos--;
    }
  }

  z->n_tuples = 0;
  if (!tuple_overflow) {
    uint32_t running_L = (uint32_t)pending_lit;
    uint32_t *tup_L = z->tup_L;
    uint32_t *tup_M = z->tup_M;
    uint32_t *tup_D = z->tup_D;

    /*@ loop invariant -1 <= r < nrev;
        loop invariant 0 <= z->n_tuples <= max_t;
        loop invariant max_t == \at(z->max_tuples, Pre);
        loop invariant tup_L == \at(z->tup_L, Pre);
        loop invariant tup_M == \at(z->tup_M, Pre);
        loop invariant tup_D == \at(z->tup_D, Pre);
        loop invariant rev_len == \at(z->rev_len, Pre);
        loop invariant rev_dist == \at(z->rev_dist, Pre);
        loop invariant rev_lit_run == \at(z->rev_lit_run, Pre);
        loop invariant \valid(tup_L + (0 .. max_t - 1));
        loop invariant \valid(tup_M + (0 .. max_t - 1));
        loop invariant \valid(tup_D + (0 .. max_t - 1));
        loop invariant \valid(rev_len + (0 .. max_t - 1));
        loop invariant \valid(rev_dist + (0 .. max_t - 1));
        loop invariant \valid(rev_lit_run + (0 .. max_t - 1));
        loop assigns r, running_L, z->n_tuples, tuple_overflow,
                     tup_L[0 .. max_t - 1],
                     tup_M[0 .. max_t - 1],
                     tup_D[0 .. max_t - 1];
        loop variant r + 1;
    */
    for (int32_t r = nrev - 1; r >= 0 && !tuple_overflow; r--) {
      if (z->n_tuples >= max_t) { tuple_overflow = 1; break; }
      tup_L[z->n_tuples] = running_L;
      tup_M[z->n_tuples] = (uint32_t)rev_len[r];
      tup_D[z->n_tuples] = (uint32_t)rev_dist[r];
      z->n_tuples++;
      running_L = (uint32_t)rev_lit_run[r];
    }
    if (!tuple_overflow && (running_L > 0 || z->n_tuples == 0)) {
      if (z->n_tuples >= max_t) {
        tuple_overflow = 1;
      } else {
        tup_L[z->n_tuples] = running_L;
        tup_M[z->n_tuples] = 0;
        tup_D[z->n_tuples] = 0;
        z->n_tuples++;
      }
    }
  }

  if (tuple_overflow) return 0;

  uint32_t *best_tup_L = z->best_tup_L;
  uint32_t *best_tup_M = z->best_tup_M;
  uint32_t *best_tup_D = z->best_tup_D;
  uint32_t *tup_L = z->tup_L;
  uint32_t *tup_M = z->tup_M;
  uint32_t *tup_D = z->tup_D;
  int32_t n = z->n_tuples;

  /*@ loop invariant 0 <= t <= n;
      loop invariant n == \at(z->n_tuples, LoopEntry);
      loop invariant max_t == \at(z->max_tuples, Pre);
      loop invariant best_tup_L == \at(z->best_tup_L, Pre);
      loop invariant best_tup_M == \at(z->best_tup_M, Pre);
      loop invariant best_tup_D == \at(z->best_tup_D, Pre);
      loop invariant tup_L == \at(z->tup_L, Pre);
      loop invariant tup_M == \at(z->tup_M, Pre);
      loop invariant tup_D == \at(z->tup_D, Pre);
      loop invariant \valid(best_tup_L + (0 .. max_t - 1));
      loop invariant \valid(best_tup_M + (0 .. max_t - 1));
      loop invariant \valid(best_tup_D + (0 .. max_t - 1));
      loop invariant \valid(tup_L + (0 .. max_t - 1));
      loop invariant \valid(tup_M + (0 .. max_t - 1));
      loop invariant \valid(tup_D + (0 .. max_t - 1));
      loop assigns t,
                   best_tup_L[0 .. max_t - 1],
                   best_tup_M[0 .. max_t - 1],
                   best_tup_D[0 .. max_t - 1];
      loop variant n - t;
  */
  for (int32_t t = 0; t < n; t++) {
    best_tup_L[t] = tup_L[t];
    best_tup_M[t] = tup_M[t];
    best_tup_D[t] = tup_D[t];
  }
  z->best_n_tuples = n;

  return 1;
}
'''

    range_contract = r'''
/*@ requires \valid(s);
    requires \valid(z);
    requires 0 <= start_pos <= end_pos <= 65536;
    requires \separated(s, z);
    requires 0 < z->max_tuples <= 10000;
    requires 1 <= z->iterations <= 16;
    requires \valid(z->best_tup_L + (0 .. z->max_tuples - 1));
    requires \valid(z->best_tup_M + (0 .. z->max_tuples - 1));
    requires \valid(z->best_tup_D + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_L + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_M + (0 .. z->max_tuples - 1));
    requires \valid(z->tup_D + (0 .. z->max_tuples - 1));
    requires \valid(z->rev_len + (0 .. z->max_tuples - 1));
    requires \valid(z->rev_dist + (0 .. z->max_tuples - 1));
    requires \valid(z->rev_lit_run + (0 .. z->max_tuples - 1));
    requires \separated(z,
                        z->best_tup_L + (0 .. z->max_tuples - 1),
                        z->best_tup_M + (0 .. z->max_tuples - 1),
                        z->best_tup_D + (0 .. z->max_tuples - 1),
                        z->tup_L + (0 .. z->max_tuples - 1),
                        z->tup_M + (0 .. z->max_tuples - 1),
                        z->tup_D + (0 .. z->max_tuples - 1),
                        z->rev_len + (0 .. z->max_tuples - 1),
                        z->rev_dist + (0 .. z->max_tuples - 1),
                        z->rev_lit_run + (0 .. z->max_tuples - 1));
    assigns z->n_tuples, z->best_n_tuples,
            z->best_tup_L[0 .. z->max_tuples - 1],
            z->best_tup_M[0 .. z->max_tuples - 1],
            z->best_tup_D[0 .. z->max_tuples - 1],
            z->tup_L[0 .. z->max_tuples - 1],
            z->tup_M[0 .. z->max_tuples - 1],
            z->tup_D[0 .. z->max_tuples - 1],
            z->rev_len[0 .. z->max_tuples - 1],
            z->rev_dist[0 .. z->max_tuples - 1],
            z->rev_lit_run[0 .. z->max_tuples - 1];
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> (0 <= z->best_n_tuples <= z->max_tuples);
    ensures \result == 1 ==> (0 <= z->n_tuples <= z->max_tuples);
*/
'''

    if mutant == 'bad_return':
        range_body = r'''
int run_dp_range(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                 lzfse_offset start_pos, lzfse_offset end_pos,
                 int max_iters)
{
  int iters = (max_iters > 0 && max_iters < z->iterations) ? max_iters : z->iterations;
  z->best_n_tuples = 0;
  z->n_tuples = 0;
  int32_t max_t = z->max_tuples;

  /*@ loop invariant 0 <= iter <= iters;
      loop invariant 0 <= z->best_n_tuples <= max_t;
      loop invariant 0 <= z->n_tuples <= max_t;
      loop invariant max_t == \at(z->max_tuples, Pre);
      loop assigns iter,
                   z->n_tuples, z->best_n_tuples,
                   z->best_tup_L[0 .. max_t - 1],
                   z->best_tup_M[0 .. max_t - 1],
                   z->best_tup_D[0 .. max_t - 1],
                   z->tup_L[0 .. max_t - 1],
                   z->tup_M[0 .. max_t - 1],
                   z->tup_D[0 .. max_t - 1],
                   z->rev_len[0 .. max_t - 1],
                   z->rev_dist[0 .. max_t - 1],
                   z->rev_lit_run[0 .. max_t - 1];
      loop variant iters - iter;
  */
  for (int iter = 0; iter < iters; iter++) {
    int ok = run_dp_step(s, z, start_pos, end_pos);
    if (!ok) return 0;
  }

  return 2;
}
'''
    elif mutant == 'corrupt_tuples':
        range_body = r'''
int run_dp_range(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                 lzfse_offset start_pos, lzfse_offset end_pos,
                 int max_iters)
{
  int iters = (max_iters > 0 && max_iters < z->iterations) ? max_iters : z->iterations;
  z->best_n_tuples = 0;
  z->n_tuples = 0;
  int32_t max_t = z->max_tuples;

  /*@ loop invariant 0 <= iter <= iters;
      loop invariant 0 <= z->best_n_tuples <= max_t;
      loop invariant 0 <= z->n_tuples <= max_t;
      loop invariant max_t == \at(z->max_tuples, Pre);
      loop assigns iter,
                   z->n_tuples, z->best_n_tuples,
                   z->best_tup_L[0 .. max_t - 1],
                   z->best_tup_M[0 .. max_t - 1],
                   z->best_tup_D[0 .. max_t - 1],
                   z->tup_L[0 .. max_t - 1],
                   z->tup_M[0 .. max_t - 1],
                   z->tup_D[0 .. max_t - 1],
                   z->rev_len[0 .. max_t - 1],
                   z->rev_dist[0 .. max_t - 1],
                   z->rev_lit_run[0 .. max_t - 1];
      loop variant iters - iter;
  */
  for (int iter = 0; iter < iters; iter++) {
    int ok = run_dp_step(s, z, start_pos, end_pos);
    if (!ok) return 0;
  }

  z->best_n_tuples = max_t + 1;
  return 1;
}
'''
    else:
        range_body = r'''
int run_dp_range(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                 lzfse_offset start_pos, lzfse_offset end_pos,
                 int max_iters)
{
  int iters = (max_iters > 0 && max_iters < z->iterations) ? max_iters : z->iterations;
  z->best_n_tuples = 0;
  z->n_tuples = 0;
  int32_t max_t = z->max_tuples;

  /*@ loop invariant 0 <= iter <= iters;
      loop invariant 0 <= z->best_n_tuples <= max_t;
      loop invariant 0 <= z->n_tuples <= max_t;
      loop invariant max_t == \at(z->max_tuples, Pre);
      loop assigns iter,
                   z->n_tuples, z->best_n_tuples,
                   z->best_tup_L[0 .. max_t - 1],
                   z->best_tup_M[0 .. max_t - 1],
                   z->best_tup_D[0 .. max_t - 1],
                   z->tup_L[0 .. max_t - 1],
                   z->tup_M[0 .. max_t - 1],
                   z->tup_D[0 .. max_t - 1],
                   z->rev_len[0 .. max_t - 1],
                   z->rev_dist[0 .. max_t - 1],
                   z->rev_lit_run[0 .. max_t - 1];
      loop variant iters - iter;
  */
  for (int iter = 0; iter < iters; iter++) {
    int ok = run_dp_step(s, z, start_pos, end_pos);
    if (!ok) return 0;
  }

  return 1;
}
'''

    return header + step_contract + step_body + range_contract + range_body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = root / 'harness/build/proofs-frama-lzfse-run-dp-range'
    output.mkdir(parents=True, exist_ok=True)
    verify('lzfse_run_dp_range', generate(), output, ['run_dp_range', 'run_dp_step'], 10, split=False)

    if args.mutants:
        verify('lzfse_run_dp_range_bad_return',
               generate(mutant='bad_return'),
               output, ['run_dp_range'], 1, False,
               split=False, timeout=5, parallelism=2)

        verify('lzfse_run_dp_range_corrupt_tuples',
               generate(mutant='corrupt_tuples'),
               output, ['run_dp_range'], 1, False,
               split=False, timeout=5, parallelism=2)

        verify('lzfse_run_dp_range_corrupt_step_tuples',
               generate(mutant='corrupt_step_tuples'),
               output, ['run_dp_step'], 1, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
