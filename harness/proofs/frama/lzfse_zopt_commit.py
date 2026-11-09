#!/usr/bin/env python3
"""Shipping lzfse_zopt_commit tuple commit and buffer bounds proof."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source, mutant=None):
    start = source.index('{\n  int ok = 1;\n  const int32_t *split_at = z->split_at;')
    end = source.index('\n}\n\nint lzfse_encode_base', start)
    fn_body = source[start:end + 2]

    # Annotate tally loop
    tally_loop = '      for (int32_t r = 0; r <= n_splits; r++) {\n        int32_t t_next = (r < n_splits) ? split_at[r] : z->best_n_tuples;'
    assert tally_loop in fn_body
    tally_replacement = r'''      /*@ loop invariant 0 <= r <= n_splits + 1;
          loop invariant n_splits <= 7;
          loop invariant 0 <= t_cur <= z->best_n_tuples;
          loop invariant r == 0 ==> t_cur == 0;
          loop invariant (1 <= r <= n_splits) ==> t_cur == z->split_at[r - 1];
          loop assigns r, t_cur,
                       ((uint32_t *)sub_l)[0 .. 8 * 20 - 1],
                       ((uint32_t *)sub_m)[0 .. 8 * 20 - 1],
                       ((uint32_t *)sub_d)[0 .. 8 * 256 - 1],
                       ((uint32_t *)sub_lit)[0 .. 8 * 256 - 1];
          loop variant n_splits + 1 - r;
      */
      for (int32_t r = 0; r <= n_splits; r++) {
        int32_t t_next = (r < n_splits) ? split_at[r] : z->best_n_tuples;
        /*@ assert 0 <= r <= 7; */'''
    fn_body = fn_body.replace(tally_loop, tally_replacement)

    # Annotate outer reparse commit loop
    reparse_loop = '    for (int32_t r = 0; r <= n_splits; r++) {\n      lzfse_offset range_end = (r < n_splits) ? z->tuple_start_pos[split_at[r]] : total_len;'
    assert reparse_loop in fn_body
    reparse_replacement = r'''    /*@ loop invariant 0 <= r <= n_splits + 1;
        loop invariant s->dst_begin == \at(s->dst_begin, Pre);
        loop invariant s->dst_end == \at(s->dst_end, Pre);
        loop invariant s->dst_begin <= s->dst <= s->dst_end;
        loop invariant 0 <= s->src_literal <= s->src_end;
        loop invariant ok == 1;
        loop assigns r, range_start, ok, s->dst, s->src_literal;
        loop variant n_splits + 1 - r;
    */
    for (int32_t r = 0; r <= n_splits; r++) {
      lzfse_offset range_end = (r < n_splits) ? z->tuple_start_pos[split_at[r]] : total_len;'''
    fn_body = fn_body.replace(reparse_loop, reparse_replacement)

    # Annotate inner reparse tuple commit loop
    reparse_inner = '      for (int32_t t = 0; t < z->best_n_tuples; t++) {\n        uint32_t L = z->best_tup_L[t], M = z->best_tup_M[t], D = z->best_tup_D[t];'
    assert reparse_inner in fn_body
    reparse_inner_rep = r'''      lzfse_offset lit_start = s->src_literal;
      /*@ loop invariant 0 <= t <= z->best_n_tuples;
          loop invariant s->dst_begin == \at(s->dst_begin, Pre);
          loop invariant s->dst_end == \at(s->dst_end, Pre);
          loop invariant s->dst_begin <= s->dst <= s->dst_end;
          loop invariant s->src_literal == lit_start + z->tuple_start_pos[t];
          loop invariant 0 <= s->src_literal <= s->src_end;
          loop invariant \valid_read(z->best_tup_L + (0 .. z->best_n_tuples - 1));
          loop invariant \valid_read(z->best_tup_M + (0 .. z->best_n_tuples - 1));
          loop invariant \valid_read(z->best_tup_D + (0 .. z->best_n_tuples - 1));
          loop invariant \valid_read(z->tuple_start_pos + (0 .. z->best_n_tuples));
          loop invariant z->tuple_start_pos[0] == 0;
          loop invariant (\forall integer i; 0 <= i < z->best_n_tuples ==>
              (z->tuple_start_pos[i] + (lzfse_offset)z->best_tup_L[i] + (lzfse_offset)z->best_tup_M[i] == z->tuple_start_pos[i + 1]));
          loop invariant (\forall integer i; 0 <= i < z->best_n_tuples ==>
              (lit_start + z->tuple_start_pos[i] + (lzfse_offset)z->best_tup_L[i] + (lzfse_offset)z->best_tup_M[i] <= s->src_end));
          loop invariant (\forall integer i; 0 <= i < z->best_n_tuples ==>
              (z->best_tup_M[i] > 0 ==> (1 <= z->best_tup_D[i] <= lit_start + z->tuple_start_pos[i] + (lzfse_offset)z->best_tup_L[i])));
          loop invariant ok == 1;
          loop assigns t, ok, s->dst, s->src_literal;
          loop variant z->best_n_tuples - t;
      */
      for (int32_t t = 0; t < z->best_n_tuples; t++) {
        uint32_t L = z->best_tup_L[t], M = z->best_tup_M[t], D = z->best_tup_D[t];'''
    fn_body = fn_body.replace(reparse_inner, reparse_inner_rep)

    reparse_lit = 'if (L > 0 && lzfse_backend_literals(s, L) != LZFSE_STATUS_OK) { ok = 0; goto END; }\n          continue;'
    assert reparse_lit in fn_body
    reparse_lit_rep = r'''if (L > 0 && lzfse_backend_literals(s, L) != LZFSE_STATUS_OK) { ok = 0; goto END; }
          /*@ assert s->src_literal == lit_start + z->tuple_start_pos[t + 1]; */
          continue;'''
    fn_body = fn_body.replace(reparse_lit, reparse_lit_rep)

    reparse_match = '        lzfse_match match;\n        match.pos = s->src_literal + L;\n        match.ref = match.pos - D;\n        match.length = M;\n        if (lzfse_backend_match(s, &match) != LZFSE_STATUS_OK) { ok = 0; goto END; }'
    assert reparse_match in fn_body
    reparse_match_rep = r'''        lzfse_match match;
        match.pos = s->src_literal + L;
        match.ref = match.pos - D;
        match.length = M;
        /*@ assert match.pos == lit_start + z->tuple_start_pos[t] + (lzfse_offset)L &&
                  1 <= (lzfse_offset)D <= match.pos;
        */
        if (lzfse_backend_match(s, &match) != LZFSE_STATUS_OK) { ok = 0; goto END; }
        /*@ assert s->src_literal == lit_start + z->tuple_start_pos[t + 1]; */'''
    fn_body = fn_body.replace(reparse_match, reparse_match_rep)

    # Annotate standard commit loop
    std_loop = '    for (int32_t t = 0; t < z->best_n_tuples; t++) {\n      if (next_split < n_splits && t == split_at[next_split]) {'
    assert std_loop in fn_body
    std_replacement = r'''    lzfse_offset lit_start = s->src_literal;
    /*@ loop invariant 0 <= t <= z->best_n_tuples;
        loop invariant 0 <= next_split <= n_splits;
        loop invariant lit_start == \at(s->src_literal, Pre);
        loop invariant s->dst_begin == \at(s->dst_begin, Pre);
        loop invariant s->dst_end == \at(s->dst_end, Pre);
        loop invariant s->dst_begin <= s->dst <= s->dst_end;
        loop invariant s->src_literal == lit_start + z->tuple_start_pos[t];
        loop invariant 0 <= s->src_literal <= s->src_end;
        loop invariant \valid_read(z->best_tup_L + (0 .. z->best_n_tuples - 1));
        loop invariant \valid_read(z->best_tup_M + (0 .. z->best_n_tuples - 1));
        loop invariant \valid_read(z->best_tup_D + (0 .. z->best_n_tuples - 1));
        loop invariant \valid_read(z->tuple_start_pos + (0 .. z->best_n_tuples));
        loop invariant z->tuple_start_pos[0] == 0;
        loop invariant (\forall integer i; 0 <= i < z->best_n_tuples ==>
            (z->tuple_start_pos[i] + (lzfse_offset)z->best_tup_L[i] + (lzfse_offset)z->best_tup_M[i] == z->tuple_start_pos[i + 1]));
        loop invariant (\forall integer i; 0 <= i < z->best_n_tuples ==>
            (lit_start + z->tuple_start_pos[i] + (lzfse_offset)z->best_tup_L[i] + (lzfse_offset)z->best_tup_M[i] <= s->src_end));
        loop invariant (\forall integer i; 0 <= i < z->best_n_tuples ==>
            (z->best_tup_M[i] > 0 ==> (1 <= z->best_tup_D[i] <= lit_start + z->tuple_start_pos[i] + (lzfse_offset)z->best_tup_L[i])));
        loop invariant ok == 1;
        loop assigns t, next_split, ok, s->dst, s->src_literal;
        loop variant z->best_n_tuples - t;
    */
    for (int32_t t = 0; t < z->best_n_tuples; t++) {
      if (next_split < n_splits && t == split_at[next_split]) {'''
    fn_body = fn_body.replace(std_loop, std_replacement)

    std_lit = 'if (L > 0 && lzfse_backend_literals(s, L) != LZFSE_STATUS_OK) { ok = 0; goto END; }\n        continue;'
    assert std_lit in fn_body
    std_lit_rep = r'''if (L > 0 && lzfse_backend_literals(s, L) != LZFSE_STATUS_OK) { ok = 0; goto END; }
        /*@ assert s->src_literal == lit_start + z->tuple_start_pos[t + 1]; */
        continue;'''
    fn_body = fn_body.replace(std_lit, std_lit_rep)

    # Add check before backend_match in standard commit loop
    std_match = '      lzfse_match match;\n      match.pos = s->src_literal + L;\n      match.ref = match.pos - D;\n      match.length = M;\n      if (lzfse_backend_match(s, &match) != LZFSE_STATUS_OK) { ok = 0; goto END; }'
    assert std_match in fn_body
    std_match_rep = r'''      lzfse_match match;
      match.pos = s->src_literal + L;
      match.ref = match.pos - D;
      match.length = M;
      /*@ assert match.pos == \at(s->src_literal, Pre) + z->tuple_start_pos[t] + (lzfse_offset)L &&
                1 <= (lzfse_offset)D <= match.pos;
      */
      if (lzfse_backend_match(s, &match) != LZFSE_STATUS_OK) { ok = 0; goto END; }
      /*@ assert s->src_literal == lit_start + z->tuple_start_pos[t + 1]; */'''
    fn_body = fn_body.replace(std_match, std_match_rep)

    if mutant == 'negative_ref':
        fn_body = fn_body.replace('match.ref = match.pos - D;', 'match.ref = -1;', 1)
    elif mutant == 'corrupt_match_pos':
        fn_body = fn_body.replace('match.pos = s->src_literal + L;',
                                  'match.pos = s->src_literal + L + 1;', 1)
    elif mutant == 'bad_return_val':
        fn_body = fn_body.replace('return ok;', 'return ok ? 2 : -1;', 1)

    acsl_contract = r'''
/*@ requires \valid(s);
    requires \valid(z);
    requires 0 <= s->src_literal <= s->src_end;
    requires s->dst_begin <= s->dst <= s->dst_end;
    requires \valid(s->dst_begin + (0 .. s->dst_end - s->dst_begin - 1));
    requires 0 <= z->best_n_tuples <= 10000;
    requires 0 <= n_splits <= 8;
    requires \valid_read(z->best_tup_L + (0 .. z->best_n_tuples - 1));
    requires \valid_read(z->best_tup_M + (0 .. z->best_n_tuples - 1));
    requires \valid_read(z->best_tup_D + (0 .. z->best_n_tuples - 1));
    requires \valid_read(z->tuple_start_pos + (0 .. z->best_n_tuples));
    requires \valid_read(z->split_at + (0 .. n_splits - 1));
    requires (\forall integer i; 0 <= i < n_splits ==> (0 <= z->split_at[i] <= z->best_n_tuples));
    requires (\forall integer i; 0 <= i < n_splits - 1 ==> (z->split_at[i] <= z->split_at[i + 1]));
    requires z->tuple_start_pos[0] == 0;
    requires s->src_literal + z->tuple_start_pos[z->best_n_tuples] <= s->src_end;
    requires (\forall integer t; 0 <= t < z->best_n_tuples ==>
                (z->tuple_start_pos[t] + (lzfse_offset)z->best_tup_L[t] + (lzfse_offset)z->best_tup_M[t] == z->tuple_start_pos[t + 1]));
    requires (\forall integer t; 0 <= t < z->best_n_tuples ==>
                (s->src_literal + z->tuple_start_pos[t] + (lzfse_offset)z->best_tup_L[t] + (lzfse_offset)z->best_tup_M[t] <= s->src_end));
    requires (\forall integer t; 0 <= t < z->best_n_tuples ==>
                (z->best_tup_M[t] > 0 ==> (1 <= z->best_tup_D[t] <= s->src_literal + z->tuple_start_pos[t] + (lzfse_offset)z->best_tup_L[t])));
    requires \separated(s, z,
                        s->dst_begin + (0 .. s->dst_end - s->dst_begin - 1),
                        z->best_tup_L + (0 .. z->best_n_tuples - 1),
                        z->best_tup_M + (0 .. z->best_n_tuples - 1),
                        z->best_tup_D + (0 .. z->best_n_tuples - 1),
                        z->tuple_start_pos + (0 .. z->best_n_tuples),
                        z->split_at + (0 .. n_splits - 1));
    assigns s->dst, s->src_literal;
    ensures \result == 0 || \result == 1;
    ensures s->dst_begin == \old(s->dst_begin);
    ensures s->dst_end == \old(s->dst_end);
    ensures s->dst_begin <= s->dst <= s->dst_end;
    ensures 0 <= s->src_literal;
    ensures s->src_literal <= s->src_end;
*/
int lzfse_zopt_commit(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                      int32_t n_splits,
                      lzfse_offset total_len, lzfse_offset search_end,
                      size_t cstride) '''
    body = acsl_contract + fn_body

    header = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define LZFSE_STATUS_OK 0
#define LZFSE_STATUS_DST_FULL -1
#define LZFSE_STATUS_ERROR -2

#define LZFSE_ENCODE_L_SYMBOLS 20
#define LZFSE_ENCODE_M_SYMBOLS 20
#define LZFSE_ENCODE_D_SYMBOLS 256

typedef int64_t lzfse_offset;

typedef struct {
  const unsigned char *src;
  lzfse_offset src_end;
  lzfse_offset src_literal;
  unsigned char *dst;
  unsigned char *dst_begin;
  unsigned char *dst_end;
} lzfse_encoder_state;

typedef struct {
  lzfse_offset pos;
  lzfse_offset ref;
  uint32_t length;
} lzfse_match;

typedef struct {
  int32_t best_n_tuples;
  int32_t enable_reparse;
  uint32_t *best_tup_L;
  uint32_t *best_tup_M;
  uint32_t *best_tup_D;
  lzfse_offset *tuple_start_pos;
  int32_t *split_at;
} lzfse_zopt_scratch;

/*@ requires 0 <= start <= end;
    requires \valid_read(tup_L + (start .. end - 1));
    requires \valid_read(tup_M + (start .. end - 1));
    requires \valid_read(tup_D + (start .. end - 1));
    requires \valid(l_occ + (0 .. 19));
    requires \valid(m_occ + (0 .. 19));
    requires \valid(d_occ + (0 .. 255));
    requires \valid(lit_occ + (0 .. 255));
    assigns l_occ[0 .. 19], m_occ[0 .. 19], d_occ[0 .. 255], lit_occ[0 .. 255];
*/
void tally_tuple_subrange(const uint32_t *tup_L, const uint32_t *tup_M, const uint32_t *tup_D,
                          int32_t start, int32_t end, const uint8_t *src_base, lzfse_offset base_pos,
                          uint32_t *l_occ, uint32_t *m_occ, uint32_t *d_occ, uint32_t *lit_occ);

/*@ requires \valid(s);
    requires \valid(z);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==> (0 <= z->best_n_tuples <= 10000);
    ensures \result == 1 ==> \valid_read(z->best_tup_L + (0 .. z->best_n_tuples - 1));
    ensures \result == 1 ==> \valid_read(z->best_tup_M + (0 .. z->best_n_tuples - 1));
    ensures \result == 1 ==> \valid_read(z->best_tup_D + (0 .. z->best_n_tuples - 1));
    ensures \result == 1 ==> \valid_read(z->tuple_start_pos + (0 .. z->best_n_tuples));
    ensures \result == 1 ==> z->tuple_start_pos[0] == 0;
    ensures \result == 1 ==> s->src_literal + z->tuple_start_pos[z->best_n_tuples] <= s->src_end;
    ensures \result == 1 ==> (\forall integer t; 0 <= t < z->best_n_tuples ==>
              (z->tuple_start_pos[t] + (lzfse_offset)z->best_tup_L[t] + (lzfse_offset)z->best_tup_M[t] == z->tuple_start_pos[t + 1]));
    ensures \result == 1 ==> (\forall integer t; 0 <= t < z->best_n_tuples ==>
              (s->src_literal + z->tuple_start_pos[t] + (lzfse_offset)z->best_tup_L[t] + (lzfse_offset)z->best_tup_M[t] <= s->src_end));
    ensures \result == 1 ==> (\forall integer t; 0 <= t < z->best_n_tuples ==>
              (z->best_tup_M[t] > 0 ==> (1 <= z->best_tup_D[t] <= s->src_literal + z->tuple_start_pos[t] + (lzfse_offset)z->best_tup_L[t])));
*/
int run_dp_range(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                 lzfse_offset start_pos, lzfse_offset end_pos,
                 lzfse_offset search_end, size_t cstride,
                 int max_iters,
                 const uint32_t *pre_l_occ, const uint32_t *pre_m_occ,
                 const uint32_t *pre_d_occ, const uint32_t *pre_lit_occ,
                 const uint32_t *lmd_seed);

/*@ requires \valid(s);
    requires s->dst_begin <= s->dst <= s->dst_end;
    requires s->src_literal + (lzfse_offset)n_literals <= s->src_end;
    assigns s->dst, s->src_literal;
    ensures \result == 0 || \result == -1 || \result == -2;
    ensures s->dst_begin == \old(s->dst_begin);
    ensures s->dst_end == \old(s->dst_end);
    ensures s->dst_begin <= s->dst <= s->dst_end;
    ensures s->src_literal == \old(s->src_literal) + (lzfse_offset)n_literals;
*/
int lzfse_backend_literals(lzfse_encoder_state *s, size_t n_literals);

/*@ requires \valid(s);
    requires \valid_read(match);
    requires s->dst_begin <= s->dst <= s->dst_end;
    requires match->pos >= s->src_literal;
    requires match->pos + (lzfse_offset)match->length <= s->src_end;
    requires match->ref >= 0;
    requires match->ref < match->pos;
    assigns s->dst, s->src_literal;
    ensures \result == 0 || \result == -1 || \result == -2;
    ensures s->dst_begin == \old(s->dst_begin);
    ensures s->dst_end == \old(s->dst_end);
    ensures s->dst_begin <= s->dst <= s->dst_end;
    ensures s->src_literal == match->pos + (lzfse_offset)match->length;
*/
int lzfse_backend_match(lzfse_encoder_state *s, const lzfse_match *match);

/*@ requires \valid(s);
    requires s->dst_begin <= s->dst <= s->dst_end;
    assigns s->dst;
    ensures \result == 0 || \result == -1 || \result == -2;
    ensures s->dst_begin == \old(s->dst_begin);
    ensures s->dst_end == \old(s->dst_end);
    ensures s->dst_begin <= s->dst <= s->dst_end;
    ensures s->src_literal == \old(s->src_literal);
*/
int lzfse_encode_matches(lzfse_encoder_state *s);
'''
    return header + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzfse_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzfse-zopt-commit'
    output.mkdir(parents=True, exist_ok=True)
    allowed = [
        r"\[wp:pedantic-assigns\] [^\n]+:\d+: Warning: \n"
        r"  No \\from specification for assigned pointer 's->dst'\.\n"
        r"  Callers assumptions might be imprecise\."
    ]
    verify('lzfse_zopt_commit', generate(source), output, ['lzfse_zopt_commit'], 10, split=False,
           allowed_warnings=allowed)

    if args.mutants:
        verify('lzfse_zopt_commit_negative_ref',
               generate(source, mutant='negative_ref'),
               output, ['lzfse_zopt_commit'], 10, False,
               split=False, timeout=5, parallelism=2, allowed_warnings=allowed)

        verify('lzfse_zopt_commit_corrupt_match_pos',
               generate(source, mutant='corrupt_match_pos'),
               output, ['lzfse_zopt_commit'], 10, False,
               split=False, timeout=5, parallelism=2, allowed_warnings=allowed)

        verify('lzfse_zopt_commit_bad_return_val',
               generate(source, mutant='bad_return_val'),
               output, ['lzfse_zopt_commit'], 10, False,
               split=False, timeout=5, parallelism=2, allowed_warnings=allowed)


if __name__ == '__main__':
    main()
