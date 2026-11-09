#!/usr/bin/env python3
"""Shipping lzfse_push_lmd under explicit copy, status, and buffer contracts."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source):
    start = source.index('{\n  if (s->n_matches + 1 + 8 > LZFSE_MATCHES_PER_BLOCK)')
    end = source.index('\n}\n\n#if defined(CRUSHLZFSE_BACKEND_MATCH_PROOF)', start)
    fn_body = source[start:end + 2]

    # Replace copy16 loop with ACSL loop invariants
    loop_target = '    while (dst < dst_end) { copy16(dst, src); dst += 16; src += 16; }'
    assert fn_body.count(loop_target) == 1
    loop_replacement = r'''    /*@ loop invariant \base_addr(dst) == \base_addr(&s->literals[0]);
        loop invariant \base_addr(src) == \base_addr(s->src);
        loop invariant &s->literals[0] <= dst <= dst_end + 16;
        loop invariant s->src <= src;
        loop invariant dst_end + 16 <= &s->literals[0] + LZFSE_LITERALS_PER_BLOCK;
        loop invariant dst - &s->literals[0] == s->n_literals + 16 + (src - (s->src + s->src_literal + 16));
        loop invariant dst < dst_end ==> dst + 16 <= &s->literals[0] + LZFSE_LITERALS_PER_BLOCK;
        loop invariant dst < dst_end ==> src + 16 <= s->src + s->src_end;
        loop assigns dst, src, s->literals[0 .. LZFSE_LITERALS_PER_BLOCK - 1];
        loop variant (dst_end + 16) - dst;
    */
    while (dst < dst_end) { copy16(dst, src); dst += 16; src += 16; }'''
    fn_body = fn_body.replace(loop_target, loop_replacement, 1)

    acsl_contract = r'''
/*@ requires \valid(s);
    requires 0 <= s->src_end <= 65536;
    requires 0 <= s->src_literal <= s->src_end;
    requires 0 <= L <= s->src_end - s->src_literal;
    requires 0 <= M <= s->src_end - s->src_literal - L;
    requires s->n_matches <= LZFSE_MATCHES_PER_BLOCK;
    requires s->n_literals <= LZFSE_LITERALS_PER_BLOCK;
    requires \valid_read(s->src + (0 .. s->src_end - 1));
    requires \separated(s, s->src + (0 .. s->src_end - 1));
    assigns s->n_matches, s->n_literals, s->src_literal,
            s->l_values[0 .. LZFSE_MATCHES_PER_BLOCK - 1],
            s->m_values[0 .. LZFSE_MATCHES_PER_BLOCK - 1],
            s->d_values[0 .. LZFSE_MATCHES_PER_BLOCK - 1],
            s->literals[0 .. LZFSE_LITERALS_PER_BLOCK - 1];
    ensures \result == 0 || \result == -2;
    ensures 0 <= s->src_literal <= s->src_end;
    ensures \result == 0 ==> s->src_literal == \old(s->src_literal) + (lzfse_offset)L + (lzfse_offset)M;
    ensures \result == 0 ==> s->n_matches == \old(s->n_matches) + 1;
    ensures \result == 0 ==> s->n_literals == \old(s->n_literals) + L;
    ensures \result == -2 ==> s->src_literal == \old(s->src_literal);
    ensures \result == -2 ==> s->n_matches == \old(s->n_matches);
    ensures \result == -2 ==> s->n_literals == \old(s->n_literals);
*/
int lzfse_push_lmd(lzfse_encoder_state *s, uint32_t L, uint32_t M, uint32_t D) '''
    body = acsl_contract + fn_body

    header = r'''
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#define LZFSE_STATUS_OK 0
#define LZFSE_STATUS_DST_FULL -2
#define LZFSE_MATCHES_PER_BLOCK 10000
#define LZFSE_LITERALS_PER_BLOCK (4 * LZFSE_MATCHES_PER_BLOCK)

typedef int64_t lzfse_offset;

typedef struct {
  const uint8_t *src;
  lzfse_offset src_end;
  lzfse_offset src_literal;
  uint8_t *dst;
  uint8_t *dst_begin;
  uint8_t *dst_end;
  uint32_t n_matches;
  uint32_t n_literals;
  uint32_t l_values[LZFSE_MATCHES_PER_BLOCK];
  uint32_t m_values[LZFSE_MATCHES_PER_BLOCK];
  uint32_t d_values[LZFSE_MATCHES_PER_BLOCK];
  uint8_t literals[LZFSE_LITERALS_PER_BLOCK];
} lzfse_encoder_state;

/*@ requires \valid((uint8_t*)dst + (0 .. 15));
    requires \valid_read((const uint8_t*)src + (0 .. 15));
    assigns ((uint8_t*)dst)[0 .. 15];
*/
void proof_copy16(uint8_t *dst, const uint8_t *src);
#define copy16 proof_copy16

/*@ requires n == 0 || (\valid((uint8_t*)d + (0 .. n - 1)) && \valid_read((const uint8_t*)s + (0 .. n - 1)));
    assigns ((uint8_t*)d)[0 .. n - 1];
    assigns \result \from d;
    ensures \result == d;
*/
void *proof_memcpy(uint8_t *d, const uint8_t *s, size_t n);
#define memcpy proof_memcpy
'''
    return header + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzfse_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzfse-push-lmd'
    output.mkdir(parents=True, exist_ok=True)
    verify('lzfse_push_lmd', generate(source), output, ['lzfse_push_lmd'], 20,
           split=False)
    if args.mutants:
        # Mutant 1: drop literals capacity check
        gen1 = generate(source).replace(
            'if (s->n_literals + L + 16 > LZFSE_LITERALS_PER_BLOCK) return LZFSE_STATUS_DST_FULL;',
            '/* dropped literal check */')
        verify('lzfse_push_lmd_no_lit_check', gen1,
               output, ['lzfse_push_lmd'], 10, False,
               split=False, timeout=5, parallelism=2)

        # Mutant 2: drop match capacity check
        gen2 = generate(source).replace(
            'if (s->n_matches + 1 + 8 > LZFSE_MATCHES_PER_BLOCK) return LZFSE_STATUS_DST_FULL;',
            '/* dropped match check */')
        verify('lzfse_push_lmd_no_match_check', gen2,
               output, ['lzfse_push_lmd'], 10, False,
               split=False, timeout=5, parallelism=2)

        # Mutant 3: wrong src_literal advance
        gen3 = generate(source).replace(
            's->src_literal += L + M;',
            's->src_literal += L;')
        verify('lzfse_push_lmd_wrong_advance', gen3,
               output, ['lzfse_push_lmd'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
