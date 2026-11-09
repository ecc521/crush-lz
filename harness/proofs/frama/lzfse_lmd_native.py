#!/usr/bin/env python3
"""Shipping LZFSE LMD loop (resume entry, tuple loop, literal budget, copies).

The function body is extracted from lzfse_decode_hot.h (the non-proof
configuration, preprocessed by Frama-C). The pending-work goto is peeled and
the two-field stream copy is scalarized for WP. The distance check is
replaced by its two-compare form (CBMC lzfse_lmd_distance_check proves them
equal). Callees are replaced by contracts that
other targets enforce: exact FSE refill/value-decode (CBMC), literal/match
copies (CBMC). The value-table row predicate and the starting-state predicate
are explicit caller obligations. This target proves the loop's spatial safety
and termination; repeatable DST_FULL state must be
checked separately before caller composition.
"""
from pathlib import Path
import argparse
import os
import re
import sys
sys.dont_write_bytecode = True
from wp_common import verify
from lzfse_literals_native import native_types

MARGIN_NATIVE = 32
# The shipping distance check and the two-compare form WP proves; CBMC
# target lzfse_lmd_distance_check proves them equal for every input here.
D_CHECK_SHIPPING = 'if ((uint64_t)((int64_t)D - 1) >= (uint64_t)(dst - dst_begin) + (uint64_t)L)'
D_CHECK_PROVED = 'if (D <= 0 || (uint32_t)D > (size_t)(dst - dst_begin) + (size_t)L)'
MARGIN_ARM = 64
PEDANTIC_POINTER_FRAMES = (
    r"\[wp:pedantic-assigns\] [^\n]+:\d+: Warning: \n"
    r"  No \\from specification for assigned pointer "
    r"'(?:s->dst|s->compressed_lzfse_block_state.current_literal)'\.\n"
    r"  Callers assumptions might be imprecise\."
)

MODELS = r'''
/*@ axiomatic Tables {
      predicate tables_ok(fse_value_decoder_entry *t);
    }
    predicate input_valid(fse_in_stream *in) =
      0 <= in->accum_nbits < 64 && (in->accum >> in->accum_nbits) == 0;
*/
/*@ requires \valid(in) && \valid(buf) && \valid(next);
    requires input_valid(in);
    requires \base_addr(*buf) == \base_addr(start);
    requires 0 <= *buf - start <= PTRDIFF_MAX;
    requires \valid_read(start - 8 + (0 .. *buf - start + 7));
    requires \separated(in, buf, next, start - 8 + (0 .. *buf - start + 7));
    requires \base_addr(in) != \base_addr(buf) && \base_addr(in) != \base_addr(start) &&
      \base_addr(buf) != \base_addr(start) && \base_addr(next) != \base_addr(in) &&
      \base_addr(next) != \base_addr(buf) && \base_addr(next) != \base_addr(start);
    assigns *in, *buf, *next \from in, buf, next, (start - 8)[0 .. *buf - start + 7];
    ensures \result == 0 || \result == -1;
    ensures \base_addr(*buf) == \base_addr(\old(*buf));
    ensures 0 <= \old(*buf) - *buf <= 8;
    ensures \result == 0 ==> start <= *buf && input_valid(in) && 56 <= in->accum_nbits <= 63;
    ensures \old(*buf) - start >= 8 ==> \result == 0;
*/
int proof_fse_flush_next(fse_in_stream *in, const uint8_t **buf, const uint8_t *start, uint64_t *next);

/*@ requires \valid(pstate) && \valid(in) && \valid_read(table + (0 .. 407));
    requires offset == 0 || offset == 72 || offset == 144;
    requires *pstate < (offset == 144 ? 256 : 64);
    requires input_valid(in);
    requires tables_ok(table);
    requires (offset == 0 ? 14 : offset == 72 ? 17 : 24) <= in->accum_nbits;
    requires \separated(pstate, in, table + (0 .. 407));
    requires \base_addr(pstate) != \base_addr(in) && \base_addr(pstate) != \base_addr(table) &&
      \base_addr(in) != \base_addr(table);
    assigns *pstate, in->accum, in->accum_nbits;
    ensures *pstate < (offset == 144 ? 256 : 64);
    ensures 0 <= \result <= (offset == 0 ? 315 : offset == 72 ? 2359 : 262139);
    ensures \old(in->accum_nbits) - (offset == 0 ? 14 : offset == 72 ? 17 : 24) <=
      in->accum_nbits <= \old(in->accum_nbits);
    ensures input_valid(in);
*/
uint32_t proof_value_decode(uint32_t *pstate, const fse_value_decoder_entry *table,
                            size_t offset, fse_in_stream *in);

/*@ requires \valid_read(p + (0 .. 7)); assigns \nothing; */
uint64_t proof_load8(const uint8_t *p);

/*@ requires \valid(dst + (0 .. length + LZFSE_DECODE_COPY_MARGIN - 1));
    requires \valid_read(src + (0 .. length + LZFSE_DECODE_COPY_MARGIN - 1));
    requires \separated(dst + (0 .. length + LZFSE_DECODE_COPY_MARGIN - 1),
                        src + (0 .. length + LZFSE_DECODE_COPY_MARGIN - 1));
    requires \base_addr(dst) != \base_addr(src);
    assigns dst[0 .. length + LZFSE_DECODE_COPY_MARGIN - 1]; */
void proof_copy_literal_wide(uint8_t *dst, const uint8_t *src, size_t length);

/*@ requires D >= 1 && M >= 0;
    requires \valid(dst + (0 .. M + LZFSE_DECODE_COPY_MARGIN - 1));
    requires \valid_read(dst - D + (0 .. D - 1));
    assigns dst[0 .. M + LZFSE_DECODE_COPY_MARGIN - 1]; */
void proof_copy_match(uint8_t *dst, ptrdiff_t D, ptrdiff_t M);

/*@ requires \valid(dst + (0 .. count - 1));
    requires \valid_read(src + (0 .. count - 1));
    requires \separated(dst + (0 .. count - 1), src + (0 .. count - 1));
    requires \base_addr(dst) != \base_addr(src);
    assigns dst[0 .. count - 1]; */
void proof_copy_literal_bytes(uint8_t *dst, const uint8_t *src, size_t count);

/*@ requires D >= 1;
    requires \valid(dst + (0 .. count - 1));
    requires \valid_read(dst - D + (0 .. D - 1));
    assigns dst[0 .. count - 1]; */
void proof_copy_match_bytes(uint8_t *dst, ptrdiff_t D, size_t count);
'''

# Starting-state predicate, doubling as the resume invariant.
BS = 's->compressed_lzfse_block_state'
START = [
    '\\valid(s)',
    '\\base_addr(s->dst_begin) == \\base_addr(s->dst)',
    '\\base_addr(s->dst_begin) == \\base_addr(s->dst_end)',
    '0 <= s->dst - s->dst_begin <= s->dst_end - s->dst_begin <= PTRDIFF_MAX',
    '\\valid(s->dst_begin + (0 .. s->dst_end - s->dst_begin - 1))',
    '\\base_addr(s->src_begin) == \\base_addr(s->src)',
    '\\base_addr(s->src_begin) == \\base_addr(s->src_end)',
    '8 <= s->src - s->src_begin <= s->src_end - s->src_begin <= PTRDIFF_MAX',
    '\\valid_read(s->src_begin + (0 .. s->src_end - s->src_begin - 1))',
    # The refill reads no byte above the cursor.
    '0 <= ' + BS + '.lmd_in_buf && ' + BS + '.lmd_in_buf <= s->src_end - s->src',
    '\\separated(s, s->dst_begin + (0 .. s->dst_end - s->dst_begin - 1), '
    's->src_begin + (0 .. s->src_end - s->src_begin - 1))',
    '\\separated(s->dst_begin + (0 .. s->dst_end - s->dst_begin - 1), '
    's->src_begin + (0 .. s->src_end - s->src_begin - 1))',
    '\\base_addr(s->dst_begin) != \\base_addr(s)',
    '\\base_addr(s->src_begin) != \\base_addr(s)',
    BS + '.n_literals <= 40000',
    '\\base_addr(' + BS + '.current_literal) == \\base_addr(&' + BS + '.literals[0])',
    '0 <= ' + BS + '.current_literal - &' + BS + '.literals[0] <= ' + BS + '.n_literals',
    BS + '.l_state < 64 && ' + BS + '.m_state < 64 && ' + BS + '.d_state < 256',
    '0 <= ' + BS + '.lmd_in_stream.accum_nbits < 64',
    '(' + BS + '.lmd_in_stream.accum >> ' + BS + '.lmd_in_stream.accum_nbits) == 0',
    '0 <= ' + BS + '.l_value <= 315 && 0 <= ' + BS + '.m_value <= 2359',
    BS + '.l_value <= ' + BS + '.n_literals - (' + BS + '.current_literal - &' + BS + '.literals[0])',
    'tables_ok(&' + BS + '.lmd_decoder[0])',
]
STATE = ('/*@ predicate lmd_start(lzfse_decoder_state *s) =\n      ' +
         ' &&\n      '.join(START) + ';\n*/\n')

CONTRACT = '''
/*@ requires lmd_start(s);
    assigns s->dst,
      ''' + BS + '''.l_value,
      ''' + BS + '''.m_value,
      ''' + BS + '''.d_value,
      ''' + BS + '''.l_state,
      ''' + BS + '''.m_state,
      ''' + BS + '''.d_state,
      ''' + BS + '''.lmd_in_stream,
      ''' + BS + '''.n_matches,
      ''' + BS + '''.lmd_in_buf,
      ''' + BS + '''.current_literal,
      s->dst_begin[0 .. s->dst_end - s->dst_begin - 1];
    ensures \\result == LZFSE_STATUS_OK ||
      \\result == LZFSE_STATUS_DST_FULL ||
      \\result == LZFSE_STATUS_ERROR;
    ensures \\base_addr(s->dst) == \\base_addr(s->dst_begin);
    ensures \\old(s->dst) <= s->dst <= s->dst_end;
    ensures \\result == LZFSE_STATUS_DST_FULL ==> s->dst == s->dst_end;
    ensures \\result == LZFSE_STATUS_DST_FULL ==> lmd_start(s);
*/\n'''


def generate(source, internal, fse, arm=False, mutant=None):
    margin = MARGIN_ARM if arm else MARGIN_NATIVE
    a = source.index('static LZFSE_HOT_ATTR __attribute__((noinline)) int\nLZFSE_HOT(lzfse_decode_lmd)')
    b = source.index('#undef LZFSE_HOT\n', a)
    body = source[a:b]
    assert body.count(D_CHECK_SHIPPING) == 1
    body = body.replace(D_CHECK_SHIPPING, D_CHECK_PROVED)
    # Mutate the shipping source before the resume tail is peeled, so a
    # mutation in that tail reaches both copies, as it would in the source.
    if mutant == 'no_l_check':
        # The shipping check, inside the lit_budget refresh; the LZFSE_PROOF
        # copy (four-space indent) is preprocessed away.
        old = '      if ((size_t)L >= (size_t)(lit_end - lit)) {'
        assert body.count(old) == 1
        body = body.replace(old, '      if (0) {')
    elif mutant == 'big_budget':
        old = '/ LZFSE_DECODE_L_MAX_VALUE;'
        assert body.count(old) == 1
        body = body.replace(old, '/ (LZFSE_DECODE_L_MAX_VALUE - 1);')
    elif mutant == 'wide_margin':
        old = 'if (L + M <= remaining_bytes) {'
        assert body.count(old) == 1
        body = body.replace(old, 'if (L + M <= remaining_bytes + 1) {')
    elif mutant == 'no_d_check':
        old = D_CHECK_PROVED
        assert body.count(old) == 1
        body = body.replace(old, 'if (D <= 0)')
    elif mutant is not None:
        raise ValueError(mutant)
    assert body.count('while (symbols > 0)\n') == 1
    assert body.count('#ifdef LZFSE_REDUCED_PROOF\n  LZFSE_LOOP_ASSIGNS') == 1
    # Drop the CBMC-only loop annotations; the WP loop contract replaces them.
    body = re.sub(r'#ifdef LZFSE_REDUCED_PROOF\n  LZFSE_LOOP_ASSIGNS.*?#endif\n', '@@LOOP@@\n', body, flags=re.S)
    assert '@@LOOP@@' in body

    bs = 's->compressed_lzfse_block_state'
    inv = r'''
        loop invariant l_state < 64 && m_state < 64 && d_state < 256;
        loop invariant stream_width: 0 <= in.accum_nbits < 64;
        loop invariant stream_accum: (in.accum >> in.accum_nbits) == 0;
        loop invariant \base_addr(src) == \base_addr(src_start);
        loop invariant 0 <= src - src_start <= \at(''' + bs + r'''.lmd_in_buf, Pre);
        loop invariant \base_addr(dst) == \base_addr(dst_begin);
        loop invariant 0 <= dst - dst_begin <= s->dst_end - dst_begin;
        loop invariant \at(s->dst, Pre) <= dst;
        loop invariant remaining_bytes == (s->dst_end - dst) - LZFSE_DECODE_COPY_MARGIN;
        loop invariant \base_addr(lit) == \base_addr(&bs->literals[0]);
        loop invariant 0 <= lit - &bs->literals[0] <= bs->n_literals;
        loop invariant 0 <= lit_budget;
        loop invariant lit_budget * LZFSE_DECODE_L_MAX_VALUE <= lit_end - lit - 1;
        loop invariant lit_end == &bs->literals[0] + bs->n_literals + 1;
        loop invariant dst_begin == s->dst_begin && src_start == s->src;
        loop assigns symbols, L, M, D, remaining_bytes, lit, lit_budget, dst, src, in, next,
          l_state, m_state, d_state,
          s->dst_begin[0 .. s->dst_end - s->dst_begin - 1];
        loop variant symbols;
'''
    copy = '  fse_in_stream in = bs->lmd_in_stream;\n'
    assert body.count(copy) == 1
    body = body.replace(copy, '  fse_in_stream in;\n'
                        '  in.accum = bs->lmd_in_stream.accum;\n'
                        '  in.accum_nbits = bs->lmd_in_stream.accum_nbits;\n')
    body = body.replace('@@LOOP@@\n', '', 1)
    body = body.replace('  while (symbols > 0)\n', '  /*@' + inv + '  */\n  while (symbols > 0)\n', 1)

    # WP rejects the goto that enters the loop body. Peel the pending-work
    # entry instead: the tail of the loop body, copied verbatim from the
    # shipping source, runs once when L or M is pending, then the loop is
    # entered normally.
    guard = ('#if !defined(LZFSE_REDUCED_PROOF) || defined(LZFSE_LMD_RESUME_PROOF)\n'
             '  if (L || M)\n    goto ExecuteMatch;\n#endif\n')
    label = ('#if !defined(LZFSE_REDUCED_PROOF) || defined(LZFSE_LMD_RESUME_PROOF)\n'
             '  ExecuteMatch:\n#endif\n')
    end = '  }\n  s->dst = dst;\n  return LZFSE_STATUS_OK;'
    assert body.count(guard) == 1 and body.count(label) == 1 and body.count(end) == 1
    rest = body[body.index(label) + len(label):body.index(end)]
    peeled = '  if (L || M) {\n' + rest.replace('DestinationBufferIsFull', 'DestinationBufferIsFull_peel') + '  }\n'
    body = body.replace(guard, peeled).replace(label, '')


    for old, new in [('fse_in_flush_next', 'proof_fse_flush_next'),
                     ('fse_value_decode_u32', 'proof_value_decode'),
                     ('copy_literal_wide', 'proof_copy_literal_wide'),
                     ('lzfse_copy_match_bytes', 'proof_copy_match_bytes'),
                     ('lzfse_copy_literal_bytes', 'proof_copy_literal_bytes'),
                     ('lzfse_copy_match', 'proof_copy_match'),
                     ('load8', 'proof_load8')]:
        body = re.sub(r'(?<![A-Za-z0-9_])' + old + r'(?![A-Za-z0-9_])', new, body)

    head = ('#define LZFSE_DECODE_COPY_MARGIN ' + str(margin) + '\n'
            '#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\n'
            'typedef uint16_t fse_state;\n' + native_types(internal, fse) +
            '#define LZFSE_STATUS_OK 0\n#define LZFSE_STATUS_DST_FULL -2\n'
            '#define LZFSE_STATUS_ERROR -3\n#define LZFSE_DECODE_L_MAX_VALUE 315\n'
            '#define LZFSE_ENCODE_MAX_M_VALUE 2359\n#define LZFSE_ENCODE_MAX_D_VALUE 262139\n'
            '#define assert(x) ((void)0)\n'
            '#define fse_in_flush2(a, b, c) 0\n'
            '#undef FSE_LOOKAHEAD_REFILL\n#define FSE_LOOKAHEAD_REFILL ' + ('1' if arm else '0') + '\n'
            '#define LZFSE_HOT(x) proof_##x\n#define LZFSE_HOT_ATTR\n'
            '#define LZFSE_HOT_CAT(a,b) a##b\n')
    return head + MODELS + STATE + CONTRACT + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arm', action='store_true')
    parser.add_argument('--mutants', action='store_true')
    parser.add_argument('--mutants-only', action='store_true')
    parser.add_argument('--output')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzfse_decode_hot.h').read_text()
    internal = (root / 'crates/crushlzfse/csrc/lzfse_internal.h').read_text()
    fse = (root / 'crates/crushlzfse/csrc/lzfse_fse.h').read_text()
    output = Path(args.output or root / 'harness/build/proofs-frama-lzfse-lmd-native')
    output.mkdir(parents=True, exist_ok=True)
    generated = generate(source, internal, fse, args.arm)
    # The resume postcondition's larger splits need more than 30 s; the
    # mutants keep the 30 s baseline timeout.
    jobs = int(os.environ.get('PROOF_JOBS', 16))
    if not args.mutants_only:
        verify('lmd_native', generated, output, ['proof_lzfse_decode_lmd'], 100, split=True,
               include_dirs=['crates/crushlzfse/csrc'], timeout=90,
               allowed_warnings=(PEDANTIC_POINTER_FRAMES,), parallelism=jobs)
    if args.mutants or args.mutants_only:
        for name in ('no_l_check', 'big_budget', 'wide_margin', 'no_d_check'):
            verify(name, generate(source, internal, fse, args.arm, name), output,
                   ['proof_lzfse_decode_lmd'], 100, expected=False, split=True,
                   include_dirs=['crates/crushlzfse/csrc'], timeout=30,
                   allowed_warnings=(PEDANTIC_POINTER_FRAMES,), parallelism=jobs)


if __name__ == '__main__':
    main()
