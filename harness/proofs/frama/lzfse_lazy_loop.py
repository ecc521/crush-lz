#!/usr/bin/env python3
"""Shipping LZFSE lazy encoder loop under explicit search/emitter contracts."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify
import re


def generate(source):
    start = source.index('LZFSE_INLINE int crushlzfse_encode_base_lazy_hw(')
    end = source.index('// One instantiation per width in the level table', start)
    body = source[start:end]
    body = body.replace('#endif\n', '', 1)

    loop_entry = '  while (ip < ilimit) {'
    assert body.count(loop_entry) == 1
    body = body.replace(loop_entry, loop_entry + '\n    const lzfse_offset loop_entry_ip = ip;', 1)

    no_match = '    if (ml == 0) {'
    assert body.count(no_match) == 1
    body = body.replace(no_match, no_match + r'''
      /*@ assert 0 <= ip - anchor <= 65536; */''', 1)
    branch_end = '      continue;'
    assert body.count(branch_end) == 1
    body = body.replace(branch_end, r'''      /*@ assert ip > loop_entry_ip; */
      continue;''', 1)

    inner_lookahead = '    for (int step = 1; step <= lookahead && ip + 1 < ilimit;) {'
    assert body.count(inner_lookahead) == 1
    body = body.replace(inner_lookahead, r'''
    /*@ loop invariant 1 <= step <= lookahead + 1;
        loop invariant \at(ip, LoopEntry) <= ip < ilimit;
        loop invariant loop_entry_ip <= start <= ip + 1;
        loop invariant anchor <= start;
        loop invariant 0 <= ref < start;
        loop invariant 4 <= ml;
        loop invariant start + ml <= s->src_end - 8;
        loop assigns step, ip, ml, start, ref,
                     hist_pos[0 .. (((1<<hash_bits)*hash_width)-1)],
                     hist_tag[0 .. (((1<<hash_bits)*hash_width) + 16 - 1)],
                     hist_cursor[0 .. ((1<<hash_bits)-1)];
        loop variant ilimit - ip;
    */
''' + inner_lookahead, 1)

    inner_back = '    while (start > anchor && ref > 0 && src[start - 1] == src[ref - 1]) { start--; ref--; ml++; }'
    assert body.count(inner_back) == 1
    body = body.replace(inner_back, r'''
    /*@ loop invariant anchor <= start;
        loop invariant 0 <= ref;
        loop invariant loop_entry_ip + 4 <= start + ml;
        loop invariant start - ref == \at(start - ref, LoopEntry);
        loop invariant start + ml == \at(start + ml, LoopEntry);
        loop assigns start, ref, ml;
        loop variant start - anchor;
    */
''' + inner_back, 1)

    inner_insert = '    for (lzfse_offset p = ip + 1; p < lim; p++)'
    assert body.count(inner_insert) == 1
    body = body.replace(inner_insert, r'''
    /*@ loop invariant ip + 1 <= p;
        loop invariant p <= lim || p == ip + 1;
        loop invariant 0 <= p <= s->src_end;
        loop assigns p,
                     hist_pos[0 .. (((1<<hash_bits)*hash_width)-1)],
                     hist_tag[0 .. (((1<<hash_bits)*hash_width) + 16 - 1)],
                     hist_cursor[0 .. ((1<<hash_bits)-1)];
        loop variant (lim > p ? lim - p : 0);
    */
''' + inner_insert, 1)

    loop = '  while (ip < ilimit) {'
    assert body.count(loop) == 1
    body = body.replace(loop, r'''
  /*@ loop invariant \valid(s);
      loop invariant 0 <= s->src_literal <= s->src_end;
      loop invariant 1 <= ip <= s->src_end + 300;
      loop invariant s->src_literal <= ip;
      loop invariant rep <= s->src_literal;
      loop assigns ip, rep, s->src_literal,
                   hist_pos[0 .. (((1<<hash_bits)*hash_width)-1)],
                   hist_tag[0 .. (((1<<hash_bits)*hash_width) + 16 - 1)],
                   hist_cursor[0 .. ((1<<hash_bits)-1)];
      loop variant s->src_end + 300 - ip;
  */
''' + loop, 1)

    body = body.replace('LZFSE_INLINE int crushlzfse_encode_base_lazy_hw(', r'''
/*@ axiomatic ShiftRight8 {
      axiom shift_right_8: \forall integer x; 0 <= x <= 65536 ==> (x >> 8) == x / 256;
    }
*/

/*@ requires \valid(s);
    requires 0 <= s->src_end <= 65536;
    requires 0 <= s->src_literal <= s->src_encode_i;
    requires s->src_encode_i <= s->src_end;
    requires 10 <= hash_bits <= 16;
    requires 1 <= hash_width <= 32;
    requires 0 <= lookahead <= 2;
    requires \valid_read(s->src + (0 .. s->src_end-1));
    requires \valid(hist_pos + (0 .. (((1<<hash_bits)*hash_width)-1)));
    requires \valid(hist_tag + (0 .. (((1<<hash_bits)*hash_width) + 16 - 1)));
    requires \valid(hist_cursor + (0 .. ((1<<hash_bits)-1)));
    requires \separated(s, s->src + (0 .. s->src_end-1),
                        hist_pos + (0 .. (((1<<hash_bits)*hash_width)-1)),
                        hist_tag + (0 .. (((1<<hash_bits)*hash_width) + 16 - 1)),
                        hist_cursor + (0 .. ((1<<hash_bits)-1)));
    assigns s->src_encode_i, s->src_literal,
            hist_pos[0 .. (((1<<hash_bits)*hash_width)-1)],
            hist_tag[0 .. (((1<<hash_bits)*hash_width) + 16 - 1)],
            hist_cursor[0 .. ((1<<hash_bits)-1)];
    ensures \result == 0 || \result == -2;
    ensures 0 <= s->src_literal <= s->src_end;
*/
LZFSE_INLINE int crushlzfse_encode_base_lazy_hw(''', 1)

    return r'''
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#define LZFSE_INLINE static
#define LZFSE_STATUS_OK 0
#define LZFSE_STATUS_DST_FULL -2
#define LZFSE_ENCODE_MAX_L_VALUE 315
typedef int64_t lzfse_offset;

typedef struct {
  const uint8_t *src;
  lzfse_offset src_end;
  lzfse_offset src_literal;
  lzfse_offset src_encode_i;
} lzfse_encoder_state;

/*@ requires \valid_read(ptr + (0 .. 3));
    assigns \nothing;
*/
uint32_t load4(const uint8_t *ptr);

/*@ requires \valid_read(ref_ptr + (0 .. max_len + 7));
    requires \valid_read(cur_ptr + (0 .. max_len + 7));
    assigns \nothing;
    ensures 4 <= \result <= max_len;
*/
uint32_t match_extend(const uint8_t *ref_ptr, const uint8_t *cur_ptr,
                      uint32_t min_len, uint32_t max_len);

/*@ requires 0 <= pos < src_end - 16;
    requires \valid_read(src + (0 .. src_end - 1));
    requires \valid(hist_pos + (0 .. (((1<< (32 - hash_shift))*hash_width)-1)));
    requires \valid(hist_tag + (0 .. (((1<< (32 - hash_shift))*hash_width) + 16 - 1)));
    requires \valid(hist_cursor + (0 .. ((1<< (32 - hash_shift))-1)));
    requires \valid(ref);
    assigns hist_pos[0 .. (((1<< (32 - hash_shift))*hash_width)-1)],
            hist_tag[0 .. (((1<< (32 - hash_shift))*hash_width) + 16 - 1)],
            hist_cursor[0 .. ((1<< (32 - hash_shift))-1)],
            *ref;
    ensures \result == 0 || (\result >= 4 && 0 <= *ref < pos && \result <= src_end - pos - 8);
*/
uint32_t crushlzfse_lazy_search(const uint8_t *src, lzfse_offset pos, lzfse_offset src_end,
                                int hash_shift, int hash_width, int32_t *hist_pos,
                                uint8_t *hist_tag, uint16_t *hist_cursor, lzfse_offset *ref);

/*@ assigns \nothing;
    ensures \result >= 0;
*/
uint32_t crushlzfse_lazy_score(uint32_t len, uint32_t dist, uint32_t rep);

/*@ requires 0 <= pos < 65536;
    requires \valid(hist_pos + (0 .. (((1<< (32 - hash_shift))*hash_width)-1)));
    requires \valid(hist_tag + (0 .. (((1<< (32 - hash_shift))*hash_width) + 16 - 1)));
    requires \valid(hist_cursor + (0 .. ((1<< (32 - hash_shift))-1)));
    assigns hist_pos[0 .. (((1<< (32 - hash_shift))*hash_width)-1)],
            hist_tag[0 .. (((1<< (32 - hash_shift))*hash_width) + 16 - 1)],
            hist_cursor[0 .. ((1<< (32 - hash_shift))-1)];
*/
void crushlzfse_lazy_insert(const uint8_t *src, lzfse_offset pos, int hash_shift, int hash_width,
                            int32_t *hist_pos, uint8_t *hist_tag, uint16_t *hist_cursor);

/*@ requires 0 <= L;
    requires \valid(s);
    assigns s->src_literal;
    ensures \result == 0 || \result == -2;
    ensures \result == 0 ==> s->src_literal == \old(s->src_literal) + L;
    ensures \old(s->src_literal) <= s->src_literal <= s->src_end;
*/
int lzfse_backend_literals(lzfse_encoder_state *s, lzfse_offset L);

/*@ requires 0 <= anchor <= start;
    requires start + ml <= s->src_end - 8;
    requires \valid(s);
    assigns s->src_literal;
    ensures \result == 0 || \result == -2;
    ensures \result == 0 ==> s->src_literal == start + ml;
    ensures 0 <= s->src_literal <= s->src_end;
*/
int crushlzfse_fast_emit(lzfse_encoder_state *s, lzfse_offset anchor, lzfse_offset start,
                         uint32_t ml, uint32_t rep);
''' + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzfse_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzfse-lazy-loop'
    output.mkdir(parents=True, exist_ok=True)
    verify('lazy_loop', generate(source), output, ['crushlzfse_encode_base_lazy_hw'], 20,
           split=False)
    if args.mutants:
        old = 'ip += ((ip - anchor) >> 8) + 1;'
        assert source.count(old) == 1
        generated = generate(source)
        assert generated.count(old) == 1
        verify('lazy_no_progress', generated.replace(old, 'ip = loop_entry_ip;'),
               output, ['crushlzfse_encode_base_lazy_hw'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
