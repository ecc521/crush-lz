#!/usr/bin/env python3
"""Shipping lzfse_zopt_build_candidates match candidate search proof."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source, mutant=None):
    start = source.index('{\n  int32_t *__restrict const son = z->bt_son;\n  int32_t *__restrict const head = z->bt_head;')
    end = source.index('\n}\n\n#if defined(LZFSE_BASE_PROOF)\nstatic __attribute__((noinline)) void lzfse_zopt_find_splits', start)
    fn_body = source[start:end + 2]

    memset_head = '  memset(head, 0xFF, ((size_t)1 << root_bits) * sizeof(*head));'
    assert memset_head in fn_body
    fn_body = fn_body.replace(memset_head, '  proof_fill_i32(head, -1, (size_t)1 << root_bits);')

    memset_count = '  memset(cand_count, 0, (size_t)total_len * sizeof(*cand_count));'
    assert memset_count in fn_body
    fn_body = fn_body.replace(memset_count, '  proof_zero_u16(cand_count, total_len);')

    loop_target = '  for (lzfse_offset pos = 0; pos < search_end; pos++) {'
    assert loop_target in fn_body
    loop_replacement = r'''  /*@ loop invariant 0 <= pos <= search_end <= total_len;
      loop invariant skip_until >= 0;
      loop invariant skip_end >= 0;
      loop invariant z->cand_len == \at(z->cand_len, Pre);
      loop invariant z->cand_dist == \at(z->cand_dist, Pre);
      loop invariant z->cand_count == \at(z->cand_count, Pre);
      loop invariant z->bt_son == \at(z->bt_son, Pre);
      loop invariant z->bt_head == \at(z->bt_head, Pre);
      loop invariant z->cand_capacity == \at(z->cand_capacity, Pre);
      loop invariant z->search_depth == \at(z->search_depth, Pre);
      loop invariant z->hash_bits == \at(z->hash_bits, Pre);
      loop invariant s->src == \at(s->src, Pre);
      loop invariant s->src_end == \at(s->src_end, Pre);
      loop invariant \separated(s, z,
                                z->cand_count + (0 .. total_len - 1),
                                z->cand_len + (0 .. total_len * cstride - 1),
                                z->cand_dist + (0 .. total_len * cstride - 1),
                                z->bt_son + (0 .. 2 * total_len + 1),
                                z->bt_head + (0 .. (1 << \at(z->hash_bits, Pre)) - 1));
      loop invariant \valid(z->cand_len + (0 .. total_len * cstride - 1));
      loop invariant \valid(z->cand_dist + (0 .. total_len * cstride - 1));
      loop invariant \valid(z->cand_count + (0 .. total_len - 1));
      loop invariant \valid(z->bt_son + (0 .. 2 * total_len + 1));
      loop invariant \valid(z->bt_head + (0 .. (1 << \at(z->hash_bits, Pre)) - 1));
      loop invariant \valid_read(s->src + (0 .. s->src_end - 1));
      loop invariant \forall integer j; 0 <= j < pos ==> z->cand_count[j] <= cstride;
      loop invariant \forall integer j; pos <= j < total_len ==> z->cand_count[j] == 0;
      loop assigns pos, skip_until, skip_end, skip_dist,
                   ml[0 .. 63], md[0 .. 63],
                   z->cand_len[0 .. total_len * cstride - 1],
                   z->cand_dist[0 .. total_len * cstride - 1],
                   z->cand_count[0 .. total_len - 1],
                   z->bt_son[0 .. 2 * total_len + 1],
                   z->bt_head[0 .. (1 << \at(z->hash_bits, Pre)) - 1];
      loop variant search_end - pos;
  */
  for (lzfse_offset pos = 0; pos < search_end; pos++) {'''
    fn_body = fn_body.replace(loop_target, loop_replacement)

    skip_target = '    if (pos < skip_until) {'
    assert skip_target in fn_body
    skip_replacement = r'''    /*@ assert lp == z->cand_len + pos * cstride; */
    /*@ assert dp == z->cand_dist + pos * cstride; */
    /*@ assert \separated(z, lp + 0, dp + 0); */
    if (pos < skip_until) {'''
    fn_body = fn_body.replace(skip_target, skip_replacement)

    call_target = '''    int n = bt_insert_find(s->src, (int32_t)pos, (uint32_t)(s->src_end - pos - 8), depth,
                           LZFSE_ENCODE_MAX_D_VALUE, ZOPT_MIN_MATCH_LEN, LZFSE_ENCODE_MAX_M_VALUE,
                           son, head + bt_hash3(s->src + pos, root_bits), ml, md, &longest, &longest_dist);'''
    assert call_target in fn_body
    call_replacement = r'''    /*@ assert \valid(lp + (0 .. cstride - 1)) && \valid(dp + (0 .. cstride - 1)); */
    /*@ assert \separated(z, lp + (0 .. cstride - 1), dp + (0 .. cstride - 1),
                          z->bt_son + (0 .. 2 * (pos + 1)), z->bt_head + (0 .. (1 << \at(z->hash_bits, Pre)) - 1)); */
    uint32_t h = bt_hash3(s->src + pos, root_bits);
    /*@ assert 0 <= h < (1 << \at(z->hash_bits, Pre)); */
    /*@ assert \subset(head + h, head + (0 .. (1 << \at(z->hash_bits, Pre)) - 1)); */
    int n = bt_insert_find(s->src, (int32_t)pos, (uint32_t)(s->src_end - pos - 8), depth,
                           LZFSE_ENCODE_MAX_D_VALUE, ZOPT_MIN_MATCH_LEN, LZFSE_ENCODE_MAX_M_VALUE,
                           son, head + h, ml, md, &longest, &longest_dist);'''
    fn_body = fn_body.replace(call_target, call_replacement)

    inner_target = '    for (int k = first; k < n; k++, cnt++) {'
    assert inner_target in fn_body
    inner_replacement = r'''    /*@ assert \subset(lp + (0 .. cstride - 1), z->cand_len + (0 .. total_len * cstride - 1)); */
    /*@ assert \subset(dp + (0 .. cstride - 1), z->cand_dist + (0 .. total_len * cstride - 1)); */
    /*@ loop invariant first <= k <= n;
        loop invariant 0 <= cnt <= cstride;
        loop invariant cnt == k - first;
        loop invariant k < n ==> cnt < cstride;
        loop invariant \valid(lp + (0 .. cstride - 1));
        loop invariant \valid(dp + (0 .. cstride - 1));
        loop assigns k, cnt, lp[0 .. cstride - 1], dp[0 .. cstride - 1];
        loop variant n - k;
    */
    for (int k = first; k < n; k++, cnt++) {'''
    fn_body = fn_body.replace(inner_target, inner_replacement)

    if mutant == 'wrong_search_end':
        fn_body = fn_body.replace('pos < search_end;', 'pos < search_end + 1;', 1)
    elif mutant == 'no_root_bits_bound':
        fn_body = fn_body.replace('const uint32_t root_bits = bt_root_bits((uint32_t)z->hash_bits, (size_t)total_len);',
                                  'const uint32_t root_bits = (uint32_t)z->hash_bits + 1;', 1)
    elif mutant == 'oob_cand_count':
        fn_body = fn_body.replace('cand_count[pos] = cnt;',
                                  'cand_count[pos + 1] = cnt;', 1)

    acsl_contract = r'''
/*@ requires \valid(s);
    requires \valid(z);
    requires 0 <= total_len <= 65536;
    requires 0 <= search_end <= total_len;
    requires 0 <= s->src_end <= 65536 + 64;
    requires search_end + 8 <= s->src_end;
    requires 1 <= cstride <= 64;
    requires cstride == z->cand_capacity;
    requires 10 <= z->hash_bits <= 20;
    requires z->search_depth >= 0;
    requires \valid(z->cand_count + (0 .. total_len - 1));
    requires \valid(z->cand_len + (0 .. total_len * cstride - 1));
    requires \valid(z->cand_dist + (0 .. total_len * cstride - 1));
    requires \valid(z->bt_son + (0 .. 2 * total_len + 1));
    requires \valid(z->bt_head + (0 .. (1 << z->hash_bits) - 1));
    requires \valid_read(s->src + (0 .. s->src_end - 1));
    requires \separated(s, z,
                        s->src + (0 .. s->src_end - 1),
                        z->cand_count + (0 .. total_len - 1),
                        z->cand_len + (0 .. total_len * cstride - 1),
                        z->cand_dist + (0 .. total_len * cstride - 1),
                        z->bt_son + (0 .. 2 * total_len + 1),
                        z->bt_head + (0 .. (1 << z->hash_bits) - 1));
    assigns z->cand_count[0 .. total_len - 1],
            z->cand_len[0 .. total_len * cstride - 1],
            z->cand_dist[0 .. total_len * cstride - 1],
            z->bt_son[0 .. 2 * total_len + 1],
            z->bt_head[0 .. (1 << \at(z->hash_bits, Pre)) - 1];
    ensures (\forall integer j; 0 <= j < total_len ==> z->cand_count[j] <= cstride);
*/
void lzfse_zopt_build_candidates(lzfse_encoder_state *s, lzfse_zopt_scratch *z,
                                 lzfse_offset search_end, size_t cstride,
                                 lzfse_offset total_len) '''
    body = acsl_contract + fn_body

    header = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define BT_MAX_MATCHES 64
#define LZFSE_ENCODE_MAX_D_VALUE 262143
#define LZFSE_ENCODE_MAX_M_VALUE 65535
#define ZOPT_MIN_MATCH_LEN 3
#define ZOPT_BT_SKIP_LEN 192
#define ZOPT_BT_SKIP_KEEP 32

typedef int64_t lzfse_offset;

typedef struct {
  const unsigned char *src;
  lzfse_offset src_end;
} lzfse_encoder_state;

typedef struct {
  int32_t search_depth;
  int32_t cand_capacity;
  int32_t hash_bits;
  int32_t *cand_len;
  int32_t *cand_dist;
  int32_t *bt_head;
  int32_t *bt_son;
  uint16_t *cand_count;
} lzfse_zopt_scratch;

/*@ axiomatic StrideBounds {
      axiom size_t_mult:
        \forall integer a, integer b;
          0 <= a <= 65536 && 0 <= b <= 64 ==>
          (size_t)a * (size_t)b == a * b;

      axiom elem_subset_range:
        \forall int32_t *base, integer i, integer n;
          0 <= i < n ==>
          \subset(base + i, base + (0 .. n - 1));

      axiom stride_range:
        \forall integer i, integer total_len, integer stride;
          0 <= i < total_len && 0 < stride ==>
          0 <= i * stride && (i + 1) * stride - 1 < total_len * stride;

      axiom cand_valid:
        \forall int32_t *base, integer i, integer cstride, integer total_len;
          0 <= i < total_len && 0 < cstride &&
          \valid(base + (0 .. total_len * cstride - 1)) ==>
          \valid(base + i * cstride + (0 .. cstride - 1));

      axiom cand_separated:
        \forall lzfse_zopt_scratch *z, int32_t *base, integer i, integer cstride, integer total_len;
          0 <= i < total_len && 0 < cstride &&
          \separated(z, base + (0 .. total_len * cstride - 1)) ==>
          \separated(z, base + i * cstride + (0 .. cstride - 1));

      axiom subslice_separated:
        \forall int32_t *a, integer i, integer stride, integer n, int32_t *b, integer m;
          0 <= i < n && 0 < stride &&
          \separated(a + (0 .. n * stride - 1), b + (0 .. m - 1)) ==>
          \separated(a + i * stride + (0 .. stride - 1), b + (0 .. m - 1));

      axiom cand_assigns:
        \forall int32_t *base, integer i, integer cstride, integer total_len;
          0 <= i < total_len && 0 < cstride ==>
          \subset(base + i * cstride + (0 .. cstride - 1),
                  base + (0 .. total_len * cstride - 1));
    }
*/

/*@ axiomatic ShiftBounds {
      axiom hash_bits_pow:
        \forall integer b; 10 <= b <= 20 ==> 1024 <= (1 << b) <= 1048576;

      axiom lsl16_bound:
        \forall integer x; 0 <= x <= 255 ==> (x << 16) <= 2147483647;
    }
*/

/*@ assigns \nothing;
    ensures 0 <= \result <= 255;
*/
uint32_t lzfse_d_symbol(uint32_t d);

/*@ requires n >= 0;
    requires \valid(p + (0 .. n - 1));
    assigns p[0 .. n - 1];
    ensures \forall integer q; 0 <= q < n ==> p[q] == 0;
*/
void proof_zero_u16(uint16_t *p, int64_t n);

/*@ requires \valid(p + (0 .. n - 1));
    assigns p[0 .. n - 1];
    ensures \forall integer q; 0 <= q < n ==> p[q] == (int32_t)-1;
*/
void proof_fill_i32(int32_t *p, int32_t v, size_t n);

/*@ requires 10 <= hash_bits <= 20;
    assigns \nothing;
    ensures 10 <= \result <= hash_bits;
    ensures (1 << \result) <= (1 << hash_bits);
*/
uint32_t bt_root_bits(uint32_t hash_bits, size_t len);

/*@ requires \valid_read(p + (0 .. 2));
    requires 0 <= bits <= 20;
    assigns \nothing;
    ensures 0 <= \result <= (1 << bits) - 1;
*/
uint32_t bt_hash3(const uint8_t *p, uint32_t bits);

/*@ requires limit >= min_len ==> \valid_read(src + (0 .. pos + limit + 7));
    requires 0 <= pos < 65536;
    requires \valid(son + (0 .. 2 * (pos + 1)));
    requires \valid(head);
    requires \valid(len + (0 .. 63));
    requires \valid(dist + (0 .. 63));
    requires \valid(longest);
    requires \valid(longest_dist);
    requires \separated(son + (0 .. 2 * (pos + 1)), head, len + (0 .. 63), dist + (0 .. 63), longest, longest_dist);
    assigns son[0 .. 2 * (pos + 1)], *head, len[0 .. 63], dist[0 .. 63], *longest, *longest_dist;
    ensures 0 <= \result <= 64;
    ensures 0 <= *longest <= 65536;
    ensures -65536 <= *longest_dist <= 262143;
*/
int bt_insert_find(const uint8_t *src, int32_t pos, uint32_t limit,
                   int32_t depth, int32_t max_dist, uint32_t min_len,
                   uint32_t cap_len, int32_t *son, int32_t *head,
                   int32_t *len, int32_t *dist, uint32_t *longest,
                   int32_t *longest_dist);
'''
    return header + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/lzfse_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzfse-zopt-build-candidates'
    output.mkdir(parents=True, exist_ok=True)
    verify('lzfse_zopt_build_candidates', generate(source), output, ['lzfse_zopt_build_candidates'], 10, split=True)

    if args.mutants:
        verify('lzfse_zopt_build_candidates_wrong_search_end',
               generate(source, mutant='wrong_search_end'),
               output, ['lzfse_zopt_build_candidates'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzfse_zopt_build_candidates_no_root_bits_bound',
               generate(source, mutant='no_root_bits_bound'),
               output, ['lzfse_zopt_build_candidates'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzfse_zopt_build_candidates_oob_cand_count',
               generate(source, mutant='oob_cand_count'),
               output, ['lzfse_zopt_build_candidates'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
