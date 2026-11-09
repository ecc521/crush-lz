#!/usr/bin/env python3
"""Shipping lzvn_zopt_build_candidates match candidate search proof."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source, mutant=None):
    start = source.index('{\n  const int32_t cstride = z->cand_capacity;\n  const uint32_t root_bits = bt_root_bits((uint32_t)z->hash_bits, (size_t)end_pos);')
    end = source.index('\n}\n\n// ===============================================================\n// Optimal-parse DP', start)
    fn_body = source[start:end + 2]

    memset_head = '  memset(z->bt_head, 0xFF, ((size_t)1 << root_bits) * sizeof(*z->bt_head));'
    assert memset_head in fn_body
    fn_body = fn_body.replace(memset_head, '  proof_fill_i32(z->bt_head, -1, (size_t)1 << root_bits);')

    memset_count = '  memset(z->cand_count, 0, (size_t)end_pos * sizeof(*z->cand_count));'
    assert memset_count in fn_body
    fn_body = fn_body.replace(memset_count, '  proof_zero_u16(z->cand_count, end_pos);')

    loop_target = '  for (int32_t i = 0; i < scan_end; i++) {'
    assert loop_target in fn_body
    loop_replacement = r'''  /*@ loop invariant 0 <= i <= scan_end <= end_pos;
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
      loop invariant \separated(z,
                                z->cand_count + (0 .. end_pos - 1),
                                z->cand_len + (0 .. end_pos * cstride - 1),
                                z->cand_dist + (0 .. end_pos * cstride - 1),
                                z->bt_son + (0 .. 2 * end_pos + 1),
                                z->bt_head + (0 .. (1 << \at(z->hash_bits, Pre)) - 1));
      loop invariant \valid(z->cand_len + (0 .. end_pos * cstride - 1));
      loop invariant \valid(z->cand_dist + (0 .. end_pos * cstride - 1));
      loop invariant \valid(z->cand_count + (0 .. end_pos - 1));
      loop invariant \valid(z->bt_son + (0 .. 2 * end_pos + 1));
      loop invariant \valid(z->bt_head + (0 .. (1 << \at(z->hash_bits, Pre)) - 1));
      loop invariant \valid_read(src + (0 .. src_end - 1));
      loop invariant \forall integer j; 0 <= j < i ==> z->cand_count[j] <= cstride;
      loop invariant \forall integer j; i <= j < end_pos ==> z->cand_count[j] == 0;
      loop assigns i, skip_until, skip_end, skip_dist,
                   ml[0 .. 63], md[0 .. 63],
                   z->cand_len[0 .. end_pos * cstride - 1],
                   z->cand_dist[0 .. end_pos * cstride - 1],
                   z->cand_count[0 .. end_pos - 1],
                   z->bt_son[0 .. 2 * end_pos + 1],
                   z->bt_head[0 .. (1 << \at(z->hash_bits, Pre)) - 1];
      loop variant scan_end - i;
  */
  for (int32_t i = 0; i < scan_end; i++) {'''
    fn_body = fn_body.replace(loop_target, loop_replacement)

    skip_target = '    if (i < skip_until) {'
    assert skip_target in fn_body
    skip_replacement = r'''    /*@ assert out_len == z->cand_len + i * cstride; */
    /*@ assert out_dist == z->cand_dist + i * cstride; */
    /*@ assert \separated(z, out_len + 0, out_dist + 0); */
    if (i < skip_until) {'''
    fn_body = fn_body.replace(skip_target, skip_replacement)

    call_target = '''    int n = bt_insert_find(src, i, limit, z->search_depth, LZVN_ENCODE_MAX_DISTANCE,
                           LZVN_ZOPT_MIN_MATCH_LEN, (uint32_t)real_room, z->bt_son,
                           z->bt_head + bt_hash3(src + i, root_bits), ml, md, &longest,
                           &longest_dist);'''
    assert call_target in fn_body
    call_replacement = r'''    /*@ assert \valid(out_len + (0 .. cstride - 1)) && \valid(out_dist + (0 .. cstride - 1)); */
    /*@ assert \separated(z, out_len + (0 .. cstride - 1), out_dist + (0 .. cstride - 1),
                          z->bt_son + (0 .. 2 * (i + 1)), z->bt_head + (0 .. (1 << \at(z->hash_bits, Pre)) - 1)); */
    uint32_t h = bt_hash3(src + i, root_bits);
    /*@ assert 0 <= h < (1 << \at(z->hash_bits, Pre)); */
    /*@ assert \subset(z->bt_head + h, z->bt_head + (0 .. (1 << \at(z->hash_bits, Pre)) - 1)); */
    int n = bt_insert_find(src, i, limit, z->search_depth, LZVN_ENCODE_MAX_DISTANCE,
                           LZVN_ZOPT_MIN_MATCH_LEN, (uint32_t)real_room, z->bt_son,
                           z->bt_head + h, ml, md, &longest,
                           &longest_dist);'''
    fn_body = fn_body.replace(call_target, call_replacement)

    inner_target = '    for (int k = first; k < n; k++, cnt++) {'
    assert inner_target in fn_body
    inner_replacement = r'''    /*@ assert \subset(out_len + (0 .. cstride - 1), z->cand_len + (0 .. end_pos * cstride - 1)); */
    /*@ assert \subset(out_dist + (0 .. cstride - 1), z->cand_dist + (0 .. end_pos * cstride - 1)); */
    /*@ loop invariant first <= k <= n;
        loop invariant 0 <= cnt <= cstride;
        loop invariant cnt == k - first;
        loop invariant k < n ==> cnt < cstride;
        loop invariant \valid(out_len + (0 .. cstride - 1));
        loop invariant \valid(out_dist + (0 .. cstride - 1));
        loop assigns k, cnt, out_len[0 .. cstride - 1], out_dist[0 .. cstride - 1];
        loop variant n - k;
    */
    for (int k = first; k < n; k++, cnt++) {'''
    fn_body = fn_body.replace(inner_target, inner_replacement)

    if mutant == 'wrong_scan_end':
        fn_body = fn_body.replace('int32_t scan_end = end_pos;',
                                  'int32_t scan_end = end_pos + 1;', 1)
    elif mutant == 'no_root_bits_bound':
        fn_body = fn_body.replace('const uint32_t root_bits = bt_root_bits((uint32_t)z->hash_bits, (size_t)end_pos);',
                                  'const uint32_t root_bits = (uint32_t)z->hash_bits + 1;', 1)
    elif mutant == 'oob_cand_count':
        fn_body = fn_body.replace('z->cand_count[i] = (uint16_t)cnt;',
                                  'z->cand_count[i + 1] = (uint16_t)cnt;', 1)

    acsl_contract = r'''
/*@ requires \valid(z);
    requires 0 <= end_pos <= 65536;
    requires 0 <= src_end <= 65536 + 64;
    requires (lzvn_offset)end_pos + 4 <= src_end;
    requires 1 <= z->cand_capacity <= 64;
    requires 10 <= z->hash_bits <= 20;
    requires z->search_depth >= 0;
    requires \valid(z->cand_count + (0 .. end_pos - 1));
    requires \valid(z->cand_len + (0 .. end_pos * z->cand_capacity - 1));
    requires \valid(z->cand_dist + (0 .. end_pos * z->cand_capacity - 1));
    requires \valid(z->bt_son + (0 .. 2 * end_pos + 1));
    requires \valid(z->bt_head + (0 .. (1 << z->hash_bits) - 1));
    requires \valid_read(src + (0 .. src_end - 1));
    requires \separated(z,
                        src + (0 .. src_end - 1),
                        z->cand_count + (0 .. end_pos - 1),
                        z->cand_len + (0 .. end_pos * z->cand_capacity - 1),
                        z->cand_dist + (0 .. end_pos * z->cand_capacity - 1),
                        z->bt_son + (0 .. 2 * end_pos + 1),
                        z->bt_head + (0 .. (1 << z->hash_bits) - 1));
    assigns z->cand_count[0 .. end_pos - 1],
            z->cand_len[0 .. end_pos * \at(z->cand_capacity, Pre) - 1],
            z->cand_dist[0 .. end_pos * \at(z->cand_capacity, Pre) - 1],
            z->bt_son[0 .. 2 * end_pos + 1],
            z->bt_head[0 .. (1 << \at(z->hash_bits, Pre)) - 1];
    ensures (\forall integer j; 0 <= j < end_pos ==> z->cand_count[j] <= z->cand_capacity);
*/
void lzvn_zopt_build_candidates(lzvn_zopt_scratch *z,
                                const unsigned char *src,
                                lzvn_offset src_end, int32_t end_pos) '''
    body = acsl_contract + fn_body

    header = r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define BT_MAX_MATCHES 64
#define LZVN_ENCODE_MAX_DISTANCE 65535
#define LZVN_ZOPT_MIN_MATCH_LEN 3
#define LZVN_ZOPT_MATCH_EXTEND_MARGIN 8
#define LZVN_ZOPT_BT_SKIP_LEN 192
#define LZVN_ZOPT_BT_SKIP_KEEP 32

typedef int64_t lzvn_offset;

typedef struct {
  int32_t search_depth;
  int32_t cand_capacity;
  int32_t max_tuples;
  int32_t hash_bits;
  int32_t *cand_len;
  int32_t *cand_dist;
  int32_t *bt_head;
  int32_t *bt_son;
  uint16_t *cand_count;
} lzvn_zopt_scratch;

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
        \forall integer i, integer end_pos, integer stride;
          0 <= i < end_pos && 0 < stride ==>
          0 <= i * stride && (i + 1) * stride - 1 < end_pos * stride;

      axiom cand_valid:
        \forall int32_t *base, integer i, integer cstride, integer end_pos;
          0 <= i < end_pos && 0 < cstride &&
          \valid(base + (0 .. end_pos * cstride - 1)) ==>
          \valid(base + i * cstride + (0 .. cstride - 1));

      axiom cand_separated:
        \forall lzvn_zopt_scratch *z, int32_t *base, integer i, integer cstride, integer end_pos;
          0 <= i < end_pos && 0 < cstride &&
          \separated(z, base + (0 .. end_pos * cstride - 1)) ==>
          \separated(z, base + i * cstride + (0 .. cstride - 1));

      axiom subslice_separated:
        \forall int32_t *a, integer i, integer stride, integer n, int32_t *b, integer m;
          0 <= i < n && 0 < stride &&
          \separated(a + (0 .. n * stride - 1), b + (0 .. m - 1)) ==>
          \separated(a + i * stride + (0 .. stride - 1), b + (0 .. m - 1));

      axiom cand_assigns:
        \forall int32_t *base, integer i, integer cstride, integer end_pos;
          0 <= i < end_pos && 0 < cstride ==>
          \subset(base + i * cstride + (0 .. cstride - 1),
                  base + (0 .. end_pos * cstride - 1));
    }
*/

/*@ axiomatic ShiftBounds {
      axiom hash_bits_pow:
        \forall integer b; 10 <= b <= 20 ==> 1024 <= (1 << b) <= 1048576;
    }
*/

/*@ requires n >= 0;
    requires \valid(p + (0 .. n - 1));
    assigns p[0 .. n - 1];
    ensures \forall integer q; 0 <= q < n ==> p[q] == 0;
*/
void proof_zero_u16(uint16_t *p, int32_t n);

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
    ensures -65536 <= *longest_dist <= 65536;
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
    source = (root / 'crates/crushlzfse/csrc/lzvn_encode_base.c').read_text()
    output = root / 'harness/build/proofs-frama-lzvn-zopt-build-candidates'
    output.mkdir(parents=True, exist_ok=True)
    verify('lzvn_zopt_build_candidates', generate(source), output, ['lzvn_zopt_build_candidates'], 10, split=True, timeout=60)

    if args.mutants:
        verify('lzvn_zopt_build_candidates_wrong_scan_end',
               generate(source, mutant='wrong_scan_end'),
               output, ['lzvn_zopt_build_candidates'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzvn_zopt_build_candidates_no_root_bits_bound',
               generate(source, mutant='no_root_bits_bound'),
               output, ['lzvn_zopt_build_candidates'], 10, False,
               split=False, timeout=5, parallelism=2)

        verify('lzvn_zopt_build_candidates_oob_cand_count',
               generate(source, mutant='oob_cand_count'),
               output, ['lzvn_zopt_build_candidates'], 10, False,
               split=False, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
