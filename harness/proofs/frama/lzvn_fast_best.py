#!/usr/bin/env python3
"""Full-block proof of the shipping fast match probe used by LZVN."""
from pathlib import Path
import argparse
import re
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source):
    start = source.index('uint32_t crushlzfse_fast_best(')
    end = source.index('// Looks for a match at ip or ip + 1', start)
    body = source[start:end]
    body = re.sub(r'#if defined\(LZFSE_PROOF\)\n.*?#endif\n', '', body,
                  flags=re.S)
    assert body.count('uint32_t crushlzfse_fast_best(') == 1
    body = body.replace('uint32_t crushlzfse_fast_best(', r'''
/*@ requires 1 <= pos <= src_end - 16;
    requires src_end <= 65536;
    requires 4 <= min_match <= 8;
    requires 10 <= hash_bits <= 16;
    requires long_table == 0 || long_table == 1;
    requires \valid_read(src + (0 .. src_end-1));
    requires \valid(table + (0 .. (1<<hash_bits)-1));
    requires \valid(ltable + (0 .. (1<<hash_bits)-1));
    requires \valid(ref);
    requires \separated(src + (0 .. src_end-1),
                        table + (0 .. (1<<hash_bits)-1),
                        ltable + (0 .. (1<<hash_bits)-1),ref);
    requires \forall integer k; 0 <= k < (1<<hash_bits) ==> table[k] < pos;
    requires \forall integer k; 0 <= k < (1<<hash_bits) ==> ltable[k] < pos;
    assigns table[0 .. (1<<hash_bits)-1],
            ltable[0 .. (1<<hash_bits)-1],*ref;
    ensures \result == 0 ||
      (4 <= \result <= src_end-pos-8 && 0 <= *ref < pos);
*/
uint32_t crushlzfse_fast_best(''', 1)
    return r'''
#include <stdint.h>
#include <stddef.h>
typedef int64_t lzfse_offset;
/*@ requires \valid_read(p + (0 .. 7)); assigns \nothing; */
uint64_t load8(const uint8_t *p);
/*@ requires \valid_read(p + (0 .. 3)); assigns \nothing; */
uint32_t load4(const uint8_t *p);
/*@ requires 4 <= min_match <= 8;
    requires 10 <= hash_bits <= 16;
    assigns \nothing;
    ensures \result < (1u << hash_bits);
*/
uint32_t crushlzfse_fast_hash(uint64_t v,int min_match,int hash_bits,
                              uint64_t prime);
/*@ requires length <= max_length;
    requires max_length <= 65536;
    requires \valid_read(a + (0 .. max_length+6));
    requires \valid_read(b + (0 .. max_length+6));
    assigns \nothing;
    ensures length <= \result <= max_length;
*/
uint32_t match_extend(const uint8_t *a,const uint8_t *b,
                      uint32_t length,uint32_t max_length);
''' + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/fast_match.h').read_text()
    output = root / 'harness/build/proofs-frama-lzvn-fast-best'
    output.mkdir(parents=True, exist_ok=True)
    verify('fast_best', generate(source), output,
           ['crushlzfse_fast_best'], 20, split=True)
    if args.mutants:
        old = 'uint32_t max_length = (uint32_t)(src_end - pos - 8);'
        assert source.count(old) == 1
        verify('fast_best_no_margin', generate(source.replace(old,
               'uint32_t max_length = (uint32_t)(src_end - pos);')),
               output, ['crushlzfse_fast_best'], 10, False,
               split=True, timeout=5, parallelism=2)


if __name__ == '__main__':
    main()
