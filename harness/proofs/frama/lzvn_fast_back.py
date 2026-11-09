#!/usr/bin/env python3
"""Full-domain safety and termination of the shipping fast-match backscan."""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source):
    marker = '  while (mpos > anchor'
    assert source.count(marker) == 1
    start = source.index(marker)
    end = source.index('\n  *mpos_out = mpos;', start)
    scan = source[start:end]
    return r'''
#include <stdint.h>
#include <stddef.h>
typedef int64_t lzfse_offset;
/*@ requires 0 <= anchor <= mpos <= src_end - 8;
    requires 0 <= mref < mpos;
    requires src_end <= 65536;
    requires len <= src_end - mpos - 8;
    requires \valid_read(src + (0 .. src_end - 1));
    assigns \nothing;
    ensures \old(len) <= \result <= src_end - anchor - 8;
*/
uint32_t fast_backscan(const uint8_t *src, lzfse_offset src_end,
                       lzfse_offset anchor, lzfse_offset mpos,
                       lzfse_offset mref, uint32_t len) {
  const lzfse_offset start_pos = mpos;
  const lzfse_offset start_ref = mref;
  const uint32_t start_len = len;
  /*@ loop invariant anchor <= mpos <= start_pos;
      loop invariant 0 <= mref < mpos;
      loop invariant mpos - mref == start_pos - start_ref;
      loop invariant len + mpos == start_len + start_pos;
      loop invariant len <= src_end - mpos - 8;
      loop assigns mpos,mref,len;
      loop variant mpos - anchor;
  */
''' + scan + r'''
  return len;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root / 'crates/crushlzfse/csrc/fast_match.h').read_text()
    output = root / 'harness/build/proofs-frama-lzvn-fast-back'
    output.mkdir(parents=True, exist_ok=True)
    verify('fast_backscan', generate(source), output, ['fast_backscan'], 10, split=True)
    if args.mutants:
        old = 'mpos > anchor && mref > 0'
        assert source.count(old) == 1
        verify('fast_backscan_no_ref_guard', generate(source.replace(old, 'mpos > anchor')),
               output, ['fast_backscan'], 10, False, split=True)


if __name__ == '__main__':
    main()
