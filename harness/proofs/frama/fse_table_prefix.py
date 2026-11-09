#!/usr/bin/env python3
"""Prove exact prefix bookkeeping for both shipping FSE table sum loops.

The prefix array is analysis-only. The extracted sum statement and loop bound
are those used by fse_init_decoder_table; a later row proof may consume this
relation instead of CBMC's unsupported quantified loop invariant.
"""
from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode = True
from wp_common import verify


def generate(source, builder, mutant=False):
    start = source.index('int ' + builder + '(')
    end = source.index('  if (sum_of_freq > nstates)', start)
    body = source[start:end]
    loop = 'for (int i = 0; i < nsymbols; i++)'
    update = 'sum_of_freq += freq[i];'
    assert body.count(loop) == 1
    assert body.count(update) == 1
    statement = update if not mutant else 'sum_of_freq += freq[i] + 1;'
    return r'''
#include <stdint.h>
/*@ requires 0 <= nsymbols <= 256;
    requires \valid_read(freq + (0 .. nsymbols-1));
    requires \valid(prefix + (0 .. nsymbols));
    requires \separated(freq + (0 .. nsymbols-1), prefix + (0 .. nsymbols));
    assigns prefix[0 .. nsymbols] \from nsymbols, freq[0 .. nsymbols-1];
    ensures prefix[0] == 0;
    ensures prefix[nsymbols] == \result;
    ensures 0 <= \result <= nsymbols * 65535;
    ensures \forall integer k; 0 <= k < nsymbols ==>
        prefix[k+1] == prefix[k] + freq[k];
*/
int proof_fse_table_prefix(int nsymbols, const uint16_t *freq, int *prefix)
{
    int sum_of_freq = 0;
    prefix[0] = 0;
    /*@ loop invariant 0 <= i <= nsymbols;
        loop invariant 0 <= sum_of_freq <= i * 65535;
        loop invariant sum_of_freq == prefix[i];
        loop invariant prefix[0] == 0;
        loop invariant \forall integer k; 0 <= k < i ==>
            prefix[k+1] == prefix[k] + freq[k];
        loop assigns i, sum_of_freq, prefix[1 .. nsymbols];
        loop variant nsymbols-i;
    */
    ''' + loop + r'''
    {
        ''' + statement + r'''
        prefix[i+1] = sum_of_freq;
    }
    return sum_of_freq;
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    source = (root/'crates/crushlzfse/csrc/lzfse_fse.c').read_text()
    output = root/'harness/build/proofs-frama-fse-table-prefix'
    output.mkdir(parents=True, exist_ok=True)
    verify('literal_prefix', generate(source, 'fse_init_decoder_table'), output,
           ['proof_fse_table_prefix'], 20, split=True)
    verify('value_prefix', generate(source, 'fse_init_value_decoder_table'), output,
           ['proof_fse_table_prefix'], 20, split=True)
    if args.mutants:
        verify('literal_wrong_sum', generate(source, 'fse_init_decoder_table', mutant=True), output,
               ['proof_fse_table_prefix'], 20, expected=False, split=True)
        verify('value_wrong_sum', generate(source, 'fse_init_value_decoder_table', mutant=True), output,
               ['proof_fse_table_prefix'], 20, expected=False, split=True)


if __name__ == '__main__':
    main()
