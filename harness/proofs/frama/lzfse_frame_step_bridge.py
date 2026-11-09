#!/usr/bin/env python3
"""Check the frame's hot-loop contracts against the shipping-step proofs.

The frame carries table validity in one ghost bit. In these lemmas that bit is
interpreted as the actual literal or LMD row predicate. Establishing that
interpretation in the frame remains a separate builder-composition obligation.
"""
from pathlib import Path
import argparse
import hashlib
import re
import subprocess
import sys

sys.dont_write_bytecode = True
import lzfse_contract_bridge as bridge
import lzfse_lmd_native as lmd
from wp_common import verify


def frame_preprocess(margin):
    probe = '#include "lzfse_internal.h"\n#include "lzfse_frame_interface.h"\n'
    result = subprocess.run(
        ['gcc', '-E', '-P', '-DLZFSE_PROOF', '-DLZFSE_EXACT_FSE',
         '-DLZFSE_PROOF_FRAME_INTERFACE', '-DCRUSH_SIMD_PORTABLE',
         '-DHAVE_LABELS_AS_VALUES=0', f'-DLZFSE_DECODE_COPY_MARGIN={margin}',
         '-I', str(bridge.CSRC),
         '-I', str(bridge.ROOT / 'harness/proofs'), '-x', 'c', '-'],
        input=probe, capture_output=True, text=True, check=True)
    return re.sub(r'\s+', ' ', result.stdout)


def generate(margin, mutant=None):
    source, _ = bridge.generate(margin)
    pre = frame_preprocess(margin)
    if mutant == 'literal_only_success':
        old = '__CPROVER_ensures(__CPROVER_return_value == 0 || __CPROVER_return_value == -1)'
        start = pre.index('int lzfse_decode_literals(lzfse_decoder_state *s,')
        at = pre.index(old, start)
        pre = pre[:at] + '__CPROVER_ensures(__CPROVER_return_value == 0)' + pre[at + len(old):]
    elif mutant == 'lmd_missing_span':
        old = '__CPROVER_requires(__CPROVER_POINTER_OFFSET(s->dst_end) - __CPROVER_POINTER_OFFSET(s->dst_begin) <= (9223372036854775807L))'
        assert pre.count(old) == 1, pre.count(old)
        pre = pre.replace(old, '')
    elif mutant is not None:
        raise ValueError(mutant)

    signatures = [
        ('literal', 'int lzfse_decode_literals(lzfse_decoder_state *s, const lzfse_compressed_block_header_v1 *header1, lzfse_compressed_block_decoder_state *bs)',
         'lzfse_decoder_state *s, const lzfse_compressed_block_header_v1 *header1, lzfse_compressed_block_decoder_state *bs',
         's, header1, bs',
         'cbmc_literal_table_ok(&bs->literal_decoder[0])'),
        ('lmd', 'int lzfse_decode_lmd(lzfse_decoder_state *s)',
         'lzfse_decoder_state *s', 's',
         'tables_ok(&s->compressed_lzfse_block_state.lmd_decoder[0])'),
    ]
    names = []
    for kind, signature, params, args, table_pred in signatures:
        contract = bridge.contract(pre, signature, False)
        assert contract.count('lzfse_proof_tables_ok == 1') == 1
        contract = contract.replace('lzfse_proof_tables_ok == 1', table_pred)
        name = 'bridge_frame_' + kind
        assertions = (''.join(f'  //@ assert {clause};\n' for clause in lmd.START)
                      if kind == 'lmd' else '')
        source += (f'/*@ {contract}\n*/\nint {name}({params}) {{\n'
                   f'{assertions}  return frama_lzfse_decode_{"literals" if kind == "literal" else "lmd"}({args});\n'
                   '}\n')
        names.append(name)
    return source, names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arm', action='store_true')
    parser.add_argument('--output')
    parser.add_argument('--print', action='store_true')
    parser.add_argument('--mutants', action='store_true')
    parser.add_argument('--mutants-only', action='store_true')
    args = parser.parse_args()
    # wp_common tracks this script and the C sources. These imported contract
    # generators are also inputs to the emitted Frama translation.
    dependencies = [Path(module.__file__) for module in (bridge, lmd, bridge.LIT)]
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in dependencies}
    margin = 64 if args.arm else 32
    source, names = generate(margin)
    if args.print:
        print(source)
        return
    output = Path(args.output or bridge.ROOT / 'harness/build/proofs-frama-lzfse-frame-step')
    output.mkdir(parents=True, exist_ok=True)
    if not args.mutants_only:
        verify('frame_step_' + str(margin), source, output, names, 100, split=True,
               include_dirs=['crates/crushlzfse/csrc'], timeout=60,
               allowed_warnings=(bridge.POINTER_FROM_WARNINGS,), parallelism=2)
    if args.mutants or args.mutants_only:
        for mutant in ('literal_only_success', 'lmd_missing_span'):
            changed, names = generate(margin, mutant)
            verify(mutant, changed, output, names, 100, expected=False,
                   split=True, include_dirs=['crates/crushlzfse/csrc'],
                   timeout=30, allowed_warnings=(bridge.POINTER_FROM_WARNINGS,),
                   parallelism=2)
    assert before == {path: hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in dependencies}, 'imported contract source changed during verification'


if __name__ == '__main__':
    main()
