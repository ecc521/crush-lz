#!/usr/bin/env python3
"""Check the shipping LZVN greedy loop's control edge and a no-progress mutant.

The full loop is verified by frama/lzvn_greedy_loop.py. This focused CBMC
lemma extracts its actual for-loop update and checks one normal iteration;
the early-return path has no obligation to advance.
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/crushlzfse/csrc/lzvn_encode_base.c'
OUTPUT = ROOT / 'harness/build/proofs-lzvn-greedy-progress'


def cbmc_command(*args):
    return ['docker', 'run', '--rm', '--memory', '8g', '--cpus', '4',
            '-v', f'{ROOT}:/work', '-w', '/work',
            '--entrypoint', 'cbmc', 'crushlz-proofs:6.11.0', *args]


def loop_update(source):
    start = source.index('LZFSE_INLINE void lzvn_encode_greedy_wide_hw(')
    end = source.index('// One wrapper per level-table width', start)
    body = source[start:end]
    matches = re.findall(
        r'for \(; state->src_current < state->src_current_end; '
        r'(state->src_current(?:\+\+| \+= 0))\)', body)
    assert len(matches) == 1, 'shipping greedy loop header changed'
    return matches[0]


def proof_source(update):
    return '''#include <stdint.h>
#include <assert.h>
typedef struct { int64_t src_current, src_current_end; } proof_cursor;
int64_t nondet_offset(void);
void harness(void) {
  proof_cursor s;
  proof_cursor *state = &s;
  s.src_current = nondet_offset();
  s.src_current_end = nondet_offset();
  __CPROVER_assume(0 <= s.src_current && s.src_current < s.src_current_end &&
                   s.src_current_end <= UINT32_MAX);
  int64_t before = s.src_current;
  ''' + update + ''';
  assert(s.src_current == before + 1);
  assert(s.src_current <= s.src_current_end);
}
'''


def run(name, update, expected):
    OUTPUT.mkdir(parents=True, exist_ok=True)
    path = OUTPUT / (name + '.c')
    path.write_text(proof_source(update))
    args = ['--bounds-check', '--pointer-check', '--signed-overflow-check',
            '--unsigned-overflow-check', '--unwinding-assertions',
            '--function', 'harness',
            str(path.relative_to(ROOT))]
    result = subprocess.run(
        cbmc_command(*args),
        cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log = OUTPUT / (name + '.log')
    log.write_text(result.stdout)
    success = 'VERIFICATION SUCCESSFUL' in result.stdout
    failed = 'VERIFICATION FAILED' in result.stdout
    assert (success if expected else failed), result.stdout
    if not expected:
        assert 'assertion s.src_current == before + 1: FAILURE' in result.stdout, result.stdout
    evidence = dict(name=name, source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
                    proof_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    cbmc_version=subprocess.check_output(cbmc_command('--version'), text=True).strip(),
                    command=cbmc_command(*args),
                    exit_code=result.returncode, success=success, failed=failed,
                    log_sha256=hashlib.sha256(log.read_bytes()).hexdigest())
    (OUTPUT / (name + '.evidence.json')).write_text(json.dumps(evidence, indent=2) + '\n')
    print(f'{name}: {"proved" if expected else "counterexample caught"}')


def main():
    source = SOURCE.read_text()
    update = loop_update(source)
    assert update == 'state->src_current++', 'shipping progress update changed'
    run('greedy_progress', update, True)
    run('greedy_missing_progress', 'state->src_current += 0', False)
    assert SOURCE.read_text() == source, 'source changed during verification'


if __name__ == '__main__':
    main()
