"""Strict result checks shared by the encoder WP targets."""
import re
import os
import subprocess
import hashlib
import json
from pathlib import Path
import sys


REPORTING_TOOLS=('inventory.py','replay.py')


def tree_hash(root=None):
    """Hash of the proof-relevant tree: codec C sources and proof programs.

    Covers crates/*/csrc and the .c/.h/.py/.sh/Dockerfile files under
    harness/proofs, except the reporting tools, so documentation, recorded
    results and the registry do not change it. replay.py records this value.
    """
    root=Path(root) if root else Path(__file__).resolve().parents[3]
    paths=[p for p in root.glob('crates/*/csrc/**/*') if p.is_file() and not p.name.startswith('.')]
    paths+=[p for p in (root/'harness/proofs').rglob('*') if p.is_file() and
            '__pycache__' not in p.parts and p.name not in REPORTING_TOOLS and
            (p.suffix in ('.c','.h','.py','.sh') or p.name=='Dockerfile')]
    digest=hashlib.sha256()
    for p in sorted(set(paths)):
        digest.update(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root)}\n'.encode())
    return digest.hexdigest()


def unproved_goals(text):
    """Map each unproved goal to its prover verdicts, e.g. ['Timeout', 'Unknown'].

    WP prints `[wp] [<prover or status>] Goal NAME` and, when the goal is
    proved, ` : Valid`; the bracket names a prover (Qed, Alt-Ergo 2.4.2, ...)
    or a status (Failed), so only the suffix decides. The per-prover verdicts
    of an unproved goal follow on indented lines. replay.py uses this too.
    """
    goals={}
    current=None
    for line in text.splitlines():
        m=re.match(r'\[wp\] \[([^\]]+)\] Goal (\S+)(?: : (\w+))?',line)
        if m:
            current=None
            if m.group(3)!='Valid':
                current=m.group(2)
                goals[current]=[] if m.group(3) is None else [m.group(3)]
            continue
        m=re.match(r'\s+\S.*?: (Timeout|Unknown|Failed|Invalid|Valid|Stepout)\b',line)
        if m and current:
            goals[current].append(m.group(1))
        elif not line.startswith(' '):
            current=None
    return goals


def source_manifest():
    root=Path(__file__).resolve().parents[3]
    paths=list(root.glob('crates/*/csrc/**/*.c'))+list(root.glob('crates/*/csrc/**/*.h'))
    paths.extend((Path(__file__).resolve(),Path(sys.argv[0]).resolve()))
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths)) if p.is_file() and p.is_relative_to(root)}


def verify(name, generated, output, functions, minimum, expected=True, *, split=False,
           include_dirs=(), timeout=30, allowed_warnings=(), parallelism=None):
    if parallelism is None:
        parallelism = int(os.environ.get('PROOF_JOBS', 4))
    # Re-examining mutants: WP_ONLY=name,... runs just those verify calls,
    # and WP_MUTANT_TIMEOUT raises the per-goal timeout of mutant runs.
    only=os.environ.get('WP_ONLY')
    if only and name not in only.split(','):
        print(f'{name}: skipped (WP_ONLY)', flush=True)
        return
    if not expected and os.environ.get('WP_MUTANT_TIMEOUT'):
        timeout=int(os.environ['WP_MUTANT_TIMEOUT'])
    path = output / (name + '.c')
    path.write_text(generated)
    before=source_manifest()
    command = ['frama-c', '-machdep', 'gcc_x86_64',
               '-cpp-extra-args=-DCRUSH_SIMD_PORTABLE -Icrates/lzbitmap/csrc' +
               ''.join(' -I' + path for path in include_dirs),
               '-wp', '-wp-rte', '-wp-fct', ','.join(functions),
               '-wp-prover', 'qed,cvc4,z3', '-wp-timeout', str(timeout), '-wp-par', str(parallelism),
               str(path)]
    if split:
        command.insert(1, '-wp-split')
    # Keep solver progress observable while a large composition is running.
    # The complete log is still checked only after the process terminates.
    log = output / (name + '.log')
    with log.open('w') as stream:
        result = subprocess.run(command, stdout=stream,
                                stderr=subprocess.STDOUT, text=True)
    output_text = log.read_text()
    counts = re.findall(r'Proved goals:\s*(\d+)\s*/\s*(\d+)', output_text)
    after=source_manifest()
    unproved=unproved_goals(output_text)
    # A mutant counts as rejected by a non-timeout goal only when some
    # unproved goal got no Timeout verdict from any prover.
    non_timeout=sorted(g for g,v in unproved.items() if v and 'Timeout' not in v)
    metadata=dict(command=command,
                  frama_version=subprocess.check_output(['frama-c','-version'],text=True).strip(),
                  script=Path(sys.argv[0]).name,name=name,
                  tree_sha256=tree_hash(),wp_timeout=timeout,
                  expected_success=expected,minimum_goals=minimum,
                  exit_code=result.returncode,goal_counts=counts,
                  unproved_goals=unproved,non_timeout_unproved=non_timeout,
                  generated_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
                  sources_before=before,sources_after=after)
    (output/(name+'.evidence.json')).write_text(json.dumps(metadata,indent=2)+'\n')
    ledger=os.environ.get('WP_EVIDENCE_LEDGER')
    if ledger:
        summary={k:metadata[k] for k in ('script','name','tree_sha256','wp_timeout',
                 'expected_success','exit_code','goal_counts','non_timeout_unproved')}
        summary['unproved']=len(unproved)
        summary['evidence']=str(output/(name+'.evidence.json'))
        with open(ledger,'a') as stream:
            stream.write(json.dumps(summary)+'\n')
    assert before==after,'source files changed during verification; replay an immutable snapshot'
    assert result.returncode == 0 and len(counts) == 1, output_text
    done, total = map(int, counts[0])
    assert total >= minimum, 'proof obligations unexpectedly disappeared'
    permitted = ("Warning: \n  No \\from specification for assigned pointer 'state->dest'.\n"
                 '  Callers assumptions might be imprecise.')
    checked_output = output_text.replace(permitted, '')
    for pattern in allowed_warnings:
        checked_output = re.sub(pattern, '', checked_output)
    assert 'Warning:' not in checked_output, output_text
    if expected:
        assert done == total, output_text
    else:
        assert done < total and '[Failed] Goal' in output_text, output_text
    kind = ('proved' if expected else
            'mutant rejected' + ('' if non_timeout else ' (timeouts only)'))
    print(f'{name}: {done}/{total} obligations; {kind}', flush=True)


def witness(output, text, native=False):
    path = output / 'witness.c'
    path.write_text(text)
    binary = output / ('witness-native' if native else 'witness')
    flags = [] if native else ['-DCRUSH_SIMD_PORTABLE']
    subprocess.run(['gcc', '-std=c11', '-O0', '-g0'] + flags + [
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-Icrates/lzbitmap/csrc', str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


SPAN = r'''\separated(&state->dest, &state->dest_end, &state->written, &state->bmp_cnt,
        state->bitmaps + (0 .. ZBM_MAX_BITMAP_COUNT - 1),
        state->periods + (0 .. ZBM_MAX_BITMAP_COUNT - 1),
        state->bmap_num_tbl + (0 .. ZBM_POSSIBLE_BMPROTS - 1),
        state->bmap_nums + (0 .. ZBM_MAX_BITMAP_COUNT + 15),
        state->dest + (0 .. state->dest_end - state->dest - 1))'''


DOMAIN = r'''(\separated(state, state->dest + (0 .. state->dest_end - state->dest - 1)) ||
    (\base_addr(state->dest) == \base_addr(&state->meta_scratch[0]) &&
     0 <= state->dest - &state->meta_scratch[0] <= ZBM_META_SCRATCH_SIZE &&
     0 <= state->dest_end - state->dest <= ZBM_META_SCRATCH_SIZE - (state->dest - &state->meta_scratch[0])))'''


def protect_span(generated, source, header=False, span=SPAN):
    """Cover external output and bounded internal metadata scratch.

    In particular, internal meta_scratch output is allowed. Prove that the
    shipping trial initialization establishes this precondition.
    """
    if header:
        previous = r'\separated(state, hdr, state->dest + (0 .. state->dest_end - state->dest - 1))'
        replacement = (span + ';\n    requires ' + r'\separated(state, hdr)' +
                       ';\n    requires ' + r'\separated(hdr, state->dest + (0 .. state->dest_end - state->dest - 1))')
    else:
        previous = r'\separated(state, state->dest + (0 .. state->dest_end - state->dest - 1))'
        replacement = span
    assert generated.count(previous) == 1
    generated = generated.replace(previous, DOMAIN + ';\n    requires ' + replacement)
    initialization = '''    state->dest = state->meta_scratch;
    state->dest_end = state->meta_scratch + ZBM_META_SCRATCH_SIZE;
    state->written = 0;'''
    assert source.count(initialization) == 1, 'trial initialization changed'
    return generated + r'''
/*@ requires \valid(state);
    assigns state->dest, state->dest_end, state->written \from state;
    ensures \valid(state->dest);
    ensures \base_addr(state->dest) == \base_addr(state->dest_end);
    ensures state->dest_end - state->dest == ZBM_META_SCRATCH_SIZE;
    ensures state->written == 0;
    ensures ''' + span + r''';
    ensures ''' + DOMAIN + r''';
*/
static void proof_trial_destination(struct zbm_compress_state *state)
{
''' + initialization + '\n}\n'
