#!/usr/bin/env python3
"""Replay every proof on one checkpoint and record the results.

  replay.py run [--work DIR] [--budget GIB] [--only cbmc,mutants,frama,checks] [NAME...]
  replay.py collect [--work DIR] --out harness/proofs/results-DATE.json

`run` starts each CBMC target, CBMC mutant and Frama-C script in its own
Docker container with a memory cap, keeping the sum of the caps under the
budget. Containers are named REPLAY_CONTAINER_PREFIX (default p0-) plus the
job, so concurrent replays from different worktrees need distinct prefixes.
The `checks` jobs are the native-SIMD checks of simd/README.md: the
intrinsic inventory and BMI2 clone check (host clang) and the CBMC
wrapper equivalence (proof image). A CBMC target or mutant killed at its cap is
retried at the next size in
MEMORY_LADDER. `collect` classifies the logs (pass, fail, timeout, oom,
error), counts properties, goals and reachability witnesses, and records
the git commit, the proof tree hash and tool versions.
"""
import argparse
import concurrent.futures
import datetime
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'harness/proofs/frama'))
sys.path.insert(0, str(ROOT / 'harness/proofs'))
from wp_common import tree_hash, unproved_goals  # noqa: E402
from inventory import inventory  # noqa: E402

CBMC_IMAGE = 'crushlz-proofs:6.11.0'
FRAMA_IMAGE = 'crushlz-frama-period:bookworm'
DEFAULT_GIB = 6
MEMORY_LADDER = (6, 16, 32, 48)
# Starting caps for targets known to need more than the default.
CBMC_GIB = {
    'lzvn_decode_threaded': 48, 'lzvn_encode_greedy_wide': 48,
    'lzvn_encode_greedy_wide_native': 48, 'lzfse_decode_frame': 16,
    'lz4_decode_block': 16, 'fse_literal_table_valid': 16,
    'fse_literal_table_preserve': 16, 'fse_literal_table_preserve_frame': 16,
    'zbm_handle_compressed_chunk': 14, 'zbm_handle_compressed_chunk_neon': 14,
    'zbm_handle_compressed_chunk_sse': 14,
}
FRAMA_GIB = 8
# Frama-C configurations beyond each script's default (with --mutants when
# the script accepts it).
FRAMA_EXTRA = {
    'lzfse_literals_native.py#arm': ['--arm', '--output', '{work}/frama-lzfse-literals-arm'],
    'lzfse_lmd_native.py#arm': ['--arm', '--output', '{work}/frama-lzfse-lmd-arm'],
    'lzfse_contract_bridge.py#arm': ['--arm', '--output', '{work}/frama-lzfse-bridge-arm'],
}
CBMC_TIMEOUT_MIN = 90
PREFIX = __import__('os').environ.get('REPLAY_CONTAINER_PREFIX', 'p0-')
# The CBMC image runs as linux/arm64, where goto-cc's plain char is unsigned;
# shipping targets (Apple arm64, x86-64) use signed char.
CHAR_SIGNEDNESS = (
    'CBMC: run.sh compiles every target with -fsigned-char, matching the '
    'shipping targets (goto-cc on linux/arm64 otherwise treats plain char as '
    'unsigned). Frama-C uses -machdep gcc_x86_64 (signed char).')
CHECKS = {
    'check_intrinsics': dict(host=['python3', 'harness/proofs/simd/check_intrinsics.py']),
    'check_bmi2_clone': dict(host=['python3', 'harness/proofs/simd/check_bmi2_clone.py']),
    'run_equiv': dict(image=['harness/proofs/simd/run_equiv.sh'], gib=6),
}
FRAMA_TIMEOUT_S = 8 * 3600


def host(command):
    start = time.time()
    out = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return dict(rc=out.returncode, output=out.stdout + out.stderr, oom_killed=False,
                memory_gib=0, wall_seconds=round(time.time() - start, 1))


def mutant_names():
    text = (ROOT / 'harness/proofs/run.sh').read_text()
    block = text[text.index("MUTANTS='") + 9:]
    block = block[:block.index("\n'")]
    return [line.split('|', 3) for line in block.strip().splitlines()]


def frama_jobs():
    jobs = []
    for script in sorted((ROOT / 'harness/proofs/frama').glob('*.py')):
        if script.name == 'wp_common.py':
            continue
        args = ['--mutants'] if "'--mutants'" in script.read_text() else []
        jobs.append((script.name, script.name, args))
    for key, args in FRAMA_EXTRA.items():
        jobs.append((key, key.split('#')[0], args))
    return jobs


class Budget:
    def __init__(self, gib):
        self.free = gib
        self.cond = threading.Condition()

    def take(self, gib):
        with self.cond:
            while self.free < gib:
                self.cond.wait()
            self.free -= gib

    def give(self, gib):
        with self.cond:
            self.free += gib
            self.cond.notify_all()


def docker(name, image, gib, command, env, timeout=None, entrypoint=None):
    cmd = ['docker', 'run', '--name', name, f'--memory={gib}g', f'--memory-swap={gib}g',
           '-v', f'{ROOT}:/work', '-w', '/work']
    for key, value in env.items():
        cmd += ['-e', f'{key}={value}']
    if entrypoint:
        cmd += ['--entrypoint', entrypoint]
    cmd += [image] + command
    subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    start = time.time()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        rc, text = out.returncode, out.stdout + out.stderr
    except subprocess.TimeoutExpired as e:
        subprocess.run(['docker', 'kill', name], capture_output=True)
        rc, text = 124, ''

    inspect = subprocess.run(['docker', 'inspect', '-f', '{{.State.OOMKilled}}', name],
                             capture_output=True, text=True)
    subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    return dict(rc=rc, output=text, oom_killed=inspect.stdout.strip() == 'true',
                memory_gib=gib, wall_seconds=round(time.time() - start, 1))


def run(args):
    work = Path(args.work)
    (ROOT / work / '_driver').mkdir(parents=True, exist_ok=True)
    only = set(args.only.split(','))
    budget = Budget(args.budget)
    targets = [t['name'] for t in inventory(ROOT, with_results=False)['targets']]
    jobs = []
    if 'cbmc' in only:
        jobs += [('proof', n, CBMC_GIB.get(n, DEFAULT_GIB)) for n in targets]
    if 'mutants' in only:
        jobs += [('mutant', m[0], CBMC_GIB.get(m[1], DEFAULT_GIB)) for m in mutant_names()]
    if 'frama' in only:
        jobs += [('frama', key, FRAMA_GIB) for key, _, _ in frama_jobs()]
    if 'checks' in only:
        jobs += [('check', key, c.get('gib', 0)) for key, c in CHECKS.items()]
    if args.names:
        jobs = [j for j in jobs if j[1] in args.names]
    jobs = [j for j in jobs if j[1] not in args.exclude.split(',')]
    if args.gib:
        jobs = [(k, n, args.gib) for k, n, _ in jobs]
    jobs.sort(key=lambda j: -j[2])
    frama = {key: (script, extra) for key, script, extra in frama_jobs()}
    env = {'PROOF_WORK': f'/work/{work}', 'PROOF_TIMEOUT': str(args.cbmc_timeout)}
    lock = threading.Lock()

    def record(kind, name, result):
        path = ROOT / work / '_driver' / f'{kind}.{name.replace("#", ".")}.json'
        path.write_text(json.dumps(result, indent=2) + '\n')
        with lock:
            print(f'{kind:6} {name:45} rc={result["rc"]:<4} oom={result["oom_killed"]!s:5} '
                  f'{result["memory_gib"]:>2}GiB {result["wall_seconds"]:>8}s', flush=True)

    def one(job):
        kind, name, gib = job
        container = PREFIX + re.sub(r'[^a-zA-Z0-9_.-]', '_', f'{kind}-{name}')
        while True:
            gib = min(gib, args.budget)
            budget.take(gib)
            try:
                if kind == 'check':
                    c = CHECKS[name]
                    result = (host(c['host']) if 'host' in c else
                              docker(container, CBMC_IMAGE, gib, [],
                                     {'PROOF_WORK': f'/work/{work}/simd'},
                                     timeout=3600, entrypoint=c['image'][0]))
                elif kind == 'frama':
                    script, extra = frama[name]
                    result = docker(container, FRAMA_IMAGE, gib,
                                    [f'harness/proofs/frama/{script}'] +
                                    [a.format(work=work) for a in extra],
                                    {'WP_EVIDENCE_LEDGER': f'/work/{work}/frama-ledger.jsonl'},
                                    timeout=FRAMA_TIMEOUT_S, entrypoint='python3')
                else:
                    result = docker(container, CBMC_IMAGE, gib,
                                    ['sh', 'harness/proofs/run.sh', kind, name], env)
            finally:
                budget.give(gib)
            killed = result['oom_killed'] or any(
                p.read_text().strip() == '137' for p in (ROOT / work).glob(
                    (f'mutant_{name}/*.exit' if kind == 'mutant' else f'{name}.*exit')))
            result['memory_killed'] = killed
            record(kind, name, result)
            if kind == 'check':
                (ROOT / work / '_driver' / f'check.{name}.log').write_text(result['output'])
            bigger = [g for g in MEMORY_LADDER if g > gib and g <= args.budget]
            if kind not in ('proof', 'mutant') or not killed or not bigger:
                return
            gib = bigger[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        list(pool.map(one, jobs))


def mutant_rejection(goals):
    verdicts = [v for vs in goals.values() for v in vs]
    if 'Invalid' in verdicts:
        return 'invalid'
    if any(v in ('Unknown', 'Failed') for v in verdicts):
        return 'prover unknown'
    return 'timeout only'


def cbmc_status(log, exit_file):
    if not log.exists():
        return 'not run', None, None
    text = log.read_text(errors='replace')
    rc = exit_file.read_text().strip() if exit_file.exists() else ''
    m = re.findall(r'^\*\* (\d+) of (\d+) failed', text, re.M)
    failed, total = map(int, m[-1]) if m else (None, None)
    if '\nVERIFICATION SUCCESSFUL' in text:
        return 'pass', total, failed
    if '\nVERIFICATION FAILED' in text:
        return 'fail', total, failed
    if rc == '124':
        return 'timeout', total, failed
    if rc == '137' or 'Killed' in text[-200:]:
        return 'oom', total, failed
    return 'error', total, failed


def collect(args):
    work = ROOT / args.work
    inv = inventory(ROOT, with_results=False)
    proofs = []
    for t in inv['targets']:
        name = t['name']
        status, total, failed = cbmc_status(work / f'{name}.log', work / f'{name}.exit')
        entry = dict(name=name, status=status, properties=total, failed=failed,
                     log=f'{args.work}/{name}.log')
        driver = work / '_driver' / f'proof.{name}.json'
        if driver.exists():
            d = json.loads(driver.read_text())
            entry.update(memory_gib=d['memory_gib'], wall_seconds=d['wall_seconds'])
        if status == 'pass':
            r_status, r_total, r_failed = cbmc_status(work / f'{name}.reach.log',
                                                      work / f'{name}.reach.exit')
            reach = (work / f'{name}.reach.log')
            text = reach.read_text(errors='replace') if reach.exists() else ''
            witnessed = len(re.findall(r'reachable: .*: FAILURE$', text, re.M))
            unwitnessed = len(re.findall(r'reachable: .*: SUCCESS$', text, re.M))
            entry.update(reachability_goals=witnessed + unwitnessed,
                         reachability_witnessed=witnessed)
            if r_status not in ('fail',) or unwitnessed or not witnessed:
                entry['status'] = 'reachability-incomplete'
            if (work / f'{name}.configuration.txt').exists():
                entry['configuration'] = (work / f'{name}.configuration.txt').read_text().splitlines()
            goto = work / f'{name}.goto'
            if goto.exists():
                entry['goto_sha256'] = subprocess.run(['shasum', '-a', '256', str(goto)],
                                                      capture_output=True, text=True).stdout.split()[0]
        if status == 'fail':
            text = (work / f'{name}.log').read_text(errors='replace')
            entry['failed_properties'] = re.findall(r'^\[(\S+)\] (.*): FAILURE$', text, re.M)[:20]
        proofs.append(entry)
    mutants = []
    for name, proof, _, _ in mutant_names():
        log = work / f'mutant_{name}' / f'{proof}.log'
        status, total, failed = cbmc_status(log, work / f'mutant_{name}' / f'{proof}.exit')
        entry = dict(name=name, proof=proof,
                     status={'fail': 'caught', 'pass': 'survived'}.get(status, status))
        if status == 'fail':
            text = log.read_text(errors='replace')
            v = re.search(r'^Violated property:\n.*\n\s*(.*)', text, re.M)
            entry['violated'] = v.group(1).strip() if v else None
        mutants.append(entry)
    frama = []
    ledger = work / 'frama-ledger.jsonl'
    rows = [json.loads(l) for l in ledger.read_text().splitlines()] if ledger.exists() else []
    extra_outputs = [a[a.index('--output') + 1].format(work=args.work)
                     for a in FRAMA_EXTRA.values() if '--output' in a]
    for key, script, extra in frama_jobs():
        driver = work / '_driver' / f'frama.{key.replace("#", ".")}.json'
        d = json.loads(driver.read_text()) if driver.exists() else None
        out = extra[extra.index('--output') + 1].format(work=args.work) if '--output' in extra else None
        own = [r for r in rows if r['script'] == script and
               (r['evidence'].startswith(out) if out else
                not any(r['evidence'].startswith(o) for o in extra_outputs))]
        runs = []
        for r in own:
            done, total = map(int, r['goal_counts'][0]) if r['goal_counts'] else (None, None)
            ok = (done == total) if r['expected_success'] else (done is not None and done < total)
            log = ROOT / r['evidence'].replace('/work/', '', 1).replace('.evidence.json', '.log')
            goals = unproved_goals(log.read_text()) if log.exists() else {}
            runs.append(dict(name=r['name'], expected=r['expected_success'], proved=done, goals=total,
                             ok=ok, tree_sha256=r['tree_sha256'], wp_timeout=r['wp_timeout'],
                             **({} if r['expected_success'] else
                                {'rejected_by': mutant_rejection(goals),
                                 'unproved_goals': len(goals)})))
        status = ('missing' if d is None else 'timeout' if d['rc'] == 124 else
                  'oom' if d['oom_killed'] else 'pass' if d['rc'] == 0 and runs and
                  all(r['ok'] for r in runs) else 'fail')
        entry = dict(script=key, args=extra, status=status, runs=runs)
        if d:
            entry.update(memory_gib=d['memory_gib'], wall_seconds=d['wall_seconds'])
            if status == 'fail':
                entry['tail'] = d['output'][-1500:]
        frama.append(entry)
    checks = []
    for key in CHECKS:
        driver = work / '_driver' / f'check.{key}.json'
        if driver.exists():
            d = json.loads(driver.read_text())
            checks.append(dict(name=key, status='pass' if d['rc'] == 0 else 'fail',
                               wall_seconds=d['wall_seconds'],
                               summary=[l for l in d['output'].splitlines()
                                        if l.startswith(('OK', 'FAIL', 'PASS', '==',
                                                         'equivalence', 'negative', '  OK'))][:20]))
    def version(cmd, image, entry=None):
        c = ['docker', 'run', '--rm'] + (['--entrypoint', entry] if entry else []) + [image] + cmd
        return subprocess.run(c, capture_output=True, text=True).stdout.strip().splitlines()[0]
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True,
                            text=True).stdout.strip()
    dirty = subprocess.run(['git', 'status', '--porcelain', '--', 'crates', 'harness/proofs'],
                           cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
    summary = {}
    for group, items, key in (('cbmc', proofs, 'status'), ('mutants', mutants, 'status'),
                              ('frama', frama, 'status'), ('checks', checks, 'status')):
        counts = {}
        for item in items:
            counts[item[key]] = counts.get(item[key], 0) + 1
        summary[group] = counts
    rejected = {}
    for f in frama:
        for r in f['runs']:
            if not r['expected']:
                key = r['rejected_by'] if r['ok'] else 'survived'
                rejected[key] = rejected.get(key, 0) + 1
    summary['frama_mutants'] = rejected
    result = dict(date=datetime.date.today().isoformat(), commit=commit,
                  tree_sha256=tree_hash(ROOT), worktree_changes=dirty,
                  toolchain=dict(cbmc=version(['cbmc', '--version'], CBMC_IMAGE),
                                 frama_c=version(['-version'], FRAMA_IMAGE, 'frama-c'),
                                 platform=f'docker linux/{platform.machine()}, LP64 little-endian'),
                  char_signedness=CHAR_SIGNEDNESS,
                  work=args.work, summary=summary, proofs=proofs, mutants=mutants,
                  frama=frama, checks=checks,
                  note='Logs and GOTO files are local ignored build artifacts under work. '
                       'tree_sha256 covers crates/*/csrc and the proof programs under '
                       'harness/proofs (see frama/wp_common.py tree_hash).')
    Path(args.out).write_text(json.dumps(result, indent=1) + '\n')
    print(json.dumps(summary))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    r = sub.add_parser('run')
    r.add_argument('--work', default='harness/build/proofs-replay')
    r.add_argument('--budget', type=int, default=56, help='GiB summed over running caps')
    r.add_argument('--jobs', type=int, default=16)
    r.add_argument('--only', default='cbmc,mutants,frama,checks')
    r.add_argument('--exclude', default='', help='comma-separated job names')
    r.add_argument('--cbmc-timeout', type=int, default=CBMC_TIMEOUT_MIN, help='minutes per cbmc run')
    r.add_argument('--gib', type=int, help='starting memory cap for every job')
    r.add_argument('names', nargs='*')
    c = sub.add_parser('collect')
    c.add_argument('--work', default='harness/build/proofs-replay')
    c.add_argument('--out', required=True)
    args = parser.parse_args()
    run(args) if args.action == 'run' else collect(args)


if __name__ == '__main__':
    main()
