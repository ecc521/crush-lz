#!/usr/bin/env python3
"""Inventory the vector intrinsics and builtins each decoder function uses.

For every shipping configuration this parses the decoder translation units
with clang (JSON AST), builds a cross-unit call graph, and lists, per
function reachable from a public decode entry point:

  intrinsic   a function or macro from a compiler intrinsic header
              (arm_neon.h, *intrin.h, cpuid.h)
  builtin     a __builtin_* / __atomic_* call written in project code
  asm         an inline asm statement
  vecop       a C operator applied to a vector-typed value

It exits nonzero if a decoder-reachable function uses an intrinsic or
builtin that harness/proofs/simd does not model, or any vecop. Functions
reachable only from encoders are counted but not checked.

  harness/proofs/simd/check_intrinsics.py            all configs
  harness/proofs/simd/check_intrinsics.py -v         also list encoder uses
  harness/proofs/simd/check_intrinsics.py --config arm64
"""
import argparse
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

sys.dont_write_bytecode = True
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
SIMD = os.path.join(ROOT, 'harness', 'proofs', 'simd')
ZBM = 'crates/lzbitmap/csrc'
LZFSE = 'crates/crushlzfse/csrc'
LZ4 = 'crates/crushlz4/csrc'

# Shipping configurations (crates/*/build.rs, harness/flags.mk).
CONFIGS = {
    'arm64': ['-target', 'arm64-apple-macos13'],
    'x86-v3': ['-target', 'x86_64-apple-macos13', '-march=x86-64-v3'],
    'x86-portable': ['-target', 'x86_64-apple-macos13', '-DCRUSH_SIMD_PORTABLE'],
}
COMMON = ['-std=gnu99', '-O3', '-DNDEBUG', '-fno-strict-aliasing',
          '-I' + ZBM, '-I' + LZFSE, '-I' + LZ4]

UNITS = [
    ZBM + '/libzbitmap.c',
    LZFSE + '/crushlzfse.c', LZFSE + '/crushlzvn.c', LZFSE + '/lzfse_decode.c',
    LZFSE + '/lzfse_decode_base.c', LZFSE + '/lzvn_decode_base.c',
    LZFSE + '/lzfse_fse.c',
    LZ4 + '/crushlz4.c',
]
ROOTS = ['crushlzbitmap_decode_buffer', 'crushlzfse_decode_buffer',
         'crushlzvn_decode_buffer', 'lzfse_decode_buffer',
         'lzfse_decode_buffer_with_scratch', 'lzfse_decode_scratch_size',
         'crushlz4_decode_buffer']

# What harness/proofs/simd models. Each intrinsic name must also be defined
# by a shadow header in harness/proofs/simd/include (checked below).
MODELLED_INTRINSICS = {
    'arm64': {'vld1_u8', 'vld1q_u8', 'vst1_u8', 'vst1q_u8', 'vcombine_u8',
              'vqtbl1_u8'},
    'x86-v3': {'_mm_loadl_epi64', '_mm_loadu_si128', '_mm_storel_epi64',
               '_mm_storeu_si128', '_mm_unpacklo_epi64', '_mm_shuffle_epi8'},
    'x86-portable': {'__get_cpuid_count'},
}
# Scalar builtins whose semantics CBMC implements natively (bit counts,
# hints, fortified libc calls) or that are trivially sequential here.
MODELLED_BUILTINS = {
    '__builtin_popcount', '__builtin_popcountll', '__builtin_clz',
    '__builtin_clzll', '__builtin_ctz', '__builtin_ctzl', '__builtin_ctzll',
    '__builtin_expect', '__builtin_constant_p', '__builtin_unreachable',
    '__builtin___memcpy_chk', '__builtin___memset_chk',
    '__builtin___memmove_chk', '__builtin_object_size',
    '__builtin_memcpy', '__builtin_memset', '__builtin_memmove',
    '__atomic_load_n', '__atomic_store_n',
}


INTRIN_HEADER = re.compile(r'^(arm_.*|.*intrin.*|cpuid)\.h$')


def is_intrinsic_header(path):
    return (path is not None and '/lib/clang/' in path and
            INTRIN_HEADER.match(os.path.basename(path)) is not None)


def is_system(path):
    return path is not None and (path.startswith('/') and not path.startswith(ROOT))


def dump(config, unit):
    cmd = ['clang'] + CONFIGS[config] + COMMON + [
        '-fsyntax-only', '-Xclang', '-ast-dump=json', unit]
    out = subprocess.run(cmd, cwd=ROOT, check=True, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL).stdout
    return json.loads(out)


def resolve_files(node, state):
    """clang elides a location's file when unchanged; restore it in order."""
    if isinstance(node, dict):
        if 'offset' in node or 'file' in node:
            if 'file' in node:
                state[0] = node['file']
            if 'line' in node:
                state[1] = node['line']
            node['_file'] = state[0]
            node['_line'] = state[1]
        for k, v in node.items():
            if k != 'includedFrom' and isinstance(v, (dict, list)):
                resolve_files(v, state)
    elif isinstance(node, list):
        for v in node:
            resolve_files(v, state)


def spelling(rng):
    b = (rng or {}).get('begin', {})
    s = b.get('spellingLoc', b)
    return s.get('_file'), s.get('_line')


MACRO_RE = re.compile(r'^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)')
_macro_cache = {}


def macro_at(path, line):
    """The macro whose definition contains `line` of an intrinsic header."""
    if path not in _macro_cache:
        names = []
        with open(path, errors='replace') as f:
            for i, text in enumerate(f, 1):
                m = MACRO_RE.match(text)
                if m:
                    names.append((i, m.group(1)))
        _macro_cache[path] = names
    best = None
    for i, n in _macro_cache[path]:
        if i <= line:
            best = n
        else:
            break
    return best


def asm_text(rng):
    """The asm statement's source, normalised: CBMC sees only this."""
    b = (rng or {}).get('begin', {})
    b = b.get('spellingLoc', b)
    e = (rng or {}).get('end', {})
    e = e.get('spellingLoc', e)
    path = b.get('_file')
    if not path:
        return '?'
    with open(os.path.join(ROOT, path), 'rb') as f:
        text = f.read()[b['offset']:e['offset'] + e.get('tokLen', 1)]
    return re.sub(r'\s+', ' ', text.decode(errors='replace'))


# An empty template whose operands are all "+r" register pins: no
# instruction, no clobber, no memory operand. See README.md (T8).
EMPTY_PIN = re.compile(r'^__asm__\s*\(\s*""\s*:(\s*"\+r"\s*\([^()]*(\([^()]*\))?[^()]*\)\s*,?)+\s*\)$')


def is_vector(t):
    q = (t or {}).get('desugaredQualType', '') + (t or {}).get('qualType', '')
    return 'vector_size' in q or 'neon_vector_type' in q or 'ext_vector_type' in q


VEC_OPS = {'BinaryOperator', 'UnaryOperator', 'CompoundAssignOperator',
           'ArraySubscriptExpr', 'ConditionalOperator'}


def scan_body(node, uses, calls):
    if isinstance(node, list):
        for v in node:
            scan_body(v, uses, calls)
        return
    if not isinstance(node, dict):
        return
    kind = node.get('kind')
    sf, sline = spelling(node.get('range'))
    if is_intrinsic_header(sf) and sline:
        # Any expression spelled inside an intrinsic header comes from one
        # of its macros, including those that expand to a bare cast.
        uses.add(('intrinsic', macro_at(sf, sline)))
    if kind == 'DeclRefExpr' and node.get('referencedDecl', {}).get('kind') == 'FunctionDecl':
        name = node['referencedDecl']['name']
        f, line = spelling(node.get('range'))
        if is_intrinsic_header(f):
            uses.add(('intrinsic', macro_at(f, line) or name))
        elif name.startswith('__builtin') or name.startswith('__atomic') \
                or name.startswith('__sync'):
            uses.add(('builtin', name))
        else:
            calls.add(name)
    elif kind in ('GCCAsmStmt', 'MSAsmStmt'):
        uses.add(('asm', asm_text(node.get('range'))))
    elif kind == 'AtomicExpr':
        uses.add(('builtin', node.get('name', '__atomic')))
    elif kind in VEC_OPS and is_vector(node.get('type')) and \
            not is_intrinsic_header(spelling(node.get('range'))[0]):
        uses.add(('vecop', kind + ':' + node.get('opcode', '')))
    for k, v in node.items():
        if k in ('inner', 'referencedDecl'):
            if k == 'inner':
                scan_body(v, uses, calls)
        elif isinstance(v, (dict, list)) and k not in ('range', 'loc', 'type'):
            scan_body(v, uses, calls)


def analyse_unit(config, unit):
    ast = dump(config, unit)
    resolve_files(ast, [None, None])
    funcs = {}    # name -> (static, uses, calls, file, line)
    intrinsic_fns = set()
    for d in ast.get('inner', []):
        if d.get('kind') != 'FunctionDecl':
            continue
        loc = d.get('loc', {})
        f = loc.get('_file')
        f = loc.get('spellingLoc', {}).get('_file', f)
        if f == '<scratch space>':
            f = loc.get('expansionLoc', {}).get('_file', f)
        body = [c for c in d.get('inner', []) if c.get('kind') == 'CompoundStmt']
        if is_intrinsic_header(f):
            intrinsic_fns.add(d['name'])
            continue
        if not body or is_system(f):
            continue
        uses, calls = set(), set()
        scan_body(body, uses, calls)
        line = loc.get('expansionLoc', loc).get('_line')
        funcs[d['name']] = (d.get('storageClass') == 'static', uses, calls, f, line)
    # Calls to intrinsic-header functions are intrinsic uses, not edges.
    for name, (st, uses, calls, f, line) in funcs.items():
        for c in list(calls):
            if c in intrinsic_fns:
                uses.add(('intrinsic', c))
                calls.discard(c)
    return funcs


def analyse(config, jobs):
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        results = list(ex.map(lambda u: (u, analyse_unit(config, u)), UNITS))
    # Global graph: static functions are keyed by unit.
    nodes, extern = {}, {}
    for unit, funcs in results:
        for name, rec in funcs.items():
            key = (unit, name) if rec[0] else (None, name)
            nodes[key] = (unit,) + rec
            if not rec[0]:
                extern[name] = key
    def resolve(unit, name):
        if (unit, name) in nodes:
            return (unit, name)
        return extern.get(name)
    reach, stack = set(), [extern[r] for r in ROOTS if r in extern]
    missing = [r for r in ROOTS if r not in extern]
    while stack:
        k = stack.pop()
        if k in reach:
            continue
        reach.add(k)
        unit = nodes[k][0]
        for c in nodes[k][3]:
            t = resolve(unit, c)
            if t is not None:
                stack.append(t)
    return nodes, reach, missing


def shadow_names():
    names = set()
    inc = os.path.join(SIMD, 'include')
    for fn in os.listdir(inc) if os.path.isdir(inc) else []:
        with open(os.path.join(inc, fn)) as f:
            text = f.read()
        names |= set(re.findall(r'#\s*define\s+([A-Za-z_]\w*)', text))
        names |= set(re.findall(r'\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{', text))
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', action='append', choices=sorted(CONFIGS))
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('-j', '--jobs', type=int, default=8)
    args = ap.parse_args()
    shadow = shadow_names()
    failed = False
    for config in args.config or list(CONFIGS):
        nodes, reach, missing = analyse(config, args.jobs)
        print('== %s: %d decoder-reachable functions of %d' %
              (config, len(reach), len(nodes)))
        if missing:
            print('  FAIL missing roots: ' + ', '.join(missing))
            failed = True
        bad, used = [], set()
        for key in sorted(reach, key=lambda k: (nodes[k][0], k[1])):
            unit, _, uses, _, f, line = nodes[key]
            if not uses:
                continue
            row = []
            for kind, name in sorted(uses):
                ok = ((kind == 'intrinsic' and name in MODELLED_INTRINSICS[config]
                       and name in shadow)
                      or (kind == 'builtin' and name in MODELLED_BUILTINS)
                                      or (kind == 'asm' and EMPTY_PIN.match(name) is not None))
                used.add((kind, name))
                row.append(('' if ok else '!') + kind + ' ' + (name or '""'))
                if not ok:
                    bad.append((key[1], kind, name))
            print('  %-40s %s:%s' % (key[1], os.path.relpath(f, ROOT) if f and f.startswith('/') else f, line))
            for r in row:
                print('      ' + r)
        enc = {}
        for key, rec in nodes.items():
            if key not in reach:
                for kind, name in rec[2]:
                    if kind in ('intrinsic', 'vecop', 'asm'):
                        enc.setdefault((kind, name), set()).add(key[1])
        print('  encoder-only (out of scope): %d distinct intrinsic/vecop/asm uses in %d functions' %
              (len(enc), len({f for s in enc.values() for f in s})))
        if args.verbose:
            for (kind, name), fs in sorted(enc.items()):
                print('      %s %s: %s' % (kind, name, ', '.join(sorted(fs))))
        unused = MODELLED_INTRINSICS[config] - {n for k, n in used if k == 'intrinsic'}
        if unused:
            print('  note: modelled but not used by decoders: ' + ', '.join(sorted(unused)))
        if bad:
            failed = True
            print('  FAIL unmodelled in decoder functions:')
            for b in bad:
                print('      %s: %s %s' % b)
        else:
            print('  OK every decoder intrinsic/builtin is modelled')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
