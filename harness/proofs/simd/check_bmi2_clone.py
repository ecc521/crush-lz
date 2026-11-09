#!/usr/bin/env python3
"""Check that the two expansions of lzfse_decode_hot.h are the same code.

On x86-64 without BMI2 (CRUSHLZ_SIMD_PORTABLE=1 builds), lzfse_decode_base.c
includes lzfse_decode_hot.h twice: suffix _baseline with no attribute, and
suffix _bmi2 with __attribute__((target("bmi2"))), then picks one per call
by CPUID. This preprocesses the unit as shipped, takes the tokens of each
inclusion, and requires them equal once the suffix is normalised and the
target attribute removed. A proof of the baseline expansion then covers the
BMI2 one at the C level; only code generation differs. The arm64 and
x86-64-v3 builds must contain the baseline expansion alone.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
SRC = 'crates/crushlzfse/csrc/lzfse_decode_base.c'
HOT = 'lzfse_decode_hot.h'
BASE = ['clang', '-std=gnu99', '-O3', '-DNDEBUG', '-Icrates/crushlzfse/csrc', '-E', SRC]
CONFIGS = {
    'x86-portable': ['-target', 'x86_64-apple-macos13', '-DCRUSH_SIMD_PORTABLE'],
    'x86-portable-proof': ['-target', 'x86_64-apple-macos13', '-DCRUSH_SIMD_PORTABLE',
                           '-DLZFSE_PROOF', '-DHAVE_LABELS_AS_VALUES=0'],
    'x86-v3': ['-target', 'x86_64-apple-macos13', '-march=x86-64-v3'],
    'arm64': ['-target', 'arm64-apple-macos13'],
}
MARKER = re.compile(r'^# (\d+) "([^"]*)"(.*)$')
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*|\d[\w.]*|'
                   r'->|\+\+|--|<<=?|>>=?|[<>=!]=|&&|\|\||[-+*/%&|^]=|\S')


def expansions(config):
    out = subprocess.run(BASE[:-2] + CONFIGS[config] + BASE[-2:], cwd=ROOT, check=True,
                         stdout=subprocess.PIPE, text=True).stdout
    found, cur, depth = [], None, 0
    for line in out.splitlines():
        m = MARKER.match(line)
        if m:
            name, flags = os.path.basename(m.group(2)), m.group(3).split()
            if name == HOT and '1' in flags:
                cur, depth = [], 0
            elif cur is not None and '1' in flags:
                depth += 1
            elif cur is not None and '2' in flags:
                if depth == 0:
                    found.append(cur)
                    cur = None
                else:
                    depth -= 1
            continue
        if cur is not None and depth == 0:
            cur.extend(TOKEN.findall(line))
    return found


def normalise(tokens, suffix):
    text = ' '.join(tokens)
    text = text.replace('__attribute__ ( ( target ( "bmi2" ) ) )', '')
    return re.sub(r'\b(\w+)' + suffix + r'\b', r'\1_SUFFIX', text).split()


def main():
    ok = True
    for config in CONFIGS:
        ex = expansions(config)
        if config.startswith('x86-portable'):
            if len(ex) != 2:
                print('FAIL %s: %d expansions, expected 2' % (config, len(ex)))
                ok = False
                continue
            a, b = normalise(ex[0], '_baseline'), normalise(ex[1], '_bmi2')
            attrs = ' '.join(ex[1]).count('target ( "bmi2" )')
            if a == b and attrs >= 2 and ' '.join(ex[0]).count('target') == 0:
                print('OK   %s: baseline and bmi2 expansions identical (%d tokens, '
                      '%d target("bmi2") attributes removed)' % (config, len(a), attrs))
            else:
                ok = False
                for i, (x, y) in enumerate(zip(a, b)):
                    if x != y:
                        print('FAIL %s: first difference at token %d: %s | %s' %
                              (config, i, ' '.join(a[max(0, i - 8):i + 8]),
                               ' '.join(b[max(0, i - 8):i + 8])))
                        break
                else:
                    print('FAIL %s: lengths %d and %d, %d attributes' % (config, len(a), len(b), attrs))
        else:
            if len(ex) == 1 and 'target' not in ex[0]:
                print('OK   %s: one expansion, no target attribute (%d tokens)' % (config, len(ex[0])))
            else:
                print('FAIL %s: %d expansions' % (config, len(ex)))
                ok = False
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
