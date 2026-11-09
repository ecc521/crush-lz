#!/usr/bin/env python3
"""Cross-tool lemmas between the CBMC and Frama-C LZFSE decoder contracts.

The literal and LMD steps have CBMC contracts in lzfse_internal.h and
Frama-C/WP contracts in lzfse_literals_native.py and lzfse_lmd_native.py.
This script checks, with WP, that those two sets of contracts agree. The
frame dispatcher's separate contracts in lzfse_frame_interface.h are checked
by lzfse_frame_step_bridge.py.

  * Each callee model used by the Frama-C proofs is implied by the callee's
    enforced CBMC contract: model precondition => CBMC precondition, and
    CBMC postcondition and frame => model postcondition and frame.
  * Each step's CBMC contract is implied by its Frama-C contract: CBMC
    precondition => Frama-C precondition (lmd_start for the LMD step), and
    Frama-C postcondition => CBMC postcondition.

The CBMC clauses are not retyped. The headers are preprocessed with the
shipping proof defines and each clause is translated mechanically
(translate()); an unrecognized construct is an error. The Frama-C side is
imported from the proof scripts themselves. The abstract LMD predicate
tables_ok is instantiated with the translation of LZFSE_LMD_TABLES_OK, which
is sound because the LMD proof holds for every interpretation of it.

Translation: rw_ok/w_ok/r_ok become \\valid/\\valid_read of the byte range
(or of the object for sizeof *p, or of N elements for N * sizeof *p);
same_object becomes equality of \\base_addr; POINTER_OFFSET(p) becomes
\\offset(p) on byte pointers; forall, old and return_value map
directly; object_upto(p, n) in a frame becomes p[0 .. n - 1].
"""
from pathlib import Path
import argparse
import re
import subprocess
import sys
sys.dont_write_bytecode = True
from wp_common import verify
import lzfse_lmd_native as LMD
import lzfse_literals_native as LIT

ROOT = Path(__file__).resolve().parents[3]
CSRC = ROOT / 'crates/crushlzfse/csrc'

# Pointer expressions of byte type, for byte-range validity and offsets.
BYTE_POINTERS = ('dst', 'src', 'buf', 'buf_start', 'ptr', 'lit', '*pbuf')


def preprocess(margin):
    # The row macros are probed on their own, then renamed inside the table
    # macros so the table predicates quantify over a named row predicate.
    probe = ('#include "lzfse_decode_base.c"\n'
             '#if LZFSE_ENCODE_LITERAL_STATES != 1024 || '
             'LZFSE_MATCHES_PER_BLOCK != 10000 || '
             'LZFSE_LITERALS_PER_BLOCK != 40000\n'
             '#error LZFSE bridge requires shipping decoder dimensions\n'
             '#endif\n'
             'PROBE_VALUE_ROW LZFSE_VALUE_ROW_OK(e, nstates, limit) PROBE_END\n'
             'PROBE_LITERAL_ROW LZFSE_LITERAL_ROW_OK(e) PROBE_END\n'
             'PROBE_LMD_TABLES_STATE LZFSE_LMD_TABLES_OK(s->compressed_lzfse_block_state.lmd_decoder) PROBE_END\n'
             'PROBE_LITERAL_TABLE_BS LZFSE_LITERAL_TABLE_OK(bs->literal_decoder) PROBE_END\n'
             '#undef LZFSE_VALUE_ROW_OK\n#undef LZFSE_LITERAL_ROW_OK\n'
             '#define LZFSE_VALUE_ROW_OK(e, N, L) cbmc_value_row_ok(e, N, L)\n'
             '#define LZFSE_LITERAL_ROW_OK(e) cbmc_literal_row_ok(e)\n'
             'PROBE_LMD_TABLES LZFSE_LMD_TABLES_OK(t) PROBE_END\n'
             'PROBE_LITERAL_TABLE LZFSE_LITERAL_TABLE_OK(t) PROBE_END\n')
    out = subprocess.run(
        ['gcc', '-E', '-P', '-DLZFSE_PROOF', '-DLZFSE_EXACT_FSE', '-DCRUSH_SIMD_PORTABLE',
         '-DHAVE_LABELS_AS_VALUES=0', f'-DLZFSE_DECODE_COPY_MARGIN={margin}',
         '-I', str(CSRC), '-I', str(ROOT / 'crates/lzbitmap/csrc'), '-x', 'c', '-'],
        input=probe, capture_output=True, text=True, check=True).stdout
    # Clang (also invoked as gcc on macOS) prints the C `restrict` keyword
    # for the source's `__restrict` spelling.  Normalize only pointer
    # qualifiers so the source-derived signature lookup stays independent of
    # the host preprocessor without changing any contract expression.
    out = re.sub(r'(\*)\s*restrict\b', r'\1__restrict', out)
    return re.sub(r'\s+', ' ', out)


def balanced(text, i, open_ch='(', close_ch=')'):
    """Index one past the bracket matching text[i]."""
    assert text[i] == open_ch, text[i:i + 40]
    depth = 0
    for j in range(i, len(text)):
        if text[j] == open_ch:
            depth += 1
        elif text[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
    raise ValueError('unbalanced: ' + text[i:i + 80])


def split_args(text):
    args, depth, cur = [], 0, ''
    for ch in text:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == ',' and depth == 0:
            args.append(cur.strip())
            cur = ''
        else:
            cur += ch
    args.append(cur.strip())
    return args


def strip_parens(e):
    e = e.strip()
    while e.startswith('(') and balanced(e, 0) == len(e):
        e = e[1:-1].strip()
    return e


def is_byte_pointer(p):
    p = strip_parens(p)
    p = strip_parens(re.split(r' [-+] ', p)[0])
    p = re.sub(r'^\\old\((.*)\)$', r'\1', p).strip()
    last = re.split(r'->|\.', p)[-1].strip()
    return last in BYTE_POINTERS or last.endswith('literals') or \
        last.endswith('current_literal') or last in ('dst_begin', 'dst_end', 'src_begin', 'src_end') \
        or re.match(r'^(dst|src|lit|buf|buf_start)\b', p) is not None


def range_of(p, n):
    n = strip_parens(n)
    m = re.fullmatch(r'sizeof \*(.+)', n)
    if m:
        assert strip_parens(m.group(1)) == strip_parens(p), (p, n)
        return f'{p}'
    m = re.fullmatch(r'(.+?) \* sizeof \*(.+)', n)
    if m:
        assert strip_parens(m.group(2)) == strip_parens(p), (p, n)
        return f'{p} + (0 .. ({m.group(1)}) - 1)'
    assert is_byte_pointer(p), ('byte range on a non-byte pointer', p, n)
    return f'{p} + (0 .. ({n}) - 1)'


def translate(text):
    out = ''
    i = 0
    while i < len(text):
        m = re.compile(r'__CPROVER_(\w+)').search(text, i)
        if not m:
            out += text[i:]
            break
        out += text[i:m.start()]
        name = m.group(1)
        j = m.end()
        while j < len(text) and text[j] == ' ':
            j += 1
        if name == 'return_value':
            out += '\\result'
            i = m.end()
            continue
        if name == 'forall':
            end = balanced(text, j, '{', '}')
            inner = text[j + 1:end - 1].strip()
            decl, body = inner.split(';', 1)
            var = decl.split()[-1]
            out += f'(\\forall integer {var}; {translate(body.strip())})'
            i = end
            continue
        end = balanced(text, j)
        args = [translate(a) for a in split_args(text[j + 1:end - 1])]
        if name == 'same_object':
            out += f'(\\base_addr({args[0]}) == \\base_addr({args[1]}))'
        elif name == 'POINTER_OFFSET':
            assert is_byte_pointer(args[0]), ('offset of a non-byte pointer', args[0])
            out += f'\\offset({args[0]})'
        elif name in ('r_ok',):
            out += f'\\valid_read({range_of(args[0], args[1])})'
        elif name in ('w_ok', 'rw_ok'):
            out += f'\\valid({range_of(args[0], args[1])})'
        elif name == 'old':
            out += f'\\old({args[0]})'
        else:
            raise ValueError('untranslated construct __CPROVER_' + name)
        i = end
    return out


ARRAY_FIELD = re.compile(r'((?:\(s\)|\bs|\bbs)(?:->|\.)(?:compressed_lzfse_block_state\.)?'
                         r'(?:literals|lmd_decoder|literal_decoder))\b(?!\s*\[)')


def arrays(text):
    """ACSL does not decay an array member to a pointer."""
    return ARRAY_FIELD.sub(r'(&\1[0])', text)


OFS = re.compile(r'@OFS(\d+)@')


def offsets(text, prove):
    """Rewrite \\offset terms. Two offsets in one difference or comparison
    become the same operation on the pointers (each such clause also
    requires a common base). A lone lower bound offset(p) >= E is checked as
    p - E readable, in positions this lemma proves only; E <= 0 is taken as
    true (every pointer in these contracts lies inside its object)."""
    terms = []
    out = ''
    i = 0
    while True:
        k = text.find('\\offset(', i)
        if k < 0:
            out += text[i:]
            break
        j = k + len('\\offset')
        end = balanced(text, j)
        out += text[i:k] + f'@OFS{len(terms)}@'
        terms.append(text[j + 1:end - 1])
        i = end
    if not terms:
        return text
    t = lambda m: '(' + terms[int(m.group(1))] + ')'
    out = re.sub(r'@OFS(\d+)@ - @OFS(\d+)@',
                 lambda m: f'({terms[int(m.group(1))]} - {terms[int(m.group(2))]})', out)
    out = re.sub(r'@OFS(\d+)@ (>=|<=|<|>|==) @OFS(\d+)@',
                 lambda m: f'{terms[int(m.group(1))]} {m.group(2)} {terms[int(m.group(3))]}', out)
    out = re.sub(r'@OFS(\d+)@ \+ (\d+) <= @OFS(\d+)@',
                 lambda m: f'{terms[int(m.group(1))]} + {m.group(2)} <= {terms[int(m.group(3))]}', out)
    def lone(m):
        assert prove, ('lone offset bound in an assumed clause', text)
        p, e = terms[int(m.group(1))], m.group(2)
        return f'(({e}) <= 0 || \\valid_read({p} - ({e})))'
    out = re.sub(r'@OFS(\d+)@ >= (\(size_t\)D|\(size_t\)\(\(63 - s->accum_nbits\) >> 3\)|\d+)',
                 lone, out)
    assert not OFS.search(out), ('untranslated offset', text)
    return out


def frame(item):
    item = item.strip()
    m = re.fullmatch(r'__CPROVER_object_upto\((.*)\)', item)
    if m:
        p, n = split_args(m.group(1))
        m2 = re.fullmatch(r'sizeof (.+)', strip_parens(n))
        if m2:
            assert strip_parens(m2.group(1)) == strip_parens(p)
            return f'{p}[0 .. LZFSE_PROBE_SIZEOF_{re.sub(r"[^A-Za-z]", "_", p)}]'
        return f'{p}[0 .. ({offsets(translate(n), False)}) - 1]'
    assert '__CPROVER' not in item, item
    m = re.fullmatch(r'\*(\w+)', item)
    return item


SUBSTITUTE = []


def contract(text, signature, prove_requires):
    """The CBMC clauses following a declaration or definition, translated.
    prove_requires: the lemma proves the requires (a callee) rather than the
    ensures (a step)."""
    k = text.index(signature)
    i = k + len(signature)
    clauses = []
    while True:
        while text[i] == ' ':
            i += 1
        m = re.match(r'__CPROVER_(requires|ensures|assigns)\s*\(', text[i:])
        if not m:
            break
        j = i + m.end() - 1
        end = balanced(text, j)
        body = text[j + 1:end - 1].strip()
        if m.group(1) == 'assigns':
            items = [frame(a) for a in split_args(body)]
            clauses.append('assigns ' + ', '.join(items) + ';')
        else:
            prove = prove_requires == (m.group(1) == 'requires')
            clause = arrays(translate(body))
            # A table predicate in a clause is the named ACSL predicate defined
            # from the same macro (exact text of its expansion).
            for old, new in SUBSTITUTE:
                clause = clause.replace(old, new)
            clauses.append(m.group(1) + ' ' + offsets(clause, prove) + ';')
        i = end
    assert clauses, signature
    return '\n    '.join(clauses)


def probe(text, name):
    m = re.search(name + r' (.*?) PROBE_END', text)
    return arrays(translate(m.group(1)))


def model_contract(models, name):
    """The ACSL contract preceding the declaration of NAME in a MODELS text."""
    k = models.index(' ' + name + '(')
    a = models.rindex('/*@', 0, k)
    b = models.index('*/', a) + 2
    decl_end = models.index(';', b) + 1
    return models[a:b], models[b:decl_end].strip()


def lemma(name, outer_contract, outer_decl, inner_name, inner_contract, inner_decl, call):
    """outer_contract (the claim) holds for a body that only calls a function
    specified by inner_contract (the hypothesis)."""
    outer_decl = re.sub(r'\b\w+\(', name + '(', outer_decl.rstrip(';'), count=1)
    inner_decl = re.sub(r'\b\w+\(', inner_name + '(', inner_decl.rstrip(';'), count=1) + ';'
    return (f'/*@ {inner_contract}\n*/\n{inner_decl}\n'
            f'{outer_contract}\n{outer_decl} {{\n  {call}\n}}\n')


# The trusted facts of the bridge: the values of 1 << v for the shift widths
# the row predicates use, and x >> 3 as a division for the refill width (C
# arithmetic on small non-negative integers, not a property of the code).
# WP evaluates such shifts only for literal constants.
SHIFTS = ('/*@ axiomatic Shifts {\n    axiom shift_values: \\forall integer v; 0 <= v <= 16 ==>\n'
          '      ((uint32_t)1 << v) == (' +
          ''.join(f'v == {v} ? {1 << v} : ' for v in range(16)) + '65536);\n'
          '    axiom shift_right_3: \\forall integer x; 0 <= x <= 63 ==> (x >> 3) == x / 8;\n  }\n*/\n')


# Mutations of the CBMC clauses (preprocessed text) that must break a lemma.
MUTANTS = {
    'refill_extra_byte': ('__CPROVER_r_ok(buf_start, (size_t)(__CPROVER_POINTER_OFFSET(*pbuf) - __CPROVER_POINTER_OFFSET(buf_start)))',
                          '__CPROVER_r_ok(buf_start, (size_t)(__CPROVER_POINTER_OFFSET(*pbuf) - __CPROVER_POINTER_OFFSET(buf_start)) + 1)', 4),
    'literal_count_over_limit': ('__CPROVER_requires(header1->n_literals <= (4 * 10000))',
                                 '__CPROVER_requires(header1->n_literals <= (4 * 10000 + 1))', 1),
    'value_result_past_l_limit': ('__CPROVER_ensures(__CPROVER_return_value <= (table_offset == 0 ? 315 :',
                                  '__CPROVER_ensures(__CPROVER_return_value <= (table_offset == 0 ? 316 :', 1),
}

# These warnings concern value dependencies of pointer assignments. The
# bridge claims spatial preconditions, postconditions and write footprints;
# each named pointer is still constrained by an explicit ensures clause.
POINTER_FROM_WARNINGS = (
    r"\[wp:pedantic-assigns\] [^\n]+:\d+: Warning: \n"
    r"  No \\from specification for assigned pointer "
    r"'(?:\*pbuf|s->dst|s->compressed_lzfse_block_state.current_literal|"
    r"s->src|bs->current_literal)'\.\n"
    r"  Callers assumptions might be imprecise\."
)


def generate(margin, mutant=None):
    pre = preprocess(margin)
    if mutant:
        old, new, count = MUTANTS[mutant]
        assert pre.count(old) == count if count else pre.count(old) > 1, (mutant, pre.count(old))
        pre = pre.replace(old, new)
    internal = (CSRC / 'lzfse_internal.h').read_text()
    fse = (CSRC / 'lzfse_fse.h').read_text()
    value_row = probe(pre, 'PROBE_VALUE_ROW')
    literal_row = probe(pre, 'PROBE_LITERAL_ROW')
    lmd_tables = probe(pre, 'PROBE_LMD_TABLES')
    literal_table = probe(pre, 'PROBE_LITERAL_TABLE')
    SUBSTITUTE[:] = [
        (probe(pre, 'PROBE_LMD_TABLES_STATE'),
         'tables_ok(&s->compressed_lzfse_block_state.lmd_decoder[0])'),
        (probe(pre, 'PROBE_LITERAL_TABLE_BS'), 'cbmc_literal_table_ok(&bs->literal_decoder[0])')]
    lmd_models = LMD.MODELS.replace(
        '''/*@ axiomatic Tables {
      predicate tables_ok(fse_value_decoder_entry *t);
    }''', '/*@ predicate tables_ok(fse_value_decoder_entry *t) =\n      ' + lmd_tables + ';')
    assert lmd_models != LMD.MODELS
    head = ('#define LZFSE_DECODE_COPY_MARGIN ' + str(margin) + '\n'
            '#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\n'
            'typedef uint16_t fse_state;\n' + LMD.native_types(internal, fse) +
            '#define LZFSE_STATUS_OK 0\n#define LZFSE_STATUS_DST_FULL -2\n'
            '#define LZFSE_STATUS_ERROR -3\n'
            '#define LZFSE_PROBE_SIZEOF_bs__literals (40000 + LZFSE_DECODE_COPY_MARGIN - 1)\n')
    lit_pred = re.search(r'predicate literal_table_valid\(int32_t \*t\)=.*?;\n', LIT.MODELS, re.S).group(0)
    parts = [head, SHIFTS,
             '/*@ predicate cbmc_value_row_ok(fse_value_decoder_entry e, integer nstates, '
             'integer limit) = ' + value_row + ';\n*/\n',
             lmd_models.split('*/', 1)[0] + '*/\n',
             '/*@ ' + lit_pred.replace('literal_table_valid', 'frama_literal_table_valid') + '*/\n',
             '/*@ predicate cbmc_literal_row_ok(int32_t e) = ' + literal_row + ';\n*/\n',
             '/*@ predicate cbmc_literal_table_ok(int32_t *t) = ' + literal_table + ';\n*/\n',
             LMD.STATE,
             '/*@ lemma lmd_rows_l: \\forall fse_value_decoder_entry *t, integer k;\n'
             '      tables_ok(t) && 0 <= k < 64 ==> cbmc_value_row_ok(t[k], 64, 315);\n'
             '    lemma lmd_rows_m: \\forall fse_value_decoder_entry *t, integer k;\n'
             '      tables_ok(t) && 0 <= k < 64 ==> cbmc_value_row_ok(t[72 + k], 64, 2359);\n'
             '    lemma lmd_rows_d: \\forall fse_value_decoder_entry *t, integer k;\n'
             '      tables_ok(t) && 0 <= k < 256 ==> cbmc_value_row_ok(t[144 + k], 256, 262139);\n*/\n']
    functions = []

    # Callee models: CBMC contract => Frama-C model.
    callee = [
        ('value_decode', lmd_models, 'proof_value_decode',
         'uint32_t fse_value_decode_u32(uint32_t *__restrict pstate, const fse_value_decoder_entry *value_decoder_table, size_t table_offset, fse_in_stream *__restrict in)',
         'uint32_t c(uint32_t *pstate, const fse_value_decoder_entry *value_decoder_table, size_t table_offset, fse_in_stream *in);',
         # Hints, each proved: the row the call reads, per table.
         '//@ assert offset == 0 ==> cbmc_value_row_ok(table[*pstate], 64, 315);\n'
         '  //@ assert offset == 72 ==> cbmc_value_row_ok(table[72 + *pstate], 64, 2359);\n'
         '  //@ assert offset == 144 ==> cbmc_value_row_ok(table[144 + *pstate], 256, 262139);\n'
         '  return cbmc_value_decode(pstate, table, offset, in);'),
        ('flush_next_lmd', lmd_models, 'proof_fse_flush_next',
         'int fse_in_flush_next(fse_in_stream *s, const uint8_t **pbuf, const uint8_t *buf_start, uint64_t *next)',
         'int c(fse_in_stream *s, const uint8_t **pbuf, const uint8_t *buf_start, uint64_t *next);',
         'return cbmc_flush_next_lmd(in, buf, start, next);'),
        ('copy_literal_wide', lmd_models, 'proof_copy_literal_wide',
         'void copy_literal_wide(uint8_t *dst, const uint8_t *src, size_t length)',
         'void c(uint8_t *dst, const uint8_t *src, size_t length);',
         'cbmc_copy_literal_wide(dst, src, length);'),
        ('copy_match', lmd_models, 'proof_copy_match',
         'void lzfse_copy_match(uint8_t *dst, ptrdiff_t D, ptrdiff_t M)',
         'void c(uint8_t *dst, ptrdiff_t D, ptrdiff_t M);',
         'cbmc_copy_match(dst, D, M);'),
        ('copy_literal_bytes', lmd_models, 'proof_copy_literal_bytes',
         'void lzfse_copy_literal_bytes(uint8_t *dst, const uint8_t *src, size_t count)',
         'void c(uint8_t *dst, const uint8_t *src, size_t count);',
         'cbmc_copy_literal_bytes(dst, src, count);'),
        ('copy_match_bytes', lmd_models, 'proof_copy_match_bytes',
         'void lzfse_copy_match_bytes(uint8_t *dst, ptrdiff_t D, size_t count)',
         'void c(uint8_t *dst, ptrdiff_t D, size_t count);',
         'cbmc_copy_match_bytes(dst, D, count);'),
        ('decode_u32', LIT.MODELS, 'proof_fse_decode',
         'uint8_t fse_decode_u32(uint32_t *__restrict pstate, const int32_t *__restrict decoder_table, fse_in_stream *__restrict in)',
         'uint8_t c(uint32_t *pstate, const int32_t *decoder_table, fse_in_stream *in);',
         'return cbmc_decode_u32(state, table, in);'),
        ('init64', LIT.MODELS, 'proof_fse_init',
         'int fse_in_checked_init64(fse_in_stream64 *s, fse_bit_count n, const uint8_t **pbuf, const uint8_t *buf_start)',
         'int c(fse_in_stream *s, fse_bit_count n, const uint8_t **pbuf, const uint8_t *buf_start);',
         'return cbmc_init64(in, bits, buf, start);'),
        ('flush_next_literals', LIT.MODELS, 'proof_fse_flush_next',
         'int fse_in_flush_next(fse_in_stream *s, const uint8_t **pbuf, const uint8_t *buf_start, uint64_t *next)',
         'int c(fse_in_stream *s, const uint8_t **pbuf, const uint8_t *buf_start, uint64_t *next);',
         'return cbmc_flush_next_literals(in, buf, start, next);'),
        ('flush64_unchecked', LIT.MODELS, 'proof_fse_flush_unchecked',
         'void fse_in_flush64_unchecked(fse_in_stream64 *s, const uint8_t **pbuf)',
         'void c(fse_in_stream *s, const uint8_t **pbuf);',
         'cbmc_flush64_unchecked(in, buf);'),
    ]
    for name, models, model_name, signature, inner_decl, call in callee:
        acsl, decl = model_contract(models, model_name)
        if models is LIT.MODELS:
            acsl = acsl.replace('literal_table_valid', 'cbmc_literal_table_ok')
        # The CBMC clauses name the callee's own parameters.
        inner = contract(pre, signature, True)
        functions.append('bridge_' + name)
        parts.append(lemma('bridge_' + name, acsl, decl, 'cbmc_' + name, inner, inner_decl, call))
    # The checked x86 refill behind fse_in_flush_next when there is no
    # lookahead: same model, CBMC contract of fse_in_checked_flush64.
    acsl, decl = model_contract(lmd_models, 'proof_fse_flush_next')
    inner = contract(pre, 'int fse_in_checked_flush64(fse_in_stream64 *s, const uint8_t **pbuf, const uint8_t *buf_start)', True)
    functions.append('bridge_flush64_lmd')
    parts.append(lemma('bridge_flush64_lmd', acsl, decl, 'cbmc_flush64_lmd', inner,
                       'int c(fse_in_stream *s, const uint8_t **pbuf, const uint8_t *buf_start);',
                       '(void)next; return cbmc_flush64_lmd(in, buf, start);'))

    # Steps: Frama-C contract => CBMC contract.
    lmd_cbmc = contract(pre, 'int lzfse_decode_lmd(lzfse_decoder_state *s)', False)
    frama_lmd = LMD.CONTRACT.strip()
    parts.append(f'{frama_lmd}\nint frama_lzfse_decode_lmd(lzfse_decoder_state *s);\n'
                 f'/*@ {lmd_cbmc}\n*/\nint bridge_lmd_step(lzfse_decoder_state *s) {{\n' +
                 ''.join(f'  //@ assert {c};\n' for c in LMD.START) +
                 f'  return frama_lzfse_decode_lmd(s);\n}}\n')
    functions.append('bridge_lmd_step')
    lit_cbmc = contract(pre, 'int lzfse_decode_literals(lzfse_decoder_state *s, const lzfse_compressed_block_header_v1 *header1, lzfse_compressed_block_decoder_state *bs)', False)
    lit_cbmc = lit_cbmc.replace('cbmc_literal_table_ok', 'cbmc_literal_table_ok')
    frama_lit = LIT.CONTRACT.strip().replace('literal_table_valid', 'cbmc_literal_table_ok')
    parts.append(f'{frama_lit}\nint frama_lzfse_decode_literals(lzfse_decoder_state *s, '
                 'const lzfse_compressed_block_header_v1 *header1, lzfse_compressed_block_decoder_state *bs);\n'
                 f'/*@ {lit_cbmc}\n*/\nint bridge_literal_step(lzfse_decoder_state *s, '
                 'const lzfse_compressed_block_header_v1 *header1, lzfse_compressed_block_decoder_state *bs) {\n'
                 '  return frama_lzfse_decode_literals(s, header1, bs);\n}\n')
    functions.append('bridge_literal_step')
    # The Frama-C literal proof's table predicate is the CBMC one.
    parts.append('/*@ lemma literal_tables_agree: \\forall int32_t *t;\n'
                 '      cbmc_literal_table_ok(t) <==> frama_literal_table_valid(t);\n*/\n')
    return ''.join(parts), functions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arm', action='store_true')
    parser.add_argument('--output')
    parser.add_argument('--print', action='store_true')
    parser.add_argument('--only', help='comma-separated bridge functions')
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    margin = 64 if args.arm else 32
    generated, functions = generate(margin)
    if args.print:
        print(generated)
        return
    if args.only:
        functions = args.only.split(',')
    output = Path(args.output or ROOT / 'harness/build/proofs-frama-lzfse-bridge')
    output.mkdir(parents=True, exist_ok=True)
    verify('contract_bridge_' + str(margin), generated, output, functions, 100, split=True,
           include_dirs=['crates/crushlzfse/csrc'], timeout=args.timeout,
           allowed_warnings=(POINTER_FROM_WARNINGS,), parallelism=2)
    if args.mutants:
        for name in MUTANTS:
            mutated, functions = generate(margin, name)
            verify(name, mutated, output, functions, 100, expected=False, split=True,
                   include_dirs=['crates/crushlzfse/csrc'], timeout=30,
                   allowed_warnings=(POINTER_FROM_WARNINGS,), parallelism=2)


if __name__ == '__main__':
    main()
