#!/usr/bin/env python3
"""Native LZVN handlers; exhaustive dispatch comes from the shipping label table.

Only computed-goto syntax is normalized. This is not the separately implemented
portable switch decoder. Copy contracts are enforced by CBMC component targets.

The CBMC contract that callers consume (LZVN_DECODE_CONTRACT in
lzvn_decode_base.h) is translated clause by clause into ACSL and attached to a
wrapper that only calls lzvn_decode. WP then proves, over the same C state,
that the CBMC precondition implies this proof's precondition and that this
proof's postcondition and frame imply the CBMC ones. The translation is a fixed
primitive table (CBMC_TO_ACSL, OFFSET_PAIR); the CBMC object-size bound is the
one model assumption added.
"""
from pathlib import Path
import argparse
import re
import sys
sys.dont_write_bytecode = True
from wp_common import verify


# CBMC primitive -> ACSL. Pointers are (object, offset) in both models:
# same_object is base-address equality, and r_ok, rw_ok and object_upto name
# the same byte ranges. For a zero-length range the ACSL form is weaker than
# CBMC's, which is sound in a precondition; no postcondition uses one.
CBMC_TO_ACSL = {
    '__CPROVER_same_object': lambda a, b: f'(\\base_addr({a})==\\base_addr({b}))',
    '__CPROVER_r_ok': lambda p, n: (f'\\valid_read({p})' if n == f'sizeof *{p}'
                                    else f'\\valid_read({p}+(0 .. ({n})-1))'),
    '__CPROVER_rw_ok': lambda p, n: (f'\\valid({p})' if n == f'sizeof *{p}'
                                     else f'\\valid({p}+(0 .. ({n})-1))'),
    '__CPROVER_old': lambda x: f'\\old({x})',
    '__CPROVER_object_upto': lambda p, n: f'{p}[0 .. ({n})-1]',
    'LZVN_PROOF_RANGES_DISJOINT': lambda a, an, b, bn: f'\\separated({a}+(0 .. ({an})-1), {b}+(0 .. ({bn})-1))',
}
# CBMC offsets are only compared or subtracted in pairs. Within one object
# that equals ACSL pointer comparison or subtraction; contract_pairs() checks
# the contract itself states each pair shares an object.
OFFSET_PAIR = re.compile(r'LZVN_DECODE_OFF\(((?:[^()]|\([^()]*\))*)\)\s*(-|<=|>=|<|>)\s*'
                         r'LZVN_DECODE_OFF\(((?:[^()]|\([^()]*\))*)\)')


def split_args(text):
    args, depth, start = [], 0, 0
    for i, c in enumerate(text):
        depth += {'(': 1, ')': -1}.get(c, 0)
        if c == ',' and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
    return args + [text[start:].strip()]


def close(text, start):
    depth = 1
    for i in range(start, len(text)):
        depth += {'(': 1, ')': -1}.get(text[i], 0)
        if depth == 0:
            return i
    raise AssertionError('unbalanced contract')


def to_acsl(expr):
    expr = OFFSET_PAIR.sub(lambda m: f'({m.group(1)} {m.group(2)} {m.group(3)})', expr)
    assert 'LZVN_DECODE_OFF' not in expr, expr
    pattern = re.compile(r'(' + '|'.join(map(re.escape, CBMC_TO_ACSL)) + r')\(')
    while (m := pattern.search(expr)):
        end = close(expr, m.end())
        args = [to_acsl(a) for a in split_args(expr[m.end():end])]
        expr = expr[:m.start()] + CBMC_TO_ACSL[m.group(1)](*args) + expr[end + 1:]
    assert '__CPROVER' not in expr, expr
    return expr


def cbmc_contract(header):
    """The clauses of LZVN_DECODE_CONTRACT, in order."""
    text = header.split('#define LZVN_DECODE_CONTRACT', 1)[1].split('\n#endif', 1)[0]
    text = ' '.join(text.replace('\\\n', ' ').split())
    clauses, rest, i = [], '', 0
    for m in re.finditer(r'__CPROVER_(requires|assigns|ensures)\(', text):
        if m.start() < i:
            continue
        rest += text[i:m.start()]
        end = close(text, m.end())
        clauses.append((m.group(1), text[m.end():end]))
        i = end + 1
    assert not (rest + text[i:]).strip(), 'unparsed contract text'
    assert [k for k, _ in clauses].count('assigns') == 1
    contract_pairs(clauses)
    return clauses


def contract_pairs(clauses):
    """Every offset pair names one object, by the contract's own clauses.

    Pre-state terms are joined by requires same_object clauses, post-state
    terms by ensures same_object clauses, and an ensures X == old(X) joins
    the two states of X.
    """
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            x = parent[x]
        return x

    def term(t, post):
        t = t.strip()
        m = re.fullmatch(r'__CPROVER_old\((.*)\)', t)
        return ('pre', m.group(1)) if m else (('post' if post else 'pre'), t)

    for kind, expr in clauses:
        post = kind == 'ensures'
        for a, b in re.findall(r'(?<!!)__CPROVER_same_object\(([^,]+),([^)]+)\)', expr):
            parent[find(term(a, post))] = find(term(b, post))
        m = re.fullmatch(r'(state->\w+) == __CPROVER_old\((state->\w+)\)', expr.strip())
        if post and m and m.group(1) == m.group(2):
            parent[find(('post', m.group(1)))] = find(('pre', m.group(1)))
    pairs = 0
    for kind, expr in clauses:
        for a, _, b in OFFSET_PAIR.findall(expr):
            ta, tb = term(a, kind == 'ensures'), term(b, kind == 'ensures')
            assert find(ta) == find(tb), f'offset pair across objects: {a}, {b}'
            pairs += 1
    assert pairs >= 10


def alignment(header):
    """ACSL wrapper whose contract is the translated CBMC contract."""
    lines = []
    for kind, expr in cbmc_contract(header):
        if kind == 'assigns':
            lines.append('assigns ' + ','.join(to_acsl(a) for a in split_args(expr)) +
                         ' \\from state,*state,state->src[0 .. state->src_end-state->src-1],'
                         'state->dst_begin[0 .. state->dst_end-state->dst_begin-1];')
        else:
            lines.append(f'{kind} {to_acsl(expr)};')
    # CBMC objects hold fewer than 2^(64-object_bits) bytes (run.sh uses 10).
    lines.insert(0, 'requires cbmc_object_size: state->src_end-state->src<=PTRDIFF_MAX && '
                 'state->dst_end-state->dst_begin<=PTRDIFF_MAX;')
    return ('\n/*@ ' + '\n    '.join(lines) + '\n*/\n'
            'void lzvn_decode_cbmc_contract(lzvn_decoder_state *state) {\n'
            '  lzvn_decode(state);\n}\n')


def generate(source, header, internal):
    table = source.split('static const void *opc_tbl[256] = {', 1)[1].split('};', 1)[0]
    labels = re.findall(r'&&([a-z_]+)', table)
    assert len(labels) == 256
    assert source.count('static const void *opc_tbl[256]') == 1
    assert len(re.findall(r'&&[a-z_]+', source)) == 256, 'label addresses outside the table'
    # The portable fallback must classify every opcode as the shipping table does.
    classes = source.split('static const unsigned char opc_class[256] = {', 1)[1].split('};', 1)[0]
    classes = [c.lower() for c in re.findall(r'LZVN_OPC_([A-Z_]+)', classes)]
    assert classes == labels, 'opc_class and opc_tbl disagree'
    state = header[header.index('typedef struct {'):header.index('} lzvn_decoder_state;') + len('} lzvn_decoder_state;')]
    macros = source[source.index('#define PTR_LEN_INC'):source.index('#ifdef LZVN_PROOF')]
    start = source.index('#else\n  const unsigned char *src_ptr = state->src;')
    body = source[start+len('#else\n'):source.index('\n// API entry points', start)]
    loop = body.index('#ifdef LZVN_THREADED_PROOF')
    opening = body.index('  goto *opc_tbl[opc];', loop)
    body = body[:loop] + LOOP + '\n  {\n' + body[opening:]
    dispatch = 'switch (opc) {\n' + '\n'.join(
        ' '.join(f'case {i}:' for i, target in enumerate(labels) if target==label)
        + f' goto {label};' for label in dict.fromkeys(labels)) + '\n}'
    assert body.count('goto *opc_tbl[opc];') == 4
    body = body.replace('goto *opc_tbl[opc];', dispatch, 1)
    backedge = '''#ifdef LZVN_THREADED_PROOF
  continue;
#elif HAVE_LABELS_AS_VALUES
  goto *opc_tbl[opc];
#else
  continue;
#endif'''
    assert body.count(backedge) == 3
    body = body.replace(backedge, 'continue;')
    distance_guard='    goto invalid_match_distance;'
    # Two guards, as on main's layout: the literal+match ops check the full
    # range; the match-only ops (copy_match) reject only D == 0 and rely on
    # the loop invariant D <= dst_ptr - dst_begin for the upper bound.
    assert body.count(distance_guard)==2
    body=body.replace(distance_guard,distance_guard+r'''
  /*@ assert copy_distance: 1<=D<=dst_ptr-state->dst_begin; */''')
    # WP does not discharge the bitwise sml_d distance in the copy guard, so
    # it calls a function whose contract is that range. lzvn_small_distance
    # (CBMC) proves the identical expression, checked textually here, over
    # every opcode and second byte.
    distance_expression='(size_t)extract(opc, 0, 3) << 8 | src_ptr[1]'
    assert body.count(distance_expression)==1
    lemma=(Path(__file__).resolve().parents[1]/'lzvn_small_distance.c').read_text()
    assert 'static size_t proof_small_distance(uint8_t opc,uint8_t second)' in lemma
    assert '__CPROVER_ensures(__CPROVER_return_value<=2047)' in lemma
    assert '    return ' + distance_expression.replace('src_ptr[1]', 'second') + ';' in lemma
    assert 'const unsigned char *src_ptr = state->src;' in body
    body=body.replace(distance_expression,'proof_small_distance(opc, src_ptr[1])')
    assert 'goto *' not in body and 'opc_tbl' not in body
    assert body.endswith('#ifdef LZVN_THREADED_PROOF\n  }\n#endif\n#endif\n}\n')
    body = body[:-len('#ifdef LZVN_THREADED_PROOF\n  }\n#endif\n#endif\n}\n')] + '  }\n}\n'
    assert set(labels) <= set(re.findall(r'^([a-z_]+):', body, re.M))
    guard = source[source.index('  size_t src_len = state->src_end - state->src;'):source.index('#if !HAVE_LABELS_AS_VALUES\n  const unsigned char *const src')]
    # The full-domain bit extraction contract is enforced by lzvn_extract.
    assert 'LZFSE_INLINE uintmax_t extract(' in internal
    extract_declaration='uintmax_t extract(uintmax_t container,unsigned lsb,unsigned width);\n'
    return PREFIX + EXTRACT_CONTRACT + extract_declaration + state + '\n' + macros + CONTRACT + '''
void lzvn_decode(lzvn_decoder_state *state) {
  const unsigned char *const src_initial=state->src;
  unsigned char *const dst_initial=state->dst;
''' + guard + body + alignment(header)


PREFIX = r'''
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <assert.h>
typedef int64_t lzvn_offset;
/*@ requires \valid_read(p+(0 .. 1)); assigns \nothing; */
uint16_t load2(const unsigned char *p);
/* Contract proved for the shipping expression by the lzvn_small_distance
 * CBMC target; generate() checks the two expressions are identical. */
/*@ assigns \nothing; ensures 0<=\result<=2047; */
size_t proof_small_distance(uint8_t opc,uint8_t second);
/*@ requires D!=0;
    requires \valid_read(dst-D+(0 .. D-1));
    requires \valid(dst+(0 .. n-1));
    requires \valid(w);
    requires \separated(w,dst-D+(0 .. D+n-1));
    requires \base_addr(w)!=\base_addr(dst);
    assigns dst[0 .. n-1],*w,\result \from (dst-D)[0 .. D+n-1],n,D,M;
    ensures \result==(M>n ? 1:0);
    ensures *w==(M>n ? n:M);
    ensures 0<=*w<=M && *w<=n;
*/
int lzvn_copy_match(unsigned char *dst,size_t n,size_t D,size_t M,size_t *w);
/*@ requires L<=sn;
    requires \valid_read(src+(0 .. sn-1));
    requires \valid(dst+(0 .. dn-1));
    requires \valid(w);
    requires \separated(w,dst+(0 .. dn-1),src+(0 .. sn-1));
    requires \base_addr(w)!=\base_addr(dst) && \base_addr(w)!=\base_addr(src);
    assigns dst[0 .. dn-1],*w,\result \from src[0 .. sn-1],dn,sn,L;
    ensures \result==(L>dn ? 1:0);
    ensures *w==(L>dn ? dn:L);
    ensures 0<=*w<=L && *w<=dn;
*/
int lzvn_copy_literal(unsigned char *dst,size_t dn,const unsigned char *src,size_t sn,size_t L,size_t *w);
/*@ requires L<=3 && L<=sn;
    requires \valid_read(src+(0 .. sn-1));
    requires \valid(dst+(0 .. dn-1));
    requires \valid(w);
    requires \separated(w,dst+(0 .. dn-1),src+(0 .. sn-1));
    requires \base_addr(w)!=\base_addr(dst) && \base_addr(w)!=\base_addr(src);
    assigns dst[0 .. dn-1],*w,\result \from src[0 .. sn-1],dn,sn,L;
    ensures \result==(L>dn ? 1:0);
    ensures *w==(L>dn ? dn:L);
    ensures 0<=*w<=L && *w<=dn;
*/
int lzvn_copy_literal_short(unsigned char *dst,size_t dn,const unsigned char *src,size_t sn,size_t L,size_t *w);
'''

EXTRACT_CONTRACT = r'''
/* The exact CBMC contract also proves the bit value. Only its range is needed
 * here: keeping bitwise terms out of pointer inequalities improves WP's
 * arithmetic abstraction without changing the primitive being verified. */
/*@ requires lsb<64 && 0<width<64 && lsb+width<=64;
    assigns \nothing;
    ensures 0<=\result<((uintmax_t)1 << width);
*/
'''

CONTRACT = r'''
/* WP's mixed struct/byte memory model needs the C byte representation stated
 * explicitly after loop havoc. The domain includes every uint8_t value. */
/*@ requires \valid(state);
    requires \base_addr(state)!=\base_addr(state->src);
    requires \base_addr(state)!=\base_addr(state->dst_begin);
    requires \base_addr(state->src)==\base_addr(state->src_end);
    requires 0<=state->src_end-state->src<=PTRDIFF_MAX;
    requires \valid_read(state->src+(0 .. state->src_end-state->src-1));
    requires \forall integer k; 0<=k<state->src_end-state->src ==>
      0<=state->src[k]<=UCHAR_MAX;
    requires \base_addr(state->dst_begin)==\base_addr(state->dst);
    requires \base_addr(state->dst_begin)==\base_addr(state->dst_end);
    requires 0<=state->dst-state->dst_begin<=state->dst_end-state->dst_begin<=PTRDIFF_MAX;
    requires \valid(state->dst_begin+(0 .. state->dst_end-state->dst_begin-1));
    requires \separated(state,state->src+(0 .. state->src_end-state->src-1),state->dst_begin+(0 .. state->dst_end-state->dst_begin-1));
    requires 0<=state->d_prev<=state->dst-state->dst_begin;
    requires 0<=state->end_of_stream<=1 && 0<=state->truncated_mid_op<=1;
    assigns state->src,state->dst,state->d_prev,state->end_of_stream,state->truncated_mid_op,
      state->dst_begin[0 .. state->dst_end-state->dst_begin-1]
      \from state,state->src,state->src_end,state->dst,state->dst_begin,state->dst_end,
        state->d_prev,state->end_of_stream,state->truncated_mid_op,
        state->src[0 .. state->src_end-state->src-1],
        state->dst_begin[0 .. state->dst_end-state->dst_begin-1];
    ensures state->src_end==\old(state->src_end);
    ensures state->dst_begin==\old(state->dst_begin) && state->dst_end==\old(state->dst_end);
    ensures \base_addr(state->src)==\base_addr(state->src_end);
    ensures source_range: 0<=state->src-\old(state->src)<=state->src_end-\old(state->src);
    ensures \base_addr(state->dst)==\base_addr(state->dst_begin);
    ensures 0<=state->dst-\old(state->dst)<=state->dst_end-\old(state->dst);
    ensures 0<=state->d_prev<=state->dst-state->dst_begin;
    ensures 0<=state->end_of_stream<=1 && 0<=state->truncated_mid_op<=1;
*/
'''

LOOP = r'''
  /*@ loop invariant \base_addr(src_ptr)==\base_addr(src_initial);
      loop invariant 0<=src_ptr-src_initial<state->src_end-src_initial;
      loop invariant src_len==state->src_end-src_ptr;
      loop invariant \valid_read(src_ptr+(0 .. src_len-1));
      loop invariant \forall integer k; 0<=k<state->src_end-src_initial ==>
        0<=src_initial[k]<=UCHAR_MAX;
      loop invariant src_len>1 ==> 0<=src_ptr[1]<=UCHAR_MAX;
      loop invariant \base_addr(dst_ptr)==\base_addr(dst_initial);
      loop invariant 0<=dst_ptr-dst_initial<=state->dst_end-dst_initial;
      loop invariant dst_len==state->dst_end-dst_ptr;
      loop invariant \valid(dst_ptr+(0 .. dst_len-1));
      loop invariant \valid_read(state->dst_begin+(0 .. dst_ptr-state->dst_begin-1));
      loop invariant \separated(state,src_ptr+(0 .. src_len-1),
        state->dst_begin+(0 .. state->dst_end-state->dst_begin-1));
      loop invariant 0<=D<=dst_ptr-state->dst_begin;
      loop invariant opc==src_ptr[0];
      loop invariant \base_addr(state->src)==\base_addr(src_initial);
      loop invariant 0<=state->src-src_initial<=src_ptr-src_initial;
      loop invariant \base_addr(state->dst)==\base_addr(dst_initial);
      loop invariant 0<=state->dst-dst_initial<=dst_ptr-dst_initial;
      loop invariant 0<=state->d_prev<=state->dst-state->dst_begin;
      loop invariant 0<=state->end_of_stream<=1 && 0<=state->truncated_mid_op<=1;
      loop assigns src_ptr,dst_ptr,src_len,dst_len,D,M,L,opc_len,opc,l_written,m_written,
        state->src,state->dst,state->d_prev,state->end_of_stream,state->truncated_mid_op,
        state->dst_begin[0 .. state->dst_end-state->dst_begin-1];
      loop variant src_len;
  */
  for (;;)
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--mutants',action='store_true')
    parser.add_argument('--output')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[3]
    source=(root/'crates/crushlzfse/csrc/lzvn_decode_base.c').read_text()
    header=(root/'crates/crushlzfse/csrc/lzvn_decode_base.h').read_text()
    internal=(root/'crates/crushlzfse/csrc/lzfse_internal.h').read_text()
    output=root/(args.output or 'harness/build/proofs-frama-lzvn-decode-native')
    output.mkdir(parents=True,exist_ok=True)
    verify('decode_native',generate(source,header,internal),output,['lzvn_decode','lzvn_decode_cbmc_contract'],1600,split=True)
    if args.mutants:
        for name,old,new in [
            ('missing_header_bound','if (src_len <= opc_len + L)','if (0)'),
            ('missing_distance_bound','if (D > (size_t)(dst_ptr - state->dst_begin) || D == 0)','if (0)'),
            ('missing_zero_distance','  if (D == 0)\n    goto invalid_match_distance;','  if (0)\n    goto invalid_match_distance;'),
        ]:
            assert old in source
            verify(name,generate(source.replace(old,new),header,internal),output,['lzvn_decode'],100,False,split=True)
        # The alignment lemma must reject a CBMC contract this proof does not
        # establish: a missing destination-window precondition, and a
        # postcondition the body does not guarantee.
        for name,old,new in [
            ('cbmc_missing_window','__CPROVER_requires(__CPROVER_rw_ok(state->dst_begin,','__CPROVER_requires(1 || __CPROVER_rw_ok(state->dst_begin,'),
            ('cbmc_strict_progress','__CPROVER_ensures(LZVN_DECODE_OFF(state->src) >=','__CPROVER_ensures(LZVN_DECODE_OFF(state->src) >'),
        ]:
            assert header.count(old)==1
            verify(name,generate(source,header.replace(old,new),internal),output,['lzvn_decode_cbmc_contract'],10,False,split=True)


if __name__=='__main__':
    main()
