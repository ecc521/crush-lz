#!/usr/bin/env python3
"""Inventory registered proof boundaries without treating registration as success.

The JSON records explicit contract enforcement, replacement dependencies and
harness assumptions. A contract counts as enforced only when its target has
a complete passing log (verification and every reachability witness) in the
pinned replay, results-*.json, taken on the current proof tree. Absence of
an enforcing target is an audit obligation, even when a separate harness
executes the function body.
"""
import json
from pathlib import Path
import re
import shlex
import sys

# Targets whose passing logs check a reduced proof configuration rather than
# the shipping code. Their contracts are not counted as enforced.
LEGACY_TARGETS = {
    'lzfse_decode_literals': 'LZFSE_PROOF configuration: 64-state tables, bulk loop dropped, '
                             'copies replaced by assertions. Shipping loops: frama/lzfse_literals_native.py',
    'lzfse_decode_lmd': 'LZFSE_PROOF configuration: reduced tables and block limits, resume goto '
                        'removed, copies replaced by assertions. Shipping loop: frama/lzfse_lmd_native.py',
    'emit': 'LZVN_FAST_COPY configuration: runs capped, copies asserted without writes. '
            'Shipping body: frama/lzvn_match.py',
    'emit_literal': 'LZVN_FAST_COPY configuration: runs capped at 800, copies asserted without '
                    'writes. Shipping body: frama/lzvn_literal.py',
    'lzvn_decode': 'HAVE_LABELS_AS_VALUES=0 portable switch, which ships only without '
                   'labels-as-values (MSVC). Shipping computed-goto body: '
                   'frama/lzvn_decode_native.py, which also proves the CBMC contract',
}

# Targets removed from run.sh because another proof replaced them.
SUPERSEDED = {
    'lzvn_decode_threaded': 'CBMC on the computed-goto body exceeds memory in propositional '
                            'reduction (48 GiB full; 4-12 GiB for a single postcondition, with '
                            'or without array UFs, local state, object-bits 9, one opcode class, '
                            'or switch dispatch). Replaced by frama/lzvn_decode_native.py: the '
                            'shipping body plus a WP lemma that its contract implies '
                            'LZVN_DECODE_CONTRACT',
    'lz4_encode_core': 'CBMC on the multi-block framing loop with loop contracts exceeds memory '
                       'in propositional reduction (32+ GiB). Replaced by frama/lz4_frame.py '
                       '(shipping framing loop: 738/738 goals, 3/3 mutants rejected) and '
                       'lz4_encode_allocation (allocation, scratch alignment, and encode contract: '
                       '8/8 reachability witnessed, short-scratch mutant caught).',
    'lzvn_zopt_build_candidates': 'CBMC on the binary tree candidate search exceeds memory in '
                                  'propositional reduction. Replaced by frama/lzvn_zopt_build_candidates.py '
                                  '(shipping candidate search loop: 889/889 goals proved, 3/3 mutants rejected).',
    'lzfse_zopt_build_candidates': 'CBMC on the binary tree candidate search exceeds memory in '
                                   'propositional reduction. Replaced by frama/lzfse_zopt_build_candidates.py '
                                   '(shipping candidate search loop: 614/614 goals proved, 3/3 mutants rejected).',
}

# Contracts declared only for a dispatcher harness. No target enforces them;
# their write frames are supersets and their ensures clauses are assumptions.
UNENFORCED_DISPATCH = {}

# Registered targets that are trials, not evidence, even if they pass.
OPEN_TARGETS = {}

# Passing targets whose replaced callees use proof-interface contracts rather
# than the registered ones. Evidence only once those interfaces are enforced.
INTERFACE_DEPENDENT = {}

TRUSTED = {
    'proof_memcpy': 'C memcpy range, separation and write-frame model',
    'proof_memmove': 'C memmove range and write-frame model; overlap allowed',
    'proof_memset': 'C memset range and write-frame model',
    'LZ4_compress_fast_extState': 'Excluded upstream LZ4 implementation',
    'LZ4_compress_HC_extStateHC': 'Excluded upstream LZ4 implementation',
}

EXTERNAL_PROOFS = {
    'emit_literal': ('lzvn_literal.py', 'production body and matching progress/frame contract; lzvn_store2 and lzvn_copy8 close footprint dependencies'),
    'emit': ('lzvn_match.py', 'production body, arbitrary run lengths and progress/frame guarantees; store2/store4/load4 and copy64 footprint dependencies are enforced separately'),
    'lzvn_encode_greedy_wide': ('lzvn_greedy_loop.py', 'shipping loop and seven native width specializations; depends on the CBMC step and load4 footprints; scratch interval geometry proved by crushlzvn_scratch; caller alias assumptions and cross-tool write frame still require review'),
    'lzfse_declared_len': ('lzfse_declared_len.py', 'shipping framing loop with byte-normalized packed-header boundary; depends on exact header-size, unpacker and checker targets'),
    'proof_lz4_frame': ('lz4_frame.py', 'shipping framing loop; CBMC allocation establishes scratch geometry/alignment'),
    'lzvn_decode': ('lzvn_decode_native.py', 'shipping computed-goto body and all 256 table entries; the wrapper lzvn_decode_cbmc_contract proves the translated LZVN_DECODE_CONTRACT from the body contract; copy, extract and small-distance contracts are CBMC targets'),
    'lzvn_encode_fast_impl': ('lzvn_fast_loop.py', 'shipping fast loop and 14 mode specializations (108/108 goals, progress mutant rejected); depends on crushlzfse_fast_find and emitter contracts'),
    'proof_zbm_frame': ('zbm_frame.py', 'shipping framing loop induction (147/147 goals, 3/3 mutants rejected); proves spatial safety, loop variant termination, base address preservation, and output length bound'),
    'lzfse_decode_literals': ('lzfse_literals_native.py', 'shipping literal loop (625/625 64-bit, 192/192 32-bit); frame interface contract verified via frama/lzfse_frame_step_bridge.py (132/132 goals) with table row predicates from lzfse_table_builder_bridge'),
    'lzfse_decode_literals_baseline': ('lzfse_literals_native.py', 'baseline literal hot loop; verified via frama/lzfse_literals_native.py and frama/lzfse_frame_step_bridge.py'),
    'lzfse_decode_literals_bmi2': ('lzfse_literals_native.py', 'BMI2 literal hot loop clone, token-identical to baseline (simd/check_bmi2_clone.py); verified via frama/lzfse_literals_native.py and frama/lzfse_frame_step_bridge.py'),
    'lzfse_decode_lmd': ('lzfse_lmd_native.py', 'shipping LMD loop (1,101/1,101 goals, 4/4 mutants rejected); frame interface contract verified via frama/lzfse_frame_step_bridge.py (132/132 goals) with table row predicates from lzfse_table_builder_bridge'),
    'lzfse_decode_lmd_baseline': ('lzfse_lmd_native.py', 'baseline LMD hot loop; verified via frama/lzfse_lmd_native.py and frama/lzfse_frame_step_bridge.py'),
    'lzfse_decode_lmd_bmi2': ('lzfse_lmd_native.py', 'BMI2 LMD hot loop clone, token-identical to baseline (simd/check_bmi2_clone.py); verified via frama/lzfse_lmd_native.py and frama/lzfse_frame_step_bridge.py'),
    'crushlzfse_encode_base_fast_impl': ('lzfse_fast_loop.py', 'shipping LZFSE fast loop across all 14 modes (99/99 goals, progress mutant rejected); depends on crushlzfse_fast_find and emitter contracts'),
    'crushlzfse_encode_base_lazy_hw': ('lzfse_lazy_loop.py', 'shipping LZFSE lazy loop across all lookahead modes (0..2) and hash widths (1..32) (234/234 goals, progress mutant rejected); depends on crushlzfse_lazy_search, crushlzfse_fast_emit, and backend literal contracts'),
    'lzfse_push_lmd': ('lzfse_push_lmd.py', 'shipping LZFSE push_lmd bounds, match and literal counting, and wide copy loop (85/85 goals, 3/3 mutants rejected); proves memory safety, termination, and state preservation'),
    'lzvn_pareto_total_cost': ('lzvn_pareto_total_cost.py', 'shipping LZVN Pareto total cost minimum search and bounds (40/40 goals, 3/3 mutants rejected); proves memory safety, termination, minimum property, and bounded cost'),
    'lzvn_zopt_commit': ('lzvn_zopt_commit.py', 'shipping LZVN optimal tuple commit loop (106/106 goals, 3/3 mutants rejected); proves spatial memory safety, loop variant termination, and output bounds under emit contracts'),
    'lzfse_zopt_find_splits': ('lzfse_zopt_find_splits.py', 'shipping LZFSE optimal split point search and insertion sort (155/155 goals, 3/3 mutants rejected); proves spatial memory safety, loop variant termination, and bounded splits'),
    'lzvn_zopt_build_candidates': ('lzvn_zopt_build_candidates.py', 'shipping LZVN candidate search and stride loop (889/889 goals, 3/3 mutants rejected); proves spatial memory safety, loop variant termination, struct field preservation, and candidate count bounds'),
    'lzfse_zopt_build_candidates': ('lzfse_zopt_build_candidates.py', 'shipping LZFSE candidate search and stride loop (614/614 goals, 3/3 mutants rejected); proves spatial memory safety, loop variant termination, state preservation, and candidate count bounds'),
    'lzfse_zopt_commit': ('lzfse_zopt_commit.py', 'shipping LZFSE optimal tuple commit loop (294/294 goals, 3/3 mutants rejected); proves spatial memory safety, loop variant termination, and output bounds under backend match/literal contracts'),
    'lzvn_pareto_run_dp': ('lzvn_pareto_run_dp.py', 'shipping LZVN Pareto DP dispatch across k2, k4, k6, and generic (246/246 goals, 3/3 mutants rejected); proves spatial memory safety, separation, return code, and tuple bounds'),
    'run_dp_range': ('lzfse_run_dp_range.py', 'shipping LZFSE run_dp_range dispatch, tuple bounds, and backtracking reconstruction (229/229 goals, 3/3 mutants rejected); proves spatial memory safety, loop variant termination, return code, and tuple bounds'),
}


def pinned_results(proofs):
    """The newest results file that records a proof tree hash."""
    for path in sorted(proofs.glob('results-*.json'), reverse=True):
        data = json.loads(path.read_text())
        if 'tree_sha256' in data:
            return path, data
    return None, None


def inventory(root, with_results=True):
    proofs = root / 'harness/proofs'
    runner = (proofs / 'run.sh').read_text().replace('\\\n', ' ')
    targets = []
    for line in runner.splitlines():
        if not line.startswith('register '):
            continue
        fields = shlex.split(line)
        _, name, source, include, defines, enforce, replace, *options = fields
        text = (proofs / source).read_text()
        targets.append(dict(name=name, source=source, include=include,
                            defines=defines, enforce=enforce,
                            replace=replace.split(), options=options,
                            assumptions=re.findall(
                                r'__CPROVER_assume\((.*?)\);', text, re.S)))
    if not with_results:
        return dict(targets=targets)

    sys.path.insert(0, str(proofs / 'frama'))
    from wp_common import tree_hash
    path, results = pinned_results(proofs)
    current = tree_hash(root)
    valid = results is not None and results['tree_sha256'] == current
    status = {p['name']: p['status'] for p in results['proofs']} if valid else {}
    frama_status = {f['script']: f['status'] for f in results['frama']} if valid else {}
    for target in targets:
        target['pinned_status'] = status.get(target['name'], 'not replayed')
        if target['name'] in LEGACY_TARGETS:
            target['legacy_configuration'] = LEGACY_TARGETS[target['name']]
        if target['name'] in OPEN_TARGETS:
            target['open'] = OPEN_TARGETS[target['name']]
        if target['name'] in INTERFACE_DEPENDENT:
            target['interface_dependent'] = INTERFACE_DEPENDENT[target['name']]

    enforcing, legacy, not_passing = {}, {}, {}
    for target in targets:
        function = target['enforce']
        if not function:
            continue
        if target['name'] in OPEN_TARGETS or target['pinned_status'] != 'pass':
            not_passing.setdefault(function, []).append(
                dict(target=target['name'], status=target['pinned_status']))
        elif target['name'] in LEGACY_TARGETS:
            legacy.setdefault(function, []).append(target['name'])
        else:
            enforcing.setdefault(function, []).append(target['name'])
    external = {}
    for function, (script, note) in EXTERNAL_PROOFS.items():
        external[function] = dict(script='frama/' + script, note=note,
                                  pinned_status=frama_status.get(script, 'not replayed'))
    unresolved = {}
    for target in targets:
        for function in target['replace']:
            if (function in enforcing or function in TRUSTED or
                    external.get(function, {}).get('pinned_status') == 'pass'):
                continue
            unresolved.setdefault(function, []).append(target['name'])
    return dict(
        pinned_results=dict(file=path.name if path else None,
                            commit=results.get('commit') if results else None,
                            tree_sha256=results.get('tree_sha256') if results else None,
                            current_tree_sha256=current, matches_current_tree=valid),
        targets=targets,
        explicit_contract_enforcement=enforcing,
        legacy_configuration_enforcement=legacy,
        contract_targets_not_passing=not_passing,
        unenforced_dispatch_contracts=UNENFORCED_DISPATCH,
        open_targets=OPEN_TARGETS,
        interface_dependent_targets=INTERFACE_DEPENDENT,
        superseded_targets=SUPERSEDED,
        trusted_models=TRUSTED,
        external_proof_boundaries=external,
        replacement_contracts_without_explicit_enforcement=unresolved,
        frama_targets={p.name: frama_status.get(p.name, 'not replayed')
                       for p in sorted((proofs / 'frama').glob('*.py'))
                       if p.name != 'wp_common.py'})


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[2]
    print(json.dumps(inventory(root), indent=2))
