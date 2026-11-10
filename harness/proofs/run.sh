#!/bin/sh
# CBMC proofs for the codec C sources. See README.md.
#
#   harness/proofs/run.sh            run every proof and its reachability goals
#   harness/proofs/run.sh mutants    check each proof fails on a known bug
#   harness/proofs/run.sh PROOF      run one proof, e.g. lz4_decode_block
#
# Proofs and mutants run in parallel, PROOF_JOBS at a time (default: one
# per CPU).
#
# Needs CBMC >= 6 (goto-cc, goto-instrument, cbmc on PATH).
set -eu

ROOT=${PROOF_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
PROOFS="$ROOT/harness/proofs"
LZ4_CSRC="$ROOT/crates/crushlz4/csrc"
ZBM_CSRC="$ROOT/crates/lzbitmap/csrc"
LZFSE_CSRC="$ROOT/crates/crushlzfse/csrc"
WORK=${PROOF_WORK:-"$ROOT/harness/build/proofs"}
mkdir -p "$WORK"
# CBMC's symbolic execution recurses deeply on large programs; the default
# 8 MiB stack segfaults on crushlzvn_encode_buffer.
ulimit -s unlimited 2>/dev/null || ulimit -s 1048576 2>/dev/null || true

# The C semantics the proofs assume: the shipping target is LP64,
# little-endian x86-64 or arm64. CaDiCaL proves lz4_decode_block in about
# 22 minutes; MiniSat, the default, had not finished when it did.
# --object-bits 10 because the contract instrumentation needs more than
# 256 objects.
CHECKS="--bounds-check --pointer-check --pointer-overflow-check \
        --signed-overflow-check --undefined-shift-check --div-by-zero-check \
        --object-bits 10 --sat-solver cadical"

# Every proof: name, harness source, the codec's source dir and proof
# defines, the function whose contract it proves (empty for an end-to-end
# proof of the harness itself), and functions whose calls are replaced by
# their contracts. A replaced function's contract must be proved by another
# proof in this list.
LZ4_DEFS="-DCLZ4_PROOF"
ZBM_DEFS="-DZBM_PROOF -DCRUSH_SIMD_PORTABLE"
LZVN_DEFS="-DLZVN_PROOF -DHAVE_LABELS_AS_VALUES=0 -DCRUSH_SIMD_PORTABLE"
LZVN_ENC_DEFS="-DLZVN_PROOF -DHAVE_LABELS_AS_VALUES=0 -DLZVN_FAST_COPY -DCRUSH_SIMD_PORTABLE"
# Shipping x86-64 builds target x86-64-v3, so __BMI2__ is defined and the
# decoder has no run-time BMI2 dispatch; the lzfse_dispatch_* targets
# undefine it to cover the pre-Haswell dispatch instead.
case "$(uname -m)" in
    x86_64|amd64) LZFSE_ISA_DEFS="-D__BMI__ -D__BMI2__" ;;
    *) LZFSE_ISA_DEFS="" ;;
esac
LZFSE_DEFS="-DLZFSE_PROOF -DHAVE_LABELS_AS_VALUES=0 -DCRUSH_SIMD_PORTABLE $LZFSE_ISA_DEFS"
# Native SIMD (simd/README.md): the shipping NEON or SSE branch of
# crush_simd.h, intrinsics replaced by the models through the shadow
# headers. A native target's source is simd/native_wrap.c, which includes
# NATIVE_TARGET and fails to compile unless that branch was taken; build()
# also runs a preflight. _neon targets need an aarch64 image; _sse targets
# forge the x86-64-v3 predefined macros on any host.
ZBM_NEON_DEFS="-DZBM_PROOF -I$PROOFS/simd/include -DNATIVE_ISA=1"
ZBM_SSE_DEFS="-DZBM_PROOF -I$PROOFS/simd/include -DNATIVE_ISA=2 \
    -U__aarch64__ -U__ARM_NEON -U__ARM_NEON__ -U__ARM_ARCH -U__ARM_64BIT_STATE \
    -D__x86_64__ -D__x86_64 -D__amd64__ -D__amd64 -D__SSE__ -D__SSE2__ -D__SSE3__ \
    -D__SSSE3__ -D__SSE4_1__ -D__SSE4_2__ -D__POPCNT__ -D__AVX__ -D__AVX2__ \
    -D__BMI__ -D__BMI2__ -D__LZCNT__ -D__FMA__ -D__MOVBE__ -D__F16C__"

# register NAME SRC INC DEFS ENFORCE REPLACE [UNWIND] [AUX_UNWIND] [CBMC_FLAGS]: add a proof to PROOF_LIST.
PROOF_LIST=""
# register NAME ... [UNWIND]: with UNWIND, the proof unrolls every loop up
# to UNWIND iterations instead of applying loop contracts. CBMC checks an
# unwinding assertion for each loop, so too small a bound fails the proof.
# A function's loops are either all contracted or all unrolled: DFCC loses
# track of an unrolled loop's locals once loop contracts are applied.
# AUX_UNWIND bounds residual instrumentation loops while retaining decoder
# loop contracts. Unwinding assertions must pass; no path is silently cut off.
register() {
    PROOF_LIST="$PROOF_LIST $1"
    eval "${1}_src=\$PROOFS/\$2 ${1}_inc=\$3 ${1}_defs=\$4 ${1}_enforce=\$5 ${1}_replace=\$6 ${1}_unwind=\${7:-} ${1}_aux_unwind=\${8:-} ${1}_cbmc_flags=\${9:-}"
}

register lz4_copy_match   lz4_copy_match.c   "$LZ4_CSRC" "$LZ4_DEFS" copy_match \
      "proof_memcpy"
register lz4_decode_block lz4_decode_block.c "$LZ4_CSRC" "$LZ4_DEFS" decode_block \
      "proof_memcpy copy_match"
register lz4_decode       lz4_decode.c       "$LZ4_CSRC" "$LZ4_DEFS" "" \
      "proof_memcpy decode_block"
register lz4_encode       lz4_encode.c       "$LZ4_CSRC" "$LZ4_DEFS" "" \
      "encode" "" "20" "--malloc-may-fail --arrays-uf-never"
register lz4_encode_allocation lz4_encode_core.c "$LZ4_CSRC" "$LZ4_DEFS -DCLZ4_ALLOC_PROOF" encode \
      "proof_lz4_frame" "" "20" "--malloc-may-fail --arrays-uf-always"
register lz4_put_le32     lz4_put_le32.c     "$LZ4_CSRC" "$LZ4_DEFS" put_le32 \
      "" "" "" "--arrays-uf-always"
register lz4_align lz4_align.c "$LZ4_CSRC" "$LZ4_DEFS" clz4_align ""
register lz4_encoder_queries lz4_encoder_queries.c "$LZ4_CSRC" "$LZ4_DEFS" "" ""
register fse_value_decode_u32 fse_value_decode_u32.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" fse_value_decode_u32 \
      "fse_in_pull64" "" "8" "--arrays-uf-always"
register fse_literal_row fse_table_rows.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" literal_row ""
register fse_literal_table_valid fse_literal_table_valid.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_TABLE_VALUE_PROOF -DLZFSE_TABLE_PREFIX_SUMMARY" "" "" "" "" "--arrays-uf-always"
register fse_literal_table_preserve fse_literal_table_valid.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_TABLE_VALUE_PROOF -DLZFSE_TABLE_PREFIX_SUMMARY -DPROOF_VALID_SEED" "" "" "" "" "--arrays-uf-always"
register fse_literal_table_preserve_frame fse_literal_table_preserve.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_TABLE_VALUE_PROOF -DLZFSE_TABLE_PREFIX_SUMMARY" "" "" "" "" "--arrays-uf-always"
register fse_value_symbol_bounds fse_value_symbol_bounds.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" "" "" "" "" "--arrays-uf-never"
register fse_value_symbol_row fse_value_symbol_row.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" "" "" "" "" "--arrays-uf-never"
register fse_l_table_coverage fse_value_table_coverage.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_VALUE_TABLE_PROOF -DLZFSE_VALUE_COVERAGE_PROOF -DLZFSE_TABLE_PREFIX_SUMMARY -DPROOF_VALUE_KIND=0" "" "" "" "" "--arrays-uf-always"
register fse_m_table_coverage fse_value_table_coverage.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_VALUE_TABLE_PROOF -DLZFSE_VALUE_COVERAGE_PROOF -DLZFSE_TABLE_PREFIX_SUMMARY -DPROOF_VALUE_KIND=1" "" "" "" "" "--arrays-uf-always"
register fse_d_table_coverage fse_value_table_coverage.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_VALUE_TABLE_PROOF -DLZFSE_VALUE_COVERAGE_PROOF -DLZFSE_TABLE_PREFIX_SUMMARY -DPROOF_VALUE_KIND=2" "" "" "" "" "--arrays-uf-always"
register fse_l_table_preserve fse_value_table_coverage.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_VALUE_TABLE_PROOF -DLZFSE_VALUE_COVERAGE_PROOF -DLZFSE_TABLE_PREFIX_SUMMARY -DPROOF_VALUE_KIND=0 -DPROOF_VALID_SEED" "" "" "" "" "--arrays-uf-always"
register fse_m_table_preserve fse_value_table_coverage.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_VALUE_TABLE_PROOF -DLZFSE_VALUE_COVERAGE_PROOF -DLZFSE_TABLE_PREFIX_SUMMARY -DPROOF_VALUE_KIND=1 -DPROOF_VALID_SEED" "" "" "" "" "--arrays-uf-always"
register fse_d_table_preserve fse_value_table_coverage.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_VALUE_TABLE_PROOF -DLZFSE_VALUE_COVERAGE_PROOF -DLZFSE_TABLE_PREFIX_SUMMARY -DPROOF_VALUE_KIND=2 -DPROOF_VALID_SEED" "" "" "" "" "--arrays-uf-always"
register fse_value_row fse_table_rows.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DPROOF_VALUE_ROW" value_row ""
register lzfse_decoder_tables_zero lzfse_decoder_tables_zero.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" "" "" "" "" "--arrays-uf-never"
register lzfse_table_predicate_bridge lzfse_table_predicate_bridge.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" "" "" "" "" "--arrays-uf-never"
register lzfse_table_builder_bridge lzfse_table_builder_bridge.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" "" "" "" "" "--arrays-uf-never"
register fse_value_unpack fse_value_unpack.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" proof_fse_value_unpack "" "" "9"
register lzfse_literal_bulk_span lzfse_literal_bulk_span.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" proof_literal_bulk_span ""
register lzfse_lmd_distance_check lzfse_lmd_distance_check.c "$LZFSE_CSRC" "$LZFSE_DEFS" "" ""
register lzfse_declared_len lzfse_declared_len.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" lzfse_declared_len \
      "proof_memcpy lzfse_decode_v1 lzfse_check_block_header_v1" "" "12" "--arrays-uf-always"
register lzfse_declared_len_alias lzfse_declared_len_alias.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" "" \
      "proof_memcpy" "1"
register lzfse_declared_len_short lzfse_declared_len_short.c "$LZFSE_CSRC" "-DCRUSH_SIMD_PORTABLE" "" "proof_memcpy" "1"
register lzfse_header_size lzfse_header_size.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" proof_header_size ""
register fse_decode_u32 fse_decode_u32.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" fse_decode_u32 \
      "fse_in_pull64" "" "8" "--arrays-uf-always"
register fse_decode_u32_32 fse_decode_u32_32.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -U_M_AMD64 -U__x86_64__ -U__arm64__ -U__aarch64__ -U_M_ARM64" fse_decode_u32 \
      "fse_in_pull32" "" "1025" "--arrays-uf-always"
register fse_in_pull64 fse_in_pull.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" fse_in_pull64 ""
register fse_in_pull32 fse_in_pull.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DPROOF_PULL32" fse_in_pull32 ""
register fse_in_init64 fse_in_init.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" fse_in_checked_init64 "proof_memcpy"
register fse_in_init32 fse_in_init.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DPROOF_INIT32" fse_in_checked_init32 "proof_memcpy"
register fse_in_flush64 fse_in_flush.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" fse_in_checked_flush64 "proof_memcpy"
register fse_in_flush32 fse_in_flush.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DPROOF_FLUSH32" fse_in_checked_flush32 "proof_memcpy"
register fse_in_flush64_unchecked fse_in_flush_unchecked.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" fse_in_flush64_unchecked "proof_memcpy"
register fse_in_flush_next fse_in_flush_next.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" fse_in_flush_next "proof_memcpy"

register lzvn_copy_match   lzvn_copy_match.c   "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_copy_match \
      "proof_memcpy"
register lzvn_copy_literal lzvn_copy_literal.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_copy_literal \
      "proof_memcpy"
register lzvn_copy_literal_short lzvn_copy_literal_short.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_copy_literal_short \
      "proof_memcpy"
register lzvn_decode       lzvn_decode.c       "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_decode \
      "lzvn_copy_match lzvn_copy_literal" "" "" "--arrays-uf-always"
register lzvn_decode_buffer lzvn_decode_buffer.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_decode_buffer \
      "lzvn_decode" "" "8" "--arrays-uf-always"
register crushlzvn_decode_buffer crushlzvn_decode_buffer.c "$LZFSE_CSRC" "$LZVN_DEFS" crushlzvn_decode_buffer \
      "lzvn_decode" "" "8" "--arrays-uf-always"
register lzvn_decode_resume lzvn_decode_resume.c "$LZFSE_CSRC" "$LZVN_DEFS" "" \
      "lzvn_decode" "" "8" "--arrays-uf-always"
register lzvn_copy8        lzvn_copy8.c        "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_copy8 \
      "proof_memcpy"
register lzvn_copy64       lzvn_copy64.c       "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_copy64 \
      "proof_memcpy"
register lzvn_encode_greedy_init_table lzvn_encode_greedy_init_table.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_encode_greedy_init_table \
      ""
register emit_literal      emit_literal.c      "$LZFSE_CSRC" "$LZVN_ENC_DEFS" emit_literal \
      "" 4
register emit_literal_exact emit_literal.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZVN_EXACT_EMIT -DLZFSE_COPY_PROOF -DLZVN_COPY_SUMMARY" emit_literal \
      "proof_memcpy" "" "8" "--arrays-uf-always"
register lzvn_store4 lzvn_words.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZFSE_COPY_PROOF" proof_store4 \
      "proof_memcpy" "" "" "--arrays-uf-always"
register lzvn_load4 lzvn_words.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZFSE_COPY_PROOF -DPROOF_WORD_LOAD" proof_load4 \
      "proof_memcpy" "" "" "--arrays-uf-always"
register lzvn_load2 lzvn_words.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZFSE_COPY_PROOF -DPROOF_WORD_LOAD -DPROOF_WORD16" proof_load2 \
      "proof_memcpy" "" "" "--arrays-uf-always"
register lzvn_extract lzvn_extract.c "$LZFSE_CSRC" "-DCRUSH_SIMD_PORTABLE" proof_extract ""
register lzvn_small_distance lzvn_small_distance.c "$LZFSE_CSRC" "-DCRUSH_SIMD_PORTABLE" proof_small_distance ""
register lzvn_store2 lzvn_store2.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZFSE_COPY_PROOF" proof_store2 \
      "proof_memcpy" "" "" "--arrays-uf-always"
register emit_literal_tail emit_literal.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZVN_EXACT_EMIT -DLZFSE_COPY_PROOF -DLZVN_COPY_SUMMARY -DPROOF_LITERAL_TAIL" emit_literal \
      "proof_memcpy" "8" "" "--arrays-uf-always"
register emit_match_tail emit.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZVN_EXACT_EMIT -DLZFSE_COPY_PROOF -DPROOF_MATCH_TAIL" emit \
      "proof_memcpy" "4" "" "--arrays-uf-always"
register emit              emit.c              "$LZFSE_CSRC" "$LZVN_ENC_DEFS" emit \
      "" 4
register lzvn_emit_end_of_stream lzvn_emit_end_of_stream.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_emit_end_of_stream \
      ""
register lzvn_emit_end_exact lzvn_emit_end_of_stream.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZFSE_COPY_PROOF -DLZVN_EXACT_EMIT" lzvn_emit_end_of_stream \
      "proof_memcpy" "" "8" "--arrays-uf-always"
register lzvn_emit_literal lzvn_emit_literal.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_emit_literal \
      "emit_literal" "" "8" "--arrays-uf-always"
register lzvn_emit_match   lzvn_emit_match.c   "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_emit_match \
      "emit" "" "8" "--arrays-uf-always"
register lzvn_encode_literal_only_buffer lzvn_encode_literal_only_buffer.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZFSE_COPY_PROOF" lzvn_encode_literal_only_buffer \
      "proof_memcpy emit_literal" "" "8" "--arrays-uf-always"
register lzvn_match_extend lzvn_match_extend.c "$LZFSE_CSRC" "$LZVN_DEFS" match_extend \
      ""
register lzvn_find_matchN  lzvn_find_matchN.c  "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_find_matchN \
      "match_extend"
register crushlzvn_encode_bound crushlzvn_encode_bound.c "$LZFSE_CSRC" "$LZVN_DEFS" "" \
      ""
register crushlzvn_params crushlzvn_params.c "$LZFSE_CSRC" "$LZVN_DEFS" "" \
      ""
register crushlzvn_scratch crushlzvn_scratch.c "$LZFSE_CSRC" "$LZVN_DEFS" "" \
      ""
register crushlzvn_encode_buffer crushlzvn_encode_buffer.c "$LZFSE_CSRC" "$LZVN_DEFS -DCRUSHLZVN_DISPATCH_PROOF" crushlzvn_encode_buffer_advanced \
      "proof_memcpy proof_memset lzvn_encode_greedy_wide_buffer lzvn_encode_literal_only_buffer lzvn_encode_fast_buffer lzvn_encode_optimal_buffer_pareto" "" "" "--malloc-may-fail --arrays-uf-always"
register lzvn_greedy_wide_step lzvn_greedy_wide_step.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_greedy_wide_step \
      "lzvn_emit_match lzvn_emit_literal lzvn_find_matchN" "" "8" "--arrays-uf-always"
register lzvn_encode_greedy_wide lzvn_encode_greedy_wide.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_encode_greedy_wide \
      "lzvn_greedy_wide_step" "" "8" "--arrays-uf-always --unwindset __CPROVER_contracts_write_set_check_assigns_clause_inclusion.0:16"
register lzvn_encode_greedy_wide_native lzvn_encode_greedy_wide.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZVN_NATIVE_GREEDY_DISPATCH" lzvn_encode_greedy_wide \
      "lzvn_greedy_wide_step" "" "8" "--arrays-uf-always --unwindset __CPROVER_contracts_write_set_check_assigns_clause_inclusion.0:16"
register lzvn_encode_greedy_wide_buffer lzvn_encode_greedy_wide_buffer.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_encode_greedy_wide_buffer \
      "lzvn_encode_greedy_init_table lzvn_encode_greedy_wide lzvn_emit_literal lzvn_emit_end_of_stream" "" "32" "--arrays-uf-always"
register lzvn_encode_fast_buffer lzvn_encode_fast_buffer.c "$LZFSE_CSRC" "$LZVN_DEFS" lzvn_encode_fast_buffer \
      "lzvn_encode_fast_impl" "" "" "--arrays-uf-always"
register lzvn_pareto_insert lzvn_pareto_insert.c "$LZFSE_CSRC" "$LZVN_DEFS" "" \
      "" "34" "" "--arrays-uf-always"
register lzvn_fast_skip_step lzvn_fast_skip_step.c "$LZFSE_CSRC" "$LZVN_DEFS" "" ""
register lzvn_encode_optimal_buffer_pareto lzvn_encode_optimal_buffer_pareto.c "$LZFSE_CSRC" "$LZVN_DEFS -DLZVN_OPTIMAL_PROOF" lzvn_encode_optimal_buffer_pareto \
      "lzvn_zopt_build_candidates lzvn_pareto_run_dp lzvn_pareto_total_cost lzvn_zopt_commit" "" "" "--arrays-uf-always"

register lzfse_copy_match_bytes lzfse_copy_match_bytes.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_COPY_PROOF" lzfse_copy_match_bytes \
      "" "" "" "--arrays-uf-always"
register lzfse_copy_literal_bytes lzfse_copy_literal_bytes.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_COPY_PROOF" lzfse_copy_literal_bytes \
      "" "" "" "--arrays-uf-always"
register lzfse_copy lzfse_copy.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_COPY_PROOF" copy \
      "proof_memcpy" "" "" "--arrays-uf-always"
register lzfse_copy_literal_wide lzfse_copy_literal_wide.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_COPY_PROOF" copy_literal_wide \
      "proof_memcpy" "" "" "--arrays-uf-always"
register lzfse_copy_match_wide lzfse_copy_match_wide.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_COPY_PROOF" copy_match_wide \
      "proof_memcpy" "" "" "--arrays-uf-always"
register lzfse_copy_match_periodic lzfse_copy_match_periodic.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_COPY_PROOF" copy_match_periodic \
      "proof_memcpy copy_match_wide" 8
register lzfse_copy_match lzfse_copy_match.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_COPY_PROOF" lzfse_copy_match \
      "copy_match_wide copy_match_periodic copy" "" "" "--arrays-uf-always"
register lzfse_check_block_header_v1 lzfse_check_block_header_v1.c "$LZFSE_CSRC" "$LZFSE_DEFS" lzfse_check_block_header_v1 \
      "" 257
register fse_init_decoder_table fse_init_decoder_table.c "$LZFSE_CSRC" "$LZFSE_DEFS" fse_init_decoder_table \
      "proof_memcpy"
register fse_init_value_decoder_table fse_init_value_decoder_table.c "$LZFSE_CSRC" "$LZFSE_DEFS" fse_init_value_decoder_table \
      "proof_memcpy"
register lzfse_decode_v1 lzfse_decode_v1.c "$LZFSE_CSRC" "$LZFSE_DEFS" lzfse_decode_v1 \
      "proof_memcpy"
register lzfse_decode_v1_exact lzfse_decode_v1.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_COPY_PROOF" lzfse_decode_v1 \
      "proof_memcpy" "" "8" "--arrays-uf-always"
register lzfse_check_block_header_v1_exact lzfse_check_block_header_v1.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" lzfse_check_block_header_v1 \
      "" 257
register lzfse_decode_literals lzfse_decode_literals.c "$LZFSE_CSRC" "$LZFSE_DEFS" lzfse_decode_literals \
      "store4"
register lzfse_decode_lmd lzfse_decode_lmd.c "$LZFSE_CSRC" "$LZFSE_DEFS" lzfse_decode_lmd ""
register lzfse_lmd_resume_tuples lzfse_lmd_resume_tuples.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" "" \
      "fse_in_flush_next fse_value_decode_u32 copy_literal_wide lzfse_copy_match lzfse_copy_literal_bytes lzfse_copy_match_bytes" "257" "" "--unwindset lzfse_decode_lmd_baseline.0:4"
register lzfse_lmd_resume lzfse_lmd_resume.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_LMD_RESUME_PROOF" "" "copy_literal_wide lzfse_copy_match lzfse_copy_literal_bytes lzfse_copy_match_bytes" "" "" "--arrays-uf-always"
LZFSE_FRAME_DEFS="$LZFSE_DEFS -DLZFSE_EXACT_FSE -DLZFSE_PROOF_FRAME_INTERFACE"
register lzfse_decode_frame lzfse_decode_frame.c "$LZFSE_CSRC" "$LZFSE_FRAME_DEFS" lzfse_decode \
      "proof_memcpy lzfse_decode_v1 lzfse_check_block_header_v1 fse_in_checked_init64 fse_init_decoder_table fse_init_value_decoder_table lzfse_decode_literals lzfse_decode_lmd lzvn_decode"
register lzfse_decode_frame_shared lzfse_decode_frame.c "$LZFSE_CSRC" "$LZFSE_FRAME_DEFS -DPROOF_SHARED_ONLY" lzfse_decode \
      "proof_memcpy lzfse_decode_v1 lzfse_check_block_header_v1 fse_in_checked_init64 fse_init_decoder_table fse_init_value_decoder_table lzfse_decode_literals lzfse_decode_lmd lzvn_decode"
LZFSE_X86_DISPATCH_DEFS="$LZFSE_FRAME_DEFS -I$PROOFS/simd/include -U__aarch64__ -U__arm64__ -U__BMI2__ -D__x86_64__=1"
register lzfse_dispatch_literals lzfse_dispatch.c "$LZFSE_CSRC" "$LZFSE_X86_DISPATCH_DEFS" lzfse_decode_literals \
      "lzfse_decode_literals_baseline lzfse_decode_literals_bmi2"
register lzfse_dispatch_lmd lzfse_dispatch.c "$LZFSE_CSRC" "$LZFSE_X86_DISPATCH_DEFS -DPROOF_DISPATCH_LMD" lzfse_decode_lmd \
      "lzfse_decode_lmd_baseline lzfse_decode_lmd_bmi2"
register store4 store4.c "$LZFSE_CSRC" "$LZFSE_DEFS" store4 ""
register lzfse_decode_buffer_with_scratch lzfse_decode_buffer.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE -DPROOF_WITH_SCRATCH" lzfse_decode_buffer_with_scratch \
      "lzfse_decode"
register lzfse_decode_buffer lzfse_decode_buffer.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" lzfse_decode_buffer \
      "lzfse_decode_buffer_with_scratch" "" "" "--malloc-may-fail --malloc-fail-null"
register crushlzfse_decode_buffer crushlzfse_decode_buffer.c "$LZFSE_CSRC" "$LZFSE_DEFS -DLZFSE_EXACT_FSE" crushlzfse_decode_buffer \
      "lzfse_decode" "" "" "--malloc-may-fail --malloc-fail-null"
register crushlzfse_params crushlzfse_params.c "$LZFSE_CSRC" "$LZFSE_DEFS" "" \
      ""
register crushlzfse_fast_hash crushlzfse_fast_hash.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_FAST_HASH_PROOF" crushlzfse_fast_hash \
      ""
register crushlzfse_fast_index_match crushlzfse_fast_index_match.c "$LZFSE_CSRC" "$LZFSE_DEFS" "" \
      "crushlzfse_fast_hash"
register crushlzfse_fast_best crushlzfse_fast_best.c "$LZFSE_CSRC" "$LZFSE_DEFS" "" \
      "match_extend"
register crushlzfse_fast_find crushlzfse_fast_find.c "$LZFSE_CSRC" "$LZFSE_DEFS" "" \
      "match_extend" "18" "" "--arrays-uf-always"
register crushlzfse_encode_bound crushlzfse_encode_bound.c "$LZFSE_CSRC" "$LZFSE_DEFS" "" \
      ""
register crushlzfse_scratch crushlzfse_scratch.c "$LZFSE_CSRC" "$LZFSE_DEFS" "" \
      ""
register write_uncompressed_block write_uncompressed_block.c "$LZFSE_CSRC" "$LZFSE_DEFS" write_uncompressed_block \
      "proof_memcpy"
register lzfse_encode_init lzfse_encode_init.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF" lzfse_encode_init ""
register crushlzfse_encode_base_fast crushlzfse_encode_base_fast.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF" crushlzfse_encode_base_fast \
      "crushlzfse_encode_base_fast_impl" "" "" "--arrays-uf-always"
register crushlzfse_encode_base_lazy crushlzfse_encode_base_lazy.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF" crushlzfse_encode_base_lazy \
      "crushlzfse_encode_base_lazy_hw" "" "" "--arrays-uf-always"
register lzfse_encode_base lzfse_base.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF -DLZFSE_BASE_PROOF" lzfse_encode_base \
      "lzfse_backend_literals lzfse_zopt_build_candidates run_dp_range lzfse_zopt_find_splits lzfse_zopt_commit" "" "" "--arrays-uf-always"
register lzfse_encode_finish lzfse_encode_finish.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF" lzfse_encode_finish \
      "lzfse_backend_match lzfse_encode_matches proof_memcpy" "" "" "--arrays-uf-always"
register crushlzfse_encode_buffer crushlzfse_encode_buffer.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF" "" \
      "proof_memcpy proof_memset write_uncompressed_block lzfse_encode_init lzfse_encode_finish crushlzfse_encode_base_fast crushlzfse_encode_base_lazy lzfse_encode_base crushlzvn_encode_buffer_advanced"
register crushlzfse_encode_buffer_chained crushlzfse_encode_buffer_chained.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF" "" \
      "proof_memcpy write_uncompressed_block lzfse_encode_init lzfse_encode_finish crushlzfse_encode_base_fast crushlzfse_encode_base_lazy lzfse_encode_base crushlzvn_encode_buffer_advanced load_seed" \
      "21" "" ""
register load_seed load_seed.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF" load_seed \
      "" "65" "" ""
register lzfse_backend_match lzfse_backend_match.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF -DCRUSHLZFSE_BACKEND_MATCH_PROOF" lzfse_backend_match \
      "lzfse_push_match lzfse_encode_matches" "" "" "--arrays-uf-always"
register lzfse_backend_literals lzfse_backend_literals.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF" lzfse_backend_literals \
      "lzfse_backend_match" "" "" "--arrays-uf-always"
register lzfse_push_match lzfse_push_match.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF -DCRUSHLZFSE_BACKEND_MATCH_PROOF -DCRUSHLZFSE_PUSH_MATCH_PROOF" lzfse_push_match \
      "lzfse_push_lmd" "5" "" "--arrays-uf-always"
register lzfse_encode_matches lzfse_encode_matches.c "$LZFSE_CSRC" "$LZFSE_DEFS -DCRUSHLZFSE_DISPATCH_PROOF" lzfse_encode_matches \
      "" "5" "" "--arrays-uf-always --unwindset lzfse_encode_matches_wrapped_for_contract_checking.3:257,lzfse_encode_matches.3:257"




register zbm_blend8_sel   zbm_blend8_sel.c   "$ZBM_CSRC" "$ZBM_DEFS" zbm_blend8_sel \
      "proof_memcpy"
register zbm_blend8_row   zbm_blend8_row.c   "$ZBM_CSRC" "$ZBM_DEFS" zbm_blend8_row \
      "proof_memcpy zbm_blend8_sel"
register zbm_sel_load zbm_sel_load.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_sel_load "proof_memcpy"
register zbm_cpy8 zbm_cpy.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_CPY_WIDTH=8" zbm_cpy8 "proof_memcpy"
register zbm_cpy16 zbm_cpy.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_CPY_WIDTH=16" zbm_cpy16 "proof_memcpy"
register zbm_cpy32 zbm_cpy.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_CPY_WIDTH=32" zbm_cpy32 "proof_memcpy"
register zbm_copy_fwd     zbm_copy_fwd.c     "$ZBM_CSRC" "$ZBM_DEFS" zbm_copy_fwd \
      "proof_memcpy"
register zbm_apply_bitmap zbm_apply_bitmap.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_apply_bitmap \
      "proof_memcpy zbm_blend8_row" 9
register zbm_apply_bitmap_number zbm_apply_bitmap_number.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_apply_bitmap_number \
      "proof_memcpy zbm_apply_bitmap" 9
register zbm_read_repetition_count zbm_read_repetition_count.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_read_repetition_count \
      "proof_memcpy"
register zbm_read_bitmaps zbm_read_bitmaps.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_read_bitmaps \
      "proof_memcpy" 13
register zbm_blend8_correct zbm_blend8_correct.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 17
register zbm_table_correct zbm_table_correct.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 18
register zbm_last_nonrepeat_nibble zbm_last_nonrepeat_nibble.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_last_nonrepeat_nibble \
      "proof_memcpy"
register zbm_apply_bitmap_run zbm_apply_bitmap_run.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_apply_bitmap_run \
      "proof_memcpy zbm_fill_periodic zbm_patch_literals zbm_apply_bitmap_run_slow"

register zbm_decompress_single_bitmap zbm_decompress_single_bitmap.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_decompress_single_bitmap "proof_memcpy zbm_read_repetition_count zbm_last_nonrepeat_nibble zbm_apply_bitmap_number zbm_apply_bitmap_run"

register zbm_pair_budget zbm_pair_budget.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_pair_budget "proof_memcpy"

register zbm_fill_periodic zbm_fill_periodic.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_fill_periodic "proof_memcpy zbm_copy_fwd"
register zbm_patch_literals zbm_patch_literals.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_patch_literals "proof_memcpy zbm_blend8_sel"

register zbm_apply_bitmap_run_slow zbm_apply_bitmap_run_slow.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_apply_bitmap_run_slow "proof_memcpy zbm_apply_bitmap"

register zbm_handle_compressed_chunk zbm_handle_compressed_chunk.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_handle_compressed_chunk "proof_memcpy zbm_read_bitmaps zbm_pair_budget zbm_decode_pairs zbm_blend8_row zbm_decompress_single_bitmap" "" 32

register zbm_handle_chunk zbm_handle_chunk.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_handle_chunk "proof_memcpy zbm_handle_compressed_chunk"
register zbm_decode zbm_decode.c "$ZBM_CSRC" "$ZBM_DEFS" "" "proof_memcpy zbm_handle_chunk"

register zbm_decode_pairs zbm_decode_pairs.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_decode_pairs "proof_memcpy zbm_blend8_row"

# The LZBITMAP decoder targets above on the native NEON and SSE branches.
# Only zbm_copy_fwd calls the copy wrappers, which on these branches are
# intrinsics; it replaces them by the contracts enforced here.
register zbm_sel_load_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_sel_load.c\"" zbm_sel_load "proof_memcpy"
register zbm_cpy8_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DPROOF_CPY_WIDTH=8 -DNATIVE_TARGET=\"../zbm_cpy.c\"" zbm_cpy8 "proof_memcpy"
register zbm_cpy16_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DPROOF_CPY_WIDTH=16 -DNATIVE_TARGET=\"../zbm_cpy.c\"" zbm_cpy16 "proof_memcpy"
register zbm_cpy32_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DPROOF_CPY_WIDTH=32 -DNATIVE_TARGET=\"../zbm_cpy.c\"" zbm_cpy32 "proof_memcpy"
register zbm_blend8_sel_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_blend8_sel.c\"" zbm_blend8_sel "proof_memcpy"
register zbm_blend8_row_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_blend8_row.c\"" zbm_blend8_row "proof_memcpy zbm_blend8_sel"
register zbm_copy_fwd_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_copy_fwd.c\"" zbm_copy_fwd "proof_memcpy zbm_cpy8 zbm_cpy16 zbm_cpy32"
register zbm_blend8_correct_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_blend8_correct.c\"" "" "" "17"
register zbm_read_bitmaps_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_read_bitmaps.c\"" zbm_read_bitmaps "proof_memcpy" "13"
register zbm_pair_budget_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_pair_budget.c\"" zbm_pair_budget "proof_memcpy"
register zbm_read_repetition_count_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_read_repetition_count.c\"" zbm_read_repetition_count "proof_memcpy"
register zbm_last_nonrepeat_nibble_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_last_nonrepeat_nibble.c\"" zbm_last_nonrepeat_nibble "proof_memcpy"
register zbm_apply_bitmap_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_apply_bitmap.c\"" zbm_apply_bitmap "proof_memcpy zbm_blend8_row" "9"
register zbm_apply_bitmap_number_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_apply_bitmap_number.c\"" zbm_apply_bitmap_number "proof_memcpy zbm_apply_bitmap" "9"
register zbm_fill_periodic_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_fill_periodic.c\"" zbm_fill_periodic "proof_memcpy zbm_copy_fwd"
register zbm_patch_literals_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_patch_literals.c\"" zbm_patch_literals "proof_memcpy zbm_blend8_sel"
register zbm_apply_bitmap_run_slow_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_apply_bitmap_run_slow.c\"" zbm_apply_bitmap_run_slow "proof_memcpy zbm_apply_bitmap"
register zbm_apply_bitmap_run_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_apply_bitmap_run.c\"" zbm_apply_bitmap_run "proof_memcpy zbm_copy_fwd zbm_fill_periodic zbm_patch_literals zbm_apply_bitmap_run_slow"
register zbm_decompress_single_bitmap_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_decompress_single_bitmap.c\"" zbm_decompress_single_bitmap "proof_memcpy zbm_read_repetition_count zbm_last_nonrepeat_nibble zbm_apply_bitmap_number zbm_apply_bitmap_run"
register zbm_decode_pairs_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_decode_pairs.c\"" zbm_decode_pairs "proof_memcpy zbm_blend8_row"
register zbm_handle_compressed_chunk_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_handle_compressed_chunk.c\"" zbm_handle_compressed_chunk "proof_memcpy zbm_read_bitmaps zbm_pair_budget zbm_decode_pairs zbm_blend8_row zbm_decompress_single_bitmap" "" "32"
register zbm_handle_chunk_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_handle_chunk.c\"" zbm_handle_chunk "proof_memcpy zbm_handle_compressed_chunk"
register zbm_decode_neon simd/native_wrap.c "$ZBM_CSRC" "$ZBM_NEON_DEFS -DNATIVE_TARGET=\"../zbm_decode.c\"" "" "proof_memcpy zbm_handle_chunk"
register zbm_sel_load_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_sel_load.c\"" zbm_sel_load "proof_memcpy"
register zbm_cpy8_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DPROOF_CPY_WIDTH=8 -DNATIVE_TARGET=\"../zbm_cpy.c\"" zbm_cpy8 "proof_memcpy"
register zbm_cpy16_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DPROOF_CPY_WIDTH=16 -DNATIVE_TARGET=\"../zbm_cpy.c\"" zbm_cpy16 "proof_memcpy"
register zbm_cpy32_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DPROOF_CPY_WIDTH=32 -DNATIVE_TARGET=\"../zbm_cpy.c\"" zbm_cpy32 "proof_memcpy"
register zbm_blend8_sel_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_blend8_sel.c\"" zbm_blend8_sel "proof_memcpy"
register zbm_blend8_row_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_blend8_row.c\"" zbm_blend8_row "proof_memcpy zbm_blend8_sel"
register zbm_copy_fwd_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_copy_fwd.c\"" zbm_copy_fwd "proof_memcpy zbm_cpy8 zbm_cpy16 zbm_cpy32"
register zbm_blend8_correct_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_blend8_correct.c\"" "" "" "17"
register zbm_read_bitmaps_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_read_bitmaps.c\"" zbm_read_bitmaps "proof_memcpy" "13"
register zbm_pair_budget_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_pair_budget.c\"" zbm_pair_budget "proof_memcpy"
register zbm_read_repetition_count_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_read_repetition_count.c\"" zbm_read_repetition_count "proof_memcpy"
register zbm_last_nonrepeat_nibble_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_last_nonrepeat_nibble.c\"" zbm_last_nonrepeat_nibble "proof_memcpy"
register zbm_apply_bitmap_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_apply_bitmap.c\"" zbm_apply_bitmap "proof_memcpy zbm_blend8_row" "9"
register zbm_apply_bitmap_number_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_apply_bitmap_number.c\"" zbm_apply_bitmap_number "proof_memcpy zbm_apply_bitmap" "9"
register zbm_fill_periodic_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_fill_periodic.c\"" zbm_fill_periodic "proof_memcpy zbm_copy_fwd"
register zbm_patch_literals_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_patch_literals.c\"" zbm_patch_literals "proof_memcpy zbm_blend8_sel"
register zbm_apply_bitmap_run_slow_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_apply_bitmap_run_slow.c\"" zbm_apply_bitmap_run_slow "proof_memcpy zbm_apply_bitmap"
register zbm_apply_bitmap_run_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_apply_bitmap_run.c\"" zbm_apply_bitmap_run "proof_memcpy zbm_copy_fwd zbm_fill_periodic zbm_patch_literals zbm_apply_bitmap_run_slow"
register zbm_decompress_single_bitmap_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_decompress_single_bitmap.c\"" zbm_decompress_single_bitmap "proof_memcpy zbm_read_repetition_count zbm_last_nonrepeat_nibble zbm_apply_bitmap_number zbm_apply_bitmap_run"
register zbm_decode_pairs_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_decode_pairs.c\"" zbm_decode_pairs "proof_memcpy zbm_blend8_row"
register zbm_handle_compressed_chunk_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_handle_compressed_chunk.c\"" zbm_handle_compressed_chunk "proof_memcpy zbm_read_bitmaps zbm_pair_budget zbm_decode_pairs zbm_blend8_row zbm_decompress_single_bitmap" "" "32"
register zbm_handle_chunk_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_handle_chunk.c\"" zbm_handle_chunk "proof_memcpy zbm_handle_compressed_chunk"
register zbm_decode_sse simd/native_wrap.c "$ZBM_CSRC" "$ZBM_SSE_DEFS -DNATIVE_TARGET=\"../zbm_decode.c\"" "" "proof_memcpy zbm_handle_chunk"

register zbm_encode_bound zbm_encode_bound.c "$ZBM_CSRC" "$ZBM_DEFS" "" ""
register zbm_diff_bitmap_correct zbm_diff_bitmap_correct.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 9
register zbm_encoder_scratch zbm_encoder_scratch.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 3 "" "--malloc-may-fail"
register zbm_fast_skip zbm_fast_skip.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_fast_skip_bytes ""
register zbm_fast_hash8 zbm_fast_search.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_FAST_HASH8" zbm_fast_hash8 "proof_memcpy" 9
register zbm_fast_score zbm_fast_search.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_fast_score "proof_memcpy" 13
register zbm_tab_bits zbm_fast_index.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_TAB_BITS" zbm_tab_bits ""
register zbm_fast_prepare_index zbm_fast_index.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_fast_prepare_index \
      "proof_memcpy proof_memset zbm_tab_bits"
register zbm_row_index_range zbm_row_index.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_ROW_RANGE" zbm_row_index_range "proof_memcpy proof_memset"
register zbm_row_prepare_index zbm_row_index.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_row_prepare_index \
      "proof_memcpy proof_memset zbm_tab_bits zbm_row_index_range"
register zbm_pack8 zbm_fast_search.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_PACK8" zbm_pack8 "" 9
register zbm_encoder_params zbm_encoder_params.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 3
register zbm_pack8_correct zbm_pack8_correct.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 9
register zbm_encoder_table zbm_encoder_table.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 137
register zbm_encoder_magic zbm_encoder_magic.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_write_magic "proof_memcpy"
register zbm_encoder_stored zbm_encoder_stored.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_build_uncompressed_chunk "proof_memcpy"
register zbm_compress_single_chunk zbm_compress_single_chunk.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_compress_single_chunk "proof_memcpy"
register crushlzbitmap_encode_chunk crushlzbitmap_encode_chunk.c "$ZBM_CSRC" "$ZBM_DEFS" "" "proof_memcpy zbm_write_magic zbm_compress_single_chunk" "" "" "--malloc-may-fail --arrays-uf-always"
register crushlzbitmap_encode_buffer crushlzbitmap_encode_buffer.c "$ZBM_CSRC" "$ZBM_DEFS" "" "proof_memcpy zbm_write_magic zbm_compress_single_chunk" "" "" "--malloc-may-fail --arrays-uf-always"
register zbm_encoder_nibbles zbm_encoder_nibbles.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_write_nibbles "proof_memcpy"
register zbm_encoder_nibble zbm_encoder_nibbles.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_NIBBLE_SINGLE" zbm_write_nibble "proof_memcpy"
register zbm_encoder_nibble_finish zbm_encoder_nibbles.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_NIBBLE_FINISH" zbm_nybl_finish "" 9
register zbm_encoder_nibbles_correct zbm_encoder_nibbles_correct.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 20
register zbm_encoder_key zbm_encoder_key.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_bmkey "" 3
register zbm_encoder_numbers zbm_encoder_numbers.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_build_bmap_nums "proof_memcpy zbm_bmkey" "" "" "--arrays-uf-never"
register zbm_encoder_numbers_values zbm_encoder_numbers.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_SELECTOR_VALUES" zbm_build_bmap_nums "proof_memcpy zbm_bmkey" "" "" "--arrays-uf-never"
register zbm_encoder_selector_values zbm_encoder_selector_values.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_SELECTOR_VALUES" "" "zbm_build_bmap_num_table zbm_build_bmap_nums" 13
register zbm_encoder_repeat zbm_encoder_repeat.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_write_repetition_count "proof_memcpy zbm_write_nibble" "" 16 "--arrays-uf-always"
register zbm_encoder_bitmap zbm_encoder_bitmap.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_calculate_bitmap "" 9
register zbm_encoder_run zbm_encoder_run.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_run_length "proof_memcpy"
register zbm_encoder_run_values zbm_encoder_run.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_RUN_VALUES" zbm_run_length "proof_memcpy"
register zbm_encoder_literal_total zbm_encoder_totals.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_literal_total "proof_memcpy"
register zbm_encoder_period_total zbm_encoder_totals.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_PERIOD_TOTAL" zbm_period_bytes_total "proof_memcpy"
register zbm_encoder_number_table zbm_encoder_number_table.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_SELECTOR_VALUES" zbm_build_bmap_num_table "proof_memcpy zbm_bmkey"
register zbm_encoder_run_cost zbm_encoder_run_cost.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_nibble_cost_for_run ""
register zbm_encoder_run_delta zbm_encoder_run_cost.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_RUN_DELTA" zbm_nibble_extend_delta "zbm_nibble_cost_for_run"
register zbm_encoder_eq16 zbm_encoder_simd_metadata.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_EQ16 -DZBM_PROOF_SIMD_VALUES" zbm_eq16_mask "" 17
register zbm_encoder_pack_nibbles zbm_encoder_simd_metadata.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_SIMD_VALUES" zbm_pack_nibbles16 "" 17
register zbm_encoder_eq16_query zbm_encoder_simd_metadata.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_EQ16 -DZBM_PROOF_BOUNDARY_VALUES" zbm_eq16_mask "" 17
register zbm_encoder_boundary_arrays zbm_encoder_boundary_arrays.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_build_run_boundaries_arrays "zbm_eq16_mask" "" 17 "--arrays-uf-never"
register zbm_encoder_boundary_arrays_values zbm_encoder_boundary_arrays.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_BOUNDARY_VALUES" zbm_build_run_boundaries_arrays "zbm_eq16_mask" "" 17 "--arrays-uf-never"
register zbm_encoder_boundaries zbm_encoder_boundaries.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_build_run_boundaries "zbm_build_run_boundaries_arrays"
register zbm_encoder_boundaries_values zbm_encoder_boundaries.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_BOUNDARY_VALUES" zbm_build_run_boundaries "zbm_build_run_boundaries_arrays"
register zbm_encoder_vector_nibbles zbm_encoder_vector_nibbles.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_write_16_nibbles "proof_memcpy"
register zbm_encoder_vector_nibbles_correct zbm_encoder_vector_nibbles_correct.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 17
register zbm_encoder_short_pattern zbm_encoder_selector_arithmetic.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_short_run_pattern ""
register zbm_encoder_word_index zbm_encoder_selector_arithmetic.c "$ZBM_CSRC" "$ZBM_DEFS -DPROOF_WORD_INDEX" zbm_selector_word_index ""
register zbm_encoder_first_boundary zbm_encoder_first_boundary.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_first_boundary_bit "" 65
register zbm_encoder_find_run_end zbm_encoder_find_run_end.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_find_run_end "zbm_first_boundary_bit"
register zbm_encoder_find_run_end_values zbm_encoder_find_run_end.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_RUN_END_VALUES" zbm_find_run_end "zbm_first_boundary_bit"
register zbm_encoder_run_end_state zbm_encoder_run_end_state.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_RUN_END_VALUES" "" "zbm_build_run_boundaries zbm_find_run_end"
register zbm_encoder_long_masks zbm_encoder_long_masks.c "$ZBM_CSRC" "$ZBM_DEFS" "" "" 5
register zbm_encoder_long_arrays zbm_encoder_long_arrays.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_build_long_runs_arrays ""
register zbm_encoder_long_arrays_values zbm_encoder_long_arrays.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_LONG_VALUES" zbm_build_long_runs_arrays ""
register zbm_encoder_long_state zbm_encoder_long_arrays.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_LONG_VALUES -DPROOF_LONG_STATE" "" "zbm_build_long_runs_arrays"
register zbm_encoder_long_member zbm_encoder_long_member.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_LONG_VALUES" "" "zbm_build_long_runs_arrays" "" "" "--arrays-uf-never"
register zbm_encoder_long_member_window zbm_encoder_long_member.c "$ZBM_CSRC" "$ZBM_DEFS -DZBM_PROOF_LONG_VALUES -DPROOF_MEMBER_WINDOW" "" "zbm_build_long_runs_arrays" "" "" "--arrays-uf-never"
register zbm_encoder_long_window zbm_encoder_long_window.c "$ZBM_CSRC" "$ZBM_DEFS" "" ""
register zbm_encoder_number_at zbm_encoder_number_at.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_bmap_num_for_index ""
register zbm_encoder_metadata3_size zbm_encoder_metadata3_size.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_metadata_3_bytes "zbm_bmap_num_for_index zbm_run_length zbm_nibble_cost_for_run"
register zbm_encoder_bit_shift zbm_encoder_bit_shift.c "$ZBM_CSRC" "$ZBM_DEFS" "" ""
register zbm_encoder_count_fold zbm_encoder_count_fold.c "$ZBM_CSRC" "$ZBM_DEFS" "" ""
register zbm_encoder_bmprot zbm_encoder_bmprot.c "$ZBM_CSRC" "$ZBM_DEFS" "" ""
register zbm_encoder_top_bits zbm_encoder_top_bits.c "$ZBM_CSRC" "$ZBM_DEFS" "" ""
register zbm_encoder_table_defaults zbm_encoder_table_defaults.c "$ZBM_CSRC" "$ZBM_DEFS" "" ""
register zbm_encoder_top zbm_encoder_top.c "$ZBM_CSRC" "$ZBM_DEFS" zbm_find_most_common_bitmaps "" "" 97 "--arrays-uf-never"

major=$(cbmc --version | sed 's/[^0-9].*//')
if [ "${major:-0}" -lt 6 ]; then
    echo "error: CBMC >= 6 required (have $(cbmc --version))" >&2
    exit 2
fi

# build NAME OUT [extra include dir] [extra define]: compile and
# instrument a proof.
source_manifest() {
    eval src=\$${1}_src inc=\$${1}_inc
    sha256sum "$src" "$PROOFS/proof.h" "$0"
    case "$1" in
        lzfse_decode_frame|lzfse_dispatch_literals|lzfse_dispatch_lmd)
            sha256sum "$PROOFS/lzfse_frame_interface.h" ;;
    esac
    if [ "$1" = fse_value_symbol_row ]; then
        sha256sum "$PROOFS/fse_table_rows.c"
    fi
    find "$inc" -type f \( -name '*.c' -o -name '*.h' \) -print0 |
        sort -z | xargs -0 sha256sum
}

# The image is linux/arm64, where plain char is unsigned; the shipping
# targets (Apple arm64, x86-64) use signed char.
SIGNED_CHAR=-fsigned-char

# native_preflight OUT CPPFLAGS...: the include trace must resolve every
# compiler intrinsic header into simd/include, and the macros must show the
# native branch. simd/native_wrap.c repeats these checks with #error.
native_preflight() {
    pout=$1; shift
    gcc -E -H "$@" -o /dev/null 2>"$pout.includes.txt" || {
        cat "$pout.includes.txt" >&2; return 1; }
    gcc -E -dM "$@" >"$pout.macros.txt"
    grep -E '(arm_neon|[a-z]+intrin|cpuid)\.h' "$pout.includes.txt" | sed 's/^\.* //' |
        sort -u >"$pout.intrinsic-headers.txt"
    [ -s "$pout.intrinsic-headers.txt" ] || {
        echo "FAIL preflight: no intrinsic header" >&2; return 1; }
    if grep -v "^$PROOFS/simd/include/" "$pout.intrinsic-headers.txt" >&2; then
        echo "FAIL preflight: a compiler intrinsic header was included" >&2; return 1
    fi
    if grep -q '^#define CRUSH_SIMD_PORTABLE' "$pout.macros.txt"; then
        echo "FAIL preflight: portable branch" >&2; return 1
    fi
    grep -E '^#define (CRUSH_SIMD_SHADOW_[A-Z0-9]+|__ARM_NEON|__x86_64__|__aarch64__|__SSE4_1__|__POPCNT__|__AVX2__|__BMI2__|__SIZEOF_POINTER__|__BYTE_ORDER__|__CHAR_UNSIGNED__) ' \
        "$pout.macros.txt" | sort >"$pout.preflight.txt"
}

# native_bodies OUT REPLACED: every function reachable from the harness has
# a body (an intrinsic model, project code or the CBMC library) unless it is
# replaced by its contract. CBMC would otherwise treat a call to an
# unmodelled intrinsic as returning anything, without failing.
native_bodies() {
    goto-instrument --reachable-call-graph "$1.4.goto" 2>/dev/null |
        sed -n 's/.*-> *"*\([A-Za-z0-9_]*\)"*;*$/\1/p' | sort -u >"$1.callees.txt"
    goto-instrument --list-undefined-functions "$1.4.goto" 2>/dev/null |
        sort -u >"$1.undefined.txt"
    printf '%s\n' $2 | sort -u >"$1.replaced.txt"
    comm -12 "$1.callees.txt" "$1.undefined.txt" | comm -23 - "$1.replaced.txt" |
        grep -vE '^(nondet_.*|__CPROVER_.*)$' >"$1.unmodelled.txt" || true
    if [ -s "$1.unmodelled.txt" ]; then
        echo "FAIL reachable functions without a body:" >&2
        cat "$1.unmodelled.txt" >&2
        return 1
    fi
    grep -E '^M_' "$1.callees.txt" >"$1.models.txt" || true
}

build() {
    eval src=\$${1}_src inc=\$${1}_inc defs=\$${1}_defs enf=\$${1}_enforce rep=\$${1}_replace unw=\$${1}_unwind
    out=$2
    case "$1" in fse_literal_row|fse_value_row|fse_value_symbol_row)
        expected=$(sed -n '1s/.*producer-sha256: \([0-9a-f]*\).*/\1/p' "$PROOFS/fse_table_rows.c")
        actual=$(sha256sum "$inc/lzfse_fse.c" | cut -d ' ' -f1)
        [ "$expected" = "$actual" ] || {
            echo 'error: regenerate FSE row lemmas after producer changes' >&2
            return 1
        } ;;
    esac
    case "$1" in lzfse_literal_bulk_span)
        expected=$(sed -n '1s/.*producer-sha256: \([0-9a-f]*\).*/\1/p' "$src")
        actual=$(sha256sum "$inc/lzfse_decode_hot.h" | cut -d ' ' -f1)
        [ "$expected" = "$actual" ] || {
            echo 'error: regenerate literal bulk-span lemma after producer changes' >&2
            return 1
        } ;;
    esac
    case "$1" in lzfse_lmd_distance_check)
        expected=$(sed -n '1s/.*producer-sha256: \([0-9a-f]*\).*/\1/p' "$src")
        actual=$(sha256sum "$inc/lzfse_decode_hot.h" | cut -d ' ' -f1)
        [ "$expected" = "$actual" ] || {
            echo 'error: regenerate LMD distance-check lemma after producer changes' >&2
            return 1
        } ;;
    esac
    case "$1" in lzfse_decoder_tables_zero)
        expected=$(sed -n '1s/.*producer-sha256: \([0-9a-f]*\).*/\1/p' "$src")
        actual=$(sha256sum "$inc/crushlzfse.c" | cut -d ' ' -f1)
        [ "$expected" = "$actual" ] || {
            echo 'error: regenerate decoder table zeroing lemma after initializer changes' >&2
            return 1
        }
        grep -Fq 'memset(s, 0, offsetof(lzfse_decoder_state, compressed_lzfse_block_state.literals));' "$inc/crushlzfse.c" || {
            echo 'error: decoder table zeroing statement changed' >&2
            return 1
        } ;;
    esac
    extra=${3:+-I$3}
    def=${4:-}
    case " $defs " in *" -DNATIVE_ISA="*)
        # shellcheck disable=SC2086
        native_preflight "$out" $SIGNED_CHAR $defs $def $extra -I"$PROOFS" -I"$inc" "$src" ||
            return 1 ;;
    esac
    # shellcheck disable=SC2086
    goto-cc $SIGNED_CHAR $defs $def --function harness $extra -I"$PROOFS" -I"$inc" \
        "$src" -o "$out.1.goto"
    goto-instrument --add-library "$out.1.goto" "$out.2.goto" >/dev/null
    goto-instrument --generate-function-body 'nondet_.*' \
        --generate-function-body-options nondet-return \
        "$out.2.goto" "$out.3.goto" >/dev/null
    # Replaced callees execute their contracts, so retaining their bodies only
    # makes DFCC instrument unreachable parser loops. Keep the symbols and
    # contracts, remove those implementations, then drop unreachable helpers.
    bodyflags=""
    for f in $rep; do bodyflags="$bodyflags --remove-function-body $f"; done
    # shellcheck disable=SC2086
    goto-instrument $bodyflags --drop-unused-functions \
        "$out.3.goto" "$out.4.goto" >/dev/null
    case " $defs " in *" -DNATIVE_ISA="*)
        native_bodies "$out" "$rep" || return 1 ;;
    esac
    rflags=${enf:+--enforce-contract $enf}
    for f in $rep; do rflags="$rflags --replace-call-with-contract $f"; done
    # shellcheck disable=SC2086
    loops=--apply-loop-contracts
    [ -z "$unw" ] || loops=""
    goto-instrument --dfcc harness $loops $rflags \
        "$out.4.goto" "$out.goto" >"$out.instrument.log" 2>&1 || {
        cat "$out.instrument.log" >&2; return 1; }
}

# Each cbmc run gets PROOF_TIMEOUT minutes (default 60), so a proof that
# grows too hard for the solver fails instead of hanging. The log records
# the formula size ("N variables, M clauses") seconds in, before solving.
TIMEOUT_CMD=$(command -v timeout || command -v gtimeout || true)
limit() {
    if [ -n "$TIMEOUT_CMD" ]; then
        "$TIMEOUT_CMD" "$(( ${PROOF_TIMEOUT:-60} * 60 ))" "$@"
    else
        "$@"
    fi
}

# stats LOG: the formula size and solver time from a cbmc log.
stats() {
    v=$(sed -n 's/^\([0-9]*\) variables, \([0-9]*\) clauses$/\1 vars, \2 clauses/p' "$1" | tail -n 1)
    t=$(sed -n 's/^Runtime decision procedure: \([0-9]*\).*/\1s/p' "$1" | tail -n 1)
    echo "${v:-no formula}${t:+, solved in $t}"
}

# unwind_flags NAME: set extra_cbmc to the target's flags and unwinding
# bounds. Every bounded run checks its unwinding assertions explicitly.
unwind_flags() {
    eval unw=\$${1}_unwind aux=\$${1}_aux_unwind flags=\$${1}_cbmc_flags
    extra_cbmc="$flags"
    [ -z "$unw" ] || extra_cbmc="$flags --unwind $unw --unwinding-assertions"
    [ -z "$aux" ] || extra_cbmc="$flags --unwind $aux --unwinding-assertions"
}

# prove NAME OUT [cbmc flags]: 0 if every property holds.
prove() {
    unwind_flags "$1"
    out=$2; shift 2
    rc=0
    # shellcheck disable=SC2086
    limit cbmc "$out.goto" $CHECKS $extra_cbmc --slice-formula --verbosity 9 "$@" \
        >"$out.log" 2>&1 || rc=$?
    # 124: PROOF_TIMEOUT expired; 137: killed, usually by the memory cap.
    echo "$rc" >"$out.exit"
    grep -q '^VERIFICATION SUCCESSFUL' "$out.log"
}

# reachable NAME OUT: 0 if CBMC finds a witness for every PROOF_REACHABLE
# goal in the harness (see proof.h).
reachable() {
    build "$1" "$2.reach" "" -DPROOF_REACH
    # Only the goals: the main run already proves every other property.
    # shellcheck disable=SC2086
    props=$(cbmc "$2.reach.goto" $CHECKS --show-properties 2>/dev/null |
        awk '/^Property /{id=$2} /reachable: /{sub(":", "", id); print "--property " id}')
    [ -n "$props" ] || return 1
    expected=$(printf '%s\n' "$props" | awk '{n += NF / 2} END {print n}')
    unwind_flags "$1"
    rc=0
    # shellcheck disable=SC2086
    limit cbmc "$2.reach.goto" $CHECKS $extra_cbmc $props --slice-formula \
        >"$2.reach.log" 2>&1 || rc=$?
    echo "$rc" >"$2.reach.exit"
    goals=$(grep -c 'reachable: .*: \(SUCCESS\|FAILURE\)$' "$2.reach.log" || true)
    [ "$goals" -eq "$expected" ] &&
        grep -q '^VERIFICATION FAILED' "$2.reach.log" &&
        ! grep -q 'reachable: .*: SUCCESS$' "$2.reach.log"
}

# Main verification and reachability run serially by default to limit memory.
# PROOF_PARALLEL_REACH=1 runs them together when enough memory is available.
run_proof() {
    p=$1
    start=$(date +%s)
    source_manifest "$p" > "$WORK/$p.sources.sha256"
    build "$p" "$WORK/$p"
    reach_pid=""
    if [ "${PROOF_PARALLEL_REACH:-0}" -eq 1 ]; then
        reachable "$p" "$WORK/$p" &
        reach_pid=$!
    fi
    if ! prove "$p" "$WORK/$p"; then
        [ -z "$reach_pid" ] || wait "$reach_pid" || true
        echo "FAIL  $p"
        grep -E 'FAILURE$' "$WORK/$p.log" | sed 's/^/      /' || true
        echo "      log: $WORK/$p.log ($(stats "$WORK/$p.log"))"
        return 1
    fi
    if [ -n "$reach_pid" ]; then
        wait "$reach_pid" || return 1
    elif ! reachable "$p" "$WORK/$p"; then
        echo "FAIL  $p: reachability check incomplete or unreachable"
        return 1
    fi
    source_manifest "$p" > "$WORK/$p.sources-after.sha256"
    if ! cmp -s "$WORK/$p.sources.sha256" "$WORK/$p.sources-after.sha256"; then
        echo "FAIL  $p: sources changed during verification; rerun an immutable snapshot"
        return 1
    fi
    sha256sum "$WORK/$p.goto" "$WORK/$p.reach.goto" \
        "$WORK/$p.log" "$WORK/$p.reach.log" > "$WORK/$p.results.sha256"
    eval defs=\$${p}_defs enf=\$${p}_enforce rep=\$${p}_replace unw=\$${p}_unwind aux=\$${p}_aux_unwind flags=\$${p}_cbmc_flags
    printf '%s\n' "cbmc=$(cbmc --version)" "cflags=$SIGNED_CHAR" "defines=$defs" "enforce=$enf" \
        "replace=$rep" "unwind=$unw" "aux_unwind=$aux" "flags=$flags" \
        "cbmc_command=cbmc $CHECKS $(unwind_flags "$p"; echo "$extra_cbmc")" \
        > "$WORK/$p.configuration.txt"
    echo "ok    $p ($(( $(date +%s) - start ))s wall; $(stats "$WORK/$p.log"))"
}

# Each mutant is a known bug: NAME|PROOF|FILE|sed expression. The proof
# must fail on every one, or it is not checking what it claims to.
MUTANTS='
lzfse_frame_magic_pointer|lzfse_decode_frame|lzfse_decode_base.c|s/if ((size_t)(s->src_end - s->src) < 4)/if (s->src + 4 > s->src_end)/
lzfse_frame_short_header_pointer|lzfse_decode_frame|lzfse_decode_base.c|s/if ((size_t)(s->src_end - s->src) < sizeof(uncompressed_block_header))/if (s->src + sizeof(uncompressed_block_header) > s->src_end)/
lzfse_frame_v2_header_pointer|lzfse_decode_frame|lzfse_decode_base.c|s/if (header_size < 32 || (size_t)(s->src_end - s->src) < header_size)/if (header_size < 32 || s->src + header_size > s->src_end)/
lzfse_frame_header_no_progress|lzfse_decode_frame|lzfse_decode_base.c|s/s->src += sizeof(uncompressed_block_header);/s->src += 0;/
lzfse_frame_lmd_payload_unchecked|lzfse_decode_frame|lzfse_decode_base.c|s/bs->n_lmd_payload_bytes > (size_t)(s->src_end - s->src))/0)/
lzfse_frame_literal_payload_unchecked|lzfse_decode_frame|lzfse_decode_base.c|s/header1.n_literal_payload_bytes > avail - header_size ||/0 ||/
lzfse_frame_stored_dst_unchecked|lzfse_decode_frame|lzfse_decode_base.c|s/if (copy_size > dst_space)/if (0)/
lzfse_frame_shared_stored_dst_overrun|lzfse_decode_frame_shared|lzfse_decode_base.c|s/if (copy_size > dst_space)/if (0)/
lzfse_frame_lzvn_dst_unlimited|lzfse_decode_frame|lzfse_decode_base.c|s/dstate.dst_end = s->dst_end;/dstate.dst_end = s->dst + bs->n_raw_bytes;/
lzfse_frame_lmd_keeps_magic|lzfse_decode_frame|lzfse_decode_base.c|s/s->block_magic = LZFSE_NO_BLOCK_MAGIC;/(void)0;/
lzfse_frame_hides_table_writes|lzfse_decode_frame|lzfse_internal.h|s/#define LZFSE_PROOF_STATE_FOOTPRINT(s) \*s/#define LZFSE_PROOF_STATE_FOOTPRINT(s) __CPROVER_object_upto((s), offsetof(lzfse_decoder_state, compressed_lzfse_block_state.lmd_decoder))/
lzfse_buffer_null_empty_source|lzfse_decode_buffer_with_scratch|lzfse_decode.c|s/if (src_size == 0)$/if (0)/
lzfse_buffer_null_empty_destination|lzfse_decode_buffer_with_scratch|lzfse_decode.c|s/if (dst_size == 0)$/if (0)/
lzfse_buffer_tables_unzeroed|lzfse_decode_buffer_with_scratch|lzfse_decode.c|s/memset(s, 0x00, sizeof(\*s));/memset(s, 0x00, offsetof(lzfse_decoder_state, compressed_lzfse_block_state.lmd_decoder));/
crushlzfse_null_empty_source|crushlzfse_decode_buffer|crushlzfse.c|s/if (src_size == 0) return CRUSHLZFSE_INVALID;/if (0) return CRUSHLZFSE_INVALID;/
crushlzfse_null_empty_destination|crushlzfse_decode_buffer|crushlzfse.c|s/if (dst_size == 0) dst = \&empty_dst;/if (0) dst = \&empty_dst;/
crushlzfse_decode_wrong_length|crushlzfse_decode_buffer|crushlzfse.c|s/\*out_len = written;/\*out_len = dst_size + 1;/
crushlzfse_tables_unzeroed|crushlzfse_decode_buffer|crushlzfse.c|s/compressed_lzfse_block_state.literals));/compressed_lzfse_block_state.literal_decoder));/
lzfse_header_literal_state_unchecked|lzfse_check_block_header_v1_exact|lzfse_internal.h|s/((literal_state\[3\] < LZFSE_ENCODE_LITERAL_STATES) ? 0 : (1 << 6))/0/
lzfse_buffer_alloc_unchecked|lzfse_decode_buffer|lzfse_decode.c|s/if (scratch_buffer == NULL)$/if (0)/
lzfse_resume_skips_pending|lzfse_lmd_resume|lzfse_decode_hot.h|s/if (L || M)/if (0)/
lzfse_resume_loses_literal|lzfse_lmd_resume|lzfse_decode_hot.h|s/bs->l_value = L;/bs->l_value = 0;/
lzfse_resume_rewinds_dst|lzfse_lmd_resume|lzfse_decode_hot.h|/DestinationBufferIsFull:/,/return LZFSE_STATUS_DST_FULL;/s/s->dst = dst;/s->dst = s->dst_begin;/
lzfse_tuples_no_l_check|lzfse_lmd_resume_tuples|lzfse_decode_hot.h|s/      if ((size_t)L >= (size_t)(lit_end - lit)) {/      if (0) {/
lzfse_tuples_no_d_check|lzfse_lmd_resume_tuples|lzfse_decode_hot.h|s/if ((uint64_t)((int64_t)D - 1) >= (uint64_t)(dst - dst_begin) + (uint64_t)L)/if (D <= 0)/
lzfse_v1_no_available_check|lzfse_decode_v1|lzfse_decode_base.c|s/^      header_size > available)$/      0)/
lzfse_parser_pointer_past_end|lzfse_declared_len_short|lzfse_decode_base.c|/int lzfse_declared_len(/,$s/if ((size_t)(src_end - src) < 4)/if (src + 4 > src_end)/
lzfse_declared_len_alias_wrong_total|lzfse_declared_len_alias|lzfse_decode_base.c|/int lzfse_declared_len(/,$s/\*out_len = total;/\*out_len = SIZE_MAX;/
lzvn_resume_no_dprev_bound|lzvn_decode_resume|lzvn_decode_base.h|s/__CPROVER_ensures(state->d_prev >= 0 && (size_t)state->d_prev <=/__CPROVER_ensures(1 || (size_t)state->d_prev <=/
lzvn_null_empty_destination|crushlzvn_decode_buffer|crushlzvn.c|s/if (dst_size == 0) dst = \&empty_dst;/if (0) dst = \&empty_dst;/
lzvn_null_empty_source|crushlzvn_decode_buffer|crushlzvn.c|s/if (src_size == 0) return CRUSHLZVN_INVALID;/if (0) return CRUSHLZVN_INVALID;/
lzvn_decode_buffer_overrun|crushlzvn_decode_buffer|crushlzvn.c|s/state.dst_end = dst + dst_size;/state.dst_end = dst + dst_size + 1;/
lzvn_decode_caller_overlap|crushlzvn_decode_buffer|crushlzvn.c|s/state.src = src;/state.src = dst;/
lzvn_decode_wrong_length|crushlzvn_decode_buffer|crushlzvn.c|s/\*out_len = (size_t)(state.dst - dst);/\*out_len = dst_size + 1;/
lzvn_literal_overread|lzvn_copy_literal|lzvn_decode_base.c|s/memcpy(dst_ptr + i, src_ptr + i, 8);/memcpy(dst_ptr + i, src_ptr + i + 1, 8);/
lzvn_short_literal_overread|lzvn_copy_literal_short|lzvn_decode_base.c|s/if (__builtin_expect(dst_len >= 4 \&\& src_len >= 4, 1)) {/if (__builtin_expect(dst_len >= 3 \&\& src_len >= 3, 1)) {/
fse_literal_invalid_next_state|fse_decode_u32|lzfse_fse.h|s/\*pstate = (uint32_t)(e >> 16) + (uint32_t)fse_in_pull(in, e \& 0xff);/\*pstate = 1024 + (uint32_t)(e >> 16) + (uint32_t)fse_in_pull(in, e \& 0xff);/
fse_literal_wrong_delta_u32|fse_decode_u32_32|lzfse_fse.h|s/\*pstate = (uint32_t)(e >> 16) + (uint32_t)fse_in_pull(in, e \& 0xff);/\*pstate = (uint32_t)(e >> 16) + 1 + (uint32_t)fse_in_pull(in, e \& 0xff);/
fse_literal_table_bad_delta|fse_literal_table_valid|lzfse_fse.c|s/uint32_t w1 = (uint8_t)(int8_t)(k - 1) | sym;/uint32_t w1 = (uint8_t)(int8_t)(k - 1) | sym | ((uint32_t)nstates << 16);/
fse_literal_preserve_bad_delta|fse_literal_table_preserve|lzfse_fse.c|s/uint32_t w1 = (uint8_t)(int8_t)(k - 1) | sym;/uint32_t w1 = (uint8_t)(int8_t)(k - 1) | sym | ((uint32_t)nstates << 16);/
fse_value_symbol_over_limit|fse_value_symbol_bounds|lzfse_internal.h|s/131068, 163836, 196604, 229372/131068, 163836, 196604, 229373/
fse_value_store_skips_row|fse_l_table_coverage|lzfse_fse.c|s/LZFSE_STORE_VALUE_ROW(t + tp + j0 + j, e, j < f - j0);/LZFSE_STORE_VALUE_ROW(t + tp + j0 + j + 1, e, j < f - j0);/
fse_value_wrong_value|fse_value_decode_u32|lzfse_fse.h|s/return (uint32_t)entry.vbase +/return (uint32_t)entry.vbase + 1 +/
lzvn_end_pointer_past_end|lzvn_emit_end_exact|lzvn_encode_base.c|s/if ((size_t)(state->dst_end - state->dst) < 8)/if (state->dst_end < state->dst + 8)/
lzvn_match_pointer_past_end|emit_match_tail|lzvn_encode_base.c|/LZVN_INLINE unsigned char [*]emit(/,/static inline int32_t offset_to_s32/s/if ((size_t)(q1 - q) <= 8)/if (q + 8 >= q1)/
lzvn_literal_pointer_past_end|emit_literal_tail|lzvn_encode_base.c|/LZVN_INLINE unsigned char [*]emit_literal(/,/CrushLZVN cost model/s/if ((size_t)(q1 - q) <= L + 10)/if (q + L + 10 >= q1)/
lzvn_fast_find_no_ref_guard|crushlzfse_fast_find|fast_match.h|s/mpos > anchor \&\& mref > 0/mpos > anchor/
lzvn_fast_stride_unclamped|lzvn_fast_skip_step|lzvn_encode_base.c|s/return step < max_stride ? step : max_stride;/return step;/
lzvn_pareto_row_shift|lzvn_pareto_insert|lzvn_encode_base.c|s/p->slots + (size_t)pos \* (size_t)k_cap;/p->slots + (size_t)pos * (size_t)k_cap + 1;/
lzvn_encode_buffer_no_params_check|crushlzvn_encode_buffer|crushlzvn.c|s/if (!crushlzvn_params_valid(params))/if (0)/
lzvn_encode_buffer_no_src_limit|crushlzvn_encode_buffer|crushlzvn.c|s/if (src_size > (size_t)LZVN_ZOPT_BLOCK_SIZE)/if (0)/
lzvn_encode_buffer_bad_scratch_check|crushlzvn_encode_buffer|crushlzvn.c|s/if (scratch && scratch_size < crushlzvn_scratch_size(params))/if (0)/
lzvn_encode_buffer_wrong_return|crushlzvn_encode_buffer|crushlzvn.c|s/return out;/return dst_size + 1;/
lzvn_greedy_carve_overlap|crushlzvn_scratch|crushlzvn.c|s/off = align8(off + n_hash \* (size_t)hash_width \* sizeof(int32_t));/off = align8(off);/
lzvn_greedy_caller_overlap|crushlzvn_encode_buffer|crushlzvn.c|s/off = align8(off + n_hash \* (size_t)hash_width \* sizeof(int32_t));/off = align8(off);/
lzvn_alt_carve_overlap|crushlzvn_scratch|crushlzvn.c|s/alt_off = align8(alt_off + alt_n \* (size_t)CRUSHLZVN_OPTIMAL_ALT_HASH_WIDTH \* sizeof(int32_t));/alt_off = align8(alt_off);/
lzvn_literal_buffer_no_null_check|lzvn_encode_literal_only_buffer|lzvn_encode_base.c|s/if (!dst || !src)/if (0)/
lzvn_literal_buffer_wrong_return|lzvn_encode_literal_only_buffer|lzvn_encode_base.c|s/return (size_t)(end - q);/return dst_size + 1;/
lzvn_literal_buffer_overrun|lzvn_encode_literal_only_buffer|lzvn_encode_base.c|s/q + dst_size - 8/q + dst_size/g
lzvn_fast_buffer_overrun|lzvn_encode_fast_buffer|lzvn_encode_base.c|s/return lzvn_encode_fast_4_0_0(d, dst_size, s,/return lzvn_encode_fast_4_0_0(d, dst_size + 1, s,/
lzvn_fast_buffer_wrong_result|lzvn_encode_fast_buffer|lzvn_encode_base.c|s/return lzvn_encode_fast_4_0_0(d, dst_size, s, src_size, hb, ss, ms, table, ltable);/return dst_size + 1;/
lzvn_greedy_buffer_no_min_dst|lzvn_encode_greedy_wide_buffer|lzvn_encode_base.c|s/if (dst_size < LZVN_ENCODE_MIN_DST_SIZE)/if (0)/
lzvn_greedy_buffer_no_src_limit|lzvn_encode_greedy_wide_buffer|lzvn_encode_base.c|s/if (src_size > LZVN_ENCODE_MAX_SRC_SIZE)/if (0)/
lzvn_greedy_buffer_dst_overflow|lzvn_encode_greedy_wide_buffer|lzvn_encode_base.c|s/state.dst_end = (unsigned char \*)dst + dst_size;/state.dst_end = (unsigned char *)dst + dst_size + 1;/
lzvn_greedy_buffer_wrong_return|lzvn_encode_greedy_wide_buffer|lzvn_encode_base.c|s/return (size_t)(LZVN_OFFSET(state.dst) - LZVN_OFFSET(state.dst_begin));/return dst_size + 1;/
lzvn_greedy_signed_slot|lzvn_greedy_wide_step|lzvn_encode_base.c|s/return (lzvn_offset)(uint32_t)x;/return (lzvn_offset)x;/
lzvn_greedy_cursor_unreduced|lzvn_greedy_wide_step|lzvn_encode_base.c|s/uint32_t cursor = (meta \& 0xFFu) % (uint32_t)hash_width;/uint32_t cursor = meta \& 0xFFu;/
lzvn_greedy_any_src_begin|lzvn_greedy_wide_step|lzvn_encode_base.c|s/state->src_begin == 0 \&\& state->src_begin <= state->src_current \&\&/0 <= state->src_begin \&\& state->src_begin <= state->src_current \&\&/
lzvn_optimal_no_size_check|lzvn_encode_optimal_buffer_pareto|lzvn_encode_base.c|s/if (src_size > (size_t)LZVN_ZOPT_BLOCK_SIZE)/if (0)/
lzvn_optimal_wrong_return|lzvn_encode_optimal_buffer_pareto|lzvn_encode_base.c|s/return committed;/return committed + dst_size + 1;/
lzvn_optimal_no_dp_check|lzvn_encode_optimal_buffer_pareto|lzvn_encode_base.c|s/if (!lzvn_pareto_run_dp(z, p, s, padded_end, 0, n))/if (!lzvn_pareto_run_dp(z, p, s, padded_end, 0, n) \&\& 0)/
lzfse_encode_init_bad_status|lzfse_encode_init|lzfse_encode_base.c|/int lzfse_encode_init(lzfse_encoder_state \*s)/,/^}/s/return LZFSE_STATUS_OK;/return -99;/
lzfse_encode_init_no_literal_zero|lzfse_encode_init|lzfse_encode_base.c|/int lzfse_encode_init(lzfse_encoder_state \*s)/,/^}/s/s->src_literal = 0;/s->src_literal = 1;/
lzfse_encode_init_no_pending_zero|lzfse_encode_init|lzfse_encode_base.c|/int lzfse_encode_init(lzfse_encoder_state \*s)/,/^}/s/s->pending = NO_MATCH;/s->pending.length = 1;/
lzfse_fast_base_wrong_status|crushlzfse_encode_base_fast|lzfse_encode_base.c|s/return crushlzfse_encode_base_fast_4_0_0(s, hb, ss, ms, table, ltable);/return -99;/
lzfse_fast_base_corrupt_dst|crushlzfse_encode_base_fast|lzfse_encode_base.c|s/return crushlzfse_encode_base_fast_4_0_0(s, hb, ss, ms, table, ltable);/do { s->dst = s->dst_end + 1; return 0; } while (0);/
lzfse_fast_base_corrupt_buf|crushlzfse_encode_base_fast|lzfse_encode_base.c|s/return crushlzfse_encode_base_fast_4_0_0(s, hb, ss, ms, table, ltable);/do { s->dst_begin = NULL; return 0; } while (0);/
lzfse_lazy_base_wrong_status|crushlzfse_encode_base_lazy|lzfse_encode_base.c|s/return crushlzfse_encode_base_lazy_hw4(s, hash_bits, lookahead, hist_pos, hist_tag, hist_cursor);/return -99;/
lzfse_lazy_base_corrupt_dst|crushlzfse_encode_base_lazy|lzfse_encode_base.c|s/return crushlzfse_encode_base_lazy_hw4(s, hash_bits, lookahead, hist_pos, hist_tag, hist_cursor);/do { s->dst = s->dst_end + 1; return 0; } while (0);/
lzfse_lazy_base_corrupt_buf|crushlzfse_encode_base_lazy|lzfse_encode_base.c|s/return crushlzfse_encode_base_lazy_hw4(s, hash_bits, lookahead, hist_pos, hist_tag, hist_cursor);/do { s->dst_begin = NULL; return 0; } while (0);/
lzfse_base_bad_status|lzfse_encode_base|lzfse_encode_base.c|s/return ok ? LZFSE_STATUS_OK : LZFSE_STATUS_DST_FULL;/return -99;/
lzfse_base_corrupt_dst|lzfse_encode_base|lzfse_encode_base.c|s/s->src_encode_i = s->src_encode_end;/s->dst = s->dst_end + 1;/
lzfse_base_no_zopt_check|lzfse_encode_base|lzfse_encode_base.c|s/if (s->zopt == NULL) return LZFSE_STATUS_ERROR;/if (0) return LZFSE_STATUS_ERROR;/
lzfse_finish_wrong_status|lzfse_encode_finish|lzfse_encode_base.c|/int lzfse_encode_finish(lzfse_encoder_state \*s)/,/^}/s/return LZFSE_STATUS_OK;/return -99;/
lzfse_finish_corrupt_dst|lzfse_encode_finish|lzfse_encode_base.c|/int lzfse_encode_finish(lzfse_encoder_state \*s)/,/^}/s/return LZFSE_STATUS_OK;/do { s->dst = s->dst_end + 1; return 0; } while (0);/
lzfse_finish_corrupt_buf|lzfse_encode_finish|lzfse_encode_base.c|/int lzfse_encode_finish(lzfse_encoder_state \*s)/,/^}/s/return LZFSE_STATUS_OK;/do { s->dst_begin = NULL; return 0; } while (0);/
write_uncompressed_block_no_size_check|write_uncompressed_block|crushlzfse.c|s/if (src_size + 12 > dst_size || src_size >= (size_t)INT32_MAX) return 0;/if (0) return 0;/
write_uncompressed_block_wrong_return|write_uncompressed_block|crushlzfse.c|s/return (size_t)(p - dst);/return (size_t)(p - dst) + 1;/
write_uncompressed_block_dst_overflow|write_uncompressed_block|crushlzfse.c|s/p += src_size;/p += src_size + 1;/
lzfse_chained_no_stats_clear|crushlzfse_encode_buffer_chained|crushlzfse.c|s/memset(stats, 0, sizeof \*stats);/\/\/ no stats clear/
lzfse_chained_wrong_return|crushlzfse_encode_buffer_chained|crushlzfse.c|s/return out;/return dst_size + 1;/
lzfse_chained_bad_magic|crushlzfse_encode_buffer_chained|crushlzfse.c|s/stats->opaque\[0\] = CRUSHLZFSE_STATS_MAGIC;/stats->opaque[0] = 0xdeadbeef;/
load_seed_no_magic_check|load_seed|crushlzfse.c|s/if (stats->opaque\[0\] != CRUSHLZFSE_STATS_MAGIC) return 0;/if (0) return 0;/
load_seed_wrong_return|load_seed|crushlzfse.c|s/return 1;/return 2;/
load_seed_buffer_overrun|load_seed|crushlzfse.c|s/seed\[i\] = (uint32_t)c;/seed[i + 1] = (uint32_t)c;/
lzfse_backend_match_wrong_status|lzfse_backend_match|lzfse_encode_base.c|/static int lzfse_backend_match(/,/^}/s/return LZFSE_STATUS_OK;/return -99;/
lzfse_backend_match_corrupt_dst|lzfse_backend_match|lzfse_encode_base.c|/static int lzfse_backend_match(/,/^}/s/return LZFSE_STATUS_OK;/do { s->dst = s->dst_end + 1; return 0; } while (0);/
lzfse_backend_match_corrupt_buf|lzfse_backend_match|lzfse_encode_base.c|/static int lzfse_backend_match(/,/^}/s/return LZFSE_STATUS_OK;/do { s->dst_begin = NULL; return 0; } while (0);/
lzfse_backend_literals_wrong_status|lzfse_backend_literals|lzfse_encode_base.c|/static int lzfse_backend_literals(/,/^}/s/return lzfse_backend_match(s, &match);/return -99;/
lzfse_backend_literals_corrupt_dst|lzfse_backend_literals|lzfse_encode_base.c|/static int lzfse_backend_literals(/,/^}/s/return lzfse_backend_match(s, &match);/do { s->dst = s->dst_end + 1; return 0; } while (0);/
lzfse_backend_literals_corrupt_buf|lzfse_backend_literals|lzfse_encode_base.c|/static int lzfse_backend_literals(/,/^}/s/return lzfse_backend_match(s, &match);/do { s->dst_begin = NULL; return 0; } while (0);/
lzfse_push_match_wrong_status|lzfse_push_match|lzfse_encode_base.c|/static.*int lzfse_push_match(/,/^}/s/return LZFSE_STATUS_OK;/return -99;/
lzfse_push_match_corrupt_dst|lzfse_push_match|lzfse_encode_base.c|/static.*int lzfse_push_match(/,/^}/s/return LZFSE_STATUS_OK;/do { s->dst = s->dst_end + 1; return 0; } while (0);/
lzfse_push_match_corrupt_buf|lzfse_push_match|lzfse_encode_base.c|/static.*int lzfse_push_match(/,/^}/s/return LZFSE_STATUS_OK;/do { s->dst_begin = NULL; return 0; } while (0);/
lzfse_push_match_corrupt_literal|lzfse_push_match|lzfse_encode_base.c|/static.*int lzfse_push_match(/,/^}/s/return LZFSE_STATUS_OK;/do { s->src_literal = s->src_end + 1; return 0; } while (0);/
lzfse_encode_matches_wrong_status|lzfse_encode_matches|lzfse_encode_base.c|/static.*int lzfse_encode_matches(/,/^}/s/return LZFSE_STATUS_OK;/return -99;/
lzfse_encode_matches_corrupt_dst|lzfse_encode_matches|lzfse_encode_base.c|/static.*int lzfse_encode_matches(/,/^}/s/return LZFSE_STATUS_OK;/do { s->dst = s->dst_end + 1; return 0; } while (0);/
lzfse_encode_matches_corrupt_buf|lzfse_encode_matches|lzfse_encode_base.c|/static.*int lzfse_encode_matches(/,/^}/s/return LZFSE_STATUS_OK;/do { s->dst_begin = NULL; return 0; } while (0);/
lzfse_table_builder_corrupt_lit|lzfse_table_builder_bridge|lzfse_internal.h|s/(((uint32_t)1 << ((e) \& 0xff)) - 1) < 1024/(((uint32_t)1 << ((e) \& 0xff)) - 1) < 512/
lzfse_table_builder_corrupt_l|lzfse_table_builder_bridge|lzfse_internal.h|s/(uint32_t)(NSTATES)/(uint32_t)(NSTATES >> 1)/
lzfse_table_builder_corrupt_bits|lzfse_table_builder_bridge|lzfse_internal.h|s/(e).total_bits >= (e).value_bits/(e).total_bits > (e).value_bits/
lz4_encoder_bound_floor|lz4_encoder_queries|crushlz4.c|s/src_size == 0 ? 0 : (src_size - 1) \/ CRUSHLZ4_BLOCK_SIZE + 1/src_size \/ CRUSHLZ4_BLOCK_SIZE/
fse_flush64_no_lower_bound|fse_in_flush64|lzfse_fse.h|/FSE_INLINE int fse_in_checked_flush64(/,/FSE_INLINE int fse_in_checked_flush32(/s/if ((size_t)(\*pbuf - buf_start) < nbytes)/if (0)/
fse_flush64_restore_wide_read|fse_in_flush64|lzfse_fse.h|/FSE_INLINE int fse_in_checked_flush64(/,/FSE_INLINE int fse_in_checked_flush32(/s/memcpy(\&word, \*pbuf - 8, 8);/memcpy(\&word, *pbuf - nbytes, 8);/
fse_flush64_lookbehind_overread|fse_in_flush64|lzfse_fse.h|/FSE_INLINE int fse_in_checked_flush64(/,/FSE_INLINE int fse_in_checked_flush32(/s/memcpy(\&word, \*pbuf - 8, 8);/memcpy(\&word, *pbuf - 16, 8);/
fse_flush32_restore_wide_read|fse_in_flush32|lzfse_fse.h|/FSE_INLINE int fse_in_checked_flush32(/,/FSE_INLINE void fse_in_flush64_unchecked(/s/memcpy(\&word, \*pbuf - 4, 4);/memcpy(\&word, *pbuf - nbytes, 4);/
fse_flush32_lookbehind_overread|fse_in_flush32|lzfse_fse.h|/FSE_INLINE int fse_in_checked_flush32(/,/FSE_INLINE void fse_in_flush64_unchecked(/s/memcpy(\&word, \*pbuf - 4, 4);/memcpy(\&word, *pbuf - 8, 4);/
fse_flush_unchecked_restore_wide_read|fse_in_flush64_unchecked|lzfse_fse.h|/FSE_INLINE void fse_in_flush64_unchecked(/,/FSE_INLINE uint64_t fse_in_pull64(/s/memcpy(\&word, buf + (nbits >> 3) - 8, 8);/memcpy(\&word, buf, 8);/
fse_init64_pointer_past_end|fse_in_init64|lzfse_fse.h|s/if ((size_t)(\*pbuf - buf_start) < 7)/if (*pbuf < buf_start + 7)/
fse_pull64_no_consume|fse_in_pull64|lzfse_fse.h|/FSE_INLINE uint64_t fse_in_pull64(/,/FSE_INLINE uint32_t fse_in_pull32(/s/s->accum_nbits -= n;/s->accum_nbits -= 0;/
fse_pull32_wrong_result|fse_in_pull32|lzfse_fse.h|/FSE_INLINE uint32_t fse_in_pull32(/,/#if FSE_IOSTREAM_64/s/return result;/return result ^ 1;/
lz4_header_store_overrun|lz4_put_le32|crushlz4.c|s/p\[3\] = (uint8_t)(v >> 24);/p[4] = (uint8_t)(v >> 24);/
lz4_encoder_short_scratch|lz4_encode_allocation|crushlz4.c|s/return base + (CLZ4_SCRATCH_ALIGN - 1);/return base;/
lzfse_copy_overrun|lzfse_copy|lzfse_decode_base.c|/LZFSE_NOINLINE void copy(/,/typedef char lzfse_decode_copy_margin/s/copy8(dst, src);/copy8(dst + 8, src);/
lzfse_wide_copy_overrun|lzfse_copy_match_wide|lzfse_decode_base.c|/LZFSE_NOINLINE void copy_match_wide(/,/#define LZFSE_MATCH_PERIOD_TARGET/s/copy16(dst + k, src + k);/copy16(dst + k + 16, src + k);/
slack_14|lz4_copy_match|crushlz4.c|s/^#define CLZ4_COPY_SLACK 16$/#define CLZ4_COPY_SLACK 14/
wide_copy_off_7|lz4_copy_match|crushlz4.c|s/if (off >= 8 \&\& mlen + CLZ4_COPY_SLACK <= room)/if (off >= 7 \&\& mlen + CLZ4_COPY_SLACK <= room)/
wide_copy_no_room_check|lz4_copy_match|crushlz4.c|s/if (off >= 8 \&\& mlen + CLZ4_COPY_SLACK <= room)/if (off >= 8)/
byte_copy_one_past|lz4_copy_match|crushlz4.c|s/for (; k < mlen; k++)$/for (; k <= mlen; k++)/
fast_dst_32|lz4_decode_block|crushlz4.c|s/^#define CLZ4_FAST_DST 64$/#define CLZ4_FAST_DST 32/
fast_src_16|lz4_decode_block|crushlz4.c|s/^#define CLZ4_FAST_SRC 32$/#define CLZ4_FAST_SRC 16/
fast_offset_zero_only|lz4_decode_block|crushlz4.c|s/^            if (off - 1 >= dp) return CLZ4_INVAL;$/            if (off == 0) return CLZ4_INVAL;/
offset_check_off_by_one|lz4_decode_block|crushlz4.c|s/^        if (off - 1 >= dp) return CLZ4_INVAL;$/        if (off - 1 > dp) return CLZ4_INVAL;/
fast_long_match_no_range|lz4_decode_block|crushlz4.c|s/if (ml > dst_cap - dp) return CLZ4_RANGE;/(void)0;/
literal_no_range|lz4_decode_block|crushlz4.c|s/if (llen > dst_cap - dp) return CLZ4_RANGE;/(void)0;/
literal_no_src_check|lz4_decode_block|crushlz4.c|s/if (llen > slen - sp) return CLZ4_INVAL;/(void)0;/
fast_ext_no_src_check|lz4_decode_block|crushlz4.c|0,/if (sp >= slen) return CLZ4_INVAL;/s//(void)0;/
copy_match_room_too_big|lz4_decode_block|crushlz4.c|s/copy_match(d, off, ml, dst_cap - dp);/copy_match(d, off, ml, dst_cap - dp + 16);/
stored_no_range|lz4_decode|crushlz4.c|s/if (n > cap - dp) { \*out_len = dp; return CLZ4_RANGE; }//
stored_empty_no_progress|lz4_decode|crushlz4.c|s/^            sp += 8;$/            sp += n ? 8 : 0;/
decode_block_cap_too_big|lz4_decode|crushlz4.c|s/decode_block(dst, dest_size, \&dp,/decode_block(dst, dest_size + 16, \&dp,/
zbm_number_no_meta2_check|zbm_apply_bitmap_number|libzbitmap.c|s/if(state->meta_2 >= state->src_end)/if(0)/
zbm_number_selector_15|zbm_apply_bitmap_number|libzbitmap.c|s/if(bmp_num == 0xf)/if(0)/
zbm_count_no_limit|zbm_read_repetition_count|libzbitmap.c|s/if(total > CRUSHLZBITMAP_CHUNK_SIZE \/ 8)/if(0)/
zbm_count_no_progress|zbm_read_repetition_count|libzbitmap.c|s/++nybl->addr;/nybl->addr += 0;/
zbm_table_pbc3|zbm_read_bitmaps|libzbitmap.c|s/if(v >> 8 > ZBM_MAX_PERIOD_BYTECNT)/if(0)/
zbm_blend_wrong_bitmap|zbm_blend8_correct|libzbitmap.c|s/zbm_blend8_row(dst, base, lits, zbm_blend_row\[bmp\]);/zbm_blend8_row(dst, base, lits, zbm_blend_row[0]);/
zbm_table_wrong_shift|zbm_table_correct|libzbitmap.c|s/w1 >> (10 \* i - 56)/w1 >> (10 * i - 55)/
zbm_history_no_rewind|zbm_last_nonrepeat_nibble|libzbitmap.c|s/zbm_rewind_nibble(\&scan);/(void)0;/
zbm_block_no_history_check|zbm_apply_bitmap|libzbitmap.c|s/if(state->prewritten + state->written < state->period)/if(0)/
zbm_fill_unclamped_doubling|zbm_fill_periodic|libzbitmap.c|s/uint32_t chunk = filled < total - filled ? filled : total - filled;/uint32_t chunk = filled;/
zbm_patch_no_vector_margin|zbm_patch_literals|libzbitmap.c|s/if(!ZBM_SHORT(lit, (size_t)nlit \* (n_blocks - 1) + 8, src_end))/if(1)/
zbm_slow_no_progress|zbm_apply_bitmap_run_slow|libzbitmap.c|s/--repeat;/(void)0;/
zbm_run_no_clamp|zbm_apply_bitmap_run|libzbitmap.c|s/if(total > remaining)/if(0)/
zbm_dispatch_bad_written|zbm_decompress_single_bitmap|libzbitmap.c|s/err = zbm_apply_bitmap_number(state, bmp_num);/err = zbm_apply_bitmap_number(state, bmp_num); state->written -= (err == 0);/
zbm_budget_no_lookahead|zbm_pair_budget|libzbitmap.c|s/d = src_end - m3a - 1;/d = src_end - m3a;/
zbm_pair_no_history|zbm_decode_pairs|libzbitmap.c|s/if(new_ < 8 [|][|] c.avail < new_)/if(0)/
zbm_parser_budget_too_big|zbm_handle_compressed_chunk|libzbitmap.c|s/bmpbase, pbcbase, rowbase, k);/bmpbase, pbcbase, rowbase, k + 1);/
zbm_chunk_no_src_bound|zbm_handle_chunk|libzbitmap.c|s/if(state->len > state->src_left)/if(0)/
zbm_chunk_no_dest_bound|zbm_handle_chunk|libzbitmap.c|s/if(state->decmp_len > state->dest_left)/if(0)/
zbm_decode_no_source_progress|zbm_decode|libzbitmap.c|s/state.src_left -= state.len;/state.src_left -= 0;/
zbm_bound_floor_chunks|zbm_encode_bound|libzbitmap.c|s/(src_size + CRUSHLZBITMAP_CHUNK_SIZE - 1) \/ CRUSHLZBITMAP_CHUNK_SIZE/src_size \/ CRUSHLZBITMAP_CHUNK_SIZE/
zbm_diff_wrong_shift|zbm_diff_bitmap_correct|libzbitmap.c|s/t \* 0x0102040810204080ULL >> 56/t * 0x0102040810204080ULL >> 55/
zbm_fast_skip_no_progress|zbm_fast_skip|libzbitmap.c|s/return 8 + 8 \* (size_t)(failures >> shift);/return 8 * (size_t)(failures >> shift);/
zbm_fast_hash_wide|zbm_fast_hash8|libzbitmap.c|s/return (key \* 0x9E3779B1u) >> sh;/return (key * 0x9E3779B1u) >> (sh - 1);/
zbm_fast_score_overread|zbm_fast_score|libzbitmap.c|s/zbm_load_u64(src - dd\[j\]))/zbm_load_u64(src - dd[j] - 1))/
zbm_pack8_overrun|zbm_pack8|crush_simd.h|s/for (int i = 0; i < 8; i++)/for (int i = 0; i < 9; i++)/
zbm_tab_bits_no_cap|zbm_tab_bits|libzbitmap.c|s/return need < hash_bits ? need : hash_bits;/return need;/
zbm_fast_index_overread|zbm_fast_prepare_index|libzbitmap.c|s/for(; p + 8 <= chunk_start; p += 8)/for(; p + 7 <= chunk_start; p += 8)/
zbm_fast_index_wide_clear|zbm_fast_prepare_index|libzbitmap.c|s/memset(state->row_tab, 0, sizeof(state->row_tab\[0\]) << (32 - state->row_sh));/memset(state->row_tab, 0, sizeof(state->row_tab[0]) << (35 - state->row_sh));/
zbm_row_range_no_clip|zbm_row_index_range|libzbitmap.c|s/if(to > state->buf_len - (ZBM_ROW_KEY_BYTES - 1))/if(0)/
zbm_row_range_no_clip2|zbm_row_index_range|libzbitmap.c|s/if(to > state->buf_len - (ZBM_ROW_KEY2_BYTES - 1))/if(0)/
zbm_row_range_short_input|zbm_row_index_range|libzbitmap.c|s/if(state->buf_len < ZBM_ROW_KEY_BYTES)/if(0)/
zbm_row_prepare_tab2_bits|zbm_row_prepare_index|libzbitmap.c|s/zbm_tab_bits(state, ZBM_ROW2_BITS)/zbm_tab_bits(state, ZBM_ROW2_BITS + 1)/
zbm_row_prepare_wide_clear2|zbm_row_prepare_index|libzbitmap.c|s/ZBM_ROW2_WAYS << (32 - state->row_sh2))/ZBM_ROW2_WAYS << (33 - state->row_sh2))/
zbm_scratch_short_dp|zbm_encoder_scratch|libzbitmap.c|s/sizeof(uint8_t)  \* ZBM_MAX_BITMAP_COUNT \* n/sizeof(uint8_t)  * (ZBM_MAX_BITMAP_COUNT - 1) * n/
zbm_encoder_table_no_room|zbm_encoder_table|libzbitmap.c|s/if(state->dest_end - state->dest < ZBM_BITMAP_BYTECNT)/if(0)/
zbm_encoder_params_bad_depth|zbm_encoder_params|libzbitmap.c|s/if(rp->depth != 1 \&\& rp->depth != 2 \&\& rp->depth != 4 \&\& rp->depth != 8 \&\& rp->depth != 16)/if(0)/
zbm_pack_wrong_bitmap|zbm_pack8_correct|libzbitmap.c|s/{1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0}/{0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0}/
zbm_scratch_free_caller|zbm_encoder_scratch|libzbitmap.c|s/if(!scratch)/if(1)/
zbm_scratch_no_alloc_check|zbm_encoder_scratch|libzbitmap.c|s/if(!state)/if(0)/
zbm_encoder_magic_no_room|zbm_encoder_magic|libzbitmap.c|s/if(state->dest_left < ZBM_MAGIC_SZ)/if(0)/
zbm_encoder_stored_bad_rewind|zbm_encoder_stored|libzbitmap.c|s/state->dest -= state->written - sizeof(struct zbm_chunk_hdr);/state->dest -= state->written;/
zbm_encoder_nibbles_bad_carry|zbm_encoder_nibbles|libzbitmap.c|s/out->acc = pat >> 4 \* (k - out->n);/out->acc = pat;/
zbm_encoder_nibble_bad_reset|zbm_encoder_nibble|libzbitmap.c|s/out->n = 0;/out->n = 16;/
zbm_encoder_nibble_finish_overrun|zbm_encoder_nibble_finish|libzbitmap.c|s/int bytes = (out->n + 1) \/ 2;/int bytes = (out->n + 1) \/ 2 + 1;/
zbm_encoder_nibbles_wrong_order|zbm_encoder_nibbles_correct|libzbitmap.c|s/out->addr\[i\] = (uint8_t)(out->acc >> 8 \* i);/out->addr[i] = (uint8_t)(out->acc >> 4 * i);/
zbm_encoder_key_wrong_lane|zbm_encoder_key|libzbitmap.c|/static unsigned zbm_bmkey(/,/static int zbm_bmprot(/s/return v;/return v << 1;/
zbm_encoder_bitmap_tail_full_load|zbm_encoder_bitmap|libzbitmap.c|/static uint8_t zbm_calculate_bitmap(/,/static const uint8_t zbm_pack_row/s/if(size == 8)/if(size > 0)/
zbm_encoder_run_wrong_termination|zbm_encoder_run_values|libzbitmap.c|/static int zbm_run_length(/,/struct zbm_nybl_out {/s/if(n != bmap_num)/if(n == bmap_num)/
zbm_encoder_run_no_bound|zbm_encoder_run|libzbitmap.c|s/for(i = idx + 1; i < state->bmp_cnt; ++i)/for(i = idx + 1; i <= state->bmp_cnt; ++i)/
zbm_encoder_literal_sum_wrong_count|zbm_encoder_literal_total|libzbitmap.c|s/total += zbm_popcount8(bmaps\[i\].bitmap);/total += 9;/
zbm_encoder_period_sum_wrong_count|zbm_encoder_period_total|libzbitmap.c|s/total += bmaps\[i\].period_bytecnt;/total += 256;/
zbm_encoder_repeat_no_progress|zbm_encoder_repeat|libzbitmap.c|/static void zbm_write_repetition_count(/,/static void zbm_build_run_boundaries(/s/repeat -= nibble;/repeat -= 0;/
zbm_encoder_number_table_bad_value|zbm_encoder_number_table|libzbitmap.c|s/(uint8_t)(i + 3);/(uint8_t)(i + 16);/
zbm_encoder_numbers_bad_value|zbm_encoder_numbers_values|libzbitmap.c|s/state->bmap_nums\[i\] = state->bmap_num_tbl\[key\];/state->bmap_nums[i] = 255;/
zbm_encoder_number_table_off_by_one|zbm_encoder_number_table|libzbitmap.c|s/for(key = 0; key < ZBM_POSSIBLE_BMPROTS; ++key)/for(key = 0; key <= ZBM_POSSIBLE_BMPROTS; ++key)/
zbm_encoder_numbers_outside_frame|zbm_encoder_numbers|libzbitmap.c|s/state->bmap_nums\[i\] = state->bmap_num_tbl\[key\];/state->bmap_nums[i + ZBM_MAX_BITMAP_COUNT + 16] = state->bmap_num_tbl[key];/
zbm_encoder_run_cost_too_large|zbm_encoder_run_cost|libzbitmap.c|s/return 2 + digits + terminator;/return r + 1;/
zbm_encoder_run_delta_wrong|zbm_encoder_run_delta|libzbitmap.c|s/return (len - 3) % 15 == 0;/return 0;/
zbm_encoder_eq16_wrong_bits|zbm_encoder_eq16|crush_simd.h|/static inline uint16_t zbm_eq16_mask(/,/static inline uint64_t zbm_pack_nibbles16(/s/1u << i/1u << (15 - i)/
zbm_encoder_pack_nibbles_wrong_order|zbm_encoder_pack_nibbles|crush_simd.h|/static inline uint64_t zbm_pack_nibbles16(/,/#elif defined(__ARM_NEON)/s/4 \* i/4 * (15 - i)/
zbm_encoder_eq16_overread|zbm_encoder_eq16|crush_simd.h|/static inline uint16_t zbm_eq16_mask(/,/static inline uint64_t zbm_pack_nibbles16(/s/a\[i\] == b\[i\]/a[i + 1] == b[i]/
zbm_encoder_pack_nibbles_overread|zbm_encoder_pack_nibbles|crush_simd.h|/static inline uint64_t zbm_pack_nibbles16(/,/#elif defined(__ARM_NEON)/s/i < 16/i <= 16/
zbm_encoder_short_pattern_overflow|zbm_encoder_short_pattern|libzbitmap.c|s/0x011, 0x111/0x011, 0x1111/
zbm_encoder_word_index_wrong_shift|zbm_encoder_word_index|libzbitmap.c|s/return index >> 6;/return index >> 5;/
zbm_encoder_first_boundary_wrong_bit|zbm_encoder_first_boundary|libzbitmap.c|s/return __builtin_ctzll(word);/return 0;/
zbm_encoder_run_end_skips_word|zbm_encoder_find_run_end|libzbitmap.c|/inline int zbm_find_run_end(/,/static int zbm_write_metadata_3(/s/++b;/b += 2;/
zbm_encoder_run_end_lost_shift|zbm_encoder_find_run_end|libzbitmap.c|s/uint64_t w = bnd\[kk\] >> sft;/uint64_t w = bnd[kk];/
zbm_encoder_vector_bad_carry|zbm_encoder_vector_nibbles|libzbitmap.c|s/out->acc = (packed >> 1) >> (63 - 4 \* out->n);/out->acc = packed;/
zbm_encoder_vector_lost_prefix|zbm_encoder_vector_nibbles_correct|libzbitmap.c|s/out->acc | packed << (4 \* out->n)/packed << (4 * out->n)/
zbm_encoder_long_tail_overrun|zbm_encoder_long_arrays|libzbitmap.c|s/lng\[words\] = 0;/& if(words == ZBM_MAX_BITMAP_COUNT \/ 64) lng[words + 1] = 0;/
zbm_encoder_long_lost_carry|zbm_encoder_long_arrays_values|libzbitmap.c|/inline void zbm_build_long_runs_arrays(/,/static int zbm_write_metadata_3(/s/prev = l;/prev = 0;/
zbm_encoder_long_skipped_next|zbm_encoder_long_arrays_values|libzbitmap.c|/inline void zbm_build_long_runs_arrays(/,/static int zbm_write_metadata_3(/s/k + 1 < words ? ~bnd\[k + 1\] : 0/k + 2 < words ? ~bnd[k + 1] : 0/
zbm_encoder_long_no_previous|zbm_encoder_long_masks|libzbitmap.c|s/ | prev >> 61 | prev >> 62 | prev >> 63;/;/
zbm_encoder_long_no_next|zbm_encoder_long_masks|libzbitmap.c|s/nb >> 2 | nb1 << 62/nb >> 2/
zbm_encoder_member_window_lost_next|zbm_encoder_long_member_window|libzbitmap.c|s/(next << 1) << (63 - shift)/UINT64_C(0)/
zbm_encoder_long_window_unsafe_shift|zbm_encoder_long_window|libzbitmap.c|s/(next << 1) << (63 - shift)/next << (64 - shift)/
zbm_encoder_long_window_wrong_next|zbm_encoder_long_window|libzbitmap.c|s/(next << 1) << (63 - shift)/(next << 2) << (63 - shift)/
zbm_encoder_boundary_changes_selector|zbm_encoder_boundary_arrays_values|libzbitmap.c|s/bnd\[(cnt - 1) >> 6\] |= (uint64_t)1 << ((cnt - 1) \& 63);/& if(cnt == 1) nums[0] ^= 1;/
zbm_encoder_boundary_wrong_bits|zbm_encoder_boundary_arrays_values|libzbitmap.c|s/bnd\[g\] = ~eq;/bnd[g] = eq;/
zbm_encoder_eq16_query_wrong_bits|zbm_encoder_eq16_query|crush_simd.h|/static inline uint16_t zbm_eq16_mask(/,/static inline uint64_t zbm_pack_nibbles16(/s/1u << i/1u << (15 - i)/
zbm_encoder_boundary_tail_overrun|zbm_encoder_boundary_arrays|libzbitmap.c|/inline void zbm_build_run_boundaries_arrays(/,/static void zbm_build_run_boundaries(/s/nums\[cnt + k\] = 0;/nums[cnt + k + 1] = 0;/
zbm_encoder_boundary_no_terminator|zbm_encoder_boundary_arrays|libzbitmap.c|s/bnd\[(cnt - 1) >> 6\] |= (uint64_t)1 << ((cnt - 1) \& 63);/bnd[(cnt - 1) >> 6] \&= ~((uint64_t)1 << ((cnt - 1) \& 63));/
zbm_encoder_number_at_off_by_one|zbm_encoder_number_at|libzbitmap.c|s/return state->bmap_nums\[idx\];/return state->bmap_nums[idx + 1];/
zbm_encoder_metadata3_cost_too_large|zbm_encoder_metadata3_size|libzbitmap.c|s/nibbles += zbm_nibble_cost_for_run(repeat);/nibbles += zbm_nibble_cost_for_run(repeat) + 1;/
zbm_encoder_bmprot_wrong_shift|zbm_encoder_bmprot|libzbitmap.c|s/return (int)bmap->bitmap << 2 | (int)bmap->period_bytecnt;/return (int)bmap->bitmap << 3 | (int)bmap->period_bytecnt;/
zbm_encoder_top_no_bar|zbm_encoder_top|libzbitmap.c|s/if(tops\[ZBM_BITMAP_COUNT - 1\].usecnt >= usecnt)/if(0)/
zbm_encoder_top_bad_index|zbm_encoder_top|libzbitmap.c|s/state->usecnts\[tops\[i\].bmprot\] = 0;/state->usecnts[tops[i].bmprot + ZBM_POSSIBLE_BMPROTS] = 0;/
zbm_single_chunk_no_dest_check|zbm_compress_single_chunk|libzbitmap.c|s/if(max_chunk_sz > state->dest_left)/if(0)/
zbm_single_chunk_no_tie_fallback|zbm_compress_single_chunk|libzbitmap.c|s/if(!err && state->written >= max_chunk_sz)/if(0)/
zbm_single_chunk_bad_header_len|zbm_compress_single_chunk|libzbitmap.c|s/decmp_hdr->len = zbm_u32_to_u24(state->written);/decmp_hdr->len = zbm_u32_to_u24(state->written - 1);/
zbm_encode_chunk_no_magic|crushlzbitmap_encode_chunk|libzbitmap.c|s/if(index == 0) {/if(0) {/
zbm_encode_chunk_no_index_overflow|crushlzbitmap_encode_chunk|libzbitmap.c|s/if(offset >> CRUSHLZBITMAP_CHUNK_SIZE_BITS != index) {/if(0) {/
zbm_encode_chunk_no_dest_advance|crushlzbitmap_encode_chunk|libzbitmap.c|s/state->prewritten += state->written;/state->prewritten += 0;/
zbm_encode_chunk_bad_scratch_check|crushlzbitmap_encode_chunk|libzbitmap.c|s/if(scratch && scratch_size < crushlzbitmap_scratch_size(params))/if(0)/
zbm_encode_buffer_no_dst_check|crushlzbitmap_encode_buffer|libzbitmap.c|s/if(!dst)/if(0)/
zbm_encode_buffer_no_dest_advance|crushlzbitmap_encode_buffer|libzbitmap.c|s/state->prewritten += state->written;/state->prewritten += 0;/
zbm_encode_buffer_bad_scratch_check|crushlzbitmap_encode_buffer|libzbitmap.c|s/if(scratch && scratch_size < crushlzbitmap_scratch_size(params))/if(0)/
zbm_number_no_meta2_check_neon|zbm_apply_bitmap_number_neon|libzbitmap.c|s/if(state->meta_2 >= state->src_end)/if(0)/
zbm_number_selector_15_neon|zbm_apply_bitmap_number_neon|libzbitmap.c|s/if(bmp_num == 0xf)/if(0)/
zbm_count_no_limit_neon|zbm_read_repetition_count_neon|libzbitmap.c|s/if(total > CRUSHLZBITMAP_CHUNK_SIZE \/ 8)/if(0)/
zbm_count_no_progress_neon|zbm_read_repetition_count_neon|libzbitmap.c|s/++nybl->addr;/nybl->addr += 0;/
zbm_table_pbc3_neon|zbm_read_bitmaps_neon|libzbitmap.c|s/if(v >> 8 > ZBM_MAX_PERIOD_BYTECNT)/if(0)/
zbm_blend_wrong_bitmap_neon|zbm_blend8_correct_neon|libzbitmap.c|s/zbm_blend8_row(dst, base, lits, zbm_blend_row\[bmp\]);/zbm_blend8_row(dst, base, lits, zbm_blend_row[0]);/
zbm_history_no_rewind_neon|zbm_last_nonrepeat_nibble_neon|libzbitmap.c|s/zbm_rewind_nibble(\&scan);/(void)0;/
zbm_block_no_history_check_neon|zbm_apply_bitmap_neon|libzbitmap.c|s/if(state->prewritten + state->written < state->period)/if(0)/
zbm_fill_unclamped_doubling_neon|zbm_fill_periodic_neon|libzbitmap.c|s/uint32_t chunk = filled < total - filled ? filled : total - filled;/uint32_t chunk = filled;/
zbm_patch_no_vector_margin_neon|zbm_patch_literals_neon|libzbitmap.c|s/if(!ZBM_SHORT(lit, (size_t)nlit \* (n_blocks - 1) + 8, src_end))/if(1)/
zbm_slow_no_progress_neon|zbm_apply_bitmap_run_slow_neon|libzbitmap.c|s/--repeat;/(void)0;/
zbm_run_no_clamp_neon|zbm_apply_bitmap_run_neon|libzbitmap.c|s/if(total > remaining)/if(0)/
zbm_dispatch_bad_written_neon|zbm_decompress_single_bitmap_neon|libzbitmap.c|s/err = zbm_apply_bitmap_number(state, bmp_num);/err = zbm_apply_bitmap_number(state, bmp_num); state->written -= (err == 0);/
zbm_budget_no_lookahead_neon|zbm_pair_budget_neon|libzbitmap.c|s/d = src_end - m3a - 1;/d = src_end - m3a;/
zbm_pair_no_history_neon|zbm_decode_pairs_neon|libzbitmap.c|s/if(new_ < 8 [|][|] c.avail < new_)/if(0)/
zbm_parser_budget_too_big_neon|zbm_handle_compressed_chunk_neon|libzbitmap.c|s/bmpbase, pbcbase, rowbase, k);/bmpbase, pbcbase, rowbase, k + 1);/
zbm_chunk_no_src_bound_neon|zbm_handle_chunk_neon|libzbitmap.c|s/if(state->len > state->src_left)/if(0)/
zbm_chunk_no_dest_bound_neon|zbm_handle_chunk_neon|libzbitmap.c|s/if(state->decmp_len > state->dest_left)/if(0)/
zbm_decode_no_source_progress_neon|zbm_decode_neon|libzbitmap.c|s/state.src_left -= state.len;/state.src_left -= 0;/
zbm_number_no_meta2_check_sse|zbm_apply_bitmap_number_sse|libzbitmap.c|s/if(state->meta_2 >= state->src_end)/if(0)/
zbm_number_selector_15_sse|zbm_apply_bitmap_number_sse|libzbitmap.c|s/if(bmp_num == 0xf)/if(0)/
zbm_count_no_limit_sse|zbm_read_repetition_count_sse|libzbitmap.c|s/if(total > CRUSHLZBITMAP_CHUNK_SIZE \/ 8)/if(0)/
zbm_count_no_progress_sse|zbm_read_repetition_count_sse|libzbitmap.c|s/++nybl->addr;/nybl->addr += 0;/
zbm_table_pbc3_sse|zbm_read_bitmaps_sse|libzbitmap.c|s/if(v >> 8 > ZBM_MAX_PERIOD_BYTECNT)/if(0)/
zbm_blend_wrong_bitmap_sse|zbm_blend8_correct_sse|libzbitmap.c|s/zbm_blend8_row(dst, base, lits, zbm_blend_row\[bmp\]);/zbm_blend8_row(dst, base, lits, zbm_blend_row[0]);/
zbm_history_no_rewind_sse|zbm_last_nonrepeat_nibble_sse|libzbitmap.c|s/zbm_rewind_nibble(\&scan);/(void)0;/
zbm_block_no_history_check_sse|zbm_apply_bitmap_sse|libzbitmap.c|s/if(state->prewritten + state->written < state->period)/if(0)/
zbm_fill_unclamped_doubling_sse|zbm_fill_periodic_sse|libzbitmap.c|s/uint32_t chunk = filled < total - filled ? filled : total - filled;/uint32_t chunk = filled;/
zbm_patch_no_vector_margin_sse|zbm_patch_literals_sse|libzbitmap.c|s/if(!ZBM_SHORT(lit, (size_t)nlit \* (n_blocks - 1) + 8, src_end))/if(1)/
zbm_slow_no_progress_sse|zbm_apply_bitmap_run_slow_sse|libzbitmap.c|s/--repeat;/(void)0;/
zbm_run_no_clamp_sse|zbm_apply_bitmap_run_sse|libzbitmap.c|s/if(total > remaining)/if(0)/
zbm_dispatch_bad_written_sse|zbm_decompress_single_bitmap_sse|libzbitmap.c|s/err = zbm_apply_bitmap_number(state, bmp_num);/err = zbm_apply_bitmap_number(state, bmp_num); state->written -= (err == 0);/
zbm_budget_no_lookahead_sse|zbm_pair_budget_sse|libzbitmap.c|s/d = src_end - m3a - 1;/d = src_end - m3a;/
zbm_pair_no_history_sse|zbm_decode_pairs_sse|libzbitmap.c|s/if(new_ < 8 [|][|] c.avail < new_)/if(0)/
zbm_parser_budget_too_big_sse|zbm_handle_compressed_chunk_sse|libzbitmap.c|s/bmpbase, pbcbase, rowbase, k);/bmpbase, pbcbase, rowbase, k + 1);/
zbm_chunk_no_src_bound_sse|zbm_handle_chunk_sse|libzbitmap.c|s/if(state->len > state->src_left)/if(0)/
zbm_chunk_no_dest_bound_sse|zbm_handle_chunk_sse|libzbitmap.c|s/if(state->decmp_len > state->dest_left)/if(0)/
zbm_decode_no_source_progress_sse|zbm_decode_sse|libzbitmap.c|s/state.src_left -= state.len;/state.src_left -= 0;/
zbm_table_selector_high_neon|zbm_blend8_correct_neon|zbm_blend_tables.h|s/^  {0,9,10,11,12,13,14,15,1,0,0,0,0,0,0,0},/  {0,137,10,11,12,13,14,15,1,0,0,0,0,0,0,0},/
zbm_table_selector_high_sse|zbm_blend8_correct_sse|zbm_blend_tables.h|s/^  {0,9,10,11,12,13,14,15,1,0,0,0,0,0,0,0},/  {0,137,10,11,12,13,14,15,1,0,0,0,0,0,0,0},/
zbm_neon_sel_overread|zbm_sel_load_neon|crush_simd.h|s/return vld1_u8(row);/return vld1_u8(row + 1);/
zbm_neon_blend_overread|zbm_blend8_sel_neon|crush_simd.h|s/vcombine_u8(vld1_u8(lits), vld1_u8(base)), sel)/vcombine_u8(vld1_u8(lits + 1), vld1_u8(base)), sel)/
zbm_neon_row_overread|zbm_blend8_row_neon|crush_simd.h|s/vld1_u8(row)));/vld1_u8(row + 1)));/
zbm_neon_cpy32_overwrite|zbm_cpy32_neon|crush_simd.h|s/vst1q_u8(d + 16, vld1q_u8(s + 16));/vst1q_u8(d + 17, vld1q_u8(s + 16));/
zbm_sse_sel_overread|zbm_sel_load_sse|crush_simd.h|/zbm_sel_load(const uint8_t \*row)$/,/^}/s/(const void \*)row)/(const void *)(row + 1))/
zbm_sse_blend_overwrite|zbm_blend8_sel_sse|crush_simd.h|s/_mm_storel_epi64((__m128i \*)(void \*)dst, _mm_shuffle_epi8(v, sel));/_mm_storel_epi64((__m128i *)(void *)(dst + 1), _mm_shuffle_epi8(v, sel));/
zbm_sse_cpy32_overwrite|zbm_cpy32_sse|crush_simd.h|s/_mm_storeu_si128((__m128i \*)(void \*)(d + 16), b);/_mm_storeu_si128((__m128i *)(void *)(d + 17), b);/
zbm_pair_table_count_high|zbm_decode_pairs|zbm_blend_tables.h|s/^  {0,1,2,3,4,5,6,7,8,0,0,0,0,0,0,0},/  {0,1,2,3,4,5,6,7,17,0,0,0,0,0,0,0},/
zbm_pair_table_count_high_neon|zbm_decode_pairs_neon|zbm_blend_tables.h|s/^  {0,1,2,3,4,5,6,7,8,0,0,0,0,0,0,0},/  {0,1,2,3,4,5,6,7,17,0,0,0,0,0,0,0},/
zbm_pair_table_count_high_sse|zbm_decode_pairs_sse|zbm_blend_tables.h|s/^  {0,1,2,3,4,5,6,7,8,0,0,0,0,0,0,0},/  {0,1,2,3,4,5,6,7,17,0,0,0,0,0,0,0},/
'

# run_mutant NAME: apply mutant NAME and check its proof fails.
run_mutant() {
    line=$(echo "$MUTANTS" | grep "^$1|") || {
        echo "error: no mutant $1" >&2; return 2; }
    IFS='|' read -r name proof file expr <<EOM
$line
EOM
    dir="$WORK/mutant_$name"
    mkdir -p "$dir"
    eval inc=\$${proof}_inc
    # Preserve the complete quoted-include closure. A header in the original
    # source directory would resolve its nested includes there, bypassing a
    # mutated sibling supplied only through -I.
    cp -R "$inc/." "$dir/"
    sed "$expr" "$inc/$file" >"$dir/$file"
    if cmp -s "$inc/$file" "$dir/$file"; then
        echo "FAIL  mutant $name: the edit no longer applies; update MUTANTS"
        return 1
    fi
    # Quoted includes search the C source's directory before -I paths.
    # Copy the source alongside a mutated header so its edit is exercised.
    build "$proof" "$dir/$proof" "$dir"
    # One counterexample is enough to catch a mutant.
    if prove "$proof" "$dir/$proof" --stop-on-fail; then
        echo "FAIL  mutant $name: $proof still passes"
        return 1
    fi
    if ! grep -q '^VERIFICATION FAILED' "$dir/$proof.log"; then
        echo "FAIL  mutant $name: cbmc did not finish"
        tail -n 3 "$dir/$proof.log" | sed 's/^/      /'
        return 1
    fi
    why=$(grep -A3 '^Violated property' "$dir/$proof.log" | sed -n '3,4s/^ *//p' |
          paste -sd '|' - | sed 's/|/: /')
    echo "ok    mutant $name caught: $why"
}

# Proofs and mutants are independent, so each runs as its own job.
# PROOF_JOBS sets how many at once; each cbmc needs about 2 GiB.
JOBS=${PROOF_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}

# parallel ACTION NAME...: run "$0 ACTION NAME" for each NAME, JOBS at a
# time. Fails if any job does.
parallel() {
    action=$1; shift
    printf '%s\n' "$@" | xargs -P "$JOBS" -n 1 "$0" "$action"
}

case "${1:-}" in
    "") # shellcheck disable=SC2086
        parallel proof $PROOF_LIST ;;
    mutants)
        # shellcheck disable=SC2046
        parallel mutant $(echo "$MUTANTS" | sed -n 's/^\([^|]*\)|.*/\1/p') ;;
    proof) run_proof "$2" ;;
    mutant) run_mutant "$2" ;;
    *)  for target in "$@"; do
            case " $PROOF_LIST " in
                *" $target "*) ;;
                *) echo "error: unknown proof $target" >&2; exit 2 ;;
            esac
        done
        parallel proof "$@" ;;
esac
