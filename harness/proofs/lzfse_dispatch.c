/*
 * Proof: on x86-64 builds without BMI2 (LZFSE_X86_BMI2_DISPATCH), the
 * lzfse_decode_literals and lzfse_decode_lmd dispatchers in
 * lzfse_decode_base.c meet the contracts the frame consumes, given that each
 * hot-loop clone meets the same contract. The CPUID answer is arbitrary
 * (simd/include/cpuid.h) and the memo starts unset or at either answer. The
 * clones are token-identical (simd/check_bmi2_clone.py), so the hot-loop
 * proofs cover both. PROOF_DISPATCH_LMD selects the LMD dispatcher;
 * otherwise literals.
 */
#include "proof.h"
#include "lzfse_internal.h"
/* The dispatcher's private CPUID memo is its only write beyond the callee
 * contracts; declared here so the contracts can name it. */
static int lzfse_x86_bmi2_cached;
#define LZFSE_PROOF_HOT_EXTRA_ASSIGNS __CPROVER_assigns(lzfse_x86_bmi2_cached)
#include "lzfse_frame_interface.h"

static int lzfse_decode_literals_baseline(lzfse_decoder_state *s,
                                          const lzfse_compressed_block_header_v1 *header1,
                                          lzfse_compressed_block_decoder_state *bs)
LZFSE_PROOF_LITERALS_CONTRACT;
static int lzfse_decode_literals_bmi2(lzfse_decoder_state *s,
                                      const lzfse_compressed_block_header_v1 *header1,
                                      lzfse_compressed_block_decoder_state *bs)
LZFSE_PROOF_LITERALS_CONTRACT;
static int lzfse_decode_lmd_baseline(lzfse_decoder_state *s) LZFSE_PROOF_LMD_CONTRACT;
static int lzfse_decode_lmd_bmi2(lzfse_decoder_state *s) LZFSE_PROOF_LMD_CONTRACT;

#include "lzfse_decode_base.c"

#if !LZFSE_X86_BMI2_DISPATCH
#error "dispatch proof needs the x86-64 non-BMI2 configuration"
#endif

size_t nondet_size(void);
int nondet_int(void);

void harness(void)
{
    int cached = nondet_int();
    __CPROVER_assume(cached == -1 || cached == 0 || cached == 1);
    lzfse_x86_bmi2_cached = cached;
    lzfse_decoder_state *s = malloc(sizeof(*s));
    __CPROVER_assume(s != NULL);
    size_t scap = nondet_size(), dcap = nondet_size();
    __CPROVER_assume(scap >= 1 && scap <= PROOF_MAX_OBJECT);
    __CPROVER_assume(dcap >= 1 && dcap <= PROOF_MAX_OBJECT);
    uint8_t *sbuf = malloc(scap);
    uint8_t *dbuf = malloc(dcap);
    __CPROVER_assume(sbuf != NULL && dbuf != NULL);
    size_t sb = nondet_size(), sp = nondet_size(), se = nondet_size();
    __CPROVER_assume(sb <= sp && sp <= se && se <= scap);
    size_t db = nondet_size(), dp = nondet_size(), de = nondet_size();
    __CPROVER_assume(db <= dp && dp <= de && de <= dcap);
    s->src_begin = sbuf + sb;
    s->src = sbuf + sp;
    s->src_end = sbuf + se;
    s->dst_begin = dbuf + db;
    s->dst = dbuf + dp;
    s->dst_end = dbuf + de;
    size_t literal_index = nondet_size();
    __CPROVER_assume(literal_index <= LZFSE_LITERALS_PER_BLOCK);
    s->compressed_lzfse_block_state.current_literal =
        s->compressed_lzfse_block_state.literals + literal_index;
#ifdef PROOF_DISPATCH_LMD
    int res = lzfse_decode_lmd(s);
    PROOF_REACHABLE(res == LZFSE_STATUS_DST_FULL && lzfse_x86_bmi2_cached == 1, "BMI2 clone");
    PROOF_REACHABLE(res == LZFSE_STATUS_DST_FULL && lzfse_x86_bmi2_cached == 0, "baseline clone");
#else
    lzfse_compressed_block_header_v1 *header1 = malloc(sizeof(*header1));
    __CPROVER_assume(header1 != NULL);
    int res = lzfse_decode_literals(s, header1, &s->compressed_lzfse_block_state);
    PROOF_REACHABLE(res == 0 && lzfse_x86_bmi2_cached == 1, "BMI2 clone");
    PROOF_REACHABLE(res == 0 && lzfse_x86_bmi2_cached == 0, "baseline clone");
#endif
    PROOF_REACHABLE(cached == -1 && lzfse_x86_bmi2_cached == 1, "CPUID reports BMI2");
    PROOF_REACHABLE(cached == -1 && lzfse_x86_bmi2_cached == 0, "CPUID reports no BMI2");
}
