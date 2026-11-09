/* Shipping LMD step: a pending L or M (or none) followed by up to
 * PROOF_LMD_TUPLES new tuples, through the compiled resume goto. Value
 * decoding, refill and the four copies run as their enforced contracts; every
 * L/M/D table row satisfies the decoder row predicate (LZFSE_VALUE_ROW_OK).
 * Bounded in the tuple count only; frama/lzfse_lmd_native.py covers any
 * count with the resume entry peeled. */
#include "proof.h"
#include "lzfse_decode_base.c"

#ifndef PROOF_LMD_TUPLES
#define PROOF_LMD_TUPLES 2
#endif

size_t nondet_size(void);
uint32_t nondet_u32(void);
int nondet_int(void);
uint64_t nondet_u64(void);

void harness(void) {
  lzfse_decoder_state *s = malloc(sizeof *s);
  __CPROVER_assume(s != NULL);
  size_t dcap = nondet_size();
  __CPROVER_assume(dcap <= PROOF_MAX_OBJECT - 1);
  uint8_t *dbuf = malloc(dcap + 1);
  __CPROVER_assume(dbuf != NULL);
  size_t dpos = nondet_size();
  __CPROVER_assume(dpos <= dcap);
  s->dst_begin = dbuf;
  s->dst = dbuf + dpos;
  s->dst_end = dbuf + dcap;

  size_t scap = nondet_size();
  __CPROVER_assume(scap >= 16 && scap <= PROOF_MAX_OBJECT);
  uint8_t *sbuf = malloc(scap);
  __CPROVER_assume(sbuf != NULL);
  s->src_begin = sbuf;
  s->src = sbuf + 8;
  s->src_end = sbuf + scap;
  lzfse_compressed_block_decoder_state *bs = &s->compressed_lzfse_block_state;
  for (int k = 0; k < 64; k++) {
    __CPROVER_assume(LZFSE_VALUE_ROW_OK(bs->lmd_decoder[k], 64, 315));
    __CPROVER_assume(LZFSE_VALUE_ROW_OK(bs->lmd_decoder[72 + k], 64, 2359));
  }
  for (int k = 0; k < 256; k++)
    __CPROVER_assume(LZFSE_VALUE_ROW_OK(bs->lmd_decoder[144 + k], 256, 262139));

  bs->lmd_in_buf = nondet_u32();
  __CPROVER_assume((size_t)bs->lmd_in_buf + 7 <= scap - 8);
  bs->n_literals = nondet_u32();
  __CPROVER_assume(bs->n_literals <= LZFSE_LITERALS_PER_BLOCK);
  size_t lit_off = nondet_size();
  __CPROVER_assume(lit_off <= bs->n_literals);
  bs->current_literal = bs->literals + lit_off;
  bs->n_matches = nondet_u32();
  __CPROVER_assume(bs->n_matches <= PROOF_LMD_TUPLES);
  bs->l_state = nondet_u32() % LZFSE_ENCODE_L_STATES;
  bs->m_state = nondet_u32() % LZFSE_ENCODE_M_STATES;
  bs->d_state = nondet_u32() % LZFSE_ENCODE_D_STATES;
  bs->l_value = nondet_int();
  bs->m_value = nondet_int();
  bs->d_value = nondet_int();
  __CPROVER_assume(bs->l_value >= 0 && bs->l_value <= LZFSE_DECODE_L_MAX_VALUE);
  __CPROVER_assume((size_t)bs->l_value <= bs->n_literals - lit_off);
  __CPROVER_assume(bs->m_value >= 0 && bs->m_value <= LZFSE_ENCODE_MAX_M_VALUE);
  bs->lmd_in_stream.accum_nbits = nondet_int();
  __CPROVER_assume(bs->lmd_in_stream.accum_nbits >= 0 &&
                   bs->lmd_in_stream.accum_nbits < 64);
  bs->lmd_in_stream.accum = nondet_u64();
  __CPROVER_assume((bs->lmd_in_stream.accum >> bs->lmd_in_stream.accum_nbits) == 0);

  uint8_t *before = s->dst;
  int pending = bs->l_value != 0 || bs->m_value != 0;
  uint32_t tuples = bs->n_matches;
  int result = lzfse_decode_lmd(s);
  __CPROVER_assert(result == LZFSE_STATUS_OK || result == LZFSE_STATUS_DST_FULL ||
                       result == LZFSE_STATUS_ERROR,
                   "documented status");
  __CPROVER_assert(s->dst >= before && s->dst <= s->dst_end,
                   "destination cursor stays in its output");
  if (result == LZFSE_STATUS_DST_FULL) {
    __CPROVER_assert(s->dst == s->dst_end, "DST_FULL fills the output");
    __CPROVER_assert(bs->l_value >= 0 && bs->l_value <= LZFSE_DECODE_L_MAX_VALUE &&
                         bs->m_value >= 0 && bs->m_value <= LZFSE_ENCODE_MAX_M_VALUE &&
                         bs->current_literal >= bs->literals &&
                         (size_t)(bs->current_literal - bs->literals) +
                                 (size_t)bs->l_value <= bs->n_literals &&
                         bs->l_state < LZFSE_ENCODE_L_STATES &&
                         bs->m_state < LZFSE_ENCODE_M_STATES &&
                         bs->d_state < LZFSE_ENCODE_D_STATES &&
                         bs->lmd_in_stream.accum_nbits >= 0 &&
                         bs->lmd_in_stream.accum_nbits < 64 &&
                         (size_t)bs->lmd_in_buf + 7 <= scap - 8 &&
                         bs->n_matches <= tuples,
                     "DST_FULL leaves a resumable state");
  }
  PROOF_REACHABLE(result == LZFSE_STATUS_OK && pending && tuples == PROOF_LMD_TUPLES &&
                      s->dst > before,
                  "pending work, then new tuples, completes");
  PROOF_REACHABLE(result == LZFSE_STATUS_DST_FULL && pending &&
                      tuples == PROOF_LMD_TUPLES && bs->n_matches < tuples,
                  "pending work, then a new tuple fills the output");
  PROOF_REACHABLE(result == LZFSE_STATUS_ERROR && pending && tuples > 0,
                  "pending work with new tuples rejected");
}
