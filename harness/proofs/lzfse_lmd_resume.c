/* Shipping LMD resume branch with a pending literal or match and no new tuple. */
#include "proof.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);
uint32_t nondet_u32(void);
int nondet_int(void);

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
  __CPROVER_assume(scap >= 8 && scap <= PROOF_MAX_OBJECT);
  uint8_t *sbuf = malloc(scap);
  __CPROVER_assume(sbuf != NULL);
  s->src_begin = sbuf;
  s->src = sbuf + 8;
  s->src_end = sbuf + scap;
  lzfse_compressed_block_decoder_state *bs = &s->compressed_lzfse_block_state;
  bs->lmd_in_buf = nondet_u32();
  __CPROVER_assume(bs->lmd_in_buf <= scap - 8);
  bs->n_literals = nondet_u32();
  __CPROVER_assume(bs->n_literals <= LZFSE_LITERALS_PER_BLOCK);
  size_t lit_off = nondet_size();
  __CPROVER_assume(lit_off <= bs->n_literals);
  bs->current_literal = bs->literals + lit_off;
  bs->n_matches = 0;
  bs->l_state = 0;
  bs->m_state = 0;
  bs->d_state = 0;
  bs->l_value = nondet_int();
  bs->m_value = nondet_int();
  bs->d_value = nondet_int();
  __CPROVER_assume(bs->l_value >= 0 && bs->l_value <= LZFSE_DECODE_L_MAX_VALUE);
  __CPROVER_assume(bs->l_value <= (int32_t)(bs->n_literals - lit_off));
  __CPROVER_assume(bs->m_value >= 0 && bs->m_value <= LZFSE_ENCODE_MAX_M_VALUE);
  __CPROVER_assume(bs->l_value != 0 || bs->m_value != 0);
  __CPROVER_assume(bs->d_value >= 1 && bs->d_value <= LZFSE_ENCODE_MAX_D_VALUE);
  bs->lmd_in_stream.accum = 0;
  bs->lmd_in_stream.accum_nbits = 0;

  uint8_t *before_dst = s->dst;
  const uint8_t *before_lit = bs->current_literal;
  int32_t pending_bytes = bs->l_value + bs->m_value;
  int32_t original_l = bs->l_value;
  int32_t original_d = bs->d_value;
  uint32_t original_in_buf = bs->lmd_in_buf;
  int result = lzfse_decode_lmd(s);
  __CPROVER_assert(result == LZFSE_STATUS_OK ||
                       result == LZFSE_STATUS_DST_FULL ||
                       result == LZFSE_STATUS_ERROR,
                   "resume returns a documented status");
  __CPROVER_assert(s->dst >= s->dst_begin && s->dst <= s->dst_end,
                   "resume keeps destination cursor in bounds");
  __CPROVER_assert(result != LZFSE_STATUS_OK ||
                       (size_t)(s->dst - before_dst) == (size_t)pending_bytes,
                   "completed resume accounts for all pending bytes");
  __CPROVER_assert(result != LZFSE_STATUS_DST_FULL || s->dst == s->dst_end,
                   "interrupted resume fills the supplied destination");
  if (result == LZFSE_STATUS_DST_FULL) {
    __CPROVER_assert(bs->l_value >= 0 && bs->m_value >= 0 &&
                         (size_t)(s->dst - before_dst) +
                             (size_t)bs->l_value + (size_t)bs->m_value ==
                             (size_t)pending_bytes,
                     "interrupted resume saves exactly the remaining bytes");
    __CPROVER_assert(bs->current_literal >= before_lit &&
                         (size_t)(bs->current_literal - before_lit) ==
                             (size_t)(original_l - bs->l_value),
                     "interrupted resume saves the literal cursor");
    __CPROVER_assert(bs->d_value == original_d &&
                         bs->lmd_in_buf == original_in_buf &&
                         bs->n_matches == 0,
                     "interrupted resume retains its distance and input position");
  }
  __CPROVER_assert(result != LZFSE_STATUS_ERROR || s->dst == before_dst,
                   "invalid pending distance leaves the destination cursor");
  PROOF_REACHABLE(result == LZFSE_STATUS_OK, "resume completes pending work");
  PROOF_REACHABLE(result == LZFSE_STATUS_DST_FULL, "resume needs more output");
  PROOF_REACHABLE(result == LZFSE_STATUS_ERROR, "resume rejects a bad distance");
}
