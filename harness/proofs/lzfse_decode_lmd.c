/*
 * Proof: lzfse_decode_lmd in crates/crushlzfse/csrc/lzfse_decode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);
int nondet_int(void);
uint32_t nondet_u32(void);

void harness(void)
{
    lzfse_decoder_state *s = malloc(sizeof(*s));
    __CPROVER_assume(s != NULL);

    // Destination buffer setup
    size_t dcap = nondet_size();
    __CPROVER_assume(dcap >= LZFSE_DECODE_COPY_MARGIN + 32 && dcap <= 256);
    uint8_t *dbuf = malloc(dcap);
    __CPROVER_assume(dbuf != NULL);
    s->dst_begin = dbuf;
    size_t dpos = nondet_size();
    __CPROVER_assume(dpos <= dcap);
    s->dst = dbuf + dpos;
    s->dst_end = dbuf + dcap;

    // Source buffer setup: at least 8 bytes prefix
    size_t scap = nondet_size();
    __CPROVER_assume(scap >= 8 + 64 && scap <= 256);
    uint8_t *sbuf = malloc(scap);
    __CPROVER_assume(sbuf != NULL);
    s->src_begin = sbuf;
    s->src = sbuf + 8;
    s->src_end = sbuf + scap;

    lzfse_compressed_block_decoder_state *bs = &(s->compressed_lzfse_block_state);
    bs->lmd_in_buf = nondet_size();
    __CPROVER_assume(bs->lmd_in_buf <= scap - 8);

    bs->n_literals = nondet_u32();
    __CPROVER_assume(bs->n_literals <= LZFSE_LITERALS_PER_BLOCK);
    size_t lit_off = nondet_size();
    __CPROVER_assume(lit_off <= bs->n_literals);
    bs->current_literal = bs->literals + lit_off;

    bs->n_matches = nondet_u32();
    __CPROVER_assume(bs->n_matches <= LZFSE_MATCHES_PER_BLOCK);

    bs->l_state = nondet_u32() % LZFSE_ENCODE_L_STATES;
    bs->m_state = nondet_u32() % LZFSE_ENCODE_M_STATES;
    bs->d_state = nondet_u32() % LZFSE_ENCODE_D_STATES;
    bs->l_value = 0;
    bs->m_value = 0;
    bs->d_value = -1;

    bs->lmd_in_stream.accum_nbits = nondet_int();
    __CPROVER_assume(bs->lmd_in_stream.accum_nbits >= 0 && bs->lmd_in_stream.accum_nbits < 64);

    int res = lzfse_decode_lmd(s);

    PROOF_REACHABLE(res == LZFSE_STATUS_OK, "lmd decoded completely");
    PROOF_REACHABLE(res == LZFSE_STATUS_DST_FULL, "dst full returned");
    PROOF_REACHABLE(res == LZFSE_STATUS_ERROR, "error returned");
}
