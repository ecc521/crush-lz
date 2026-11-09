/*
 * Proof: lzfse_decode_literals in crates/crushlzfse/csrc/lzfse_decode_base.c meets its contract.
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
    lzfse_compressed_block_header_v1 header1;
    lzfse_compressed_block_decoder_state *bs = malloc(sizeof(*bs));
    __CPROVER_assume(bs != NULL);

    // Buffer backing: at least 16 bytes prefix + payload
    uint8_t src_buf[16 + 256];
    s->src_begin = src_buf;
    s->src = src_buf + 16;
    s->src_end = src_buf + sizeof(src_buf);

    header1.n_literal_payload_bytes = nondet_size();
    __CPROVER_assume(header1.n_literal_payload_bytes <= 256);

    header1.n_literals = nondet_u32();
    __CPROVER_assume(header1.n_literals <= LZFSE_LITERALS_PER_BLOCK);
    __CPROVER_assume((header1.n_literals & 3) == 0);

    header1.literal_bits = nondet_int();
    __CPROVER_assume(header1.literal_bits >= -7 && header1.literal_bits <= 0);

    header1.literal_state[0] = nondet_int() & (LZFSE_ENCODE_LITERAL_STATES - 1);
    header1.literal_state[1] = nondet_int() & (LZFSE_ENCODE_LITERAL_STATES - 1);
    header1.literal_state[2] = nondet_int() & (LZFSE_ENCODE_LITERAL_STATES - 1);
    header1.literal_state[3] = nondet_int() & (LZFSE_ENCODE_LITERAL_STATES - 1);

    int res = lzfse_decode_literals(s, &header1, bs);

    PROOF_REACHABLE(res == 0, "literals decoded");
    PROOF_REACHABLE(res == -1, "malformed literals rejected");
}
