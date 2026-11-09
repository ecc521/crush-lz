/*
 * Proof: lzfse_check_block_header_v1 in crates/crushlzfse/csrc/lzfse_internal.h meets its contract.
 */
#include "proof.h"
#include "lzfse_internal.h"

void harness(void)
{
    lzfse_compressed_block_header_v1 header;

    int res = lzfse_check_block_header_v1(&header);

    if (res == 0) {
        __CPROVER_assert(header.magic == LZFSE_COMPRESSEDV1_BLOCK_MAGIC, "magic valid");
        __CPROVER_assert(header.n_literals <= LZFSE_LITERALS_PER_BLOCK, "n_literals valid");
        __CPROVER_assert(header.n_matches <= LZFSE_MATCHES_PER_BLOCK, "n_matches valid");
        __CPROVER_assert(header.l_state < LZFSE_ENCODE_L_STATES, "l_state valid");
        __CPROVER_assert(header.m_state < LZFSE_ENCODE_M_STATES, "m_state valid");
        __CPROVER_assert(header.d_state < LZFSE_ENCODE_D_STATES, "d_state valid");
        __CPROVER_assert(header.literal_bits >= -7 && header.literal_bits <= 0, "literal_bits valid");
        __CPROVER_assert(header.lmd_bits >= -7 && header.lmd_bits <= 0, "lmd_bits valid");
    }

    PROOF_REACHABLE(res == 0, "valid header accepted");
    PROOF_REACHABLE(res != 0, "invalid header rejected");
}
