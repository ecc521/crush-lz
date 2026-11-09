/*
 * Proof: lzfse_decode_v1 in crates/crushlzfse/csrc/lzfse_decode_base.c meets its contract.
 * The input object is exactly `available` bytes, so a declared header longer
 * than the readable span must be rejected rather than read.
 */
#include "proof.h"
#include "lzfse_decode_base.c"

size_t nondet_size(void);
int nondet_int(void);

void harness(void)
{
    lzfse_compressed_block_header_v1 out;
    size_t available = nondet_size();
    __CPROVER_assume(available >= 32 &&
                     available <= sizeof(lzfse_compressed_block_header_v2));
    lzfse_compressed_block_header_v2 *in = malloc(available);
    __CPROVER_assume(in != NULL);
    uint32_t declared = (uint32_t)in->packed_fields[2];

    int res = lzfse_decode_v1(&out, in, available);

    PROOF_REACHABLE(res == 0, "header unpacked");
    PROOF_REACHABLE(res == 0 && available < sizeof *in, "short object unpacked");
    PROOF_REACHABLE(res == -1, "malformed header rejected");
    PROOF_REACHABLE(res == -1 && declared >= 32 && declared <= sizeof *in &&
                    declared > available, "header longer than available rejected");
}
