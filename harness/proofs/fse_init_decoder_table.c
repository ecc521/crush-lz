/*
 * Proof: fse_init_decoder_table in crates/crushlzfse/csrc/lzfse_fse.c meets its contract.
 */
#include "proof.h"
#include "lzfse_fse.c"

size_t nondet_size(void);
int nondet_int(void);

void harness(void)
{
    // The complete contract domain, including the shipping 1024-state
    // literal table and all 256 literal symbols.
    int nstates = nondet_int();
    int nsymbols = nondet_int();
    uint16_t freq[256];
    int32_t t[1024 + FSE_DECODER_TABLE_SLACK];

    int res = fse_init_decoder_table(nstates, nsymbols, freq, t);

    PROOF_REACHABLE(res == 0, "table initialized");
    PROOF_REACHABLE(res == 0 && nstates == 1024 && nsymbols == 256, "full literal dimensions");
    PROOF_REACHABLE(res == 0 && nstates == 256 && nsymbols == 64, "distance dimensions");
    PROOF_REACHABLE(res == -1, "oversized frequency sum rejected");
}
