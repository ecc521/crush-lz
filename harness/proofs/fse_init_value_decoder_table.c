/*
 * Proof: fse_init_value_decoder_table in crates/crushlzfse/csrc/lzfse_fse.c meets its contract.
 */
#include "proof.h"
#include "lzfse_fse.c"

size_t nondet_size(void);
int nondet_int(void);

void harness(void)
{
    // The complete contract domain, including the 256-state/64-symbol
    // shipping distance table and arbitrary input value metadata.
    int nstates = nondet_int();
    int nsymbols = nondet_int();
    uint16_t freq[256];
    uint8_t symbol_vbits[256];
    int32_t symbol_vbase[256];
    fse_value_decoder_entry t[1024 + FSE_DECODER_TABLE_SLACK];

    int res = fse_init_value_decoder_table(nstates, nsymbols, freq,
                                          symbol_vbits, symbol_vbase, t);

    PROOF_REACHABLE(res == 0, "table initialized");
    PROOF_REACHABLE(res == 0 && nstates == 1024 && nsymbols == 256, "full literal dimensions");
    PROOF_REACHABLE(res == 0 && nstates == 256 && nsymbols == 64, "distance dimensions");
    PROOF_REACHABLE(res == -1, "oversized frequency sum rejected");
}
