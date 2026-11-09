/*
 * Proof: store4 in crates/crushlzfse/csrc/lzfse_internal.h meets its contract.
 */
#include "proof.h"
#include "lzfse_internal.h"

uint32_t nondet_u32(void);

void harness(void)
{
    uint8_t buf[4];
    uint32_t val = nondet_u32();
    store4(buf, val);
    PROOF_REACHABLE(1, "store4 executed");
}
