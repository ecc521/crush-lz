/*
 * Proof: lzfse_encode_init in crates/crushlzfse/csrc/lzfse_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzfse_encode_base.c"

void harness(void) {
  lzfse_encoder_state s;
  int res = lzfse_encode_init(&s);
  __CPROVER_assert(res == LZFSE_STATUS_OK, "status OK");
  __CPROVER_assert(s.pending.length == 0, "pending cleared");
  __CPROVER_assert(s.src_literal == 0, "src_literal zeroed");
  PROOF_REACHABLE(res == LZFSE_STATUS_OK, "init successful");
}
