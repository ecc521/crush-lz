/* The frame carries decoder-table validity in a ghost bit. Prove that each
 * row predicate represented by that bit is exactly the predicate required by
 * the shipping literal and LMD step contracts. Builder coverage/preservation
 * targets separately prove these predicates for an arbitrary selected row. */
#include "proof.h"
#include "lzfse_internal.h"

void harness(void) {
  int32_t literal;
  fse_value_decoder_entry value;

  __CPROVER_assert(LZFSE_PROOF_LITERAL_ROW_OK(literal) ==
                       LZFSE_LITERAL_ROW_OK(literal),
                   "frame literal-row ghost matches the shipping predicate");
  __CPROVER_assert(LZFSE_PROOF_VALUE_ROW_OK(value, 64, 6, 315) ==
                       LZFSE_VALUE_ROW_OK(value, 64, 315),
                   "frame L-row ghost matches the shipping predicate");
  __CPROVER_assert(LZFSE_PROOF_VALUE_ROW_OK(value, 64, 6, 2359) ==
                       LZFSE_VALUE_ROW_OK(value, 64, 2359),
                   "frame M-row ghost matches the shipping predicate");
  __CPROVER_assert(LZFSE_PROOF_VALUE_ROW_OK(value, 256, 8, 262139) ==
                       LZFSE_VALUE_ROW_OK(value, 256, 262139),
                   "frame D-row ghost matches the shipping predicate");

  PROOF_REACHABLE(LZFSE_PROOF_LITERAL_ROW_OK(literal),
                  "a valid literal row");
  PROOF_REACHABLE(!LZFSE_PROOF_LITERAL_ROW_OK(literal),
                  "an invalid literal row");
  PROOF_REACHABLE(LZFSE_PROOF_VALUE_ROW_OK(value, 64, 6, 315),
                  "a valid value row");
  PROOF_REACHABLE(!LZFSE_PROOF_VALUE_ROW_OK(value, 64, 6, 315),
                  "an invalid value row");
}
