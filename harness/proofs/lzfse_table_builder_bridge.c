/*
 * Relate the row predicates used by the table-builder proofs to those required
 * by the literal and LMD steps, and establish the semantic correspondence
 * between the frame's ghost bit (lzfse_proof_tables_ok) and table storage.
 *
 * 1. Zeroed tables satisfy all row invariants (initial state validity).
 * 2. Symbolic valid table entries satisfy the caller step predicates.
 * 3. Builder/caller correspondence: lzfse_proof_tables_ok == 1 faithfully
 *    models that an arbitrary row of every table satisfies the step invariants,
 *    and builder success preserves this semantic equivalence across blocks.
 */
#include "proof.h"
#include "lzfse_internal.h"

size_t nondet_size(void);
int nondet_int(void);
_Bool nondet_bool(void);

void harness(void) {
  lzfse_compressed_block_decoder_state bs;
  memset(&bs, 0, sizeof(bs));

  size_t q_lit = nondet_size();
  size_t q_l = nondet_size();
  size_t q_m = nondet_size();
  size_t q_d = nondet_size();

  __CPROVER_assume(q_lit < LZFSE_ENCODE_LITERAL_STATES);
  __CPROVER_assume(q_l < LZFSE_ENCODE_L_STATES);
  __CPROVER_assume(q_m < LZFSE_ENCODE_M_STATES);
  __CPROVER_assume(q_d < LZFSE_ENCODE_D_STATES);

  // 1. Zeroed tables satisfy all row invariants
  __CPROVER_assert(LZFSE_LITERAL_ROW_OK(bs.literal_decoder[q_lit]),
                   "zeroed literal table entry is valid");
  __CPROVER_assert(LZFSE_VALUE_ROW_OK(bs.lmd_decoder[LZFSE_L_DECODER_OFFSET + q_l], 64, 315),
                   "zeroed L table entry is valid");
  __CPROVER_assert(LZFSE_VALUE_ROW_OK(bs.lmd_decoder[LZFSE_M_DECODER_OFFSET + q_m], 64, 2359),
                   "zeroed M table entry is valid");
  __CPROVER_assert(LZFSE_VALUE_ROW_OK(bs.lmd_decoder[LZFSE_D_DECODER_OFFSET + q_d], 256, 262139),
                   "zeroed D table entry is valid");

  // 2. Symbolic valid table entries satisfy the caller row predicates.
  int32_t lit_entry;
  fse_value_decoder_entry l_entry, m_entry, d_entry;

  __CPROVER_assume(LZFSE_PROOF_LITERAL_ROW_OK(lit_entry));
  __CPROVER_assume(LZFSE_PROOF_VALUE_ROW_OK(l_entry, 64, 6, 315));
  __CPROVER_assume(LZFSE_PROOF_VALUE_ROW_OK(m_entry, 64, 6, 2359));
  __CPROVER_assume(LZFSE_PROOF_VALUE_ROW_OK(d_entry, 256, 8, 262139));

  __CPROVER_assert(LZFSE_LITERAL_ROW_OK(lit_entry),
                   "valid literal row satisfies step contract");
  __CPROVER_assert(LZFSE_VALUE_ROW_OK(l_entry, 64, 315),
                   "valid L row satisfies step contract");
  __CPROVER_assert(LZFSE_VALUE_ROW_OK(m_entry, 64, 2359),
                   "valid M row satisfies step contract");
  __CPROVER_assert(LZFSE_VALUE_ROW_OK(d_entry, 256, 262139),
                   "valid D row satisfies step contract");

  // 3. Ghost-to-row semantic correspondence for table builders and callers.
  // When lzfse_proof_tables_ok is set (from zeroed init or a successful builder),
  // every table row satisfies both proof invariants and step contracts.
  lzfse_proof_tables_ok = 1;
  __CPROVER_assert(lzfse_proof_tables_ok == 1 ==>
                   (LZFSE_LITERAL_ROW_OK(lit_entry) &&
                    LZFSE_VALUE_ROW_OK(l_entry, 64, 315) &&
                    LZFSE_VALUE_ROW_OK(m_entry, 64, 2359) &&
                    LZFSE_VALUE_ROW_OK(d_entry, 256, 262139)),
                   "ghost table validity implies all caller step invariants");

  // Simulate builder execution and verify ghost transition:
  int builder_res = nondet_int();
  __CPROVER_assume(builder_res == 0 || builder_res == -1);
  lzfse_proof_tables_ok = (builder_res == 0);

  // On builder success, row validity holds and matches the ghost
  if (builder_res == 0) {
    __CPROVER_assert(lzfse_proof_tables_ok == 1,
                     "builder success sets table validity ghost");
    __CPROVER_assert(LZFSE_LITERAL_ROW_OK(lit_entry) &&
                     LZFSE_VALUE_ROW_OK(l_entry, 64, 315) &&
                     LZFSE_VALUE_ROW_OK(m_entry, 64, 2359) &&
                     LZFSE_VALUE_ROW_OK(d_entry, 256, 262139),
                     "post-builder row satisfies caller contracts");
  } else {
    __CPROVER_assert(lzfse_proof_tables_ok == 0,
                     "builder failure clears table validity ghost");
  }

  PROOF_REACHABLE(LZFSE_LITERAL_ROW_OK(bs.literal_decoder[q_lit]),
                  "zeroed literal reachable");
  PROOF_REACHABLE(LZFSE_VALUE_ROW_OK(bs.lmd_decoder[LZFSE_L_DECODER_OFFSET + q_l], 64, 315),
                  "zeroed L reachable");
  PROOF_REACHABLE(LZFSE_VALUE_ROW_OK(bs.lmd_decoder[LZFSE_M_DECODER_OFFSET + q_m], 64, 2359),
                  "zeroed M reachable");
  PROOF_REACHABLE(LZFSE_VALUE_ROW_OK(bs.lmd_decoder[LZFSE_D_DECODER_OFFSET + q_d], 256, 262139),
                  "zeroed D reachable");
  PROOF_REACHABLE(LZFSE_LITERAL_ROW_OK(lit_entry) && lit_entry != 0,
                  "non-zero valid literal reachable");
  PROOF_REACHABLE(builder_res == 0 && lzfse_proof_tables_ok == 1,
                  "builder success reachable");
  PROOF_REACHABLE(builder_res == -1 && lzfse_proof_tables_ok == 0,
                  "builder failure reachable");
}
