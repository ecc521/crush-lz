/* Track an arbitrary row through the shipping L/M/D builder's write loops.
 * The owned-row content is discharged by fse_value_symbol_row and
 * fse_value_unpack; this target proves every final row has an owned write or
 * remains the initialized zero entry. */
#include "proof.h"
#undef memcpy
size_t proof_value_query;
int proof_value_limit;
int proof_row_valid;
int nondet_int(void);
#include "lzfse_fse.c"

size_t nondet_size(void);

void harness(void) {
#if PROOF_VALUE_KIND == 2
  uint16_t freq[64];
#ifdef PROOF_VALID_SEED
  fse_value_decoder_entry table[256 + FSE_DECODER_TABLE_SLACK];
#else
  fse_value_decoder_entry table[256 + FSE_DECODER_TABLE_SLACK] = {{0}};
#endif
  const int nstates = LZFSE_ENCODE_D_STATES;
  const int nsymbols = LZFSE_ENCODE_D_SYMBOLS;
  const uint8_t *vbits = d_extra_bits;
  const int32_t *base = d_base_value;
  proof_value_limit = LZFSE_ENCODE_MAX_D_VALUE;
#elif PROOF_VALUE_KIND == 1
  uint16_t freq[20];
#ifdef PROOF_VALID_SEED
  fse_value_decoder_entry table[64 + FSE_DECODER_TABLE_SLACK];
#else
  fse_value_decoder_entry table[64 + FSE_DECODER_TABLE_SLACK] = {{0}};
#endif
  const int nstates = LZFSE_ENCODE_M_STATES;
  const int nsymbols = LZFSE_ENCODE_M_SYMBOLS;
  const uint8_t *vbits = m_extra_bits;
  const int32_t *base = m_base_value;
  proof_value_limit = LZFSE_ENCODE_MAX_M_VALUE;
#else
  uint16_t freq[20];
#ifdef PROOF_VALID_SEED
  fse_value_decoder_entry table[64 + FSE_DECODER_TABLE_SLACK];
#else
  fse_value_decoder_entry table[64 + FSE_DECODER_TABLE_SLACK] = {{0}};
#endif
  const int nstates = LZFSE_ENCODE_L_STATES;
  const int nsymbols = LZFSE_ENCODE_L_SYMBOLS;
  const uint8_t *vbits = l_extra_bits;
  const int32_t *base = l_base_value;
  proof_value_limit = LZFSE_ENCODE_MAX_L_VALUE;
#endif
  size_t query = nondet_size();
  __CPROVER_assume(query < (size_t)nstates);
  proof_value_query = query;
  fse_value_decoder_entry initial = table[query];
#ifdef PROOF_VALID_SEED
  __CPROVER_assume(initial.value_bits <= 16 &&
                   initial.total_bits >= initial.value_bits &&
                   initial.total_bits - initial.value_bits <= (nstates == 256 ? 8 : 6) &&
                   initial.delta >= 0 &&
                   (uint32_t)initial.delta +
                       (((uint32_t)1 << (initial.total_bits - initial.value_bits)) - 1) <
                       (uint32_t)nstates &&
                   initial.vbase >= 0 &&
                   (uint32_t)initial.vbase +
                       (((uint32_t)1 << initial.value_bits) - 1) <=
                       (uint32_t)proof_value_limit);
#else
  __CPROVER_assert(initial.total_bits == 0 && initial.value_bits == 0 &&
                       initial.delta == 0 && initial.vbase == 0,
                   "queried row starts as a valid zero row");
#endif
  proof_row_valid = 1; /* zero-initialized rows satisfy both entry predicates */
  int result = fse_init_value_decoder_table(nstates, nsymbols, freq, vbits, base, table);
  if (result == 0)
    __CPROVER_assert(proof_row_valid, "queried row is covered by a valid owned write or remains zero");
  PROOF_REACHABLE(result == 0 && query == (size_t)nstates - 1,
                  "last row of the selected table");
}
