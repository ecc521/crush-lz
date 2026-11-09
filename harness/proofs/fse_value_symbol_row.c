/* Compose the shipping symbol tables with extracted row arithmetic. */
#include "proof.h"
#include "lzfse_internal.h"
#define harness unused_row_harness
#include "fse_table_rows.c"
#undef harness

size_t nondet_size(void);

void harness(void) {
  int mode = nondet_int();
  size_t symbol = nondet_size();
  int f = nondet_int();
  int j = nondet_int();
  __CPROVER_assume(mode >= 0 && mode <= 2);
  int nstates = mode == 2 ? LZFSE_ENCODE_D_STATES : LZFSE_ENCODE_L_STATES;
  __CPROVER_assume(symbol < (size_t)(mode == 2 ? LZFSE_ENCODE_D_SYMBOLS :
                                     LZFSE_ENCODE_L_SYMBOLS));
  __CPROVER_assume(f >= 1 && f <= nstates && j >= 0 && j < f);
  const uint8_t *bits = mode == 0 ? l_extra_bits :
                        mode == 1 ? m_extra_bits : d_extra_bits;
  const int32_t *base = mode == 0 ? l_base_value :
                        mode == 1 ? m_base_value : d_base_value;
  uint32_t limit = mode == 0 ? LZFSE_ENCODE_MAX_L_VALUE :
                   mode == 1 ? LZFSE_ENCODE_MAX_M_VALUE : LZFSE_ENCODE_MAX_D_VALUE;
  uint64_t word = value_row(nstates, f, j, bits[symbol], base[symbol]);
  uint32_t total = (uint8_t)word;
  uint32_t extra = (uint8_t)(word >> 8);
  uint32_t delta = (uint16_t)(word >> 16);
  uint32_t first = (uint32_t)(word >> 32);
  __CPROVER_assert(extra <= 16 && total >= extra &&
                       total - extra <= (nstates == 256 ? 8 : 6) &&
                       delta + (((uint32_t)1 << (total - extra)) - 1) <
                           (uint32_t)nstates,
                   "owned value row has a bounded successor state");
  __CPROVER_assert(first + (((uint32_t)1 << extra) - 1) <= limit,
                   "owned value row has a bounded decoded value");
  PROOF_REACHABLE(mode == 0 && symbol == 19 && f == 1 && j == 0,
                  "maximum L symbol owns a row");
  PROOF_REACHABLE(mode == 1 && symbol == 19 && f == 1 && j == 0,
                  "maximum M symbol owns a row");
  PROOF_REACHABLE(mode == 2 && symbol == 63 && f == 1 && j == 0,
                  "maximum D symbol owns a row");
}
