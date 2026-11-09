/* Every shipping L/M/D symbol's extra bits and base fit decoder value bounds. */
#include "proof.h"
#include "lzfse_internal.h"

size_t nondet_size(void);
int nondet_int(void);

void harness(void) {
  int mode = nondet_int();
  size_t symbol = nondet_size();
  __CPROVER_assume(mode >= 0 && mode <= 2);
  __CPROVER_assume(symbol < (size_t)(mode == 2 ? LZFSE_ENCODE_D_SYMBOLS :
                                     LZFSE_ENCODE_L_SYMBOLS));
  const uint8_t *bits = mode == 0 ? l_extra_bits :
                        mode == 1 ? m_extra_bits : d_extra_bits;
  const int32_t *base = mode == 0 ? l_base_value :
                        mode == 1 ? m_base_value : d_base_value;
  uint32_t limit = mode == 0 ? LZFSE_ENCODE_MAX_L_VALUE :
                   mode == 1 ? LZFSE_ENCODE_MAX_M_VALUE : LZFSE_ENCODE_MAX_D_VALUE;
  uint8_t b = bits[symbol];
  int32_t v = base[symbol];
  __CPROVER_assert(b <= 16, "value symbol uses at most 16 extra bits");
  __CPROVER_assert(v >= 0 && (uint32_t)v + (((uint32_t)1 << b) - 1) <= limit,
                   "value symbol's maximum fits its shipping decoder range");
  PROOF_REACHABLE(mode == 0 && symbol == LZFSE_ENCODE_L_SYMBOLS - 1 &&
                      v == 60 && b == 8, "maximum L symbol");
  PROOF_REACHABLE(mode == 1 && symbol == LZFSE_ENCODE_M_SYMBOLS - 1 &&
                      v == 312 && b == 11, "maximum M symbol");
  PROOF_REACHABLE(mode == 2 && symbol == LZFSE_ENCODE_D_SYMBOLS - 1 &&
                      v == 229372 && b == 15, "maximum D symbol");
}
