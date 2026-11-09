/* The shipping literal-table builder must leave a valid state row at every
 * index, including rows an underfull table does not own. Those keep their
 * previous contents: zero-initialized storage, or with PROOF_VALID_SEED the
 * previous block's valid table, as a multi-block stream rebuilds in place. */
#include "proof.h"
size_t proof_literal_query;
int nondet_int(void);
#include "lzfse_fse.c"

size_t nondet_size(void);

void harness(void) {
  uint16_t freq[LZFSE_ENCODE_LITERAL_SYMBOLS];
#ifdef PROOF_VALID_SEED
  int32_t table[LZFSE_ENCODE_LITERAL_STATES + FSE_DECODER_TABLE_SLACK];
#else
  int32_t table[LZFSE_ENCODE_LITERAL_STATES + FSE_DECODER_TABLE_SLACK] = {0};
#endif
  size_t query = nondet_size();
  __CPROVER_assume(query < LZFSE_ENCODE_LITERAL_STATES);
  proof_literal_query = query;
  uint32_t seed = (uint32_t)table[query];
#ifdef PROOF_VALID_SEED
  /* The literal-table predicate (LZFSE_LITERAL_ROW_OK) on the queried row;
   * every other row is arbitrary. */
  __CPROVER_assume((seed & 255) <= 10 && (seed >> 31) == 0 &&
                   (seed >> 16) + (((uint32_t)1 << (seed & 255)) - 1) <
                       LZFSE_ENCODE_LITERAL_STATES);
#else
  __CPROVER_assert(seed == 0, "queried row starts as a valid zero row");
#endif
  int result = fse_init_decoder_table(LZFSE_ENCODE_LITERAL_STATES,
                                      LZFSE_ENCODE_LITERAL_SYMBOLS,
                                      freq, table);
  if (result == 0) {
    uint32_t row = (uint32_t)table[query];
    uint32_t bits = row & 255;
    __CPROVER_assert(bits <= 10, "literal row consumes at most ten bits");
    __CPROVER_assert(bits <= 10 &&
                         (row >> 16) + (((uint32_t)1 << bits) - 1) <
                             LZFSE_ENCODE_LITERAL_STATES,
                     "literal row transition remains in the state table");
  }
  PROOF_REACHABLE(result == 0 && query == LZFSE_ENCODE_LITERAL_STATES - 1,
                  "last literal state after an underfull table");
#ifdef PROOF_VALID_SEED
  PROOF_REACHABLE(result == 0 && seed != 0 && (uint32_t)table[query] == seed,
                  "nonzero previous row kept by an underfull table");
#endif
}
