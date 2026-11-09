/* The shipping literal-table builder keeps every row valid when it starts
 * from a valid previous table instead of zeroed storage. An underfull table
 * leaves rows unwritten, so a later block reads the previous block's rows;
 * the frame contract (lzfse_decode_frame) carries "every row valid" across
 * blocks and imports this preservation step. */
#include "proof.h"
size_t proof_literal_query;
int nondet_int(void);
#include "lzfse_fse.c"

size_t nondet_size(void);

void harness(void) {
  uint16_t freq[LZFSE_ENCODE_LITERAL_SYMBOLS];
  /* Only the queried row is tracked, so the other rows' contents are
   * irrelevant; they start zeroed as in fse_literal_table_valid. */
  int32_t table[LZFSE_ENCODE_LITERAL_STATES + FSE_DECODER_TABLE_SLACK] = {0};
  size_t query = nondet_size();
  __CPROVER_assume(query < LZFSE_ENCODE_LITERAL_STATES);
  proof_literal_query = query;
  table[query] = nondet_int();
  uint32_t initial = (uint32_t)table[query];
  __CPROVER_assume((initial & 255) <= 10 &&
                   (initial >> 16) + (((uint32_t)1 << (initial & 255)) - 1) <
                       LZFSE_ENCODE_LITERAL_STATES);
  int result = fse_init_decoder_table(LZFSE_ENCODE_LITERAL_STATES,
                                      LZFSE_ENCODE_LITERAL_SYMBOLS,
                                      freq, table);
  if (result == 0) {
    uint32_t row = (uint32_t)table[query];
    uint32_t bits = row & 255;
    __CPROVER_assert(bits <= 10 &&
                         (row >> 16) + (((uint32_t)1 << bits) - 1) <
                             LZFSE_ENCODE_LITERAL_STATES,
                     "literal row transition remains in the state table");
  }
  PROOF_REACHABLE(result == 0 && query == LZFSE_ENCODE_LITERAL_STATES - 1,
                  "last literal state after an underfull table");
  PROOF_REACHABLE(result == 0 && (uint32_t)table[query] == initial &&
                      initial != 0,
                  "a nonzero previous row survives");
}
