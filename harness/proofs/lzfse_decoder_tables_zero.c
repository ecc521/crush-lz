/* producer-sha256: 050a1b2e1170ed671d8929e48494635a2c69998a2341f60735981d646b666a1b */
/* The allocation initializer in crushlzfse_decode_buffer zeroes both FSE
 * tables, including entries left unwritten by underfull block frequencies. */
#include "proof.h"
#include <stdlib.h>
#include "lzfse_internal.h"

_Static_assert(offsetof(lzfse_decoder_state, compressed_lzfse_block_state.literals) >=
                   offsetof(lzfse_decoder_state, compressed_lzfse_block_state.literal_decoder) +
                       sizeof(((lzfse_compressed_block_decoder_state *)0)->literal_decoder),
               "literal decoder table precedes the zeroing boundary");
_Static_assert(offsetof(lzfse_decoder_state, compressed_lzfse_block_state.literals) >=
                   offsetof(lzfse_decoder_state, compressed_lzfse_block_state.lmd_decoder) +
                       sizeof(((lzfse_compressed_block_decoder_state *)0)->lmd_decoder),
               "value decoder table precedes the zeroing boundary");

size_t nondet_size(void);
void harness(void) {
  lzfse_decoder_state *s = malloc(sizeof *s);
  __CPROVER_assume(s != NULL);
  memset(s, 0, offsetof(lzfse_decoder_state, compressed_lzfse_block_state.literals));
  size_t literal = nondet_size();
  size_t lmd = nondet_size();
  __CPROVER_assume(literal < LZFSE_ENCODE_LITERAL_STATES);
  __CPROVER_assume(lmd < sizeof s->compressed_lzfse_block_state.lmd_decoder /
                              sizeof s->compressed_lzfse_block_state.lmd_decoder[0]);
  __CPROVER_assert(s->compressed_lzfse_block_state.literal_decoder[literal] == 0,
                   "all literal decoder entries start zero");
  fse_value_decoder_entry entry = s->compressed_lzfse_block_state.lmd_decoder[lmd];
  __CPROVER_assert(entry.total_bits == 0 && entry.value_bits == 0 &&
                       entry.delta == 0 && entry.vbase == 0,
                   "all value decoder fields start zero");
  PROOF_REACHABLE(literal == LZFSE_ENCODE_LITERAL_STATES - 1 &&
                      lmd == sizeof s->compressed_lzfse_block_state.lmd_decoder /
                                 sizeof s->compressed_lzfse_block_state.lmd_decoder[0] - 1,
                  "last table entries");
}
