/* Shipping 32-bit literal step (FSE_IOSTREAM_64 == 0): fse_in_stream32 and
 * fse_in_pull32, over every 1024-row literal table satisfying the row
 * invariant and every input with accum_nbits in [10, 32). The configuration
 * is selected by run.sh, which undefines the 64-bit architecture macros. */
#include "proof.h"
#include "lzfse_fse.h"

_Static_assert(FSE_IOSTREAM_64 == 0, "fse_decode_u32_32 needs the 32-bit stream");

uint32_t nondet_u32(void);
int32_t nondet_i32(void);
void harness(void)
{
    int32_t *table = malloc(LZFSE_ENCODE_LITERAL_STATES * sizeof *table);
    __CPROVER_assume(table != NULL);
    for (uint32_t k = 0; k < LZFSE_ENCODE_LITERAL_STATES; k++) {
        __CPROVER_assume((table[k] & 0xff) <= 10);
        __CPROVER_assume((table[k] >> 16) >= 0);
        __CPROVER_assume((uint32_t)(table[k] >> 16) +
            (((uint32_t)1 << (table[k] & 0xff)) - 1) < LZFSE_ENCODE_LITERAL_STATES);
    }
    uint32_t state = nondet_u32();
    __CPROVER_assume(state < LZFSE_ENCODE_LITERAL_STATES);
    fse_in_stream32 input;
    input.accum = nondet_u32();
    input.accum_nbits = nondet_i32();
    __CPROVER_assume(input.accum_nbits >= 10 && input.accum_nbits < 32);
    __CPROVER_assume((input.accum >> input.accum_nbits) == 0);
    uint32_t before = state;
    fse_bit_count nbits = input.accum_nbits;
    uint8_t symbol = fse_decode_u32(&state, table, &input);
    PROOF_REACHABLE(before == 1023, "shipping upper literal state");
    PROOF_REACHABLE((table[before] & 0xff) == 0, "zero-bit transition");
    PROOF_REACHABLE((table[before] & 0xff) == 10, "ten-bit transition");
    PROOF_REACHABLE(nbits == 10 && (table[before] & 0xff) == 10, "ten bits from exactly ten");
    PROOF_REACHABLE(nbits == 31 && (table[before] & 0xff) == 10, "maximum buffered bits");
    PROOF_REACHABLE(symbol == 255, "upper literal symbol");
}
