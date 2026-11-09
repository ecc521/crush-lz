/* Shipping L/M/D transitions and value bounds, under explicit table-row
 * invariants. Connecting these invariants to builders remains open. */
#include "proof.h"
#include "lzfse_internal.h"
uint32_t nondet_u32(void);
uint64_t nondet_u64(void);
int32_t nondet_i32(void);
size_t nondet_size(void);
void harness(void)
{
    _Static_assert(LZFSE_L_DECODER_OFFSET == 0 &&
                   LZFSE_M_DECODER_OFFSET == 72 &&
                   LZFSE_D_DECODER_OFFSET == 144,
                   "proof contract must match shipping decoder table layout");
    _Static_assert(sizeof(((lzfse_compressed_block_decoder_state *)0)->lmd_decoder) /
                       sizeof(fse_value_decoder_entry) == 408,
                   "proof table size must match shipping decoder state");
    fse_value_decoder_entry *table=malloc(408*sizeof *table);
    __CPROVER_assume(table!=NULL);
    uint32_t state=nondet_u32();
    size_t offset=nondet_size();
    fse_in_stream input;
    input.accum=nondet_u64();
    input.accum_nbits=nondet_i32();
    uint32_t before=state;
    uint32_t value=fse_value_decode_u32(&state,table,offset,&input);
    PROOF_REACHABLE(offset==0 && before==63 && value==315,"upper literal-length value");
    PROOF_REACHABLE(offset==LZFSE_M_DECODER_OFFSET && before==63 && value==2359,"upper match-length value");
    PROOF_REACHABLE(offset==LZFSE_D_DECODER_OFFSET && before==255 && value==262139,"upper distance state/value");
    PROOF_REACHABLE(table[offset+before].total_bits==0,"zero-bit value transition");
}
