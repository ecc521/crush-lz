/* Shipping eight-byte word serialization into the actual value-table layout.
 * Keep CBMC's exact standard memcpy semantics here rather than the general
 * range-only summary: this target proves field values, not only its footprint.
 */
#include "proof.h"
#include "lzfse_fse.h"
#undef memcpy

_Static_assert(sizeof(fse_value_decoder_entry)==8,"value-table layout changed");

static void proof_fse_value_unpack(fse_value_decoder_entry *row,uint64_t word)
__CPROVER_requires(__CPROVER_w_ok(row,sizeof *row))
__CPROVER_assigns(*row)
__CPROVER_ensures(row->total_bits==(uint8_t)__CPROVER_old(word))
__CPROVER_ensures(row->value_bits==(uint8_t)(__CPROVER_old(word)>>8))
__CPROVER_ensures(row->delta==(int16_t)(__CPROVER_old(word)>>16))
__CPROVER_ensures(row->vbase==(int32_t)(__CPROVER_old(word)>>32))
{
    memcpy(row,&word,8);
}

uint64_t nondet_u64(void);
void harness(void)
{
    fse_value_decoder_entry row;
    uint64_t word=nondet_u64();
    proof_fse_value_unpack(&row,word);
    PROOF_REACHABLE(row.total_bits==26 && row.value_bits==16,
                    "maximum shipping distance bits");
    PROOF_REACHABLE(row.delta<0,"signed delta representation");
    PROOF_REACHABLE(row.vbase==262139,"upper distance base");
}
