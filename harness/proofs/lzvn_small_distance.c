/* Exact native sml_d distance expression; byte operands have full domains. */
#include "proof.h"
#include "lzfse_internal.h"
static size_t proof_small_distance(uint8_t opc,uint8_t second)
__CPROVER_assigns()
__CPROVER_ensures(__CPROVER_return_value<=2047)
__CPROVER_ensures(__CPROVER_return_value==(size_t)(opc & 7)*256+second)
{
    return (size_t)extract(opc, 0, 3) << 8 | second;
}
uint8_t nondet_u8(void);
void harness(void)
{
    uint8_t opc=nondet_u8(),second=nondet_u8();
    size_t D=proof_small_distance(opc,second);
    PROOF_REACHABLE(D==0,"invalid zero distance");
    PROOF_REACHABLE(D==2047,"largest small distance");
    PROOF_REACHABLE(D==1,"minimum valid distance");
}
