/* Native packed-prefix read and exact size field used by framing proofs. */
#include "proof.h"
#include "lzfse_decode_base.c"
static uint32_t proof_header_size(const lzfse_compressed_block_header_v2 *in)
__CPROVER_requires(__CPROVER_r_ok(in, 32))
__CPROVER_assigns()
__CPROVER_ensures(__CPROVER_return_value == (uint32_t)in->packed_fields[2])
{
    return lzfse_decode_v2_header_size(in);
}
size_t nondet_size(void);
void harness(void)
{
    size_t n=nondet_size(),offset=nondet_size();
    __CPROVER_assume(n>=32 && n<=PROOF_MAX_OBJECT && offset<=n-32);
    uint8_t *src=malloc(n);
    __CPROVER_assume(src!=NULL);
    uint32_t size=proof_header_size((const lzfse_compressed_block_header_v2 *)(src+offset));
    PROOF_REACHABLE(offset%8==1,"unaligned packed prefix");
    PROOF_REACHABLE(size==32,"minimal v2 header");
    PROOF_REACHABLE(size==0xffffffffU,"largest declared header");
}
