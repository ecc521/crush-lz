#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"
uint8_t nondet_u8(void);

void harness(void)
{
    size_t sn, dn;
    uint8_t *src, *dst;
    zbm_any_buffers(&src, &sn, &dst, &dn);
    const uint8_t *data = zbm_any_ptr(src, sn), *end = zbm_any_ptr(src, sn);
    uint8_t *dest = zbm_any_ptr(dst, dn);
    uint8_t bmp = nondet_u8();
    uint32_t blocks = nondet_u32();
    const uint8_t *after = zbm_patch_literals(dest, data, end, bmp, blocks);
    PROOF_REACHABLE(blocks == 4096 && bmp == 15 && after < end, "full chunk with bulk blends");
    PROOF_REACHABLE(blocks == 16 && bmp == 1 && after == end, "literal area ends flush");
    PROOF_REACHABLE(blocks == 1 && bmp == 1 && after == end, "scalar patch only");
    PROOF_REACHABLE(blocks > 1 && __CPROVER_same_object(src, dst),
                    "literals and output in one object");
}
