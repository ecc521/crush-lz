#include "proof.h"
#undef memcpy
#include "libzbitmap.c"

uint8_t nondet_u8(void);

void harness(void)
{
    uint8_t src[8], dst[8];
    uint8_t bm = nondet_u8();
    for(unsigned i = 0; i < 8; ++i) src[i] = nondet_u8();
    zbm_pack8(dst, src, zbm_pack_row[bm]);
    unsigned n = 0;
    for(unsigned i = 0; i < 8; ++i) {
        __CPROVER_assert(zbm_pack_row[bm][i] < 8, "every pack selector is a valid lane");
        if((bm >> i) & 1)
            __CPROVER_assert(dst[n++] == src[i], "literal lanes packed in source order");
    }
    __CPROVER_assert(n == zbm_pack_row[bm][8] && n == zbm_popcount8(bm),
                      "pack consumption agrees with bitmap popcount");
    PROOF_REACHABLE(bm == 0, "no literals");
    PROOF_REACHABLE(bm == 255, "all literals");
    PROOF_REACHABLE(bm == 0x55, "alternating literals");
}
