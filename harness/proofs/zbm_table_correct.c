/* Compare the optimized two-word extraction to a bit-by-bit format model.
 * All 17 input bytes are symbolic; memcpy retains actual byte values. */
#include "proof.h"
#undef memcpy
#include "libzbitmap.c"

uint8_t nondet_u8(void);

void harness(void)
{
    uint8_t table[17];
    for (unsigned i = 0; i < 17; ++i) table[i] = nondet_u8();
    struct zbm_bmap want[12];
    _Bool invalid = 0;
    for (unsigned i = 0; i < 12; ++i) {
        unsigned bits = 0;
        for (unsigned j = 0; j < 10; ++j) {
            unsigned bit = 10 * i + j;
            bits |= ((table[bit / 8] >> (bit % 8)) & 1u) << j;
        }
        want[i].bitmap = (uint8_t)bits;
        want[i].period_bytecnt = (uint8_t)(bits >> 8);
        invalid |= want[i].period_bytecnt == 3;
    }
    struct zbm_state st = {0};
    st.src = table; st.src_end = table + 17; st.len = 17;
    int rc = zbm_read_bitmaps(&st);
    __CPROVER_assert(rc == (invalid ? ZBM_INVAL : 0), "table validity matches model");
    if (!invalid)
        for (unsigned i = 0; i < 12; ++i) {
            __CPROVER_assert(st.bitmaps[i].bitmap == want[i].bitmap, "table bitmap bytes");
            __CPROVER_assert(st.bitmaps[i].period_bytecnt == want[i].period_bytecnt,
                             "table period byte counts");
        }
    PROOF_REACHABLE(rc == 0, "supported table");
    PROOF_REACHABLE(rc == ZBM_INVAL, "unsupported table entry");
}
