/* Exact default-selector expression used by zbm_build_bmap_num_table. */
#include "proof.h"
#include "libzbitmap.c"
unsigned nondet_u32(void);
void harness(void)
{
    unsigned key = nondet_u32();
    __CPROVER_assume(key < ZBM_POSSIBLE_BMPROTS);
    uint8_t value = (uint8_t)(key >> 8);
    __CPROVER_assert(value == key / 256, "default selector equals high-byte quotient");
    __CPROVER_assert(value <= 3, "default selector in zero through three");
    __CPROVER_assert((value < ZBM_BITMAP_BASE) == (key < (3u << 8)),
                     "supported keys default to explicit bitmap selectors");
    PROOF_REACHABLE(key == 0 && value == 0, "first default selector");
    PROOF_REACHABLE(key == 767 && value == 2, "last supported default selector");
    PROOF_REACHABLE(key == 1023 && value == 3, "last reserved default selector");
}
