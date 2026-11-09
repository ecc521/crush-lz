#include "proof.h"
#include "libzbitmap.c"
int nondet_int(void);
unsigned nondet_u32(void);
void harness(void)
{
    uint64_t boundary[ZBM_MAX_BITMAP_COUNT / 64 + 1];
    int cnt = nondet_int(), idx = nondet_int();
#ifdef ZBM_PROOF_RUN_END_VALUES
    zbm_proof_end_index = nondet_u32();
#endif
    int end = zbm_find_run_end(&boundary, idx, cnt);
    PROOF_REACHABLE(cnt == ZBM_MAX_BITMAP_COUNT && idx == 0 && end == cnt - 1,
        "full chunk with only its final boundary");
    PROOF_REACHABLE(idx == cnt - 1 && end == idx, "last block boundary");
    PROOF_REACHABLE(cnt == 65 && idx == 63 && end == 64, "next word boundary");
    PROOF_REACHABLE(cnt == 4 && idx == 1 && end == 3, "later boundary in current word");
    PROOF_REACHABLE(cnt == 4 && idx == 1 && end == 1, "immediate boundary");
}
