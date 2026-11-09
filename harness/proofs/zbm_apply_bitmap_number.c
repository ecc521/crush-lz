#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

uint8_t nondet_u8(void);

void harness(void)
{
    struct zbm_state *st = zbm_any_state();
    uint8_t selector = nondet_u8();
    uint32_t before = st->written;
    int rc = zbm_apply_bitmap_number(st, selector);
    PROOF_REACHABLE(rc == 0 && selector < 3 && st->written > before,
                    "explicit bitmap");
    PROOF_REACHABLE(rc == 0 && selector >= 3 && st->written > before,
                    "table bitmap");
    PROOF_REACHABLE(rc == ZBM_INVAL && selector == 15, "repeat as selector");
    PROOF_REACHABLE(rc == ZBM_INVAL && selector < 3, "truncated explicit bitmap");
}
