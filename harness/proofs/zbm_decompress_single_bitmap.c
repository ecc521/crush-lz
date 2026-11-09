#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_state *st = zbm_any_state();
    uint32_t before = st->written;
    uint8_t first = 0;
    if(__CPROVER_r_ok(st->meta_3.addr, 1) && (st->meta_3.nibble == 0 || st->meta_3.nibble == 1))
        first = (*st->meta_3.addr >> (4 * st->meta_3.nibble)) & 15;
    size_t start_offset = nondet_size();
    __CPROVER_assume(start_offset <= __CPROVER_OBJECT_SIZE(st->src) -
                                  (size_t)__CPROVER_POINTER_OFFSET(st->src));
    const uint8_t *selector_start = st->src + start_offset;
    int rc = zbm_decompress_single_bitmap(st, selector_start);
    PROOF_REACHABLE(rc == 0 && first < 3 && st->written > before, "explicit selector");
    PROOF_REACHABLE(rc == 0 && first >= 3 && first < 15 && st->written > before, "table selector");
    PROOF_REACHABLE(rc == 0 && first == 15 && st->written > before, "standalone history selector");
    PROOF_REACHABLE(rc == ZBM_INVAL, "invalid selection or run");
}
