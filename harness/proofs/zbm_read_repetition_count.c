#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_state *st = zbm_any_state();
    uint16_t *repeat; /* supplied by the enforced is_fresh contract */
    uint16_t base = nondet_u16();
    int rc = zbm_read_repetition_count(st, repeat, base);
    PROOF_REACHABLE(rc == 0 && *repeat == 1, "single block");
    PROOF_REACHABLE(rc == 0 && *repeat == 4, "minimum run");
    PROOF_REACHABLE(rc == 0 && *repeat == 4096, "saturated final run");
    PROOF_REACHABLE(rc == 0 && base == 3 && *repeat == 3, "standalone repeat marker");
    PROOF_REACHABLE(rc == ZBM_INVAL, "truncated count");
}
