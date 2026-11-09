#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_compress_state *st = malloc(sizeof(*st));
    __CPROVER_assume(st != NULL);
    size_t n;
    uint8_t *dst = zbm_any_buffer(&n);
    st->dest = zbm_any_ptr(dst, n);
    st->dest_left = nondet_size();
    st->prewritten = nondet_size();
    int rc = zbm_write_magic(st);
    PROOF_REACHABLE(rc == 0 && st->dest_left == 0, "exact magic capacity");
    PROOF_REACHABLE(rc == ZBM_INVAL && st->dest_left == 3, "one byte short");
    PROOF_REACHABLE(rc == ZBM_INVAL && st->dest_left == 0, "no magic capacity");
}
