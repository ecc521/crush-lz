#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_state *st = zbm_any_state();
    if(nondet_bool()) st->dest = NULL;
    int rc = zbm_handle_chunk(st);
    PROOF_REACHABLE(rc == 0 && st->dest != NULL && st->decmp_len > 0 &&
                    st->len == st->decmp_len + 6, "stored chunk");
    PROOF_REACHABLE(rc == 0 && st->dest != NULL && st->decmp_len > 0 &&
                    st->len != st->decmp_len + 6, "compressed chunk");
    PROOF_REACHABLE(rc == 0 && st->dest == NULL && st->dest_left > ((size_t)1 << 48), "large size-probe cap");
    PROOF_REACHABLE(rc == ZBM_RANGE, "insufficient destination capacity");
    PROOF_REACHABLE(rc == ZBM_INVAL, "invalid chunk header");
    PROOF_REACHABLE(rc == 0 && st->decmp_len > 0 && __CPROVER_same_object(st->src, st->dest),
                    "chunk and output in one object");
}
