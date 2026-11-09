#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_state *st = zbm_any_state();
    int rc = zbm_handle_compressed_chunk(st);
    PROOF_REACHABLE(rc == 0 && st->decmp_len == 32768, "complete maximum chunk");
    PROOF_REACHABLE(rc == 0 && st->decmp_len == 7, "partial chunk");
    PROOF_REACHABLE(rc == ZBM_INVAL, "invalid chunk");
    PROOF_REACHABLE(rc == 0 && st->decmp_len > 0 && __CPROVER_same_object(st->src, st->dest),
                    "chunk and output in one object");
}
