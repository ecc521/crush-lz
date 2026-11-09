#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
#ifdef ZBM_PROOF_BOUNDARY_VALUES
    zbm_proof_boundary_index = nondet_u32();
#endif
    size_t sn, tn;
    uint8_t *src = zbm_any_buffer(&sn), *other = zbm_any_buffer(&tn);
    const uint8_t *a = zbm_any_ptr(src, sn);
#ifdef PROOF_EQ16
    const uint8_t *b = nondet_bool() ? zbm_any_ptr(src, sn) : zbm_any_ptr(other, tn);
    zbm_eq16_mask(a, b);
    PROOF_REACHABLE(a == b, "identical compared spans");
    PROOF_REACHABLE(__CPROVER_same_object(a, b) && b == a + 1, "overlapping adjacent selector spans");
    PROOF_REACHABLE(!__CPROVER_same_object(a, b), "separate compared spans");
#else
    zbm_pack_nibbles16(a);
    PROOF_REACHABLE(sn == 16 && a == src, "exact sixteen-byte source");
    PROOF_REACHABLE(a > src, "interior selector span");
#endif
}
