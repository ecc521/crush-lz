/*
 * Proof: lzvn_encode_literal_only_buffer in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
 */
#include "proof.h"
#include "lzvn_encode_base.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    const uint8_t *src = NULL;
    size_t src_size = nondet_size();
    if (nondet_bool()) {
        size_t n = nondet_size(), o = nondet_size();
        __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT && o <= n);
        uint8_t *buf = malloc(n);
        __CPROVER_assume(buf != NULL);
        __CPROVER_assume(src_size <= n - o);
        src = buf + o;
    }

    uint8_t *dst = NULL;
    size_t dst_size = nondet_size();
    if (nondet_bool()) {
        size_t n = nondet_size(), o = nondet_size();
        __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT && o <= n);
        uint8_t *buf = malloc(n);
        __CPROVER_assume(buf != NULL);
        __CPROVER_assume(dst_size <= n - o);
        dst = buf + o;
    }

    size_t out = lzvn_encode_literal_only_buffer(dst, dst_size, src, src_size);

    __CPROVER_assert(out <= dst_size, "out <= dst_size");

    PROOF_REACHABLE(dst != NULL && src != NULL && dst_size >= 8 && out > 0, "successful literal encode");
    PROOF_REACHABLE(dst != NULL && dst_size < 8 && out == 0, "dst too small < 8 rejected");
    PROOF_REACHABLE(dst != NULL && src != NULL && out == 0, "destination full during emission");
}
