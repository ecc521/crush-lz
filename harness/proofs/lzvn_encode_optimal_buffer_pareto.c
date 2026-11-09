/*
 * Proof: lzvn_encode_optimal_buffer_pareto in crates/crushlzfse/csrc/lzvn_encode_base.c meets its contract.
 */
#include "proof.h"
#include <stdint.h>
#include <string.h>

#include "lzvn_encode_base.c"

size_t nondet_size(void);
int nondet_int(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t src_size = nondet_size();
    _Bool test_overflow = nondet_bool();
    if (test_overflow) {
        src_size = (size_t)LZVN_ZOPT_BLOCK_SIZE + 1;
    } else {
        __CPROVER_assume(src_size <= 256);
    }

    uint8_t *src = malloc(src_size + LZVN_ZOPT_SRC_PADDING);
    __CPROVER_assume(src != NULL);

    size_t dst_size = nondet_size();
    __CPROVER_assume(dst_size <= 256);

    uint8_t *dst = malloc(dst_size);
    __CPROVER_assume(dst != NULL);
    __CPROVER_assume(!__CPROVER_same_object(src, dst));

    uint8_t *z_buf = malloc(1024);
    __CPROVER_assume(z_buf != NULL);
    __CPROVER_assume(!__CPROVER_same_object(src, z_buf));
    __CPROVER_assume(!__CPROVER_same_object(dst, z_buf));

    size_t n_pos = test_overflow ? 1 : src_size + 1;
    size_t p_bytes = 64 + n_pos * (2 * sizeof(int32_t) + 2 * sizeof(lzvn_pareto_slot));
    uint8_t *p_buf = malloc(p_bytes);
    __CPROVER_assume(p_buf != NULL);
    __CPROVER_assume(!__CPROVER_same_object(src, p_buf));
    __CPROVER_assume(!__CPROVER_same_object(dst, p_buf));
    __CPROVER_assume(!__CPROVER_same_object(z_buf, p_buf));

    lzvn_zopt_scratch *z = (lzvn_zopt_scratch *)z_buf;
    memset(z, 0, sizeof(*z));
    z->max_tuples = 4;
    z->tup_M = (uint32_t *)(z_buf + 256);
    z->tup_L = (uint32_t *)(z_buf + 512);
    z->tup_D = (uint32_t *)(z_buf + 768);

    lzvn_pareto_scratch *p = (lzvn_pareto_scratch *)p_buf;
    memset(p, 0, sizeof(*p));
    p->k_cap = 2;
    p->count = (int32_t *)(p_buf + 64);
    p->worst_cost = p->count + n_pos;
    p->slots = (lzvn_pareto_slot *)(p->worst_cost + n_pos);
    __CPROVER_assert(test_overflow || LZVN_PARETO_STORAGE_OK(z, p, src_size),
                     "Pareto tuple and state arrays are valid and separate");

    size_t res = lzvn_encode_optimal_buffer_pareto(dst, dst_size, src, src_size, z, p);
    __CPROVER_assert(res <= dst_size, "return value <= dst_size");
    if (test_overflow) {
        __CPROVER_assert(res == 0, "oversized src returns 0");
    }

    PROOF_REACHABLE(test_overflow, "oversized src branch");
    PROOF_REACHABLE(!test_overflow && res == 0, "failure return");
    PROOF_REACHABLE(!test_overflow && res > 0, "successful commit");
}
