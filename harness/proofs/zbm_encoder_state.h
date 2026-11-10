/*
 * Shared by the LZBITMAP encoder search harnesses, in place of including
 * libzbitmap.c directly.
 *
 * memset clears tables whose contents the search never trusts: these
 * proofs hold for any table contents. The contract checks the range is
 * writable and leaves the bytes as they were.
 *
 * The state is a typed allocation with every field unconstrained. zbm_any_encoder_scratch follows it with the
 * second row index, as zbm_state_begin carves caller scratch for DP and
 * beam.
 */
#ifndef ZBM_ENCODER_STATE_H
#define ZBM_ENCODER_STATE_H

#include "proof.h"

void *proof_memset(void *s, int c, size_t n)
__CPROVER_requires(__CPROVER_w_ok(s, n))
__CPROVER_assigns()
__CPROVER_ensures(__CPROVER_return_value == s);

#define memset(s, c, n) proof_memset(s, c, n)

#include "libzbitmap.c"

static struct zbm_compress_state *zbm_any_encoder_state(void)
{
    struct zbm_compress_state *p = malloc(sizeof(*p));
    __CPROVER_assume(p != NULL);
    return p;
}

struct zbm_proof_scratch {
    struct zbm_compress_state state;
    uint32_t row_tab2[ZBM_ROW2_BYTES / sizeof(uint32_t)];
};

static struct zbm_compress_state *zbm_any_encoder_scratch(void)
{
    struct zbm_proof_scratch *p = malloc(sizeof(*p));
    __CPROVER_assume(p != NULL);
    p->state.row_tab2 = p->row_tab2;
    return &p->state;
}

#endif
