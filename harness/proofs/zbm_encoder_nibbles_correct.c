#include "proof.h"
#undef memcpy
#include "libzbitmap.c"
#include "zbm_state.h"

uint64_t nondet_u64(void);

void harness(void)
{
    uint8_t dst[16], model[19];
    int n = nondet_int(), k = nondet_int();
    uint64_t acc = nondet_u64(), pat = nondet_u64();
    __CPROVER_assume(n >= 0 && n < 16 && k >= 1 && k <= 4);
    __CPROVER_assume((acc >> (4 * n)) == 0 && (pat >> (4 * k)) == 0);
    for(int i = 0; i < n; ++i) model[i] = (uint8_t)((acc >> (4 * i)) & 15);
    for(int i = 0; i < k; ++i) model[n + i] = (uint8_t)((pat >> (4 * i)) & 15);
    struct zbm_nybl_out out = { dst, acc, n };
    _Bool single = nondet_bool();
    if(single) {
        __CPROVER_assume(k == 1);
        zbm_write_nibble(&out, (uint8_t)pat);
    } else {
        zbm_write_nibbles(&out, pat, k);
    }
    uint8_t *end = zbm_nybl_finish(&out);
    __CPROVER_assert(end == dst + (n + k + 1) / 2, "exact serialized byte count");
    for(int i = 0; i < n + k; ++i)
        __CPROVER_assert(((dst[i / 2] >> (4 * (i % 2))) & 15) == model[i], "nibbles serialized in order");
    if((n + k) & 1)
        __CPROVER_assert((end[-1] >> 4) == 0, "odd final nibble padded with zero");
    PROOF_REACHABLE(single && n == 15, "single writer and full flush");
    PROOF_REACHABLE(!single && n == 15 && k == 4, "batch carry and partial flush");
    PROOF_REACHABLE(!single && n == 0 && k == 1, "odd nibble padding");
}
