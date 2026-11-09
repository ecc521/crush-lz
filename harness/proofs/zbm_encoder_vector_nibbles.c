#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"
uint64_t nondet_u64(void);
void harness(void)
{
    size_t n;
    uint8_t *buffer = zbm_any_buffer(&n);
    struct zbm_nybl_out out;
    out.addr = zbm_any_ptr(buffer, n);
    out.acc = nondet_u64(); out.n = nondet_int();
    uint64_t packed = nondet_u64();
    int pending = out.n;
    zbm_write_16_nibbles(&out, packed);
    PROOF_REACHABLE(pending == 0 && n == 8, "exact vector span without pending nibbles");
    PROOF_REACHABLE(pending == 15, "maximum pending vector carry");
    PROOF_REACHABLE(pending == 7, "odd pending nibble count");
}
