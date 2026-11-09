#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

uint64_t nondet_u64(void);

void harness(void)
{
    struct zbm_nybl_out out;
    size_t dn;
    uint8_t *dst = zbm_any_buffer(&dn);
    out.addr = zbm_any_ptr(dst, dn);
    out.n = nondet_int();
    out.acc = nondet_u64();
    int repeat = nondet_int();
    zbm_write_repetition_count(&out, repeat);
    PROOF_REACHABLE(repeat == 4, "minimum repeat and zero digit");
    PROOF_REACHABLE(repeat == 19, "full fifteen digit and zero terminator");
    PROOF_REACHABLE(repeat == 18, "non-fifteen final digit");
    PROOF_REACHABLE(repeat == ZBM_MAX_BITMAP_COUNT, "maximum repetition count");
}
