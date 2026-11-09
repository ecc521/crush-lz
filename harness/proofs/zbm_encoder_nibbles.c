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
    size_t room = dn - __CPROVER_POINTER_OFFSET(out.addr);
#if defined(PROOF_NIBBLE_SINGLE)
    uint8_t val = (uint8_t)nondet_u32();
    int before = out.n;
    zbm_write_nibble(&out, val);
    PROOF_REACHABLE(before == 15, "single nibble flush");
    PROOF_REACHABLE(before == 0, "single nibble start");
    PROOF_REACHABLE(before == 0 && room == 0, "single buffered append without output room");
#elif defined(PROOF_NIBBLE_FINISH)
    int before = out.n;
    zbm_nybl_finish(&out);
    PROOF_REACHABLE(before == 0, "empty flush");
    PROOF_REACHABLE(before == 15, "maximum partial flush");
    PROOF_REACHABLE(before == 1, "half-byte padding");
#else
    int k = nondet_int(), before = out.n;
    zbm_write_nibbles(&out, nondet_u64(), k);
    PROOF_REACHABLE(before == 15 && k == 4, "three carried nibbles");
    PROOF_REACHABLE(before == 12 && k == 4, "exact accumulator fill");
    PROOF_REACHABLE(before == 0 && k == 1, "no flush");
    PROOF_REACHABLE(before == 0 && k == 4 && room == 0, "batch buffered append without output room");
#endif
}
