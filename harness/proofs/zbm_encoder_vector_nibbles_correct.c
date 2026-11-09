#include "proof.h"
#undef memcpy
#include "libzbitmap.c"
uint64_t nondet_u64(void);
int nondet_int(void);
void harness(void)
{
    uint8_t bytes[8];
    int pending = nondet_int();
    uint64_t initial = nondet_u64(), packed = nondet_u64();
    __CPROVER_assume(pending >= 0 && pending < 16);
    __CPROVER_assume((initial >> (4 * pending)) == 0);
    struct zbm_nybl_out out = {bytes, initial, pending};
    zbm_write_16_nibbles(&out, packed);
    __CPROVER_assert(out.addr == bytes + 8 && out.n == pending, "vector cursor and pending count");
    for(int q = 0; q < 16; ++q) {
        unsigned expected = q < pending ? (unsigned)((initial >> (4 * q)) & 15u) :
            (unsigned)((packed >> (4 * (q - pending))) & 15u);
        __CPROVER_assert(((bytes[q / 2] >> (4 * (q & 1))) & 15u) == expected,
            "written vector nibbles retain prefix and append in source order");
    }
    for(int q = 0; q < pending; ++q)
        __CPROVER_assert(((out.acc >> (4 * q)) & 15u) == ((packed >> (4 * (16 - pending + q))) & 15u),
            "pending suffix contains precisely the remaining packed nibbles");
    __CPROVER_assert((out.acc >> (4 * pending)) == 0, "pending accumulator has no unused high bits");
    PROOF_REACHABLE(pending == 0, "no pending nibble prefix");
    PROOF_REACHABLE(pending == 15, "maximum prefix and suffix");
    PROOF_REACHABLE(pending == 7, "odd prefix and suffix");
}
