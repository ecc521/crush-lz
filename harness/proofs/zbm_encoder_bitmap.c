#include "proof.h"
#undef memcpy
#include "libzbitmap.c"
#include "zbm_state.h"

uint8_t nondet_u8(void);
uint16_t nondet_u16(void);

void harness(void)
{
    size_t an, bn;
    uint8_t *abuf = zbm_any_buffer(&an), *bbuf = zbm_any_buffer(&bn);
    const uint8_t *a = zbm_any_ptr(abuf, an), *b = zbm_any_ptr(bbuf, bn);
    uint8_t size = nondet_u8();
    __CPROVER_assume(size <= 8);
    uint16_t period = nondet_u16();
    zbm_calculate_bitmap(a, b, size, period);
    PROOF_REACHABLE(size == 8, "full block loads");
    PROOF_REACHABLE(size == 1, "one-byte partial block");
    PROOF_REACHABLE(size == 7, "seven-byte partial block");
    PROOF_REACHABLE(size == 0, "empty block");
}
