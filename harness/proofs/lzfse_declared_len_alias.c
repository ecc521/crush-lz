/* Shipping parser with source and out_len in disjoint ranges of one object.
 * The full-span contract is enforced by lzfse_declared_len; this target
 * checks the shared-allocation domain and reaches both range orders. */
#include "proof.h"
#include "lzfse_decode_base.c"
_Bool nondet_bool(void);

void harness(void)
{
    union {
        size_t words[8];
        uint8_t bytes[8 * sizeof(size_t)];
    } arena;
    _Bool before = nondet_bool();
    uint8_t *src = arena.bytes + (before ? 2 * sizeof(size_t) : 0);
    size_t *out_len = before ? &arena.words[0] : &arena.words[2];
    uint32_t magic = LZFSE_ENDOFSTREAM_BLOCK_MAGIC;
    src[0] = (uint8_t)magic;
    src[1] = (uint8_t)(magic >> 8);
    src[2] = (uint8_t)(magic >> 16);
    src[3] = (uint8_t)(magic >> 24);
    *out_len = SIZE_MAX;

    __CPROVER_assert(__CPROVER_same_object(src, out_len),
                     "source and output share one allocation");
    int status = lzfse_declared_len(src, src + 4, out_len);
    __CPROVER_assert(status == 0 && *out_len == 0,
                     "end marker reports zero length in shared allocation");
    __CPROVER_assert(src[0] == (uint8_t)magic &&
                     src[1] == (uint8_t)(magic >> 8) &&
                     src[2] == (uint8_t)(magic >> 16) &&
                     src[3] == (uint8_t)(magic >> 24),
                     "source remains unchanged");
    PROOF_REACHABLE(before && status == 0, "output before source");
    PROOF_REACHABLE(!before && status == 0, "output after source");
}
