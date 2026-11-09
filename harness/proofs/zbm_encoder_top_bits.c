/* Pure consequence of the shipping top-table period-byte expression.
 * Covers every nonnegative int key in the 1024-entry table, independently
 * of use counts or table contents. LP64/int32/eight-bit bytes as run.sh.
 */
#include "proof.h"
#include "libzbitmap.c"
int nondet_int(void);
void harness(void)
{
    int key = nondet_int();
    __CPROVER_assume(0 <= key && key < ZBM_POSSIBLE_BMPROTS);
    int bits = key & 3;
    __CPROVER_assert(0 <= bits && bits <= 3, "two low bits bounded");
    __CPROVER_assert(bits == key % 4, "two low bits equal remainder");
    __CPROVER_assert((uint8_t)bits == bits, "byte conversion preserves low bits");
    int bitmap = key >> 2;
    __CPROVER_assert(bitmap == key / 4 && 0 <= bitmap && bitmap <= 255,
                     "top bitmap shift is bounded quotient");
    __CPROVER_assert((uint8_t)bitmap == bitmap, "byte conversion preserves top bitmap");
    __CPROVER_assert(4 * (int)(uint8_t)bitmap + (uint8_t)bits == key,
                     "top bitmap pair reconstructs original key");
    PROOF_REACHABLE(key == 0 && bits == 0, "first top key");
    PROOF_REACHABLE(key == ZBM_POSSIBLE_BMPROTS - 2 && bits == 2, "last valid top key");
    PROOF_REACHABLE(key == ZBM_POSSIBLE_BMPROTS - 1 && bits == 3, "last reserved top key");
}
