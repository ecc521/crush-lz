#include "proof.h"
#include "libzbitmap.c"
int nondet_int(void);
unsigned nondet_u32(void);
void harness(void)
{
#ifdef PROOF_WORD_INDEX
    int index = nondet_int();
    int word = zbm_selector_word_index(index);
    PROOF_REACHABLE(index == 0 && word == 0, "first selector word");
    PROOF_REACHABLE(index == 64 && word == 1, "second selector word");
    PROOF_REACHABLE(index == ZBM_MAX_BITMAP_COUNT - 1 && word == 63, "last selector word");
#else
    int repeat = nondet_int();
    unsigned number = nondet_u32();
    uint64_t packed = zbm_short_run_pattern(repeat, number);
    PROOF_REACHABLE(repeat == 1 && number == 0 && packed == 0, "one zero selector");
    PROOF_REACHABLE(repeat == 2 && number == 14 && packed == 0xee, "two maximum selectors");
    PROOF_REACHABLE(repeat == 3 && number == 14 && packed == 0xeee, "three maximum selectors");
#endif
}
