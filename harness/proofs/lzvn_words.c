/* Actual memcpy-based word operations used by the Frama emitter models. */
#include "proof.h"
#include "lzfse_internal.h"
#ifdef PROOF_WORD16
#define WORD_BYTES 2
#define word_type uint16_t
#define load_word load2
#define proof_load_word proof_load2
#else
#define WORD_BYTES 4
#define word_type uint32_t
#define load_word load4
#define proof_load_word proof_load4
#endif
#ifdef PROOF_WORD_LOAD
static word_type proof_load_word(const void *source)
__CPROVER_requires(__CPROVER_r_ok(source, WORD_BYTES))
__CPROVER_assigns()
{
    return load_word(source);
}
#else
static void proof_store4(void *destination, uint32_t value)
__CPROVER_requires(__CPROVER_w_ok(destination, 4))
__CPROVER_assigns(__CPROVER_object_upto(destination, 4))
{
    store4(destination, value);
}
#endif
size_t nondet_size(void);
uint32_t nondet_u32(void);
void harness(void)
{
    size_t size=nondet_size(),offset=nondet_size();
    __CPROVER_assume(size>=WORD_BYTES && size<=PROOF_MAX_OBJECT && offset<=size-WORD_BYTES);
    uint8_t *buffer=malloc(size);
    __CPROVER_assume(buffer!=NULL);
#ifdef PROOF_WORD_LOAD
    (void)proof_load_word(buffer+offset);
#else
    proof_store4(buffer+offset,nondet_u32());
#endif
    PROOF_REACHABLE(offset==size-WORD_BYTES,"word at exact upper bound");
}
