/* producer-sha256: 04d1600f0dc94d786ab3be625dd2cc187304a46232652f9965b12c58e68dec1d */

#include "proof.h"
#include "lzfse_internal.h"
static uint8_t *proof_literal_bulk_span(uint8_t *lp,uint8_t *lp_end,
                                      const uint8_t *buf,const uint8_t *buf_start)
__CPROVER_requires(__CPROVER_same_object(lp,lp_end))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(lp)<=__CPROVER_POINTER_OFFSET(lp_end))
__CPROVER_requires(__CPROVER_w_ok(lp,(size_t)(lp_end-lp)))
__CPROVER_requires(__CPROVER_same_object(buf,buf_start))
__CPROVER_requires(__CPROVER_POINTER_OFFSET(buf_start)<=__CPROVER_POINTER_OFFSET(buf))
__CPROVER_requires(__CPROVER_r_ok(buf_start,(size_t)(buf-buf_start)))
__CPROVER_assigns()
__CPROVER_ensures(__CPROVER_same_object(__CPROVER_return_value,lp))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(__CPROVER_return_value)>=__CPROVER_POINTER_OFFSET(lp))
__CPROVER_ensures(__CPROVER_POINTER_OFFSET(__CPROVER_return_value)<=__CPROVER_POINTER_OFFSET(lp_end))
__CPROVER_ensures((size_t)(__CPROVER_return_value-lp)==
  (4 * ((size_t)(buf-buf_start)/8) < (size_t)(lp_end-lp)
    ? 4 * ((size_t)(buf-buf_start)/8) : (size_t)(lp_end-lp)))
{
    size_t safe_groups = (size_t)(buf - buf_start) / 8;
    // Clamp the byte span before forming a pointer into the literal array.
    // A large encoded payload can otherwise put that pointer far beyond it.
    size_t safe_bytes = 4 * safe_groups;
    size_t literal_bytes = (size_t)(lp_end - lp);
    if (safe_bytes > literal_bytes)
      safe_bytes = literal_bytes;
    uint8_t *lp_safe = lp + safe_bytes;

    return lp_safe;
}
size_t nondet_size(void);
void harness(void)
{
    size_t source_size=nondet_size(),source_pos=nondet_size();
    __CPROVER_assume(source_size>0 && source_size<=PROOF_MAX_OBJECT && source_pos<=source_size);
    uint8_t *source=malloc(source_size);
    __CPROVER_assume(source!=NULL);
    uint8_t literals[LZFSE_LITERALS_PER_BLOCK+LZFSE_DECODE_COPY_MARGIN];
    size_t count=nondet_size();
    __CPROVER_assume(count<=LZFSE_LITERALS_PER_BLOCK);
    uint8_t *end=proof_literal_bulk_span(literals,literals+count,source+source_pos,source);
    PROOF_REACHABLE(source_pos>LZFSE_LITERALS_PER_BLOCK,"payload larger than literal capacity");
    PROOF_REACHABLE(count==40000 && end==literals+count,"shipping literal block capacity");
    PROOF_REACHABLE(count==3 && end==literals+3,"malformed non-multiple-of-four count");
}
