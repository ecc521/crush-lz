/* Public decoder boundary, including nullable zero-length buffers and shared allocation. */
#include "proof.h"
#include "lzvn_decode_base.c"
#include "crushlzvn.c"
size_t nondet_size(void);
_Bool nondet_bool(void);
void harness(void)
{
    size_t sn=nondet_size(),dn=nondet_size();
    __CPROVER_assume(sn<=PROOF_MAX_OBJECT && dn<=PROOF_MAX_OBJECT);
    uint8_t *src=NULL,*dst=NULL;
    size_t *arena_out=NULL;
    size_t gap=0,lead=0;
    _Bool shared = nondet_bool();
    if(shared) {
        _Bool shared_out=nondet_bool();
        size_t prefix=shared_out ? sizeof(size_t) : 0;
        __CPROVER_assume(dn <= PROOF_MAX_OBJECT - prefix);
        __CPROVER_assume(sn <= PROOF_MAX_OBJECT - prefix - dn);
        gap=nondet_size();
        lead=nondet_size();
        __CPROVER_assume(gap <= PROOF_MAX_OBJECT - prefix - sn - dn);
        __CPROVER_assume(lead <= PROOF_MAX_OBJECT - prefix - sn - dn - gap);
        size_t total = prefix + lead + sn + gap + dn;
        uint8_t *arena = malloc(total != 0 ? total : 1);
        __CPROVER_assume(arena != NULL);
        if(shared_out) arena_out=(size_t *)arena;
        uint8_t *first=arena+prefix+lead;
        if(nondet_bool()) {
            src = (sn != 0 || nondet_bool()) ? first : NULL;
            dst = (dn != 0 || nondet_bool()) ? first + sn + gap : NULL;
        } else {
            dst = (dn != 0 || nondet_bool()) ? first : NULL;
            src = (sn != 0 || nondet_bool()) ? first + dn + gap : NULL;
        }
    } else {
        if(sn!=0 || nondet_bool()) {
            src=malloc(sn!=0?sn:1);
            __CPROVER_assume(src!=NULL);
        }
        if(dn!=0 || nondet_bool()) {
            dst=malloc(dn!=0?dn:1);
            __CPROVER_assume(dst!=NULL);
        }
    }
    size_t output=nondet_size();
    size_t *out=nondet_bool()?(arena_out!=NULL && nondet_bool()?arena_out:&output):NULL;
    int status=crushlzvn_decode_buffer(dst,dn,src,sn,out);
    PROOF_REACHABLE(src==NULL && sn==0 && out!=NULL && status==CRUSHLZVN_INVALID,"null empty source rejected");
    PROOF_REACHABLE(dst==NULL && dn==0 && out!=NULL && status==0 && output==0,"empty destination accepts end marker");
    PROOF_REACHABLE(out==NULL && status==CRUSHLZVN_INVALID,"null output length rejected");
    PROOF_REACHABLE(out!=NULL && status==CRUSHLZVN_OUTPUT_TOO_SMALL,"destination exhausted");
    PROOF_REACHABLE(out!=NULL && status==0 && output>0,"nonempty decode");
    PROOF_REACHABLE(shared && src!=NULL && dst!=NULL && out!=NULL && status==0 && output>0, "shared allocation decode");
    PROOF_REACHABLE(arena_out!=NULL && out==arena_out && status==0 && *out>0,
                    "output length shares allocation with disjoint buffers");
    PROOF_REACHABLE(shared && gap>0 && lead>0 && out!=NULL && status==0 && *out>0,
                    "shared allocation has leading offset and gap");
}
