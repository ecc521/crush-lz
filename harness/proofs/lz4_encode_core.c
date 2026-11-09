/* The actual multi-block framing loop, including allocation failure and
 * arbitrary caller scratch. Only excluded upstream calls and proven scalar
 * helpers are replaced. There is no source-size or block-count unwind cap. */
#include "proof.h"
void *proof_memmove(void *dst, const void *src, size_t count)
__CPROVER_requires(__CPROVER_w_ok(dst, count) && __CPROVER_r_ok(src, count))
__CPROVER_assigns(__CPROVER_object_upto(dst, count))
__CPROVER_ensures(__CPROVER_return_value == dst);
#define memmove(dst, src, count) proof_memmove(dst, src, count)
#include "crushlz4.c"

size_t nondet_size(void);
int nondet_int(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t sn = nondet_size(), dn = nondet_size(), scratch_size = nondet_size();
    __CPROVER_assume(sn > 0 && sn <= PROOF_MAX_OBJECT);
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT);
    __CPROVER_assume(scratch_size <= PROOF_MAX_OBJECT - CLZ4_SCRATCH_ALIGN);
    uint8_t *src = malloc(sn), *dst = malloc(dn);
    __CPROVER_assume(src != NULL && dst != NULL);
    size_t src_size = nondet_size(), dst_size = nondet_size();
    __CPROVER_assume(src_size <= sn && dst_size <= dn);
    void *scratch = NULL;
    if (nondet_bool()) {
        uint8_t *storage = malloc(scratch_size + CLZ4_SCRATCH_ALIGN);
        __CPROVER_assume(storage != NULL);
        size_t offset = nondet_size();
        __CPROVER_assume(offset < CLZ4_SCRATCH_ALIGN);
        scratch = storage + offset;
    }
    struct clz4_level_row row;
    row.mode = nondet_int();
    row.param = nondet_int();
    size_t written = nondet_size();
    int status = encode(dst, dst_size, src, src_size, &written,
                        scratch, scratch_size, &row);
    PROOF_REACHABLE(status == 0 && src_size == 0, "empty frame");
    PROOF_REACHABLE(status == 0 && src_size > CRUSHLZ4_BLOCK_SIZE, "multiple blocks");
    PROOF_REACHABLE(status == 0 && row.mode == CRUSHLZ4_MODE_FAST, "fast mode");
    PROOF_REACHABLE(status == 0 && row.mode == CRUSHLZ4_MODE_HC, "HC mode");
    PROOF_REACHABLE(status == 0 && scratch != NULL, "caller scratch");
    PROOF_REACHABLE(status == CLZ4_NOMEM, "internal allocation failure");
    PROOF_REACHABLE(status == CLZ4_RANGE, "destination exhausted");
    PROOF_REACHABLE(status == CLZ4_INVAL, "short caller scratch");
}
