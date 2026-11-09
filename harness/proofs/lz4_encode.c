/* Our complete encoder wrapper, with upstream LZ4 as an explicit dependency.
 * All lengths and bytes are symbolic; the loop contracts impose no block
 * count limit. Caller scratch may be unaligned and contain arbitrary bytes. */
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
    size_t sn = nondet_size(), so = nondet_size();
    __CPROVER_assume(sn > 0 && sn <= PROOF_MAX_OBJECT && so <= sn);
    uint8_t *sbuf = malloc(sn);
    __CPROVER_assume(sbuf != NULL);
    size_t src_size = nondet_size();
    __CPROVER_assume(src_size <= sn - so);
    const uint8_t *src = nondet_bool() ? sbuf + so : NULL;

    size_t dn = nondet_size(), dof = nondet_size();
    __CPROVER_assume(dn > 0 && dn <= PROOF_MAX_OBJECT && dof <= dn);
    uint8_t *dbuf = malloc(dn);
    __CPROVER_assume(dbuf != NULL);
    size_t dst_size = nondet_size();
    __CPROVER_assume(dst_size <= dn - dof);
    uint8_t *dst = nondet_bool() ? dbuf + dof : NULL;

    crushlz4_encode_params params;
    params.mode = nondet_int();
    params.acceleration = nondet_int();
    params.hc_level = nondet_int();
    _Bool advanced = nondet_bool();
    int level = nondet_int();
    size_t scratch_size = nondet_size();
    __CPROVER_assume(scratch_size <= PROOF_MAX_OBJECT - CLZ4_SCRATCH_ALIGN);
    uint8_t *scratch_buf = NULL;
    void *scratch = NULL;
    if (nondet_bool()) {
        scratch_buf = malloc(scratch_size + CLZ4_SCRATCH_ALIGN);
        __CPROVER_assume(scratch_buf != NULL);
        size_t offset = nondet_size();
        __CPROVER_assume(offset < CLZ4_SCRATCH_ALIGN);
        scratch = scratch_buf + offset;
    }

    size_t out = advanced
        ? crushlz4_encode_buffer_advanced(dst, dst_size, src, src_size,
                                          scratch, scratch_size, &params)
        : crushlz4_encode_buffer(dst, dst_size, src, src_size,
                                 scratch, scratch_size, level);
    __CPROVER_assert(out <= dst_size, "encoded length within destination");
    PROOF_REACHABLE(out > 0 && src_size == 0, "empty stream");
    PROOF_REACHABLE(out > 0 && src_size > CRUSHLZ4_BLOCK_SIZE, "multiple blocks");
    PROOF_REACHABLE(out > 0 && scratch != NULL, "caller scratch");
    PROOF_REACHABLE(out > 0 && scratch == NULL, "internal scratch");
    PROOF_REACHABLE(out > 0 && advanced && params.mode == CRUSHLZ4_MODE_HC, "HC mode");
    PROOF_REACHABLE(out > 0 && advanced && params.mode == CRUSHLZ4_MODE_FAST, "fast mode");
    PROOF_REACHABLE(out == 0 && dst == NULL, "null destination");
    PROOF_REACHABLE(out == 0 && src != NULL && dst != NULL && dst_size == 0,
                    "insufficient destination");
    free(scratch_buf);
}
