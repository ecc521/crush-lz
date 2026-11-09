/*
 * Proof: crushlz4_decode_buffer, the LZ4 decoder's public entry point, is
 * memory safe and terminates for every input.
 *
 * This is the end-to-end proof. Its assumptions are the only ones the LZ4
 * decoder proofs trust, and they are the API contract in crushlz4.h:
 *   - src is NULL, or readable for src_size bytes;
 *   - dst is NULL, or writable for dst_size bytes;
 *   - out_len is NULL, or writable.
 *   - src and dst are distinct objects (no in-place decoding); decode_block's
 *     contract states this and the call site checks it.
 * The bytes of src are unconstrained, and so are both sizes (dst_size may be
 * SIZE_MAX with a NULL dst, the documented "no cap" probe).
 *
 * decode_block is replaced by its contract, proved in lz4_decode_block.c,
 * which in turn relies on copy_match's, proved in lz4_copy_match.c. Each
 * replacement checks the callee's requires clauses at the call site, so the
 * three proofs together cover the whole decoder with no gap between them.
 *
 * Beyond safety it checks that *out_len never exceeds dst_size and that the
 * return value is one of the three the header documents.
 */
#include "proof.h"
#include "crushlz4.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    const uint8_t *src = NULL;
    size_t src_size = nondet_size();
    if (nondet_bool()) {
        size_t n = nondet_size(), o = nondet_size();
        __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT && o <= n);
        uint8_t *buf = malloc(n);
        __CPROVER_assume(buf != NULL);
        __CPROVER_assume(src_size <= n - o);
        src = buf + o;
    }

    uint8_t *dst = NULL;
    size_t dst_size = nondet_size();
    if (nondet_bool()) {
        size_t n = nondet_size(), o = nondet_size();
        __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT && o <= n);
        uint8_t *buf = malloc(n);
        __CPROVER_assume(buf != NULL);
        __CPROVER_assume(dst_size <= n - o);
        dst = buf + o;
    }

    size_t out = nondet_size();
    size_t *out_len = nondet_bool() ? &out : NULL;

    int rc = crushlz4_decode_buffer(dst, dst_size, src, src_size, out_len);

    __CPROVER_assert(rc == 0 || rc == CRUSHLZ4_INVALID ||
                     rc == CRUSHLZ4_OUTPUT_TOO_SMALL, "documented status");
    if (out_len)
        __CPROVER_assert(out <= dst_size, "*out_len <= dst_size");

    PROOF_REACHABLE(rc == 0 && dst != NULL && out > 0,
                    "stream decoded into dst");
    PROOF_REACHABLE(rc == 0 && dst == NULL && dst_size == SIZE_MAX &&
                    out > 0, "uncapped size probe");
    PROOF_REACHABLE(rc == CRUSHLZ4_OUTPUT_TOO_SMALL && dst != NULL && out > 0,
                    "dst too small after a complete block");
    PROOF_REACHABLE(rc == CRUSHLZ4_INVALID && src != NULL, "malformed stream");
    PROOF_REACHABLE(rc == 0 && out > ((size_t)1 << 40),
                    "output longer than 2^40");
}
