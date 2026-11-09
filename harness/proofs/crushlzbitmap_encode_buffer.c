#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

size_t nondet_size(void);
uint32_t nondet_u32(void);
int nondet_int(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t sn, dn;
    uint8_t *src_buf = zbm_any_buffer(&sn);
    uint8_t *dst_buf = zbm_any_buffer(&dn);
    __CPROVER_assume(!__CPROVER_same_object(src_buf, dst_buf));

    void *dst = dst_buf;
    size_t dst_size = dn;

    size_t src_size = nondet_size();
    __CPROVER_assume(src_size <= sn);
    const void *src = src_buf;

    _Bool test_error = nondet_bool();
    crushlzbitmap_params params_val;
    const crushlzbitmap_params *params = NULL;
    _Bool supply_scratch = nondet_bool();
    void *scratch = NULL;
    size_t scratch_size = 0;

    if (test_error) {
        int err_type = nondet_int();
        if (err_type == 0) {
            /* Null destination */
            dst = NULL;
            dst_size = 0;
            size_t out = crushlzbitmap_encode_buffer_advanced(dst, dst_size, src, src_size, NULL, 0, NULL);
            __CPROVER_assert(out == 0, "null destination rejected");
            PROOF_REACHABLE(test_error && err_type == 0, "error null destination");
            return;
        } else if (err_type == 1) {
            /* Invalid params */
            crushlzbitmap_params_for_level(0, &params_val);
            params_val.p.row.hash_bits = 4; /* invalid < 8 */
            params = &params_val;
            size_t out = crushlzbitmap_encode_buffer_advanced(dst, dst_size, src, src_size, NULL, 0, params);
            __CPROVER_assert(out == 0, "invalid params rejected");
            PROOF_REACHABLE(test_error && err_type == 1, "error invalid params");
            return;
        } else if (err_type == 2) {
            /* Oversized source */
            size_t oversized = (size_t)CRUSHLZBITMAP_MAX_SRC_SIZE + 1;
            size_t out = crushlzbitmap_encode_buffer_advanced(dst, dst_size, src, oversized, NULL, 0, NULL);
            __CPROVER_assert(out == 0, "oversized source rejected");
            PROOF_REACHABLE(test_error && err_type == 2, "error oversized source");
            return;
        } else {
            /* Insufficient scratch */
            crushlzbitmap_params_for_level(0, &params_val);
            params = &params_val;
            size_t req = crushlzbitmap_scratch_size(params);
            scratch = malloc(16);
            __CPROVER_assume(scratch != NULL);
            __CPROVER_assume(!__CPROVER_same_object(scratch, src_buf) && !__CPROVER_same_object(scratch, dst_buf));
            scratch_size = (req > 0) ? (req - 1) : 0;
            size_t out = crushlzbitmap_encode_buffer_advanced(dst, dst_size, src, src_size, scratch, scratch_size, params);
            __CPROVER_assert(out == 0, "insufficient scratch rejected");
            PROOF_REACHABLE(test_error && err_type != 0 && err_type != 1 && err_type != 2, "error insufficient scratch");
            free(scratch);
            return;
        }
    }

    /* Valid encoding path */
    _Bool test_simple_api = nondet_bool();
    int level = nondet_int();

    if (!test_simple_api) {
        _Bool use_default = nondet_bool();
        if (!use_default) {
            __CPROVER_assume(level >= CRUSHLZBITMAP_LEVEL_MIN && level <= CRUSHLZBITMAP_LEVEL_MAX);
            crushlzbitmap_params_for_level(level, &params_val);
            params = &params_val;
        }
    }

    if (supply_scratch) {
        crushlzbitmap_params dflt_params;
        const crushlzbitmap_params *p = params;
        if (!p) {
            crushlzbitmap_params_for_level(test_simple_api ? level : CRUSHLZBITMAP_LEVEL_DEFAULT, &dflt_params);
            p = &dflt_params;
        }
        size_t req = crushlzbitmap_scratch_size(p);
        scratch = malloc(req);
        __CPROVER_assume(scratch != NULL);
        __CPROVER_assume(!__CPROVER_same_object(scratch, src_buf) && !__CPROVER_same_object(scratch, dst_buf));
        scratch_size = req;
    }

    size_t out;
    if (test_simple_api) {
        out = crushlzbitmap_encode_buffer(dst, dst_size, src, src_size,
                                          scratch, scratch_size, level);
    } else {
        out = crushlzbitmap_encode_buffer_advanced(dst, dst_size, src, src_size,
                                                   scratch, scratch_size, params);
    }

    if (out > 0) {
        __CPROVER_assert(out <= dst_size, "out never exceeds dst_size");
        __CPROVER_assert(out >= 4 + sizeof(struct zbm_chunk_hdr), "out includes magic and terminator chunk");
    }

    /* Reachability witnesses for valid execution */
    PROOF_REACHABLE(!test_error && test_simple_api && out > 0, "simple api success");
    PROOF_REACHABLE(!test_error && !test_simple_api && out > 0, "advanced api success");
    PROOF_REACHABLE(!test_error && out > 0 && src_size == 0, "empty input success");
    PROOF_REACHABLE(!test_error && out > 0 && src_size > 0 && src_size <= CRUSHLZBITMAP_CHUNK_SIZE, "single chunk input success");
    PROOF_REACHABLE(!test_error && supply_scratch && out > 0, "caller scratch success");
    PROOF_REACHABLE(!test_error && !supply_scratch && out > 0, "internal scratch success");
    PROOF_REACHABLE(!test_error && !supply_scratch && out == 0, "internal scratch allocation failure");
    PROOF_REACHABLE(!test_error && out == 0 && dst_size < 4 + sizeof(struct zbm_chunk_hdr), "destination too small returns 0");

    if (scratch)
        free(scratch);
}
