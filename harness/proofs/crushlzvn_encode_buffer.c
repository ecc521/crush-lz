/*
 * Proof: crushlzvn_encode_buffer_advanced and crushlzvn_encode_buffer
 * in crates/crushlzfse/csrc/crushlzvn.c.
 */
#include "proof.h"

void *proof_memset(void *s, int c, size_t n)
__CPROVER_requires(__CPROVER_w_ok(s, n))
__CPROVER_assigns()
__CPROVER_ensures(__CPROVER_return_value == s);

#define memset(s, c, n) proof_memset(s, c, n)

#include "crushlzvn.c"

size_t nondet_size(void);
int nondet_int(void);
_Bool nondet_bool(void);

void harness(void)
{
    /* Bounded source buffer */
    size_t sn = nondet_size();
    __CPROVER_assume(sn >= 16 && sn <= 256);
    uint8_t *sbuf = malloc(sn);
    __CPROVER_assume(sbuf != NULL);

    /* Bounded destination buffer */
    size_t dn = nondet_size();
    __CPROVER_assume(dn >= 16 && dn <= 256);
    uint8_t *dbuf = malloc(dn);
    __CPROVER_assume(dbuf != NULL);
    __CPROVER_assume(!__CPROVER_same_object(sbuf, dbuf));

    _Bool test_error = nondet_bool();
    if (test_error) {
        int err_type = nondet_int();
        crushlzvn_encode_params params;
        memset(&params, 0, sizeof(params));
        params.strategy = CRUSHLZVN_STRATEGY_GREEDY;
        params.p.greedy.hash_bits = 10;
        params.p.greedy.hash_width = 1;

        if (err_type == 0) {
            crushlzvn_encode_params inv;
            memset(&inv, 0, sizeof(inv));
            inv.strategy = CRUSHLZVN_STRATEGY_GREEDY;
            inv.p.greedy.hash_bits = 4; /* invalid < 10 */
            size_t out = crushlzvn_encode_buffer_advanced(dbuf, dn, sbuf, sn, NULL, 0, &inv);
            __CPROVER_assert(out == 0, "invalid params rejected");
            PROOF_REACHABLE(test_error && err_type == 0, "error invalid params");
        } else if (err_type == 1) {
            size_t big_sn = (size_t)LZVN_ZOPT_BLOCK_SIZE + 1;
            uint8_t *big_src = malloc(big_sn);
            __CPROVER_assume(big_src != NULL);
            size_t out = crushlzvn_encode_buffer_advanced(dbuf, dn, big_src, big_sn, NULL, 0, &params);
            __CPROVER_assert(out == 0, "oversized input rejected");
            PROOF_REACHABLE(test_error && err_type == 1, "error oversized input");
            free(big_src);
        } else if (err_type == 2) {
            size_t req = crushlzvn_scratch_size(&params);
            void *small_scratch = malloc(req);
            __CPROVER_assume(small_scratch != NULL);
            size_t out = crushlzvn_encode_buffer_advanced(dbuf, dn, sbuf, sn, small_scratch, req - 1, &params);
            __CPROVER_assert(out == 0, "insufficient scratch rejected");
            PROOF_REACHABLE(test_error && err_type == 2, "error insufficient scratch");
            free(small_scratch);
        } else if (err_type == 3) {
            size_t out = crushlzvn_encode_buffer_advanced(dbuf, dn, NULL, 0, NULL, 0, &params);
            __CPROVER_assert(out == 0, "null empty source rejected safely");
            PROOF_REACHABLE(test_error && err_type == 3, "null empty source");
        } else {
            size_t out = crushlzvn_encode_buffer_advanced(NULL, 0, sbuf, sn, NULL, 0, &params);
            __CPROVER_assert(out == 0, "null empty destination rejected safely");
            PROOF_REACHABLE(test_error && err_type != 0 && err_type != 1 && err_type != 2 && err_type != 3,
                            "null empty destination");
        }
    } else {
        _Bool test_level_api = nondet_bool();
        if (test_level_api) {
            /* Public level-based API */
            size_t out = crushlzvn_encode_buffer(dbuf, dn, sbuf, sn, NULL, 0, CRUSHLZVN_LEVEL_DEFAULT);
            __CPROVER_assert(out <= dn, "out <= dst_size");
            PROOF_REACHABLE(!test_error && test_level_api, "level-based encode");
        } else {
            /* Advanced parameter API */
            crushlzvn_encode_params params;
            memset(&params, 0, sizeof(params));
            params.strategy = CRUSHLZVN_STRATEGY_GREEDY;
            params.p.greedy.hash_bits = 10;
            params.p.greedy.hash_width = 1;

            size_t req_scratch = crushlzvn_scratch_size(&params);
            __CPROVER_assert(req_scratch > 0, "scratch size positive");

            _Bool user_scratch = nondet_bool();
            _Bool adjacent_scratch = nondet_bool();
            void *scratch = NULL;
            uint8_t *encode_dst = dbuf;
            size_t scratch_size = 0;
            if (user_scratch) {
                scratch_size = req_scratch;
                if (adjacent_scratch)
                    __CPROVER_assume(scratch_size <= SIZE_MAX - dn);
                /* The LZFSE fallback puts scratch and output in adjacent
                 * ranges of one allocation. Exercise that valid geometry as
                 * well as independently allocated caller scratch. */
                scratch = malloc(scratch_size + (adjacent_scratch ? dn : 0));
                __CPROVER_assume(scratch != NULL);
                if (adjacent_scratch) {
                    encode_dst = (uint8_t *)scratch + scratch_size;
                    __CPROVER_assert(__CPROVER_same_object(scratch, encode_dst),
                                     "adjacent scratch and output share an allocation");
                    __CPROVER_assert(CRUSHLZVN_PROOF_RANGES_DISJOINT(
                                         scratch, scratch_size, encode_dst, dn),
                                     "adjacent scratch and output ranges do not overlap");
                }
            }

            size_t out = crushlzvn_encode_buffer_advanced(encode_dst, dn, sbuf, sn, scratch, scratch_size, &params);
            __CPROVER_assert(out <= dn, "out <= dst_size");

            PROOF_REACHABLE(!test_error && !test_level_api && out > 0, "advanced successful encode");
            PROOF_REACHABLE(!test_error && !test_level_api && user_scratch, "user provided scratch");
            PROOF_REACHABLE(!test_error && !test_level_api && !user_scratch, "internal scratch allocation");
            PROOF_REACHABLE(!test_error && !test_level_api && user_scratch && adjacent_scratch,
                            "adjacent scratch and output");

            if (scratch)
                free(scratch);
        }
    }
}
