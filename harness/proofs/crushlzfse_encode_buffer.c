/*
 * Proof: crushlzfse_encode_buffer_advanced and crushlzfse_encode_buffer
 * in crates/crushlzfse/csrc/crushlzfse.c.
 */
#include "proof.h"
#include <string.h>
#include "crushlzvn.h"

/* Both dispatch sources define these file-static names. */
#define cand_capacity_for lzvn_cand_capacity_for
#define encode_block lzvn_encode_block
#define fast_params_valid lzvn_fast_params_valid
#define optimal_params_valid lzvn_optimal_params_valid
#define LEVEL_TABLE lzvn_LEVEL_TABLE
#include "crushlzvn.c"
#undef cand_capacity_for
#undef encode_block
#undef fast_params_valid
#undef optimal_params_valid
#undef LEVEL_TABLE

void *proof_memset(void *s, int c, size_t n)
__CPROVER_requires(__CPROVER_w_ok(s, n))
__CPROVER_assigns()
__CPROVER_ensures(__CPROVER_return_value == s);

#define memset(s, c, n) proof_memset(s, c, n)

#include "crushlzfse.c"

size_t nondet_size(void);
int nondet_int(void);
_Bool nondet_bool(void);

void harness(void)
{
    /* Bounded source buffer, including empty input. */
    size_t sn = nondet_size();
    __CPROVER_assume(sn <= (size_t)LZFSE_ZOPT_BLOCK_SIZE);
    uint8_t *sbuf = malloc(sn);
    __CPROVER_assume(sbuf != NULL);

    /* Bounded destination buffer, including zero capacity. */
    size_t dn = nondet_size();
    __CPROVER_assume(dn <= (size_t)LZFSE_ZOPT_BLOCK_SIZE + 16);
    uint8_t *dbuf = malloc(dn);
    __CPROVER_assume(dbuf != NULL);
    __CPROVER_assume(!__CPROVER_same_object(sbuf, dbuf));

    _Bool test_error = nondet_bool();
    if (test_error) {
        int err_type = nondet_int();
        crushlzfse_encode_params params;
        params.strategy = CRUSHLZFSE_STRATEGY_FAST;
        params.p.fast.hash_bits = 10;
        params.p.fast.min_match = 4;
        params.p.fast.skip_shift = 1;
        params.p.fast.max_step = 1;
        params.p.fast.long_table = 0;
        params.p.fast.lazy = 0;

        if (err_type == 0) {
            crushlzfse_encode_params inv;
            inv.strategy = CRUSHLZFSE_STRATEGY_FAST;
            inv.p.fast.hash_bits = 4; /* invalid < 10 */
            inv.p.fast.min_match = 4;
            inv.p.fast.skip_shift = 1;
            inv.p.fast.max_step = 1;
            inv.p.fast.long_table = 0;
            inv.p.fast.lazy = 0;
            size_t out = crushlzfse_encode_buffer_advanced(dbuf, dn, sbuf, sn, NULL, 0, &inv);
            __CPROVER_assert(out == 0, "invalid params rejected");
            PROOF_REACHABLE(test_error && err_type == 0, "error invalid params");
        } else if (err_type == 1) {
            size_t out = crushlzfse_encode_buffer_advanced(dbuf, dn, sbuf, (size_t)LZFSE_ZOPT_BLOCK_SIZE + 1, NULL, 0, &params);
            __CPROVER_assert(out == 0, "oversized input rejected");
            PROOF_REACHABLE(test_error && err_type == 1, "error oversized input");
        } else {
            size_t req = crushlzfse_scratch_size(&params);
            uint8_t dummy[16];
            size_t out = crushlzfse_encode_buffer_advanced(dbuf, dn, sbuf, sn, dummy, req - 1, &params);
            __CPROVER_assert(out == 0, "insufficient scratch rejected");
            PROOF_REACHABLE(test_error && err_type != 0 && err_type != 1, "error insufficient scratch");
        }
    } else {
        _Bool test_level_api = nondet_bool();
        if (test_level_api) {
            /* Public level-based API with level -5 */
            size_t out = crushlzfse_encode_buffer(dbuf, dn, sbuf, sn, NULL, 0, -5);
            __CPROVER_assert(out <= dn, "out <= dst_size");
            PROOF_REACHABLE(!test_error && test_level_api, "level-based encode");
        } else {
            /* Advanced parameter API */
            crushlzfse_encode_params params;
            params.strategy = CRUSHLZFSE_STRATEGY_FAST;
            params.p.fast.hash_bits = 10;
            params.p.fast.min_match = 4;
            params.p.fast.skip_shift = 1;
            params.p.fast.max_step = 1;
            params.p.fast.long_table = 0;
            params.p.fast.lazy = 0;

            size_t req_scratch = crushlzfse_scratch_size(&params);
            __CPROVER_assert(req_scratch > 0, "scratch size positive");

            _Bool user_scratch = nondet_bool();
            void *scratch = NULL;
            size_t scratch_size = 0;
            if (user_scratch) {
                scratch_size = req_scratch;
                scratch = malloc(scratch_size);
                __CPROVER_assume(scratch != NULL);
            }

            size_t out = crushlzfse_encode_buffer_advanced(dbuf, dn, sbuf, sn, scratch, scratch_size, &params);
            __CPROVER_assert(out <= dn, "out <= dst_size");

            PROOF_REACHABLE(!test_error && !test_level_api && user_scratch, "user scratch");
            PROOF_REACHABLE(!test_error && !test_level_api && !user_scratch, "internal scratch");

            if (scratch)
                free(scratch);
        }
    }
    PROOF_REACHABLE(sn == 0 && dn == 0, "empty input and zero output capacity");
    PROOF_REACHABLE(sn == 0 && dn >= 12, "empty input with raw frame capacity");
    PROOF_REACHABLE(sn > 0 && dn == 0, "nonempty input and zero output capacity");
    PROOF_REACHABLE(sn == (size_t)LZFSE_ZOPT_BLOCK_SIZE && dn == sn + 16,
                    "maximum single-block input and bound-sized output");
}
