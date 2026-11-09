/*
 * Proof: write_uncompressed_block in crates/crushlzfse/csrc/crushlzfse.c.
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

#include "crushlzfse.c"

size_t nondet_size(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t sn = nondet_size();
    __CPROVER_assume(sn <= (size_t)LZFSE_ZOPT_BLOCK_SIZE);
    uint8_t *sbuf = malloc(sn);
    __CPROVER_assume(sbuf != NULL);

    size_t dn = nondet_size();
    __CPROVER_assume(dn <= (size_t)LZFSE_ZOPT_BLOCK_SIZE + 12);
    uint8_t *dbuf = malloc(dn);
    __CPROVER_assume(dbuf != NULL);
    __CPROVER_assume(!__CPROVER_same_object(sbuf, dbuf));

    size_t written = write_uncompressed_block(dbuf, dn, sbuf, sn);

    if (sn + 12 > dn) {
        __CPROVER_assert(written == 0, "fails when dst too small");
    } else {
        __CPROVER_assert(written == sn + 12, "writes exactly sn + 12 bytes");
        __CPROVER_assert(written <= dn, "written within dst bounds");
    }

    PROOF_REACHABLE(sn + 12 > dn, "insufficient dst");
    PROOF_REACHABLE(sn + 12 <= dn, "successful write");
    PROOF_REACHABLE(sn == 0 && dn >= 12, "empty input write");
    PROOF_REACHABLE(sn == (size_t)LZFSE_ZOPT_BLOCK_SIZE && dn == sn + 12,
                    "maximum single-block raw write");
}
