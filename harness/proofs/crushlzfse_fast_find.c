/*
 * Memory safety and result geometry for the shared fast match finder used by
 * LZVN. A zeroed table is the caller's initial state; the finder itself may
 * overwrite entries at ip and ip + 1, including hash collisions.
 */
#include "proof.h"
#include "lzfse_internal.h"
#include "fast_match.h"

int nondet_int(void);
_Bool nondet_bool(void);
uint32_t nondet_uint32(void);

void harness(void)
{
    enum { SRC_CAP = 32, HASH_BITS = 10, TABLE_ENTRIES = 1 << HASH_BITS };
    uint8_t *src = malloc(SRC_CAP);
    uint16_t *table = calloc(TABLE_ENTRIES, sizeof(*table));
    uint16_t *ltable = calloc(TABLE_ENTRIES, sizeof(*ltable));
    __CPROVER_assume(src != NULL && table != NULL && ltable != NULL);

    lzfse_offset src_end = nondet_int();
    lzfse_offset ip = nondet_int();
    lzfse_offset anchor = nondet_int();
    __CPROVER_assume(src_end >= 18 && src_end <= SRC_CAP);
    lzfse_offset ilimit = src_end - 16;
    __CPROVER_assume(1 <= ip && ip < ilimit);
    __CPROVER_assume(0 <= anchor && anchor <= ip);

    uint32_t rep = nondet_uint32();
    __CPROVER_assume(rep <= (uint32_t)ip);
    int min_match = nondet_int();
    int long_table = nondet_bool();
    int lazy = nondet_bool();
    __CPROVER_assume(4 <= min_match && min_match <=
                     (long_table || lazy ? 6 : 8));

    lzfse_offset mpos = -1, mref = -1;
    uint32_t len = crushlzfse_fast_find(src, src_end, ilimit, ip, anchor,
                                         rep, min_match, HASH_BITS,
                                         CRUSHLZFSE_FAST_PRIME, table,
                                         ltable, long_table, lazy,
                                         &mpos, &mref);
    if (len != 0) {
        __CPROVER_assert(anchor <= mpos && mpos <= ilimit,
                         "match begins in probed source span");
        __CPROVER_assert(0 <= mref && mref < mpos,
                         "match reference precedes match");
        __CPROVER_assert(len >= 4 && len <= (uint32_t)(src_end - mpos - 8),
                         "match length preserves eight-byte margin");
        __CPROVER_assert((uint32_t)(mpos - mref) <= 65535,
                         "distance fits LZVN encoding");
    }

    PROOF_REACHABLE(len == 0, "no match");
    PROOF_REACHABLE(len != 0 && long_table && lazy, "lazy long match");
    PROOF_REACHABLE(len != 0 && long_table && !lazy, "long match");
    PROOF_REACHABLE(len != 0 && !long_table && lazy, "lazy short match");
    PROOF_REACHABLE(len != 0 && !long_table && !lazy, "short match");
}
