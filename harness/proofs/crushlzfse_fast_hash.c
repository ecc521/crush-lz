/*
 * Proof: crushlzfse_fast_hash in crates/crushlzfse/csrc/fast_match.h.
 */
#include "proof.h"
#include "lzfse_internal.h"
#include "fast_match.h"

uint64_t nondet_uint64(void);
int nondet_int(void);

void harness(void)
{
    uint64_t v = nondet_uint64();
    int min_match = nondet_int();
    int hash_bits = nondet_int();
    uint64_t prime = CRUSHLZFSE_FAST_PRIME;

    __CPROVER_assume(min_match >= CRUSHLZFSE_FAST_MIN_MIN_MATCH &&
                     min_match <= CRUSHLZFSE_FAST_MAX_MIN_MATCH);
    __CPROVER_assume(hash_bits >= CRUSHLZFSE_FAST_MIN_HASH_BITS &&
                     hash_bits <= CRUSHLZFSE_FAST_MAX_HASH_BITS);

    uint32_t h = crushlzfse_fast_hash(v, min_match, hash_bits, prime);

    __CPROVER_assert(h < (1u << hash_bits), "hash result within bounds");

    PROOF_REACHABLE(min_match == 4, "reach min_match 4");
    PROOF_REACHABLE(min_match > 4, "reach min_match > 4");
}
