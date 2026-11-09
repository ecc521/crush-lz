/*
 * Proof: zbm_copy_fwd in crates/lzbitmap/csrc/libzbitmap.c meets its
 * contract: given a source that does not overlap the destination (before
 * it, after it or in another buffer), it reads only s[0, n), writes only
 * d[0, n), and hands memcpy (zbm_cpy8/16/32) no overlapping ranges.
 */
#include "proof.h"
#include "libzbitmap.c"

size_t nondet_size(void);
uint32_t nondet_u32(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t n = nondet_size();
    __CPROVER_assume(n > 0 && n <= PROOF_MAX_OBJECT);
    uint8_t *buf = malloc(n);
    __CPROVER_assume(buf != NULL);
    size_t dpos = nondet_size(), spos = nondet_size();
    __CPROVER_assume(dpos <= n && spos <= n);

    uint8_t *d = buf + dpos;
    const uint8_t *s = buf + spos;
    if (nondet_bool()) {
        size_t m = nondet_size();
        __CPROVER_assume(m > 0 && m <= PROOF_MAX_OBJECT);
        uint8_t *other = malloc(m);
        __CPROVER_assume(other != NULL);
        s = other;
    }
    uint32_t len = nondet_u32();
    zbm_copy_fwd(d, s, len);

    PROOF_REACHABLE(len > 64 && len % 32 != 0, "long copy with a tail");
    PROOF_REACHABLE(len >= 32 && len <= 64, "32..64 bytes");
    PROOF_REACHABLE(len >= 16 && len < 32, "16..31 bytes");
    PROOF_REACHABLE(len >= 8 && len < 16, "8..15 bytes");
    PROOF_REACHABLE(len > 0 && len < 8, "1..7 bytes");
    PROOF_REACHABLE(len > 64 && s + len == d, "source flush against dest");
    PROOF_REACHABLE(len > 64 && d + len == s, "dest flush against source");
    PROOF_REACHABLE(len == CRUSHLZBITMAP_CHUNK_SIZE, "a whole chunk");
}
