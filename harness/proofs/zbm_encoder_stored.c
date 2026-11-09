#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

void harness(void)
{
    struct zbm_compress_state *st = malloc(sizeof(*st));
    __CPROVER_assume(st != NULL);
    size_t sn, dn;
    uint8_t *src = zbm_any_buffer(&sn), *dst = zbm_any_buffer(&dn);
    uint32_t len = nondet_u32(), read = nondet_u32(), written = nondet_u32();
    __CPROVER_assume(len <= CRUSHLZBITMAP_CHUNK_SIZE && read <= len);
    __CPROVER_assume(written >= sizeof(struct zbm_chunk_hdr) && written <= len + sizeof(struct zbm_chunk_hdr));
    size_t so = nondet_size(), d = nondet_size();
    __CPROVER_assume(len <= sn && so <= sn - len);
    __CPROVER_assume(len + sizeof(struct zbm_chunk_hdr) <= dn && d <= dn - len - sizeof(struct zbm_chunk_hdr));
    st->src = src + so + read;
    st->dest = dst + d + written;
    st->decmp_len = len;
    st->read = read;
    st->written = written;
    int rc = zbm_build_uncompressed_chunk(st);
    PROOF_REACHABLE(rc == 0 && len == 0, "empty terminator body");
    PROOF_REACHABLE(rc == 0 && len == CRUSHLZBITMAP_CHUNK_SIZE, "maximum stored chunk");
    PROOF_REACHABLE(rc == 0 && read > 0 && written > sizeof(struct zbm_chunk_hdr), "undo partial compressed attempt");
    PROOF_REACHABLE(rc == 0 && len == 1, "one-byte stored chunk");
}
