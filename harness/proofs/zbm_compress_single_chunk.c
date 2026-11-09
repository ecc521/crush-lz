#include "proof.h"
#include "libzbitmap.c"
#include "zbm_state.h"

int nondet_int(void);
uint32_t nondet_u32(void);
size_t nondet_size(void);
_Bool nondet_bool(void);

static int mock_builder_behavior;
static uint32_t mock_builder_written;
static uint32_t mock_builder_read;

static int mock_build_chunk(struct zbm_compress_state *state)
{
    __CPROVER_assert(state != NULL, "builder receives valid state");
    __CPROVER_assert(state->written == sizeof(struct zbm_chunk_hdr), "chunk header space reserved");
    __CPROVER_assert(state->read == 0, "builder starts at offset 0");
    __CPROVER_assert(state->dest_end == state->dest - sizeof(struct zbm_chunk_hdr) + state->decmp_len + sizeof(struct zbm_chunk_hdr), "destination end properly bounded");

    if (mock_builder_behavior == 0) {
        /* Success: compressed size strictly less than max_chunk_sz */
        state->read = state->decmp_len;
        state->written = mock_builder_written;
        state->dest += mock_builder_written - sizeof(struct zbm_chunk_hdr);
        state->src += state->read;
        return 0;
    } else if (mock_builder_behavior == 1) {
        /* Success but ties or exceeds max_chunk_sz */
        state->read = state->decmp_len;
        state->written = mock_builder_written;
        state->dest += mock_builder_written - sizeof(struct zbm_chunk_hdr);
        state->src += state->read;
        return 0;
    } else if (mock_builder_behavior == 2) {
        /* Fallback: returns ZBM_CANT_COMPRESS, having made partial attempt */
        state->read = mock_builder_read;
        state->written = mock_builder_written;
        state->dest += mock_builder_written - sizeof(struct zbm_chunk_hdr);
        state->src += state->read;
        return ZBM_CANT_COMPRESS;
    } else {
        /* Other builder failure (e.g. ZBM_NOMEM or internal error) */
        return ZBM_NOMEM;
    }
}

void harness(void)
{
    struct zbm_compress_state *state = malloc(sizeof(*state));
    __CPROVER_assume(state != NULL);

    size_t sn, dn;
    uint8_t *src = zbm_any_buffer(&sn);
    uint8_t *dst = zbm_any_buffer(&dn);
    __CPROVER_assume(!__CPROVER_same_object(src, dst));
    __CPROVER_assume(!__CPROVER_same_object(state, src));
    __CPROVER_assume(!__CPROVER_same_object(state, dst));

    size_t src_left = nondet_size();
    size_t dest_left = nondet_size();
    __CPROVER_assume(src_left <= sn && dest_left <= dn);

    state->src = src;
    state->src_left = src_left;
    state->dest = dst;
    state->dest_left = dest_left;
    state->read = nondet_u32();
    state->written = nondet_u32();
    state->decmp_len = nondet_u32();

    uint32_t expected_decmp_len = MIN(src_left, (size_t)CRUSHLZBITMAP_CHUNK_SIZE);
    __CPROVER_assume(sn >= expected_decmp_len);

    mock_builder_behavior = nondet_int();
    __CPROVER_assume(mock_builder_behavior >= 0 && mock_builder_behavior <= 3);

    uint32_t max_chunk_sz = expected_decmp_len + sizeof(struct zbm_chunk_hdr);

    if (mock_builder_behavior == 0) {
        mock_builder_written = nondet_u32();
        __CPROVER_assume(mock_builder_written >= sizeof(struct zbm_chunk_hdr) &&
                         mock_builder_written < max_chunk_sz);
    } else if (mock_builder_behavior == 1) {
        mock_builder_written = max_chunk_sz + 1;
        __CPROVER_assume(dest_left > max_chunk_sz);
    } else if (mock_builder_behavior == 2) {
        mock_builder_read = nondet_u32();
        __CPROVER_assume(mock_builder_read <= expected_decmp_len);
        mock_builder_written = nondet_u32();
        __CPROVER_assume(mock_builder_written >= sizeof(struct zbm_chunk_hdr) &&
                         mock_builder_written <= max_chunk_sz);
    }

    uint8_t *entry_dest = state->dest;
    const uint8_t *entry_src = state->src;
    size_t entry_src_left = state->src_left;
    size_t entry_dest_left = state->dest_left;

    int rc = zbm_compress_single_chunk(state, mock_build_chunk);

    if (rc == 0) {
        __CPROVER_assert(state->decmp_len == expected_decmp_len, "decmp_len matches expectation");
        __CPROVER_assert(state->read == expected_decmp_len, "read matches decmp_len");
        __CPROVER_assert(state->written >= sizeof(struct zbm_chunk_hdr), "written at least header size");
        __CPROVER_assert(state->written <= max_chunk_sz, "written does not exceed max_chunk_sz");
        __CPROVER_assert(state->dest == entry_dest + state->written, "dest pointer advanced by written");
        __CPROVER_assert(state->src == entry_src + state->read, "src pointer advanced by read");

        struct zbm_chunk_hdr *hdr = (struct zbm_chunk_hdr *)entry_dest;
        uint32_t hdr_len = zbm_u24_to_u32(hdr->len);
        uint32_t hdr_decmp_len = zbm_u24_to_u32(hdr->decmp_len);
        __CPROVER_assert(hdr_len == state->written, "header len matches written");
        __CPROVER_assert(hdr_decmp_len == state->decmp_len, "header decmp_len matches decmp_len");
    } else if (rc == ZBM_RANGE) {
        __CPROVER_assert(max_chunk_sz > entry_dest_left, "RANGE returned only when destination is too small");
    } else {
        __CPROVER_assert(mock_builder_behavior == 3, "other error only from builder failure");
    }

    PROOF_REACHABLE(rc == 0 && mock_builder_behavior == 0, "compressed chunk success");
    PROOF_REACHABLE(rc == 0 && mock_builder_behavior == 1, "tie forced uncompressed fallback");
    PROOF_REACHABLE(rc == 0 && mock_builder_behavior == 2, "explicit CANT_COMPRESS fallback");
    PROOF_REACHABLE(rc == 0 && expected_decmp_len == 0, "terminator chunk 0 bytes");
    PROOF_REACHABLE(rc == 0 && expected_decmp_len == CRUSHLZBITMAP_CHUNK_SIZE, "full chunk 32 KiB");
    PROOF_REACHABLE(rc == ZBM_RANGE, "destination too small returns RANGE");
    PROOF_REACHABLE(rc == ZBM_NOMEM, "builder error propagated");
}
