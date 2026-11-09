/* Public parameter and size queries over their full scalar input domains. */
#include "proof.h"
#include "crushlz4.c"

size_t nondet_size(void);
int nondet_int(void);
_Bool nondet_bool(void);

void harness(void)
{
    size_t size = nondet_size();
    size_t bound = crushlz4_encode_bound(size);
    if (size <= PROOF_MAX_OBJECT) {
        size_t blocks = size / CRUSHLZ4_BLOCK_SIZE + (size % CRUSHLZ4_BLOCK_SIZE != 0);
        __CPROVER_assert(bound >= size + 4, "bound covers source and terminator");
        __CPROVER_assert(bound - size - 4 == 8 * blocks, "eight bytes per actual block");
    }

    crushlz4_encode_params params;
    int requested = nondet_int();
    int actual = crushlz4_params_for_level(requested, &params);
    __CPROVER_assert(actual >= CRUSHLZ4_LEVEL_MIN && actual <= CRUSHLZ4_LEVEL_MAX,
                      "reported level in supported domain");
    __CPROVER_assert(clz4_validate_params(&params) == 0, "every preset is valid");
    __CPROVER_assert(crushlz4_scratch_size(&params) >= CLZ4_SCRATCH_ALIGN,
                      "preset scratch contains alignment allowance");
    __CPROVER_assert(crushlz4_params_for_level(requested, NULL) == CRUSHLZ4_LEVEL_INVALID,
                      "null parameter output rejected");
    __CPROVER_assert(crushlz4_scratch_size(NULL) == 0, "null scratch parameters rejected");

    params.mode = nondet_int();
    params.acceleration = nondet_int();
    params.hc_level = nondet_int();
    size_t scratch = crushlz4_scratch_size(&params);
    if (scratch != 0) {
        __CPROVER_assert(params.mode == CRUSHLZ4_MODE_FAST || params.mode == CRUSHLZ4_MODE_HC,
                          "accepted mode");
        if (params.mode == CRUSHLZ4_MODE_FAST) {
            __CPROVER_assert(params.acceleration >= 1 && params.acceleration <= CLZ4_ACCEL_MAX,
                              "accepted acceleration");
            __CPROVER_assert(scratch >= sizeof(LZ4_stream_t) + CLZ4_SCRATCH_ALIGN - 1,
                              "fast scratch extent");
        } else {
            __CPROVER_assert(params.hc_level >= 1 && params.hc_level <= LZ4HC_CLEVEL_MAX,
                              "accepted HC level");
            __CPROVER_assert(scratch >= sizeof(LZ4_streamHC_t) + CLZ4_SCRATCH_ALIGN - 1,
                              "HC scratch extent");
        }
    }
    PROOF_REACHABLE(size == 0 && bound == 4, "empty bound");
    PROOF_REACHABLE(size == PROOF_MAX_OBJECT, "maximum modeled source");
    PROOF_REACHABLE(actual == CRUSHLZ4_LEVEL_MIN && requested < actual, "low level clamping");
    PROOF_REACHABLE(actual == CRUSHLZ4_LEVEL_MAX && requested > actual, "high level clamping");
    PROOF_REACHABLE(scratch != 0 && params.mode == CRUSHLZ4_MODE_FAST, "fast parameters");
    PROOF_REACHABLE(scratch != 0 && params.mode == CRUSHLZ4_MODE_HC, "HC parameters");
    PROOF_REACHABLE(scratch == 0, "invalid parameters");
}
