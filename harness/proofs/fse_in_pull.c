/* Exact production bit pulls. No clamping or modeled return values. */
#include "proof.h"
#include "lzfse_fse.h"

int32_t nondet_i32(void);
uint64_t nondet_u64(void);
uint32_t nondet_u32(void);

void harness(void)
{
    int32_t count = nondet_i32();
#ifdef PROOF_PULL32
    fse_in_stream32 stream;
    stream.accum = nondet_u32();
    stream.accum_nbits = nondet_i32();
    (void)fse_in_pull32(&stream, count);
    PROOF_REACHABLE(count == 31, "maximum pull");
#else
    fse_in_stream64 stream;
    stream.accum = nondet_u64();
    stream.accum_nbits = nondet_i32();
    (void)fse_in_pull64(&stream, count);
    PROOF_REACHABLE(count == 63, "maximum pull");
#endif
    PROOF_REACHABLE(count == 0, "zero bits");
    PROOF_REACHABLE(count > 0 && stream.accum_nbits == 0, "all buffered bits");
    PROOF_REACHABLE(count > 0 && stream.accum_nbits > 0, "partial pull");
}
