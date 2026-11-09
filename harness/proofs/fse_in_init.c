/* Shipping input-stream initialization, including an allocation with no
 * available bytes. A failing check must not form an out-of-object pointer. */
#include "proof.h"
#include "lzfse_fse.h"

#ifdef PROOF_INIT32
#define init_stream fse_in_stream32
#define init_function fse_in_checked_init32
#define INIT_BYTES 4
#else
#define init_stream fse_in_stream64
#define init_function fse_in_checked_init64
#define INIT_BYTES 8
#endif

int32_t nondet_i32(void);
size_t nondet_size(void);

void harness(void)
{
    size_t size = nondet_size(), begin = nondet_size(), end = nondet_size();
    __CPROVER_assume(size > 0 && size <= PROOF_MAX_OBJECT);
    __CPROVER_assume(begin <= end && end <= size);
    uint8_t *buffer = malloc(size);
    __CPROVER_assume(buffer != NULL);
    const uint8_t *cursor = buffer + end;
    init_stream stream;
    int32_t count = nondet_i32();
    int status = init_function(&stream, count, &cursor, buffer + begin);
    PROOF_REACHABLE(status == 0 && count == 0, "short initialization");
    PROOF_REACHABLE(status == 0 && count < 0, "full initialization");
    PROOF_REACHABLE(status == -1 && end == begin, "no input bytes");
    PROOF_REACHABLE(status == -1 && end - begin >= INIT_BYTES, "nonzero padding rejected");
}
