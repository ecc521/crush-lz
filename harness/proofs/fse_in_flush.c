/* Exact checked refill, including an exact-sized input object with no
 * trailing bytes. The refill loads the word ending at the cursor, so the
 * caller provides one word of readable bytes below the lower bound. All
 * positions and accumulator contents are symbolic. */
#include "proof.h"
#include "lzfse_fse.h"

size_t nondet_size(void);
int32_t nondet_i32(void);
uint64_t nondet_u64(void);

#ifdef PROOF_FLUSH32
#define WORD_BITS 32
#define stream_type fse_in_stream32
#define checked_flush fse_in_checked_flush32
#else
#define WORD_BITS 64
#define stream_type fse_in_stream64
#define checked_flush fse_in_checked_flush64
#endif

void harness(void)
{
    size_t size = nondet_size(), begin = nondet_size(), pos = nondet_size();
    __CPROVER_assume(size >= 1 && size <= PROOF_MAX_OBJECT);
    __CPROVER_assume(begin >= WORD_BITS / 8 && begin <= pos && pos <= size);
    uint8_t *buffer = malloc(size);
    __CPROVER_assume(buffer != NULL);
    const uint8_t *cursor = buffer + pos;
    stream_type stream;
    stream.accum = nondet_u64();
    stream.accum_nbits = nondet_i32();
    int32_t before = stream.accum_nbits;
    int status = checked_flush(&stream, &cursor, buffer + begin);
    PROOF_REACHABLE(status == 0 && before >= WORD_BITS-8, "full accumulator skips load");
    PROOF_REACHABLE(status == 0 && before == 0, "maximum refill");
    PROOF_REACHABLE(status == 0 && cursor == buffer + begin && before < WORD_BITS-8,
                    "refill at exact lower bound");
    PROOF_REACHABLE(status == -1 && pos == begin, "insufficient source");
    PROOF_REACHABLE(status == 0 && before == 0 &&
                    ((size_t)(cursor-buffer) % 4) == 1, "unaligned refill");
    PROOF_REACHABLE(status == 0 && pos == size && before < WORD_BITS-8,
                    "refill from exact-sized source tail");
}
