/*
 * Shared by every proof harness. Include before the codec source.
 *
 * PROOF_REACHABLE(cond, name): a path the proof must cover. The normal
 * build ignores it; run.sh rebuilds with PROOF_REACH, where it asserts the
 * path is impossible, and requires CBMC to refute every such assertion
 * with a witness input. A goal it cannot refute means the harness's
 * assumptions exclude that path, and the proof would pass without
 * checking it.
 *
 * memcpy, as a proof sees it: the C standard's requirements and nothing
 * else. Safety does not depend on which bytes are copied, only on where, so
 * the proofs replace every memcpy call with this contract (DFCC
 * --replace-call-with-contract proof_memcpy). Each call site must show both
 * ranges are valid and do not overlap; the call may then write anything in
 * d[0, n) and nothing else.
 */
#ifndef PROOF_H
#define PROOF_H

#include <stddef.h>
#include <string.h>

void *proof_memcpy(void *d, const void *s, size_t n)
__CPROVER_requires(__CPROVER_w_ok(d, n) && __CPROVER_r_ok(s, n))
__CPROVER_requires(!__CPROVER_same_object(d, s) ||
                   (const char *)d + n <= (const char *)s ||
                   (const char *)s + n <= (const char *)d)
__CPROVER_assigns(__CPROVER_object_upto(d, n))
__CPROVER_ensures(__CPROVER_return_value == d);

#define memcpy(d, s, n) proof_memcpy(d, s, n)

/* The largest buffer a harness allocates. CBMC's object model with
 * --object-bits 10 (run.sh) leaves 54 offset bits; 2^48 keeps sums of
 * a few sizes clear of that limit. */
#define PROOF_MAX_OBJECT ((size_t)1 << 48)

#ifdef PROOF_REACH
#define PROOF_REACHABLE(cond, name) __CPROVER_assert(!(cond), "reachable: " name)
#else
#define PROOF_REACHABLE(cond, name) ((void)0)
#endif

#endif
