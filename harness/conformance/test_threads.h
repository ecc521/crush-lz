// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
#ifndef CRUSHLZ_TEST_THREADS_H
#define CRUSHLZ_TEST_THREADS_H

#include <stdlib.h>
#include <unistd.h>

/* Worker count for the concurrency tests: every online core, or
 * CRUSHLZ_TEST_THREADS when set. Raise it above the core count to force
 * preemption when hunting a specific race. */
static inline int crushlz_test_threads(void) {
    const char *env = getenv("CRUSHLZ_TEST_THREADS");
    if (env) {
        int v = atoi(env);
        if (v > 0) return v;
    }
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 1 ? (int)n : 2;
}

#endif /* CRUSHLZ_TEST_THREADS_H */
