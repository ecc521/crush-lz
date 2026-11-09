// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//
// Regression test for an infinite loop: zbm_handle_chunk() returned early
// when state->dest was NULL (a "just tell me the decoded length" mode) —
// before the check, inside the compressed/uncompressed handlers, that would
// otherwise reject a chunk shorter than its own 6-byte header. With dst ==
// NULL and a crafted 10-byte stream carrying a zero-length first chunk, the
// caller in zbm_decompress_raw() does `state.src += state.len` with
// state.len == 0, so the cursor never advances and its
// `while (state.decmp_len != 0)` loop spins forever re-parsing the same
// bytes — 100% CPU, no crash, just a hang. (Not reachable from this repo's
// own Rust wrapper, which never passes a null destination pointer, but
// crushlzbitmap.h neither documents nor forbids one, and any C caller
// probing "how big is this?" before allocating is a reasonable thing to do.)
//
// The fix rejects state->len < sizeof(chunk header) right after the header
// is read, before the dst == NULL early return, guaranteeing the parse loop
// always advances regardless of whether dst is NULL.
//
// This test must terminate promptly; a background watchdog aborts and fails
// it instead of hanging the test runner if the regression comes back.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "crushlzbitmap.h"

static void on_alarm(int sig) {
    (void)sig;
    // write(2, ...) is async-signal-safe; fprintf is not.
    static const char msg[] = "FAILED: decode with dst=NULL did not return "
                              "within the timeout (infinite loop regressed)\n";
    write(2, msg, sizeof msg - 1);
    _exit(1);
}

int main(void) {
    // "ZBM\x09" magic, then a chunk header: 3-byte len = 0, 3-byte
    // decmp_len = 1. A real chunk's own header is 6 bytes, so len == 0 is
    // never valid — this is purely a malformed/hostile stream.
    uint8_t stream[10] = {
        'Z', 'B', 'M', 0x09,
        0x00, 0x00, 0x00,   // len = 0
        0x01, 0x00, 0x00,   // decmp_len = 1
    };

    signal(SIGALRM, on_alarm);
    alarm(5);  // generous; a correct decode returns essentially instantly

    size_t out_len = 0;
    int rc = crushlzbitmap_decode_buffer(NULL, 0, stream, sizeof stream, &out_len);

    alarm(0);
    printf("decode with dst=NULL returned: rc=%d out_len=%zu\n", rc, out_len);

    // The exact status doesn't matter — CRUSHLZBITMAP_INVALID is expected,
    // since a zero-length chunk is malformed — only that it returned at all
    // rather than hanging, which the alarm handler above already enforces by
    // aborting the process if it didn't.
    printf("ok\n");
    return 0;
}
