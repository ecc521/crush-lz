#!/usr/bin/env python3
# Copyright (c) 2026 Tucker Willenborg
# SPDX-License-Identifier: MPL-2.0
"""Require successful valid accesses and the expected sanitizer failures."""
import os
import resource
import signal
import subprocess
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
binary, mode = os.path.abspath(sys.argv[1]), sys.argv[2]

def run(case):
    # MSan startup can collide with ASLR. Retry only that explicit runtime
    # failure; never turn a finding or an unrelated crash into a pass.
    for _ in range(8):
        result = subprocess.run([binary, case], capture_output=True, timeout=30)
        if b"MemorySanitizer can not mmap the shadow memory" not in result.stderr:
            return result
    sys.exit("MSan could not map shadow memory after eight startup attempts")

valid = run("valid")
if valid.returncode:
    sys.exit(f"valid sanitizer probe failed: {valid.stderr.decode(errors='replace')}")
checks = [("undefined", b"signed integer overflow")] if mode != "msan" else []
if mode == "asan":
    checks += [("overflow", b"AddressSanitizer: heap-buffer-overflow"),
               ("freed", b"AddressSanitizer: heap-use-after-free")]
elif mode == "msan":
    checks += [("uninitialized", b"MemorySanitizer: use-of-uninitialized-value")]
elif mode == "mte":
    result = run("tag")
    if result.returncode not in [-signal.SIGSEGV, -signal.SIGBUS, -signal.SIGKILL]:
        sys.exit(f"MTE tag mismatch did not fault as expected: {result.returncode}\n{result.stderr.decode(errors='replace')}")
else:
    sys.exit(f"unknown sanitizer mode: {mode}")
for case, diagnostic in checks:
    result = run(case)
    if not result.returncode or diagnostic not in result.stderr:
        sys.exit(f"{case} failed to produce {diagnostic!r}: {result.returncode}\n{result.stderr.decode(errors='replace')}")
print(f"{mode}: valid access and expected sanitizer faults verified")
