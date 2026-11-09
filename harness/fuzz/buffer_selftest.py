#!/usr/bin/env python3
# Copyright (c) 2026 Tucker Willenborg
# SPDX-License-Identifier: MPL-2.0
"""Verify accessible buffers and crashing one-byte reads/writes at boundaries.
Usage: buffer_selftest.py <binary> [asan]
Build binary with and without ASan to check both shadow and physical guards.
"""
import os
import resource
import signal
import subprocess
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
binary = os.path.abspath(sys.argv[1])
asan = len(sys.argv) > 2 and sys.argv[2] == "asan"
checks = 0
for kind in (["guard", "heap"] if asan else ["guard"]):
    for placement in ["front", "back"]:
        for length in [0, 1, 7, 8, 9, 16, 17, 4095, 4096, 4097]:
            command = [binary, kind, placement, str(length)]
            valid = subprocess.run(command + ["valid", "write"], capture_output=True)
            if valid.returncode:
                sys.exit(f"valid view failed: {command}\n{valid.stderr.decode()}")
            checks += 1
            for side in ["under", "over"]:
                # Back placement's partial leading ASan granule is documented.
                if kind == "guard" and side == "under" and placement == "back":
                    continue
                if not asan and side != ("under" if placement == "front" else "over"):
                    continue
                for operation in ["read", "write"]:
                    result = subprocess.run(command + [side, operation], capture_output=True)
                    if result.returncode == 0:
                        sys.exit(f"invalid access escaped: {command + [side, operation]}")
                    diagnostic = b"AddressSanitizer" in result.stderr
                    if kind == "heap" and not any(marker in result.stderr for marker in
                            [b"heap-buffer-overflow", b"use-after-poison"]):
                        sys.exit(f"heap boundary probe lacked an ASan bounds report: {result.stderr.decode()}")
                    if not diagnostic and result.returncode not in [-signal.SIGSEGV, -signal.SIGBUS]:
                        sys.exit(f"probe failed for an unrelated reason: {result.stderr.decode()}")
                    checks += 1
print(f"{checks} buffer self-tests passed ({'ASan + guards' if asan else 'page guards'})")
