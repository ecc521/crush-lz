// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Compiles crushlz4.c and the vendored upstream LZ4 straight into the Rust
// crate. csrc/vendor/lz4 is BSD-2-Clause and unmodified — it is built with
// its own warning posture rather than ours, because warnings we would fix in
// our own code are not ours to fix there and a bump must stay a file copy.

fn main() {
    let mut build = cc::Build::new();
    build
        .file("csrc/crushlz4.c")
        // Reports the C ABI so rust/ffi.rs's abi_tests can assert the mirrors
        // against it, see csrc/crushlz4_abi.c for why that is not optional.
        .file("csrc/crushlz4_abi.c")
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fno-strict-aliasing") // matches the sibling crates' own CFLAGS
        .warnings(true)
        // GCC on x86_64 regresses under -O3 (worst -3.8%, tapering to ~1% by
        // the higher levels); not worth a compiler/arch branch for that.
        .opt_level(3);
    // Haswell on x86-64, as lzbitmap/build.rs; CRUSHLZ_SIMD_PORTABLE opts out.
    println!("cargo:rerun-if-env-changed=CRUSHLZ_SIMD_PORTABLE");
    let haswell = haswell();
    if haswell {
        build.flag_if_supported("-march=x86-64-v3");
    }
    build.compile("crushlz4_c");

    // Upstream LZ4, its own translation units, warnings off: see above.
    let mut lz4 = cc::Build::new();
    lz4.file("csrc/vendor/lz4/lz4.c")
        .file("csrc/vendor/lz4/lz4hc.c")
        .flag_if_supported("-fvisibility=hidden")
        .warnings(false)
        .opt_level(3);
    if haswell {
        lz4.flag_if_supported("-march=x86-64-v3");
    }
    lz4.compile("crushlz4_vendor_lz4");

    println!("cargo:rerun-if-changed=csrc/crushlz4.c");
    println!("cargo:rerun-if-changed=csrc/vendor/lz4/lz4.c");
    println!("cargo:rerun-if-changed=csrc/vendor/lz4/lz4hc.c");
    println!("cargo:rerun-if-changed=csrc/vendor/lz4/lz4.h");
    println!("cargo:rerun-if-changed=csrc/vendor/lz4/lz4hc.h");
    println!("cargo:rerun-if-changed=csrc/crushlz4_abi.c");
    println!("cargo:rerun-if-changed=csrc/crushlz4.h");
    println!("cargo:rerun-if-changed=build.rs");
}

fn haswell() -> bool {
    let portable = std::env::var("CRUSHLZ_SIMD_PORTABLE")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    !portable && arch == "x86_64"
}
