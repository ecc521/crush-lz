// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Compiles libzbitmap.c straight into the Rust crate, this repo's whole C
// surface is one file, so there's no LIB_OBJS-style list to mirror (compare
// ../crushlzfse/build.rs, which does have one).

fn main() {
    let mut build = cc::Build::new();
    build
        .file("csrc/libzbitmap.c")
        // Reports the C ABI so rust/ffi.rs's abi_tests can assert its mirrors
        // against it, see csrc/zbm_abi.c for why that is not optional.
        .file("csrc/zbm_abi.c")
        .opt_level(3)
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fno-strict-aliasing") // matches Makefile's own CFLAGS
        .warnings(true);
    // Builds for pre-Haswell x86-64: no -march=x86-64-v3, and crush_simd.h's
    // scalar branch. Unset, unsupported targets still get the scalar branch
    // automatically; this is only for opting a *supported* target out of the
    // fast path.
    println!("cargo:rerun-if-env-changed=CRUSHLZ_SIMD_PORTABLE");
    let portable = std::env::var("CRUSHLZ_SIMD_PORTABLE")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);
    if portable {
        build.define("CRUSH_SIMD_PORTABLE", None);
    } else {
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        if target_arch == "x86_64" {
            // Haswell (AVX2, BMI1/2, FMA), which every Intel Mac macOS still
            // supports has; see harness/flags.mk.
            build.flag_if_supported("-march=x86-64-v3");
        }
    }
    build.compile("zbitmap_c");

    println!("cargo:rerun-if-changed=csrc/libzbitmap.c");
    println!("cargo:rerun-if-changed=csrc/zbm_abi.c");
    println!("cargo:rerun-if-changed=csrc/crushlzbitmap.h");
    println!("cargo:rerun-if-changed=csrc/crush_simd.h");
    println!("cargo:rerun-if-changed=csrc/zbm_blend_tables.h");
    println!("cargo:rerun-if-changed=build.rs");
}
