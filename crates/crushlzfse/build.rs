// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
// Compiles this repo's own C sources straight into the Rust crate; keep
// this list in step with the crushlzfse target in CMakeLists.txt.

fn main() {
    let files = [
        "csrc/lzfse_encode.c",
        "csrc/lzfse_encode_base.c",
        "csrc/lzfse_decode.c",
        "csrc/lzfse_decode_base.c",
        "csrc/lzvn_encode_base.c",
        "csrc/lzvn_decode_base.c",
        "csrc/lzfse_fse.c",
        "csrc/crushlzfse.c",
        "csrc/crushlzvn.c",
        // Reports the C ABI so ffi.rs can assert its mirrors against it, see
        // that file for why eyeballing them is not sufficient.
        "csrc/crushlzfse_abi.c",
    ];

    let mut build = cc::Build::new();
    build
        .files(files)
        // -O3, not -Os: lzfse_encode_base.c's match_extend measurably
        // benefits, and the rest of the library along for the ride is fine
        // either way.
        .opt_level(3)
        .define("NDEBUG", None)
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fno-strict-aliasing") // matches lzbitmap/build.rs and harness/flags.mk
        .warnings(true);
    // Haswell on x86-64, as lzbitmap/build.rs; CRUSHLZ_SIMD_PORTABLE opts out.
    println!("cargo:rerun-if-env-changed=CRUSHLZ_SIMD_PORTABLE");
    if haswell() {
        build.flag_if_supported("-march=x86-64-v3");
    }
    build.compile("crushlzfse_c");

    // `src` covers every header these files include too (lzfse_internal.h,
    // lzfse_zopt.h, crushlzfse.h, ...), so watching the whole directory is
    // simpler than enumerating each header individually and can't drift out
    // of sync with it.
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=build.rs");
}

fn haswell() -> bool {
    let portable = std::env::var("CRUSHLZ_SIMD_PORTABLE")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    !portable && arch == "x86_64"
}
