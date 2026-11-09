// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

fn main() {
    let mut build = cc::Build::new();
    build
        .file("csrc/crushlzmesh.c")
        .opt_level(3)
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-fno-strict-aliasing")
        .warnings(true);

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_arch == "x86_64" {
        build.flag_if_supported("-march=x86-64-v3");
    }

    build.compile("crushlzmesh_c");

    println!("cargo:rerun-if-changed=csrc/crushlzmesh.c");
    println!("cargo:rerun-if-changed=csrc/crushlzmesh.h");
    println!("cargo:rerun-if-changed=build.rs");
}
