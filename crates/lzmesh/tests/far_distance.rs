// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

//! New distances of 2^32 or more keep their low 32 bits, as Apple's decoder
//! does. Expected results were measured against Apple's decoder.

use lzmesh::{decompress_into, native};

fn data(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Decodes with the C and native decoders twice, over zeroed and 0xAB-filled
/// output, and requires all four results to agree.
fn decode(name: &str) -> Option<Vec<u8>> {
    let src = data(name);
    let mut results = Vec::new();
    for fill in [0x00u8, 0xAB] {
        let mut c = vec![fill; 1 << 20];
        let mut n = vec![fill; 1 << 20];
        results.push(decompress_into(&mut c, &src).ok().map(|len| c[..len].to_vec()));
        results.push(native::decompress_into(&mut n, &src).ok().map(|len| n[..len].to_vec()));
    }
    assert!(results.windows(2).all(|w| w[0] == w[1]), "{name}: decoders disagree");
    results.pop().unwrap()
}

#[test]
fn distance_over_32_bits_wraps() {
    // k=31: true distance 0x500001680, used as 5760 at output position 43697.
    let out = decode("far_wraps_to_5760.lzm").expect("Apple accepts this stream");
    assert_eq!(out.len(), 64864);
    assert_eq!(out[43697..43701], out[43697 - 5760..43701 - 5760]);
}

#[test]
fn distance_wrapping_to_zero_is_rejected() {
    assert_eq!(decode("far_wraps_to_0.lzm"), None);
    assert_eq!(decode("far_wraps_to_0_one_match_byte.lzm"), None);
}

#[test]
fn distance_wrapping_to_zero_is_unchecked_without_match_bytes() {
    let out = decode("far_wraps_to_0_no_match_bytes.lzm").expect("Apple accepts this stream");
    assert_eq!(out.len(), 20000);
}
