// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! The README's usage block, compiled. A README example that does not build
//! is the one kind of documentation error a reader finds the hard way.
use crushlz4::{Level, Params, capabilities, compress, compress_with, decompress};

#[test]
fn readme_example_compiles_and_runs() {
    let owned = b"the quick brown fox jumps over the lazy dog, repeatedly. ".repeat(400);
    let input: &[u8] = &owned;

    let packed = compress(input, Level::DEFAULT).unwrap();
    let back = decompress(&packed).unwrap();
    assert_eq!(back, input);

    let packed = compress(input, Level::MAX).unwrap();
    assert_eq!(decompress(&packed).unwrap(), input);

    let mut params = Params::for_level(Level::DEFAULT).0;
    params.acceleration = 4;
    let packed = compress_with(input, &params).unwrap();
    assert_eq!(decompress(&packed).unwrap(), input);

    // And the claim the README makes about params: rejected, not clamped.
    let mut bad = params;
    bad.acceleration = capabilities().acceleration.1 + 1;
    assert!(compress_with(input, &bad).is_err(), "out-of-range params must be rejected");
}
