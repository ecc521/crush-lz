// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

use lzmesh::{compress, decompress, decompress_into, Level};

fn sample(n: usize) -> Vec<u8> {
    const WORDS: [&str; 8] = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"];
    let mut x: u32 = 0x1234_5678;
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        out.extend_from_slice(WORDS[(x % 8) as usize].as_bytes());
        out.push(b' ');
    }
    out.truncate(n);
    out
}

#[test]
fn every_level_roundtrips_sample() {
    let sizes = [0, 1, 14, 15, 16, 64, 500, 4096, 32768];
    for &sz in &sizes {
        let data = sample(sz);
        for lvl in [Level::MIN, Level(-2), Level(0), Level(1), Level(5), Level::MAX] {
            let packed = compress(&data, lvl).unwrap_or_else(|e| panic!("compress failed sz={sz} lvl={lvl:?}: {e}"));
            let unpacked = match decompress(&packed) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("sz={sz} lvl={lvl:?} packed.len()={} packed[0]={:#x}", packed.len(), packed[0]);
                    if packed.len() > 20 {
                        eprintln!("packed header: {:02x?}", &packed[..12]);
                        eprintln!("packed tail: {:02x?}", &packed[packed.len() - 16..]);
                    }
                    panic!("decompress failed sz={sz} lvl={lvl:?}: {e}");
                }
            };
            assert_eq!(unpacked, data, "roundtrip mismatch sz={sz} lvl={lvl:?}");

            if sz > 0 {
                let mut dst = vec![0u8; sz];
                let n = decompress_into(&mut dst, &packed).expect("decompress_into");
                assert_eq!(n, sz);
                assert_eq!(dst, data);
            }
        }
    }
}

#[test]
fn periodic_data_compresses_well() {
    for period in 1..=8 {
        let pattern: Vec<u8> = (0..period).map(|i| b'a' + i as u8).collect();
        let data: Vec<u8> = pattern.repeat(200);
        let packed = compress(&data, Level(0)).expect("compress");
        assert!(
            packed.len() < data.len() / 4,
            "period {period}: packed len {} was not < 1/4 of {}",
            packed.len(),
            data.len()
        );
        let unpacked = decompress(&packed).expect("decompress");
        assert_eq!(unpacked, data);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn differential_crosscheck_apple() {
    use std::os::raw::{c_uint, c_void};
    #[link(name = "compression")]
    unsafe extern "C" {
        fn compression_decode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut c_void,
            algorithm: c_uint,
        ) -> usize;

        #[allow(dead_code)]
        fn compression_encode_buffer(
            dst: *mut u8,
            dst_size: usize,
            src: *const u8,
            src_size: usize,
            scratch: *mut c_void,
            algorithm: c_uint,
        ) -> usize;
    }

    let test_inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![b'A'],
        vec![b'X'; 50],
        vec![b'X'; 500],
        b"ABCDEFGH".repeat(50),
        b"The quick brown fox jumps over the lazy dog. ".repeat(15),
        sample(2048),
    ];

    for data in &test_inputs {
        for lvl in [Level::MIN, Level(0), Level::MAX] {
            let ours = compress(data, lvl).expect("our compress failed");
            let mut apple_dst = vec![0u8; data.len() + 64];
            let n = unsafe {
                compression_decode_buffer(
                    apple_dst.as_mut_ptr(),
                    apple_dst.len(),
                    ours.as_ptr(),
                    ours.len(),
                    std::ptr::null_mut(),
                    0xE05,
                )
            };
            assert_eq!(n, data.len(), "Apple decode size mismatch");
            assert_eq!(&apple_dst[..n], data.as_slice(), "Apple decode data mismatch");
        }
    }
}
