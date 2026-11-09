// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

pub mod compress;
pub mod decompress;
pub mod error;
pub mod ffi;
pub mod native;
pub mod params;
pub mod scratch;

pub use compress::{compress, compress_bound, compress_into_with, compress_with};
pub use decompress::{decoded_len, decompress, decompress_into};
pub use error::Error;
pub use params::{Level, Params};
pub use scratch::scratch_size;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let empty = b"";
        let enc = compress(empty, Level::DEFAULT).expect("encode failed");
        let dec = decompress(&enc).expect("decode failed");
        assert_eq!(dec, empty);
    }

    #[test]
    fn roundtrip_short() {
        let data = b"Hello world!";
        let enc = compress(data, Level::DEFAULT).expect("encode failed");
        let dec = decompress(&enc).expect("decode failed");
        assert_eq!(dec, data);
    }

    #[test]
    fn roundtrip_repeats() {
        let patterns: Vec<Vec<u8>> = vec![
            vec![b'A'; 500],
            b"The quick brown fox jumps over the lazy dog. ".repeat(20),
            b"01234567".repeat(40),
            b"ab".repeat(100),
            (0..256u32).map(|i| (i % 7) as u8).collect(),
        ];
        for data in &patterns {
            for l in [Level::MIN, Level(-1), Level::DEFAULT, Level(1), Level(5), Level::MAX] {
                let enc = compress(data, l).expect("encode failed");
                let dec = decompress(&enc).expect("decode failed");
                assert_eq!(&dec, data, "Mismatch at level {:?}", l);
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn roundtrip_apple_crosscheck() {
        let patterns: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"Hi".to_vec(),
            vec![b'A'; 200],
            vec![b'A'; 2000],
            b"The quick brown fox jumps over the lazy dog. ".repeat(20),
            b"ABCDEFGH".repeat(30),
            b"0123456789".repeat(25),
        ];

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
        }

        for data in &patterns {
            for l in [Level::MIN, Level::DEFAULT, Level::MAX] {
                let enc = compress(data, l).expect("encode failed");

                // Decode with our decoder
                let our_dec = decompress(&enc).expect("our decoder failed");
                assert_eq!(&our_dec, data);

                if data.is_empty() {
                    continue;
                }

                // Verify with Apple libcompression
                let mut apple_dst = vec![0u8; data.len() + 64];
                let n = unsafe {
                    compression_decode_buffer(
                        apple_dst.as_mut_ptr(),
                        apple_dst.len(),
                        enc.as_ptr(),
                        enc.len(),
                        std::ptr::null_mut(),
                        0xE05,
                    )
                };
                assert_eq!(n, data.len(), "Apple decoder returned size mismatch at level {:?}", l);
                assert_eq!(&apple_dst[..n], &data[..], "Apple decoder output mismatch at level {:?}", l);
            }
        }
    }
}
