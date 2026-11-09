// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! An encoder and decoder for Apple's `COMPRESSION_LZ4`: the published LZ4
//! block format inside Apple's `bv4` frame, the format behind decmpfs types
//! 15 and 16.
//!
//! Any input size is accepted. -2 and -1 trade ratio for speed against the
//! default (0), 1 to 10 the reverse. Levels outside
//! [`Level::MIN`]`..=`[`Level::MAX`] are clamped.
//!
//! No call site needs `unsafe`; every FFI call lives inside this crate.

mod compress;
mod decompress;
mod error;
mod ffi;
mod params;
mod scratch;

pub use compress::{compress, compress_bound, compress_into, compress_into_with, compress_with};
pub use decompress::{decoded_len, decompress, decompress_into};
pub use error::Error;
pub use params::{Capabilities, Level, Params, capabilities, scratch_size};
pub use scratch::Scratch;

#[cfg(test)]
mod tests {
    use super::*;

    const SIZES: [usize; 7] = [0, 1, 4095, 32767, 32768, 32769, 300_000];

    fn levels() -> impl Iterator<Item = Level> {
        (Level::MIN.0..=Level::MAX.0).map(Level)
    }

    /// Deterministic xorshift, so the crate needs no RNG dependency.
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut x: u32 = 0x2545_F491;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 0xff) as u8
            })
            .collect()
    }

    /// Semi-compressible: periodic runs with noise sprinkled in.
    fn mixed(len: usize) -> Vec<u8> {
        let noise = pseudo_random(len);
        (0..len).map(|i| if i % 11 == 0 { noise[i] } else { (i % 251) as u8 }).collect()
    }

    /// Walks the `bv4` frame layer of a stream and returns each block's
    /// (magic, decoded size), having checked that the stream is terminated.
    /// A second, independent reader of the framing, deliberately not shared
    /// with the decoder.
    fn walk_frames(stream: &[u8]) -> Vec<(u32, usize)> {
        let le32 = |at: usize| u32::from_le_bytes(stream[at..at + 4].try_into().expect("4 bytes for a frame word"));
        let mut blocks = Vec::new();
        let mut at = 0usize;
        loop {
            assert!(at + 4 <= stream.len(), "stream ran out before its terminator");
            let magic = le32(at);
            if magic == ffi::CRUSHLZ4_MAGIC_END {
                at += 4;
                break;
            }
            if magic == ffi::CRUSHLZ4_MAGIC_STORED {
                let decoded = le32(at + 4) as usize;
                blocks.push((magic, decoded));
                at += 8 + decoded;
            } else if magic == ffi::CRUSHLZ4_MAGIC_COMPRESSED {
                let decoded = le32(at + 4) as usize;
                let encoded = le32(at + 8) as usize;
                blocks.push((magic, decoded));
                at += 12 + encoded;
            } else {
                panic!("unknown block magic {magic:#010x} at offset {at}");
            }
        }
        assert_eq!(at, stream.len(), "trailing bytes after the bv4$ terminator");
        blocks
    }

    #[test]
    fn every_level_roundtrips_every_size() {
        for len in SIZES {
            let data = mixed(len);
            for level in levels() {
                let packed = compress(&data, level).unwrap_or_else(|e| panic!("len {len} level {level:?}: {e}"));
                assert_eq!(decompress(&packed).unwrap(), data, "len {len} level {level:?}: round-trip mismatch");
                assert!(packed.len() <= compress_bound(len), "len {len} level {level:?}: over the bound");
                walk_frames(&packed);
            }
        }
    }

    #[test]
    fn random_and_periodic_roundtrip() {
        for data in [pseudo_random(65536), (0..65536u32).map(|i| (i % 8) as u8).collect(), vec![0u8; 100_000]] {
            for level in [Level::MIN, Level(0), Level::DEFAULT, Level::MAX] {
                assert_eq!(decompress(&compress(&data, level).unwrap()).unwrap(), data);
            }
        }
    }

    #[test]
    fn multi_block() {
        let data = mixed(200_000);
        let blocks = walk_frames(&compress(&data, Level::DEFAULT).unwrap());
        assert!(blocks.len() > 1, "200 KB should span more than one 64 KB block");
        assert_eq!(
            blocks.iter().map(|&(_, decoded)| decoded).sum::<usize>(),
            data.len(),
            "the blocks' decoded sizes must account for every input byte"
        );
    }

    /// The match window spans blocks, so a run repeated across a block
    /// boundary must still round-trip.
    #[test]
    fn match_across_block_boundary() {
        let unique = pseudo_random(40_000);
        let mut data = Vec::new();
        data.extend_from_slice(&unique);
        data.extend_from_slice(&vec![0xA5u8; 40_000]);
        data.extend_from_slice(&unique);
        for level in levels() {
            assert_eq!(decompress(&compress(&data, level).unwrap()).unwrap(), data, "level {level:?}");
        }
    }

    #[test]
    fn compress_into_too_small_is_output_too_small() {
        let data = mixed(100_000);
        let mut scratch = Scratch::new();
        for len in [0usize, 1, 4, 100, 10_000] {
            let mut dst = vec![0u8; len];
            assert_eq!(
                compress_into(&mut dst, &data, Level::DEFAULT, &mut scratch).unwrap_err(),
                Error::OutputTooSmall { written: 0 },
                "dst of {len} bytes"
            );
        }
        let mut dst = vec![0u8; compress_bound(data.len())];
        let n = compress_into(&mut dst, &data, Level::DEFAULT, &mut scratch).unwrap();
        assert_eq!(dst[..n], compress(&data, Level::DEFAULT).unwrap()[..]);
    }

    #[test]
    fn scratch_reuse_is_deterministic() {
        let data = mixed(150_000);
        let mut scratch = Scratch::new();
        let mut dst = vec![0u8; compress_bound(data.len())];
        for level in [Level::MAX, Level::MIN, Level::DEFAULT, Level::MAX, Level::MIN] {
            let n = compress_into(&mut dst, &data, level, &mut scratch).unwrap();
            assert_eq!(dst[..n], compress(&data, level).unwrap()[..], "level {level:?} differs after reuse");
        }
    }

    #[test]
    fn levels_clamp() {
        let data = mixed(65536);
        assert_eq!(compress(&data, Level(i32::MIN)).unwrap(), compress(&data, Level::MIN).unwrap());
        assert_eq!(compress(&data, Level(i32::MAX)).unwrap(), compress(&data, Level::MAX).unwrap());
        assert_eq!(compress(&data, Level(Level::MIN.0 - 1)).unwrap(), compress(&data, Level::MIN).unwrap());
        assert_eq!(compress(&data, Level(Level::MAX.0 + 1)).unwrap(), compress(&data, Level::MAX).unwrap());
        assert_eq!(Level::default(), Level::DEFAULT);
        assert!(Level::MIN < Level::DEFAULT && Level::DEFAULT < Level::MAX);
    }

    #[test]
    fn corrupted_input_is_invalid() {
        assert_eq!(decompress(b"not a real crushlz4 stream").unwrap_err(), Error::InvalidInput);
        assert_eq!(decompress(&[]).unwrap_err(), Error::InvalidInput);
        let data = mixed(70_000);
        let full = compress(&data, Level::DEFAULT).unwrap();
        assert_eq!(decompress(&full[..full.len() - 8]).unwrap_err(), Error::InvalidInput);
        let mut bad = full.clone();
        bad[0] ^= 0xff;
        assert_eq!(decompress(&bad).unwrap_err(), Error::InvalidInput);
    }

    #[test]
    fn empty_input_is_a_bare_terminator() {
        let stream = compress(&[], Level::DEFAULT).unwrap();
        assert_eq!(stream, ffi::CRUSHLZ4_MAGIC_END.to_le_bytes(), "an empty input should encode to just bv4$");
        assert!(walk_frames(&stream).is_empty());
    }

    /// A round-trip test alone passes for an encoder that stores everything.
    #[test]
    fn repetitive_input_actually_compresses() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 8) as u8).collect();
        let out = compress(&data, Level::DEFAULT).unwrap();
        assert!(out.len() * 10 < data.len(), "an 8-byte cycle should compress far better than 10:1, got {} bytes", out.len());
        assert!(
            walk_frames(&out).iter().all(|&(magic, _)| magic == ffi::CRUSHLZ4_MAGIC_COMPRESSED),
            "every block of a trivially compressible input should be a bv41 block"
        );
    }

    #[test]
    fn error_display_and_scratch_send() {
        for e in [Error::OutputTooSmall { written: 0 }, Error::InvalidInput, Error::InvalidParams, Error::Encode] {
            assert!(!e.to_string().is_empty());
        }
        fn assert_send<T: Send>() {}
        assert_send::<Scratch>();
    }
}
