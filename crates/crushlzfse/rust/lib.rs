// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
//! LZFSE and LZVN encoders and decoders. The bitstreams are the ones
//! Apple's decoders already read.
//!
//! The crate root is LZFSE; [`lzvn`] has the same items for raw LZVN.
//! Every level, whatever its [`Params`] strategy, works a
//! single fixed 64 KiB block per call, matching decmpfs's own chunk size,
//! and rejects anything larger outright rather than chunk or stream it,
//! since the real caller never hands one more than one such piece. One call
//! is one stream. Higher levels are denser and slower, lower ones faster
//! and looser.
//! LZVN output has no header, so [`lzvn::decompress`] relies on the
//! caller knowing the stream is LZVN.
//!
//! ```
//! use crushlzfse::{Level, compress, decompress};
//!
//! let input = b"the quick brown fox jumps over the lazy dog, repeatedly, repeatedly";
//! let packed = compress(input, Level::DEFAULT)?;
//! assert_eq!(decompress(&packed)?, input);
//! # Ok::<(), crushlzfse::Error>(())
//! ```
//!
//! Nothing here requires `unsafe` at the call site; the FFI boundary is
//! wrapped completely.

#![deny(missing_docs)]

mod chunks;
mod decode;
mod ffi;
pub mod lzvn;
mod params;
mod scratch;

pub use chunks::{DEFAULT_SEGMENT_SIZE, compress_chunks};
pub use decode::{decompress, decompress_into};
pub use params::{BLOCK_SIZE, Capabilities, Level, Params, capabilities, scratch_size};
pub use scratch::{
    Scratch, Stats, compress, compress_bound, compress_into, compress_into_chained, compress_into_with, compress_with,
};

/// Why a compress or decompress call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The destination buffer cannot hold the whole output.
    ///
    /// On the decode side, `written` is the exact number of bytes of real,
    /// correct decoded content already in the destination: the position
    /// the decoder would resume from given more room. On the encode side
    /// `written` is always 0: the encoder's C contract is
    /// bytes-written-or-zero, with no partial-progress concept to report.
    OutputTooSmall {
        /// Bytes of real, valid output already in the destination buffer.
        written: usize,
    },
    /// The input is not a valid stream.
    InvalidInput,
    /// A [`Params`] field is outside the range [`capabilities`] reports.
    InvalidParams,
    /// The encode call was given more input than the fixed 64 KiB block it
    /// works over, whatever the strategy. The real caller (decmpfs) never
    /// does this; anyone else compressing something larger chunks it and
    /// calls once per chunk.
    InputTooLarge,
    /// The encoder produced nothing despite a large enough buffer; treat as
    /// out of memory.
    Encode,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::OutputTooSmall { .. } => "output buffer too small",
            Error::InvalidInput => "invalid compressed data",
            Error::InvalidParams => "encoder params out of range",
            Error::InputTooLarge => "input larger than the fixed 64 KiB block",
            Error::Encode => "encoder failed",
        })
    }
}

impl std::error::Error for Error {}
