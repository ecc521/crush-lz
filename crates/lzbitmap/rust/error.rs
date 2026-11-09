// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0
use std::fmt;

/// Everything this crate can fail with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The destination buffer cannot hold the output.
    ///
    /// On the decode side, `written` is how many bytes of the destination
    /// hold real, correct decoded content even so: every chunk fully
    /// completed before the one that didn't fit (chunk granularity, not
    /// byte-exact within that last chunk). On the encode side `written` is
    /// always 0: the encoder's C contract is bytes-written-or-zero, with no
    /// partial-progress concept to report.
    OutputTooSmall {
        /// Bytes of real, valid output already in the destination buffer.
        written: usize,
    },
    /// The compressed input is not a valid LZBITMAP stream.
    InvalidInput,
    /// A [`Params`](crate::Params) field is outside its documented range.
    InvalidParams,
    /// The encoder failed for a reason other than the two above, such as an
    /// index whose byte offset overflows or an allocation failure.
    Encode,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::OutputTooSmall { .. } => "destination buffer is too small",
            Error::InvalidInput => "compressed input is invalid",
            Error::InvalidParams => "encoder parameters are out of range",
            Error::Encode => "encoding failed",
        })
    }
}

impl std::error::Error for Error {}
