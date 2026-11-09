// Copyright (c) 2026 Tucker Willenborg
// SPDX-License-Identifier: MPL-2.0

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    OutputTooSmall { written: usize },
    InvalidParams,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInput => write!(f, "corrupted or invalid LZMESH input"),
            Error::OutputTooSmall { written } => {
                write!(f, "output buffer too small (wrote {written} bytes)")
            }
            Error::InvalidParams => write!(f, "invalid LZMESH encoder parameters"),
        }
    }
}

impl std::error::Error for Error {}
