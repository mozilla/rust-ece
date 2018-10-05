/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use ece_crypto;
use failure::{Backtrace, Context, Fail};
use std::boxed::Box;
use std::{fmt, result};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(Box<Context<ErrorKind>>);

impl Fail for Error {
    #[inline]
    fn cause(&self) -> Option<&Fail> {
        self.0.cause()
    }

    #[inline]
    fn backtrace(&self) -> Option<&Backtrace> {
        self.0.backtrace()
    }
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl Error {
    #[inline]
    pub fn kind(&self) -> &ErrorKind {
        &*self.0.get_context()
    }
}

impl From<ErrorKind> for Error {
    #[inline]
    fn from(kind: ErrorKind) -> Error {
        Error(Box::new(Context::new(kind)))
    }
}

impl From<Context<ErrorKind>> for Error {
    #[inline]
    fn from(inner: Context<ErrorKind>) -> Error {
        Error(Box::new(inner))
    }
}

#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Invalid auth secret")]
    InvalidAuthSecret,

    #[fail(display = "Invalid salt")]
    InvalidSalt,

    #[fail(display = "Invalid key length")]
    InvalidKeyLength,

    #[fail(display = "Invalid record size")]
    InvalidRecordSize,

    #[fail(display = "Invalid header size (too short)")]
    HeaderTooShort,

    #[fail(display = "Truncated ciphertext")]
    DecryptTruncated,

    #[fail(display = "Zero-length ciphertext")]
    ZeroCiphertext,

    #[fail(display = "Block too short")]
    BlockTooShort,

    #[fail(display = "Invalid decryption padding")]
    DecryptPadding,

    #[fail(display = "Crypto error")]
    CryptoError,
}

// This is bad design, however handling cross-crates errors
// with failure is a pain and I spent too much time on this already.
impl From<ece_crypto::Error> for ErrorKind {
    #[inline]
    fn from(_: ece_crypto::Error) -> ErrorKind {
        ErrorKind::CryptoError
    }
}

impl From<ece_crypto::Error> for Error {
    #[inline]
    fn from(e: ece_crypto::Error) -> Error {
        ErrorKind::from(e).into()
    }
}
