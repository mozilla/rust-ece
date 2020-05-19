/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use backtrace::Backtrace;
use std::{boxed::Box, fmt, result};

struct Context<T: fmt::Display + Sync + 'static> {
    context: T,
    backtrace: Backtrace,
}

impl<T: fmt::Display + Send + Sync + 'static> Context<T> {
    pub fn new(context: T) -> Self {
        Context {
            context,
            backtrace: Backtrace::new(),
        }
    }

    pub fn get_context(&self) -> &T {
        &self.context
    }
}

impl<D: fmt::Display + Send + Sync + 'static> fmt::Debug for Context<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}\n\n{}", self.backtrace, self.context)
    }
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(Box<Context<ErrorKind>>);

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0.get_context(), f)
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

#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    #[error("Invalid auth secret")]
    InvalidAuthSecret,

    #[error("Invalid salt")]
    InvalidSalt,

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid record size")]
    InvalidRecordSize,

    #[error("Invalid header size (too short)")]
    HeaderTooShort,

    #[error("Truncated ciphertext")]
    DecryptTruncated,

    #[error("Zero-length ciphertext")]
    ZeroCiphertext,

    #[error("Zero-length plaintext")]
    ZeroPlaintext,

    #[error("Block too short")]
    BlockTooShort,

    #[error("Invalid decryption padding")]
    DecryptPadding,

    #[error("Invalid encryption padding")]
    EncryptPadding,

    #[error("Could not decode base64 entry")]
    DecodeError,

    #[error("Crypto backend error")]
    CryptoError,

    #[cfg(feature = "backend-openssl")]
    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[source] openssl::error::ErrorStack),
}

impl From<base64::DecodeError> for Error {
    #[inline]
    fn from(_: base64::DecodeError) -> Error {
        ErrorKind::DecodeError.into()
    }
}

#[cfg(feature = "backend-openssl")]
macro_rules! impl_from_error {
    ($(($variant:ident, $type:ty)),+) => ($(
        impl From<$type> for ErrorKind {
            #[inline]
            fn from(e: $type) -> ErrorKind {
                ErrorKind::$variant(e)
            }
        }

        impl From<$type> for Error {
            #[inline]
            fn from(e: $type) -> Error {
                ErrorKind::from(e).into()
            }
        }
    )*);
}

#[cfg(feature = "backend-openssl")]
impl_from_error! {
    (OpenSSLError, ::openssl::error::ErrorStack)
}
