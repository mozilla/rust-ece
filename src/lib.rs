/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate byteorder;
extern crate ece_crypto;
extern crate failure;
#[macro_use]
extern crate failure_derive;

pub mod aes128gcm;
// TODO: pub mod aesgcm;
mod common;
mod error;

pub use error::*;

#[cfg(feature = "openssl")]
extern crate ece_crypto_openssl;
#[cfg(feature = "openssl")]
use ece_crypto_openssl::CryptoImpl;
#[cfg(feature = "openssl")]
use ece_crypto_openssl::KeysImpl;
