/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! This module implements the parts of ECE that are currently shared by all
//! supported schemes, such as the actual AES-GCM encryption of a single record.
//! It can't be used in isolation; you must instead provide a concrete instantiation
//! of an ECE encryption scheme by implementing the `EncryptionScheme` trait.

use crate::{crypto::Cryptographer, error::*};
use byteorder::{BigEndian, ByteOrder};

pub(crate) const ECE_AES_KEY_LENGTH: usize = 16;
pub(crate) const ECE_NONCE_LENGTH: usize = 12;
pub(crate) const ECE_SALT_LENGTH: usize = 16;
pub(crate) const ECE_TAG_LENGTH: usize = 16;
pub(crate) const ECE_WEBPUSH_PUBLIC_KEY_LENGTH: usize = 65;
pub(crate) const ECE_WEBPUSH_AUTH_SECRET_LENGTH: usize = 16;
pub(crate) const ECE_WEBPUSH_DEFAULT_RS: u32 = 4096;

/// Parameters that control the details of the encryption process.
///
/// These are the various configuration knobs that could potentially be
/// tweaked when encrypting a given piece of data, packaged together
/// in a struct for convenience.
///
pub(crate) struct WebPushParams {
    /// The record size, for chunking the plaintext into multiple records.
    pub rs: u32,
    /// The total amount of padding to add to the plaintext before encryption.
    pub pad_length: usize,
    /// The salt to use when deriving keys.
    /// The recommended and default value is `None`, which causes a new random
    /// salt to be used for every encryption. Specifying a specific salt may
    /// be useful for testing purposes.
    pub salt: Option<Vec<u8>>,
}

impl WebPushParams {
    /// Convenience method for getting an appropriate salt value.
    ///
    /// If we have a pre-configured salt then it is returned, transferring ownership
    /// to ensure it is only used once. If we do not have a pre-configured salt then
    /// a new random one is generated.
    pub fn take_or_generate_salt(&mut self, cryptographer: &dyn Cryptographer) -> Result<Vec<u8>> {
        Ok(match self.salt.take() {
            Some(salt) => salt,
            None => {
                let mut salt = [0u8; ECE_SALT_LENGTH];
                cryptographer.random_bytes(&mut salt)?;
                salt.to_vec()
            }
        })
    }
}

impl Default for WebPushParams {
    fn default() -> Self {
        // Random salt, no padding, record size = 4096.
        Self {
            rs: ECE_WEBPUSH_DEFAULT_RS,
            pad_length: 0,
            salt: None,
        }
    }
}

/// Randomly select a padding length to apply to the given plaintext.
///
/// Some care is taken not to exceed the maximum record size.
///
pub fn get_random_padding_length(
    plaintext: &[u8],
    cryptographer: &dyn Cryptographer,
) -> Result<usize> {
    // For `aesgcm`, we need to ensure we don't exceed the size of a single record
    // after the plaintext has been padded (minimum 2 bytes) and encrypted.
    const MAX_SIZE: usize = (ECE_WEBPUSH_DEFAULT_RS as usize) - ECE_TAG_LENGTH - 2 - 1;
    let mut padr = [0u8; 2];
    cryptographer.random_bytes(&mut padr)?;
    let mut pad_length = ((usize::from(padr[0]) + (usize::from(padr[1]) << 8)) % MAX_SIZE) + 1;
    if plaintext.len() + pad_length >= MAX_SIZE {
        pad_length = MAX_SIZE - plaintext.len();
    }
    Ok(pad_length)
}

/// Flag to indicate whether we're encrypting or decrypting.
/// Used when deriving keys.
///
pub(crate) enum EceMode {
    ENCRYPT,
    DECRYPT,
}

/// Convenience tuple for "key" and "nonce" pair.
/// These are always derived as a pair.
///
pub(crate) type KeyAndNonce = (Vec<u8>, Vec<u8>);

/// Generates the AES-GCM IV to use for encrypting a single record.
///
/// Each record in ECE is encrypted with a unique IV, that combines a "global" nonce
/// for the whole data with with the record's sequence number.
///
pub(crate) fn generate_iv_for_record(nonce: &[u8], counter: usize) -> [u8; ECE_NONCE_LENGTH] {
    let mut iv = [0u8; ECE_NONCE_LENGTH];
    let offset = ECE_NONCE_LENGTH - 8;
    iv[0..offset].copy_from_slice(&nonce[0..offset]);
    // Combine the remaining unsigned 64-bit integer with the record sequence
    // number using XOR. See the "nonce derivation" section of the draft.
    let mask = BigEndian::read_u64(&nonce[offset..]);
    BigEndian::write_u64(&mut iv[offset..], mask ^ (counter as u64));
    iv
}
