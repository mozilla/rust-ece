/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use byteorder::{BigEndian, ByteOrder};
use ece_crypto::Crypto;
use error::*;
use {CryptoImpl, KeysImpl};

// From keys.h:
pub const ECE_AES_KEY_LENGTH: usize = 16;
pub const ECE_NONCE_LENGTH: usize = 12;

// From ece.h:
pub const ECE_SALT_LENGTH: usize = 16;
const ECE_TAG_LENGTH: usize = 16;
const ECE_WEBPUSH_PRIVATE_KEY_LENGTH: usize = 32;
pub const ECE_WEBPUSH_PUBLIC_KEY_LENGTH: usize = 65;
const ECE_WEBPUSH_AUTH_SECRET_LENGTH: usize = 16;
const ECE_WEBPUSH_DEFAULT_RS: usize = 4096;

const ECE_AESGCM_MIN_RS: u8 = 3;
const ECE_AESGCM_PAD_SIZE: u8 = 2;

pub enum EceMode {
    ENCRYPT,
    DECRYPT,
}

pub type KeyAndNonce = (Vec<u8>, Vec<u8>);

pub trait EceWebPush {
    fn decrypt(
        keys: KeysImpl,
        auth_secret: &[u8],
        salt: &[u8],
        rs: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if auth_secret.len() != ECE_WEBPUSH_AUTH_SECRET_LENGTH {
            return Err(ErrorKind::InvalidAuthSecret.into());
        }
        if salt.len() != ECE_SALT_LENGTH {
            return Err(ErrorKind::InvalidSalt.into());
        }
        if ciphertext.len() == 0 {
            return Err(ErrorKind::ZeroCiphertext.into());
        }
        if Self::needs_trailer(rs, ciphertext.len()) {
            // If we're missing a trailing block, the ciphertext is truncated.
            return Err(ErrorKind::DecryptTruncated.into());
        }
        let (key, nonce) = Self::webpush_derive_key_and_nonce(
            EceMode::DECRYPT,
            keys,
            auth_secret,
            salt,
        )?;
        Self::ece_decrypt_records(&key, &nonce, rs, ciphertext)
    }

    fn ece_decrypt_records(
        key: &[u8],
        nonce: &[u8],
        rs: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let chunks = ciphertext.chunks(rs as usize);
        let records_count = chunks.len();
        let items = chunks
            .enumerate()
            .map(|(count, record)| {
                if record.len() <= ECE_TAG_LENGTH {
                    return Err(ErrorKind::BlockTooShort.into());
                }
                let iv = ece_generate_iv(nonce, count);
                let plaintext = ece_decrypt_record(key, &iv, record)?;
                let last_record = count == records_count - 1;
                Ok(Self::unpad(&plaintext, last_record)?.to_vec())
            })
            .collect::<Result<Vec<Vec<u8>>>>()?;
        // TODO: There was a way to do it without this last line.
        Ok(items.into_iter().flatten().collect::<Vec<u8>>())
    }

    fn needs_trailer(rs: u32, ciphertext_len: usize) -> bool;
    // Check that `plaintext.len() < PAD_SIZE` in the implementation.
    fn unpad(block: &[u8], last_record: bool) -> Result<&[u8]>;
    fn webpush_derive_key_and_nonce(
        ece_mode: EceMode,
        keys: KeysImpl,
        auth_secret: &[u8],
        salt: &[u8],
    ) -> Result<KeyAndNonce>;
}

/// Converts an encrypted record to a decrypted block.
fn ece_decrypt_record(key: &[u8], iv: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    assert!(record.len() > ECE_TAG_LENGTH);
    let block_len = record.len() - ECE_TAG_LENGTH;
    let data = &record[0..block_len];
    let tag = &record[block_len..];
    CryptoImpl::aes_gcm_128_decrypt(key, &iv, data, tag).map_err(|e| e.into())
}

/// Generates a 96-bit IV for decryption, 48 bits of which are populated.
fn ece_generate_iv(nonce: &[u8], counter: usize) -> [u8; ECE_NONCE_LENGTH] {
    let mut iv = [0u8; ECE_NONCE_LENGTH];
    let offset = ECE_NONCE_LENGTH - 8;
    iv[0..offset].copy_from_slice(&nonce[0..offset]);
    // Combine the remaining unsigned 64-bit integer with the record sequence
    // number using XOR. See the "nonce derivation" section of the draft.
    let mask = BigEndian::read_u64(&nonce[offset..]);
    BigEndian::write_u64(&mut iv[offset..], mask ^ (counter as u64));
    iv
}
