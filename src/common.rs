/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use byteorder::{BigEndian, ByteOrder};
use ece_crypto::{Crypto, LocalKeyPair, RemotePublicKey};
use error::*;
use std::cmp::min;

// From keys.h:
pub const ECE_AES_KEY_LENGTH: usize = 16;
pub const ECE_NONCE_LENGTH: usize = 12;

// From ece.h:
pub const ECE_SALT_LENGTH: usize = 16;
const ECE_TAG_LENGTH: usize = 16;
const ECE_WEBPUSH_PRIVATE_KEY_LENGTH: usize = 32;
pub const ECE_WEBPUSH_PUBLIC_KEY_LENGTH: usize = 65;
const ECE_WEBPUSH_AUTH_SECRET_LENGTH: usize = 16;

const ECE_AESGCM_MIN_RS: u8 = 3;
const ECE_AESGCM_PAD_SIZE: u8 = 2;

pub enum EceMode {
    ENCRYPT,
    DECRYPT,
}

pub type KeyAndNonce = (Vec<u8>, Vec<u8>);

pub trait EceWebPush {
    type Crypto: Crypto<LocalKeyPair = Self::LocalKeyPair, RemotePublicKey = Self::RemotePublicKey>;
    type LocalKeyPair: LocalKeyPair;
    type RemotePublicKey: RemotePublicKey;

    fn common_encrypt(
        local_prv_key: &Self::LocalKeyPair,
        remote_pub_key: &Self::RemotePublicKey,
        auth_secret: &[u8],
        salt: &[u8],
        rs: u32,
        pad_len: usize,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        if auth_secret.len() != ECE_WEBPUSH_AUTH_SECRET_LENGTH {
            return Err(ErrorKind::InvalidAuthSecret.into());
        }
        if salt.len() != ECE_SALT_LENGTH {
            return Err(ErrorKind::InvalidSalt.into());
        }
        if plaintext.len() == 0 {
            return Err(ErrorKind::ZeroPlaintext.into());
        }
        let (key, nonce) = Self::derive_key_and_nonce(
            EceMode::ENCRYPT,
            local_prv_key,
            remote_pub_key,
            auth_secret,
            salt,
        )?;
        let overhead = (Self::pad_size() + ECE_TAG_LENGTH) as u32;
        // The maximum amount of plaintext and padding that will fit into a full
        // block. The last block can be smaller.
        assert!(rs > overhead);
        let max_block_len = (rs - overhead) as usize;

        // TODO: We should at least try to guess the capacity beforehand by
        // re-implementing ece_ciphertext_max_length.
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        // The offset at which to start reading the plaintext.
        let mut plaintext_start = 0;
        let mut pad_len = pad_len;
        let mut last_record = false;
        let mut counter = 0;
        while !last_record {
            let block_pad_len = Self::min_block_pad_length(pad_len, max_block_len);
            assert!(block_pad_len <= pad_len);
            pad_len -= block_pad_len;

            // Fill the rest of the block with plaintext.
            assert!(block_pad_len <= max_block_len);
            let max_block_plaintext_len = max_block_len - block_pad_len;
            let plaintext_end = min(plaintext_start + max_block_plaintext_len, plaintext.len());

            // The length of the plaintext.
            assert!(plaintext_end >= plaintext_start);
            let block_plaintext_len = plaintext_end - plaintext_start;

            // The length of the plaintext and padding. This should never overflow
            // because `max_block_plaintext_len` accounts for `block_pad_len`.
            assert!(block_plaintext_len <= max_block_plaintext_len);
            let block_len = block_plaintext_len + block_pad_len;

            // The length of the full encrypted record, including the plaintext,
            // padding, padding delimiter, and auth tag. This should never overflow
            // because `max_block_len` accounts for `overhead`.
            assert!(block_len <= max_block_len);
            let record_len = block_len + overhead as usize;

            let plaintext_exhausted = plaintext_end >= plaintext.len();
            if pad_len == 0
                && plaintext_exhausted
                && !Self::needs_trailer(rs, ciphertext.len() + record_len)
            {
                // We've reached the last record when the padding and plaintext are
                // exhausted, and we don't need to write an empty trailing record.
                last_record = true;
            }

            if !last_record && block_len < max_block_len {
                // We have padding left, but not enough plaintext to form a full record.
                // Writing trailing padding-only records will still leak size information,
                // so we force the caller to pick a smaller padding length.
                return Err(ErrorKind::EncryptPadding.into());
            }

            let iv = generate_iv(&nonce, counter);
            let block = Self::pad(
                &plaintext[plaintext_start..plaintext_end],
                block_pad_len,
                last_record,
            )?;
            let mut record = Self::Crypto::aes_gcm_128_encrypt(&key, &iv, &block, ECE_TAG_LENGTH)?;
            ciphertext.append(&mut record);
            plaintext_start = plaintext_end;
            counter += 1;
        }
        Ok(ciphertext)
    }

    fn common_decrypt(
        local_prv_key: &Self::LocalKeyPair,
        remote_pub_key: &Self::RemotePublicKey,
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
        let (key, nonce) = Self::derive_key_and_nonce(
            EceMode::DECRYPT,
            local_prv_key,
            remote_pub_key,
            auth_secret,
            salt,
        )?;
        let chunks = ciphertext.chunks(rs as usize);
        let records_count = chunks.len();
        let items = chunks
            .enumerate()
            .map(|(count, record)| {
                if record.len() <= ECE_TAG_LENGTH {
                    return Err(ErrorKind::BlockTooShort.into());
                }
                let iv = generate_iv(&nonce, count);
                assert!(record.len() > ECE_TAG_LENGTH);
                let block_len = record.len() - ECE_TAG_LENGTH;
                let data = &record[0..block_len];
                let tag = &record[block_len..];
                let plaintext = Self::Crypto::aes_gcm_128_decrypt(&key, &iv, data, tag)?;
                let last_record = count == records_count - 1;
                if plaintext.len() < Self::pad_size() {
                    return Err(ErrorKind::BlockTooShort.into());
                }
                Ok(Self::unpad(&plaintext, last_record)?.to_vec())
            })
            .collect::<Result<Vec<Vec<u8>>>>()?;
        // TODO: There was a way to do it without this last line.
        Ok(items.into_iter().flatten().collect::<Vec<u8>>())
    }

    fn pad_size() -> usize;
    /// Calculates the padding so that the block contains at least one plaintext
    /// byte.
    fn min_block_pad_length(pad_len: usize, max_block_len: usize) -> usize;
    fn needs_trailer(rs: u32, ciphertext_len: usize) -> bool;
    fn pad(plaintext: &[u8], block_pad_len: usize, last_record: bool) -> Result<Vec<u8>>;
    fn unpad(block: &[u8], last_record: bool) -> Result<&[u8]>;
    fn derive_key_and_nonce(
        ece_mode: EceMode,
        local_prv_key: &Self::LocalKeyPair,
        remote_pub_key: &Self::RemotePublicKey,
        auth_secret: &[u8],
        salt: &[u8],
    ) -> Result<KeyAndNonce>;
}

// Calculates the padding so that the block contains at least one plaintext
// byte.
pub fn ece_min_block_pad_length(pad_len: usize, max_block_len: usize) -> usize {
    assert!(max_block_len >= 1);
    let mut block_pad_len = max_block_len - 1;
    if pad_len > 0 && block_pad_len == 0 {
        // If `max_block_len` is 1, we can only include 1 byte of data, so write
        // the padding first.
        block_pad_len += 1;
    }
    return if block_pad_len > pad_len {
        pad_len
    } else {
        block_pad_len
    };
}

/// Generates a 96-bit IV, 48 bits of which are populated.
fn generate_iv(nonce: &[u8], counter: usize) -> [u8; ECE_NONCE_LENGTH] {
    let mut iv = [0u8; ECE_NONCE_LENGTH];
    let offset = ECE_NONCE_LENGTH - 8;
    iv[0..offset].copy_from_slice(&nonce[0..offset]);
    // Combine the remaining unsigned 64-bit integer with the record sequence
    // number using XOR. See the "nonce derivation" section of the draft.
    let mask = BigEndian::read_u64(&nonce[offset..]);
    BigEndian::write_u64(&mut iv[offset..], mask ^ (counter as u64));
    iv
}
