/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! Web Push encryption using the AES128GCM encoding scheme ([RFC8591](https://tools.ietf.org/html/rfc8291)).
//!
//! This module is meant for advanced use. For simple encryption/decryption, use the crate's top-level
//! [`encrypt`](crate::encrypt) and [`decrypt`](crate::decrypt) functions.

use crate::{
    common::*,
    crypto::{self, LocalKeyPair, RemotePublicKey},
    error::*,
    Cryptographer,
};
use byteorder::{BigEndian, ByteOrder};

// Each record has a 16 byte authentication tag and 1 padding delimiter byte.
// Thus, a record size of less than 18 could never store any plaintext.
const ECE_AES128GCM_MIN_RS: u32 = 18;
const ECE_AES128GCM_HEADER_LENGTH: usize = 21;
pub(crate) const ECE_AES128GCM_PAD_SIZE: usize = 1;

const ECE_WEBPUSH_AES128GCM_IKM_INFO_PREFIX: &str = "WebPush: info\0";
const ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH: usize = 144; // 14 (prefix len) + 65 (pub key len) * 2;

const ECE_WEBPUSH_IKM_LENGTH: usize = 32;
const ECE_AES128GCM_KEY_INFO: &str = "Content-Encoding: aes128gcm\0";
const ECE_AES128GCM_NONCE_INFO: &str = "Content-Encoding: nonce\0";

/// Encrypts a Web Push message using the "aes128gcm" scheme, with an explicit sender key.
///
/// It is the caller's responsibility to ensure that this function is used correctly,
/// where "correctly" means important cryptographic details like:
///
///    * use a new ephemeral local keypair for each encryption
///    * use a randomly-generated salt
///
/// In general-purpose AES128GM ECE, the "keyid" field in the header may be up to 255 octects
/// and provides a string that allows the application to find the right key material in some
/// application-defined way. We only currently support the specific scheme used by WebPush, where
/// the "keyid" is an ephemeral ECDH public key and always has a fixed length.
///
pub(crate) fn encrypt(
    local_prv_key: &dyn LocalKeyPair,
    remote_pub_key: &dyn RemotePublicKey,
    auth_secret: &[u8],
    plaintext: &[u8],
    mut params: WebPushParams,
) -> Result<Vec<u8>> {
    let cryptographer = crypto::holder::get_cryptographer();

    if plaintext.is_empty() {
        return Err(Error::ZeroPlaintext);
    }

    let salt = params.take_or_generate_salt(cryptographer)?;
    let (key, nonce) = derive_key_and_nonce(
        cryptographer,
        EceMode::ENCRYPT,
        local_prv_key,
        remote_pub_key,
        auth_secret,
        &salt,
    )?;

    // Encode the ephemeral public key in the "kid" header field.
    let keyid = local_prv_key.pub_as_raw()?;
    if keyid.len() != ECE_WEBPUSH_PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidKeyLength);
    }

    let header = Header {
        salt: &salt,
        rs: params.rs,
        keyid: &keyid,
    };

    // We always add at least one padding byte, for the delimiter.
    let padding = std::cmp::max(params.pad_length, ECE_AES128GCM_PAD_SIZE);

    // For now, everything must fit in a single record.
    // Calling code will ensure that this is the case.
    if params.rs < ECE_AES128GCM_MIN_RS {
        return Err(Error::InvalidRecordSize);
    }
    if plaintext.len() + padding + ECE_TAG_LENGTH > params.rs as usize {
        dbg!(format!(
            "Message content too long for a single record (rs={}, plaintext={}, padding={})",
            params.rs,
            plaintext.len(),
            padding
        ));
        return Err(Error::MultipleRecordsNotSupported);
    }
    let record = PlaintextRecord {
        plaintext,
        padding,
        sequence_number: 0,
        is_final: true,
    };

    let mut ciphertext = vec![0; header.encoded_size() + record.encrypted_size()];

    header.write_into(&mut ciphertext);
    record.encrypt_into(
        cryptographer,
        &key,
        &nonce,
        &mut ciphertext[header.encoded_size()..],
    )?;

    Ok(ciphertext)
}

/// Decrypts a Web Push message encrypted using the "aes128gcm" scheme.
///
pub(crate) fn decrypt(
    local_prv_key: &dyn LocalKeyPair,
    auth_secret: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cryptographer = crypto::holder::get_cryptographer();
    if ciphertext.is_empty() {
        return Err(Error::ZeroCiphertext);
    }

    // Buffer into which to write the output.
    // This will avoid any reallocations because plaintext will always be smaller than ciphertext.
    // We could calculate a tighter bound if memory usage is an issue in future.
    let mut output = Vec::<u8>::with_capacity(ciphertext.len());

    let header = Header::read_from(ciphertext)?;
    if ciphertext.len() == header.encoded_size() {
        return Err(Error::ZeroCiphertext);
    }

    // The `keyid` field must contain the serialized ephemeral public key.
    if header.keyid.len() != ECE_WEBPUSH_PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidKeyLength);
    }
    let remote_pub_key = cryptographer.import_public_key(&header.keyid)?;

    let (key, nonce) = derive_key_and_nonce(
        cryptographer,
        EceMode::DECRYPT,
        local_prv_key,
        &*remote_pub_key,
        auth_secret,
        header.salt,
    )?;

    // We'll re-use this buffer as scratch space for decrypting each record.
    // This is nice for memory usage, but actually the main motivation is to have the decryption
    // output a `PlaintextRecord` struct, which holds a borrowed slice of plaintext.
    // TODO: pre-allocate the final output buffer, and let `decrypt_from` write directly into it.
    let mut plaintext_buffer = vec![0u8; (header.rs as usize) - ECE_TAG_LENGTH];

    let records = ciphertext[header.encoded_size()..].chunks(header.rs as usize);

    let mut seen_final_record = false;
    for (sequence_number, ciphertext) in records.enumerate() {
        // The record marked as final must actually be the final record.
        // We check this inline in the loop because the loop consumes ownership of `records`,
        // which means we can't do a separate "did we consume all the records?" check after loop termination.
        // There's probably a way, but I didn't find it.
        if seen_final_record {
            return Err(Error::DecryptPadding);
        }
        let record = PlaintextRecord::decrypt_from(
            cryptographer,
            &key,
            &nonce,
            sequence_number,
            ciphertext,
            plaintext_buffer.as_mut_slice(),
        )?;
        if record.is_final {
            seen_final_record = true;
        }
        output.extend(record.plaintext)
    }
    if !seen_final_record {
        return Err(Error::DecryptTruncated);
    }

    Ok(output)
}

/// Encapsulates header data for aes128gcm encryption scheme.
///
/// The header is always written at the start of the encrypted data, like so:
///
/// ```txt
///    +-----------+--------+-----------+---------------+
///    | salt (16) | rs (4) | idlen (1) | keyid (idlen) |
///    +-----------+--------+-----------+---------------+
/// ```
///
/// To avoid copying data when parsing, this struct stores references to its
/// field, borrowed from the underlying data.
///
pub(crate) struct Header<'a> {
    salt: &'a [u8],
    rs: u32,
    keyid: &'a [u8],
}

impl<'a> Header<'a> {
    /// Read a `Header` from the data at the start of the given input buffer.
    ///
    fn read_from(input: &'a [u8]) -> Result<Header<'a>> {
        if input.len() < ECE_AES128GCM_HEADER_LENGTH {
            return Err(Error::HeaderTooShort);
        }

        let keyid_len = input[ECE_AES128GCM_HEADER_LENGTH - 1] as usize;
        if input.len() < ECE_AES128GCM_HEADER_LENGTH + keyid_len {
            return Err(Error::HeaderTooShort);
        }

        let salt = &input[0..ECE_SALT_LENGTH];
        let rs = BigEndian::read_u32(&input[ECE_SALT_LENGTH..]);
        if rs < ECE_AES128GCM_MIN_RS {
            return Err(Error::InvalidRecordSize);
        }
        let keyid = &input[ECE_AES128GCM_HEADER_LENGTH..ECE_AES128GCM_HEADER_LENGTH + keyid_len];

        Ok(Header { salt, rs, keyid })
    }

    /// Write this `Header` at the start of the given output buffer.
    ///
    /// This assumes that the buffer has sufficient space for the data, and will
    /// panic (via Rust's runtime safety checks) if it does not.
    ///
    pub fn write_into(&self, output: &mut [u8]) {
        output[0..ECE_SALT_LENGTH].copy_from_slice(self.salt);
        BigEndian::write_u32(&mut output[ECE_SALT_LENGTH..], self.rs);
        output[ECE_AES128GCM_HEADER_LENGTH - 1] = self.keyid.len() as u8;
        output[ECE_AES128GCM_HEADER_LENGTH..ECE_AES128GCM_HEADER_LENGTH + self.keyid.len()]
            .copy_from_slice(self.keyid);
    }

    /// Get the size occupied by this header when written to the encrypted data.
    ///
    pub fn encoded_size(&self) -> usize {
        ECE_AES128GCM_HEADER_LENGTH + self.keyid.len()
    }
}

/// Struct representing an individual plaintext record.
///
/// The encryption process splits up the input plaintext to fixed-size records,
/// each of which is encrypted independently. This struct encapsulates all the
/// data about a particular record. This diagram from the RFC may help you to
/// visualize how this data gets encrypted:
///
/// ```txt
///   +-----------+             content
///   |   data    |             any length up to rs-17 octets
///   +-----------+
///        |
///        v
///   +-----------+-----+       add a delimiter octet (0x01 or 0x02)
///   |   data    | pad |       then 0x00-valued octets to rs-16
///   +-----------+-----+       (or less on the last record)
///            |
///            v
///   +--------------------+    encrypt with AEAD_AES_128_GCM;
///   |    ciphertext      |    final size is rs;
///   +--------------------+    the last record can be smaller
/// ```
///
/// To avoid copying data when chunking a plaintext into multiple records, this struct
/// stores a reference to its portion of the plaintext, borrowed from the underlying data.
///
struct PlaintextRecord<'a> {
    /// The plaintext, to go at the start of the record.
    plaintext: &'a [u8],
    /// The amount of padding to be added to the end of the record.
    /// Always >= 1 in practice, because the first byte of padding is a delimiter.
    padding: usize,
    /// The position of this record in the overall sequence of records for some data.
    sequence_number: usize,
    /// Whether this is the final record in the data.
    is_final: bool,
}

impl<'a> PlaintextRecord<'a> {
    /// Decrypt a single record from the given ciphertext, into its corresponding plaintext.
    ///
    /// The caller must provide a buffer with sufficient space to store the decrypted plaintext,
    /// and this method will panic (via Rust's runtime safety checks) if there is insufficient
    /// space available.
    ///
    pub(crate) fn decrypt_from(
        cryptographer: &dyn Cryptographer,
        key: &[u8],
        nonce: &[u8],
        sequence_number: usize,
        ciphertext: &[u8],
        plaintext_buffer: &'a mut [u8],
    ) -> Result<Self> {
        if ciphertext.len() <= ECE_TAG_LENGTH {
            return Err(Error::BlockTooShort);
        }
        let iv = generate_iv_for_record(&nonce, sequence_number);
        // It would be nice if we could decrypt directly into `plaintext_buffer` here,
        // but that will require some refactoring in the crypto backend.
        let padded_plaintext = cryptographer.aes_gcm_128_decrypt(&key, &iv, &ciphertext)?;
        // Scan backwards for the first non-zero byte from the end of the data, which delimits the padding.
        let padding_delimiter_idx = padded_plaintext
            .iter()
            .rposition(|&b| b != 0u8)
            .ok_or(Error::DecryptPadding)?;
        // The padding delimiter tells is whether this is the final record.
        let is_final = match padded_plaintext[padding_delimiter_idx] {
            1 => false,
            2 => true,
            _ => return Err(Error::DecryptPadding),
        };
        // Everything before the padding delimiter is the plaintext.
        plaintext_buffer[0..padding_delimiter_idx]
            .copy_from_slice(&padded_plaintext[0..padding_delimiter_idx]);
        // That's it!
        Ok(PlaintextRecord {
            plaintext: &plaintext_buffer[0..padding_delimiter_idx],
            padding: padded_plaintext.len() - padding_delimiter_idx,
            sequence_number,
            is_final,
        })
    }

    /// Encrypt this record into the given output buffer.
    ///
    /// The caller must provide a buffer with sufficient space to store the encrypted data,
    /// and this method will panic (via Rust's runtime safety checks) if there is insufficient
    /// space available.
    ///
    pub(crate) fn encrypt_into(
        &self,
        cryptographer: &dyn Cryptographer,
        key: &[u8],
        nonce: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        // We're going to use the output buffer as scratch space for padding the plaintext.
        // Since the ciphertext is always longer than the plaintext, there will definitely
        // be enough space.
        let padded_plaintext_len = self.plaintext.len() + self.padding;
        // Plaintext goes at the start of the buffer.
        output[0..self.plaintext.len()].copy_from_slice(self.plaintext);
        // The first byte of padding is always the delimiter.
        assert!(self.padding >= 1);
        output[self.plaintext.len()] = if self.is_final { 2 } else { 1 };
        // And the rest of the padding is all zeroes.
        output[self.plaintext.len() + 1..padded_plaintext_len].fill(0);
        // Now we can encrypt!
        let iv = generate_iv_for_record(&nonce, self.sequence_number);
        let ciphertext =
            cryptographer.aes_gcm_128_encrypt(&key, &iv, &output[0..padded_plaintext_len])?;
        output[0..ciphertext.len()].copy_from_slice(&ciphertext);
        Ok(ciphertext.len())
    }

    pub(crate) fn encrypted_size(&self) -> usize {
        self.plaintext.len() + self.padding + ECE_TAG_LENGTH
    }
}

/// Derives the "aes128gcm" decryption key and nonce given the receiver private
/// key, sender public key, authentication secret, and sender salt.
fn derive_key_and_nonce(
    cryptographer: &dyn Cryptographer,
    ece_mode: EceMode,
    local_prv_key: &dyn LocalKeyPair,
    remote_pub_key: &dyn RemotePublicKey,
    auth_secret: &[u8],
    salt: &[u8],
) -> Result<KeyAndNonce> {
    if auth_secret.len() != ECE_WEBPUSH_AUTH_SECRET_LENGTH {
        return Err(Error::InvalidAuthSecret);
    }
    if salt.len() != ECE_SALT_LENGTH {
        return Err(Error::InvalidSalt);
    }

    let shared_secret = cryptographer.compute_ecdh_secret(remote_pub_key, local_prv_key)?;
    let raw_remote_pub_key = remote_pub_key.as_raw()?;
    let raw_local_pub_key = local_prv_key.pub_as_raw()?;

    // The "aes128gcm" scheme includes the sender and receiver public keys in
    // the info string when deriving the Web Push IKM.
    let ikm_info = match ece_mode {
        EceMode::ENCRYPT => generate_info(&raw_remote_pub_key, &raw_local_pub_key),
        EceMode::DECRYPT => generate_info(&raw_local_pub_key, &raw_remote_pub_key),
    }?;
    let ikm = cryptographer.hkdf_sha256(
        auth_secret,
        &shared_secret,
        &ikm_info,
        ECE_WEBPUSH_IKM_LENGTH,
    )?;
    let key = cryptographer.hkdf_sha256(
        salt,
        &ikm,
        ECE_AES128GCM_KEY_INFO.as_bytes(),
        ECE_AES_KEY_LENGTH,
    )?;
    let nonce = cryptographer.hkdf_sha256(
        salt,
        &ikm,
        ECE_AES128GCM_NONCE_INFO.as_bytes(),
        ECE_NONCE_LENGTH,
    )?;
    Ok((key, nonce))
}

// The "aes128gcm" IKM info string is "WebPush: info\0", followed by the
// receiver and sender public keys.
fn generate_info(
    raw_recv_pub_key: &[u8],
    raw_sender_pub_key: &[u8],
) -> Result<[u8; ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH]> {
    let mut info = [0u8; ECE_WEBPUSH_AES128GCM_IKM_INFO_LENGTH];
    let prefix = ECE_WEBPUSH_AES128GCM_IKM_INFO_PREFIX.as_bytes();
    let mut offset = prefix.len();
    info[0..offset].copy_from_slice(prefix);
    info[offset..offset + ECE_WEBPUSH_PUBLIC_KEY_LENGTH].copy_from_slice(raw_recv_pub_key);
    offset += ECE_WEBPUSH_PUBLIC_KEY_LENGTH;
    info[offset..].copy_from_slice(raw_sender_pub_key);
    Ok(info)
}
