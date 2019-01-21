/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::error::*;

pub trait RemotePublicKey {
    /// Export the key component in the
    /// binary uncompressed point representation.
    fn as_raw(&self) -> Result<Vec<u8>>;
}

pub trait LocalKeyPair {
    /// Generate a random local key pair.
    fn generate_random() -> Result<Self>
    where
        Self: Sized;
    /// Export the public key component in the
    /// binary uncompressed point representation.
    fn pub_as_raw(&self) -> Result<Vec<u8>>;
}

pub trait Crypto: Sized {
    type RemotePublicKey: RemotePublicKey;
    type LocalKeyPair: LocalKeyPair;
    /// Construct a `RemotePublicKey` from raw bytes typically obtained in a HTTP ECE header.
    fn public_key_from_raw(raw: &[u8]) -> Result<Self::RemotePublicKey>;
    fn generate_ephemeral_keypair() -> Result<Self::LocalKeyPair>;
    fn compute_ecdh_secret(
        remote: &Self::RemotePublicKey,
        local: &Self::LocalKeyPair,
    ) -> Result<Vec<u8>>;
    fn hkdf_sha256(salt: &[u8], secret: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>>;
    /// Should return [ciphertext, auth_tag].
    fn aes_gcm_128_encrypt(key: &[u8], iv: &[u8], data: &[u8], tag_len: usize) -> Result<Vec<u8>>;
    fn aes_gcm_128_decrypt(key: &[u8], iv: &[u8], data: &[u8], tag: &[u8]) -> Result<Vec<u8>>;
    fn random(dest: &mut [u8]) -> Result<()>;
}
