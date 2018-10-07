/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate failure;

pub type Error = failure::Error;
type Result<T> = std::result::Result<T, Error>;

pub trait RemotePublicKey {
    /// From raw bytes obtained in a HTTP ECE header.
    fn from_raw(raw: &[u8]) -> Result<Box<Self>>
    where
        Self: Sized;
    fn as_raw(&self) -> Result<Vec<u8>>;
}

pub trait LocalKeyPair {
    fn generate_ephemeral() -> Result<Box<Self>>
    where
        Self: Sized;
    /// Export the public key component in the
    /// binary uncompressed point representation.
    fn pub_as_raw(&self) -> Result<Vec<u8>>;
}

pub trait Crypto {
    type RemotePublicKey: RemotePublicKey;
    type LocalKeyPair: LocalKeyPair;
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
