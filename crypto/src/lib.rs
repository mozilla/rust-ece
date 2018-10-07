/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate failure;

pub type Error = failure::Error;

pub trait Keys {
    fn compute_ecdh_secret(&self) -> Result<Vec<u8>, Error>;
    fn raw_remote_pub_key(&self) -> Result<Vec<u8>, Error>;
    /// Export the local KeyPair public key component in the
    /// binary uncompressed point representation.
    fn raw_local_pub_key(&self) -> Result<Vec<u8>, Error>;
}

pub trait Crypto<'a> {
    type PrivateKey;
    type PublicKey;
    type Keys: Keys;
    fn keys_with_ephemeral_local_keypair(remote_pub_key: Self::PublicKey) -> Result<Self::Keys, Error>;
    fn keys_with_existing_local_keypair(remote_pub_key: Self::PublicKey, local_prv_key: Self::PrivateKey) -> Result<Self::Keys, Error>;
    fn hkdf_sha256(salt: &[u8], secret: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Error>;
    fn aes_gcm_128_decrypt(
        key: &[u8],
        iv: &[u8],
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error>;
    // TODO: encrypt
}
