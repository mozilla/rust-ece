/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::error::*;

pub trait RemotePublicKey {
    /// Import the key component in the
    /// binary uncompressed point representation.
    fn from_raw(raw: &[u8]) -> Result<Self>
    where
        Self: Sized;
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
    /// Import a keypair from its raw components.
    fn from_raw_components(components: &EcKeyComponents) -> Result<Self>
    where
        Self: Sized;
    /// Export the raw components of the keypair.
    fn raw_components(&self) -> Result<(EcKeyComponents)>;
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serializable-keys",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum EcCurve {
    P256,
}

impl Default for EcCurve {
    fn default() -> Self {
        EcCurve::P256
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serializable-keys",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct EcKeyComponents {
    // The curve is only kept in case the ECE standard changes in the future.
    curve: EcCurve,
    // The `d` value of the EC Key.
    private_key: Vec<u8>,
    // The uncompressed x,y-representation of the public component of the EC Key.
    public_key: Vec<u8>,
}

impl EcKeyComponents {
    pub fn new<T: Into<Vec<u8>>>(private_key: T, public_key: T) -> Self {
        EcKeyComponents {
            private_key: private_key.into(),
            public_key: public_key.into(),
            curve: Default::default(),
        }
    }
    pub fn curve(&self) -> &EcCurve {
        &self.curve
    }
    /// The `d` value of the EC Key.
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
    /// The uncompressed x,y-representation of the public component of the EC Key.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

pub trait Crypto: Sized {
    type RemotePublicKey: RemotePublicKey;
    type LocalKeyPair: LocalKeyPair;
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
