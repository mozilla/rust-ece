/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Silence deprecation warnings from generic-array < 1.0 used by aes-gcm 0.10
// This will be resolved when upgrading to aes-gcm 0.11+ (currently RC)
#![allow(deprecated)]

use crate::{
    crypto::{Cryptographer, EcKeyComponents, LocalKeyPair, RemotePublicKey},
    error::*,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use hkdf::Hkdf;
use p256::{
    ecdh::diffie_hellman,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey, SecretKey,
};
use rand_core::OsRng;
use sha2::Sha256;
use std::{any::Any, fmt};

// Types and methods may appear unused when both backends are enabled,
// but they're required by the Cryptographer trait implementation
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct RustCryptoRemotePublicKey {
    public_key: PublicKey,
    raw_pub_key: Vec<u8>,
}

#[allow(dead_code)]
impl RustCryptoRemotePublicKey {
    fn from_raw(raw: &[u8]) -> Result<Self> {
        let encoded_point = EncodedPoint::from_bytes(raw).map_err(|_| Error::InvalidKeyLength)?;
        let public_key = PublicKey::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or(Error::InvalidKeyLength)?;
        Ok(RustCryptoRemotePublicKey {
            public_key,
            raw_pub_key: raw.to_vec(),
        })
    }

    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl RemotePublicKey for RustCryptoRemotePublicKey {
    fn as_raw(&self) -> Result<Vec<u8>> {
        Ok(self.raw_pub_key.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct RustCryptoLocalKeyPair {
    secret_key: SecretKey,
}

impl fmt::Debug for RustCryptoLocalKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}",
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE,
                self.secret_key.to_bytes()
            )
        )
    }
}

#[allow(dead_code)]
impl RustCryptoLocalKeyPair {
    /// Generate a random local key pair using p256's RNG.
    fn generate_random() -> Result<Self> {
        let secret_key = SecretKey::random(&mut OsRng);
        Ok(RustCryptoLocalKeyPair { secret_key })
    }

    fn from_raw_components(components: &EcKeyComponents) -> Result<Self> {
        // Verify the public key matches the private key
        let private_bytes = components.private_key();
        if private_bytes.len() != 32 {
            return Err(Error::InvalidKeyLength);
        }

        let secret_key =
            SecretKey::from_slice(private_bytes).map_err(|_| Error::InvalidKeyLength)?;

        // Verify the public key component matches
        let derived_public = secret_key.public_key();
        let derived_raw = derived_public.to_encoded_point(false);

        if derived_raw.as_bytes() != components.public_key() {
            return Err(Error::InvalidKeyLength);
        }

        Ok(RustCryptoLocalKeyPair { secret_key })
    }

    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl LocalKeyPair for RustCryptoLocalKeyPair {
    /// Export the public key component in the binary uncompressed point representation.
    fn pub_as_raw(&self) -> Result<Vec<u8>> {
        let public_key = self.secret_key.public_key();
        let encoded = public_key.to_encoded_point(false);
        Ok(encoded.as_bytes().to_vec())
    }

    fn raw_components(&self) -> Result<EcKeyComponents> {
        let private_key = self.secret_key.to_bytes();
        let public_key = self.pub_as_raw()?;
        Ok(EcKeyComponents::new(private_key.to_vec(), public_key))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[allow(dead_code)]
pub struct RustCryptoCryptographer;

impl Cryptographer for RustCryptoCryptographer {
    fn generate_ephemeral_keypair(&self) -> Result<Box<dyn LocalKeyPair>> {
        Ok(Box::new(RustCryptoLocalKeyPair::generate_random()?))
    }

    fn import_key_pair(&self, components: &EcKeyComponents) -> Result<Box<dyn LocalKeyPair>> {
        Ok(Box::new(RustCryptoLocalKeyPair::from_raw_components(
            components,
        )?))
    }

    fn import_public_key(&self, raw: &[u8]) -> Result<Box<dyn RemotePublicKey>> {
        Ok(Box::new(RustCryptoRemotePublicKey::from_raw(raw)?))
    }

    fn compute_ecdh_secret(
        &self,
        remote: &dyn RemotePublicKey,
        local: &dyn LocalKeyPair,
    ) -> Result<Vec<u8>> {
        let local_any = local.as_any();
        let local = local_any
            .downcast_ref::<RustCryptoLocalKeyPair>()
            .ok_or(Error::CryptoError)?;

        let remote_any = remote.as_any();
        let remote = remote_any
            .downcast_ref::<RustCryptoRemotePublicKey>()
            .ok_or(Error::CryptoError)?;

        // Perform ECDH using the diffie_hellman function
        let shared_secret = diffie_hellman(
            local.secret_key.to_nonzero_scalar(),
            remote.public_key.as_affine(),
        );

        Ok(shared_secret.raw_secret_bytes().to_vec())
    }

    fn hkdf_sha256(&self, salt: &[u8], secret: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
        let (_, hk) = Hkdf::<Sha256>::extract(Some(salt), secret);
        let mut okm = vec![0u8; len];
        hk.expand(info, &mut okm).map_err(|_| Error::CryptoError)?;
        Ok(okm)
    }

    fn aes_gcm_128_encrypt(&self, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 16 {
            return Err(Error::CryptoError);
        }
        if iv.len() != 12 {
            return Err(Error::CryptoError);
        }

        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Error::CryptoError)?;
        let nonce = Nonce::from_slice(iv);

        // AES-GCM encrypt returns [ciphertext || tag]
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|_| Error::CryptoError)?;

        Ok(ciphertext)
    }

    fn aes_gcm_128_decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>> {
        if key.len() != 16 {
            return Err(Error::CryptoError);
        }
        if iv.len() != 12 {
            return Err(Error::CryptoError);
        }

        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| Error::CryptoError)?;
        let nonce = Nonce::from_slice(iv);

        // aes-gcm crate expects [ciphertext || tag] format
        let plaintext = cipher
            .decrypt(nonce, ciphertext_and_tag)
            .map_err(|_| Error::CryptoError)?;

        Ok(plaintext)
    }

    fn random_bytes(&self, dest: &mut [u8]) -> Result<()> {
        use rand_core::RngCore;
        OsRng.fill_bytes(dest);
        Ok(())
    }
}
