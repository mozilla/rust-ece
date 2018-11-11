/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate ece_crypto;
extern crate hkdf;
#[macro_use]
extern crate lazy_static;
extern crate openssl;
extern crate sha2;

use ece_crypto::*;

use hkdf::Hkdf;
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use sha2::Sha256;

lazy_static! {
    static ref GROUP_P256: EcGroup = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
}

type Result<T> = std::result::Result<T, Error>;

pub fn generate_keys() -> Result<(OpenSSLLocalKeyPair, OpenSSLLocalKeyPair)> {
    let local_ec = EcKey::generate(&GROUP_P256)?;
    let local_key = OpenSSLLocalKeyPair { ec_key: local_ec };
    let remote_ec = EcKey::generate(&GROUP_P256)?;
    let remote_key = OpenSSLLocalKeyPair { ec_key: remote_ec };
    Ok((local_key, remote_key))
}

pub struct OpenSSLRemotePublicKey {
    raw_pub_key: Vec<u8>,
}

impl OpenSSLRemotePublicKey {
    fn to_pkey(&self) -> Result<PKey<Public>> {
        let mut bn_ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&GROUP_P256, &self.raw_pub_key, &mut bn_ctx)?;
        let ec = EcKey::from_public_key(&GROUP_P256, &point)?;
        PKey::from_ec_key(ec).map_err(|e| e.into())
    }

    pub fn from_raw(raw: &[u8]) -> Self {
        OpenSSLRemotePublicKey {
            raw_pub_key: raw.to_vec(),
        }
    }
}

impl RemotePublicKey for OpenSSLRemotePublicKey {
    fn as_raw(&self) -> Result<Vec<u8>> {
        Ok(self.raw_pub_key.to_vec())
    }
}

pub struct OpenSSLLocalKeyPair {
    ec_key: EcKey<Private>,
}

impl OpenSSLLocalKeyPair {
    pub fn new(raw_ec_prv_key: &[u8]) -> Result<Self> {
        let d = BigNum::from_slice(raw_ec_prv_key)?;
        let bn_ctx = BigNumContext::new()?;
        let mut pub_key_point = EcPoint::new(&GROUP_P256)?;
        pub_key_point.mul_generator(&GROUP_P256, &d, &bn_ctx)?;
        let ec_key = EcKey::from_private_components(&GROUP_P256, &d, &pub_key_point)?;
        Ok(OpenSSLLocalKeyPair { ec_key })
    }

    fn to_pkey(&self) -> Result<PKey<Private>> {
        PKey::from_ec_key(self.ec_key.clone()).map_err(|e| e.into())
    }
}

impl LocalKeyPair for OpenSSLLocalKeyPair {
    fn pub_as_raw(&self) -> Result<Vec<u8>> {
        let pub_key_point = self.ec_key.public_key();
        let mut bn_ctx = BigNumContext::new()?;
        let uncompressed =
            pub_key_point.to_bytes(&GROUP_P256, PointConversionForm::UNCOMPRESSED, &mut bn_ctx)?;
        Ok(uncompressed)
    }
}

pub struct OpenSSLCrypto;
impl Crypto for OpenSSLCrypto {
    type RemotePublicKey = OpenSSLRemotePublicKey;
    type LocalKeyPair = OpenSSLLocalKeyPair;

    fn public_key_from_raw(raw: &[u8]) -> Result<Self::RemotePublicKey> {
        Ok(OpenSSLRemotePublicKey::from_raw(raw))
    }

    fn generate_ephemeral_keypair() -> Result<Self::LocalKeyPair> {
        let ec_key = EcKey::generate(&GROUP_P256)?;
        Ok(OpenSSLLocalKeyPair { ec_key })
    }

    fn compute_ecdh_secret(
        remote: &Self::RemotePublicKey,
        local: &Self::LocalKeyPair,
    ) -> Result<Vec<u8>> {
        let private = local.to_pkey()?;
        let public = remote.to_pkey()?;
        let mut deriver = Deriver::new(&private)?;
        deriver.set_peer(&public)?;
        let shared_key = deriver.derive_to_vec()?;
        Ok(shared_key)
    }

    fn hkdf_sha256(salt: &[u8], secret: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
        let hk = Hkdf::<Sha256>::extract(Some(&salt[..]), &secret);
        let mut okm = vec![0u8; len];
        hk.expand(&info, &mut okm).unwrap();
        Ok(okm)
    }

    fn aes_gcm_128_encrypt(key: &[u8], iv: &[u8], data: &[u8], tag_len: usize) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_gcm();
        let mut c = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;
        let mut out = vec![0u8; data.len() + cipher.block_size()];
        let count = c.update(data, &mut out)?;
        let rest = c.finalize(&mut out[count..])?;
        let mut tag = vec![0u8; tag_len];
        c.get_tag(&mut tag)?;
        out.truncate(count + rest);
        out.append(&mut tag);
        Ok(out)
    }

    fn aes_gcm_128_decrypt(key: &[u8], iv: &[u8], data: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::aes_128_gcm();
        let mut c = Crypter::new(cipher, Mode::Decrypt, key, Some(iv))?;
        let mut out = vec![0u8; data.len() + cipher.block_size()];
        let count = c.update(data, &mut out)?;
        c.set_tag(tag)?;
        let rest = c.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    }

    fn random(dest: &mut [u8]) -> Result<()> {
        Ok(rand_bytes(dest)?)
    }
}
